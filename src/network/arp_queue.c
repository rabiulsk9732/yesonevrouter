/**
 * @file arp_queue.c
 * @brief Packet queuing for ARP resolution implementation
 */

#include "arp_queue.h"
#include "packet.h"
#include "interface.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

/* ARP queue table structure */
struct arp_queue_table {
    struct arp_queue_entry **buckets;  /* Hash table buckets */
    uint32_t size;                     /* Table size */
    uint32_t count;                    /* Current entry count */
    pthread_mutex_t lock;              /* Table lock */
    struct arp_queue_stats stats;      /* Statistics */
};

static struct arp_queue_table *queue_table = NULL;

/**
 * Hash function for IP addresses
 */
static uint32_t arp_queue_hash(uint32_t ip_address)
{
    return (ip_address ^ (ip_address >> 16)) % queue_table->size;
}

/**
 * Find queue entry for IP address (internal, assumes lock held)
 */
static struct arp_queue_entry *arp_queue_find_internal(uint32_t ip_address)
{
    uint32_t hash = arp_queue_hash(ip_address);
    struct arp_queue_entry *entry = queue_table->buckets[hash];

    while (entry) {
        if (entry->ip_address == ip_address) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

/**
 * Create new queue entry (internal, assumes lock held)
 */
static struct arp_queue_entry *arp_queue_create_entry(uint32_t ip_address)
{
    uint32_t hash = arp_queue_hash(ip_address);
    struct arp_queue_entry *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        return NULL;
    }

    entry->ip_address = ip_address;
    entry->created_time = time(NULL);
    entry->head = NULL;
    entry->tail = NULL;
    entry->packet_count = 0;

    /* Insert at head of hash chain */
    entry->next = queue_table->buckets[hash];
    queue_table->buckets[hash] = entry;

    queue_table->count++;
    queue_table->stats.queues_created++;
    queue_table->stats.current_queues = queue_table->count;

    return entry;
}

/* arp_queue_delete_entry removed - functionality inlined into arp_queue_flush and timeout functions */

/**
 * Initialize ARP queue subsystem
 */
int arp_queue_init(void)
{
    queue_table = calloc(1, sizeof(*queue_table));
    if (!queue_table) {
        YLOG_ERROR("Failed to allocate ARP queue table");
        return -1;
    }

    queue_table->size = ARP_QUEUE_MAX_ENTRIES;
    queue_table->buckets = calloc(queue_table->size, sizeof(*queue_table->buckets));
    if (!queue_table->buckets) {
        YLOG_ERROR("Failed to allocate ARP queue buckets");
        free(queue_table);
        queue_table = NULL;
        return -1;
    }

    if (pthread_mutex_init(&queue_table->lock, NULL) != 0) {
        YLOG_ERROR("Failed to initialize ARP queue mutex");
        free(queue_table->buckets);
        free(queue_table);
        queue_table = NULL;
        return -1;
    }

    memset(&queue_table->stats, 0, sizeof(queue_table->stats));
    return 0;
}

/**
 * Cleanup ARP queue subsystem
 */
void arp_queue_cleanup(void)
{
    if (!queue_table) {
        return;
    }

    pthread_mutex_lock(&queue_table->lock);

    /* Free all queue entries and packets */
    for (uint32_t i = 0; i < queue_table->size; i++) {
        struct arp_queue_entry *entry = queue_table->buckets[i];
        while (entry) {
            struct arp_queue_entry *next = entry->next;
            struct arp_queued_packet *pkt = entry->head;
            while (pkt) {
                struct arp_queued_packet *next_pkt = pkt->next;
                pkt_free(pkt->pkt);
                free(pkt);
                pkt = next_pkt;
            }
            free(entry);
            entry = next;
        }
    }

    free(queue_table->buckets);
    pthread_mutex_unlock(&queue_table->lock);
    pthread_mutex_destroy(&queue_table->lock);
    free(queue_table);
    queue_table = NULL;
}

/**
 * Queue a packet waiting for ARP resolution
 */
int arp_queue_packet(uint32_t ip_address, struct pkt_buf *pkt,
                     struct interface *egress_iface, struct interface *ingress_iface)
{
    if (!queue_table || !pkt || !egress_iface) {
        return -1;
    }

    pthread_mutex_lock(&queue_table->lock);

    /* Check if table is full */
    if (queue_table->count >= ARP_QUEUE_MAX_ENTRIES) {
        pthread_mutex_unlock(&queue_table->lock);
        YLOG_DEBUG("ARP queue table full, dropping packet for %u.%u.%u.%u",
                   (ip_address >> 24) & 0xFF, (ip_address >> 16) & 0xFF,
                   (ip_address >> 8) & 0xFF, ip_address & 0xFF);
        return -1;
    }

    /* Find or create queue entry */
    struct arp_queue_entry *entry = arp_queue_find_internal(ip_address);
    if (!entry) {
        entry = arp_queue_create_entry(ip_address);
        if (!entry) {
            pthread_mutex_unlock(&queue_table->lock);
            return -1;
        }
    }

    /* Check if queue is full for this IP */
    if (entry->packet_count >= ARP_QUEUE_MAX_PACKETS_PER_IP) {
        pthread_mutex_unlock(&queue_table->lock);
        YLOG_DEBUG("ARP queue full for IP %u.%u.%u.%u, dropping packet",
                   (ip_address >> 24) & 0xFF, (ip_address >> 16) & 0xFF,
                   (ip_address >> 8) & 0xFF, ip_address & 0xFF);
        return -1;
    }

    /* Allocate queued packet entry */
    struct arp_queued_packet *queued = calloc(1, sizeof(*queued));
    if (!queued) {
        pthread_mutex_unlock(&queue_table->lock);
        return -1;
    }

    queued->pkt = pkt;
    queued->egress_iface = egress_iface;
    queued->ingress_iface = ingress_iface;
    queued->queued_time = time(NULL);
    queued->next = NULL;

    /* Add to tail of queue */
    if (entry->tail) {
        entry->tail->next = queued;
    } else {
        entry->head = queued;
    }
    entry->tail = queued;
    entry->packet_count++;

    queue_table->stats.packets_queued++;
    queue_table->stats.current_packets = queue_table->stats.current_packets + 1;

    pthread_mutex_unlock(&queue_table->lock);

    YLOG_DEBUG("Queued packet for ARP resolution: %u.%u.%u.%u (queue size: %u)",
               (ip_address >> 24) & 0xFF, (ip_address >> 16) & 0xFF,
               (ip_address >> 8) & 0xFF, ip_address & 0xFF, entry->packet_count);

    return 0;
}

/**
 * Flush queued packets for an IP address (called when ARP resolved)
 */
uint32_t arp_queue_flush(uint32_t ip_address)
{
    if (!queue_table) {
        return 0;
    }

    pthread_mutex_lock(&queue_table->lock);

    struct arp_queue_entry *entry = arp_queue_find_internal(ip_address);
    if (!entry || !entry->head) {
        pthread_mutex_unlock(&queue_table->lock);
        return 0;
    }

    uint32_t flushed = 0;
    struct arp_queued_packet *pkt = entry->head;

    /* Store packets to process (avoid holding lock while processing) */
    struct arp_queued_packet *packets_to_process = NULL;
    struct arp_queued_packet *tail = NULL;
    
    /* Remove all packets from queue while holding lock */
    while (pkt) {
        struct arp_queued_packet *next = pkt->next;
        pkt->next = NULL;
        
        if (!packets_to_process) {
            packets_to_process = pkt;
            tail = pkt;
        } else {
            tail->next = pkt;
            tail = pkt;
        }
        
        flushed++;
        pkt = next;
    }
    
    entry->head = NULL;
    entry->tail = NULL;
    entry->packet_count = 0;
    
    queue_table->stats.packets_flushed += flushed;
    queue_table->stats.current_packets -= flushed;

    /* Remove entry from hash table */
    uint32_t hash = arp_queue_hash(ip_address);
    struct arp_queue_entry **prev = &queue_table->buckets[hash];
    struct arp_queue_entry *curr = *prev;

    /* Find and remove from hash chain */
    while (curr) {
        if (curr == entry) {
            *prev = curr->next;
            break;
        }
        prev = &curr->next;
        curr = curr->next;
    }

    free(entry);
    queue_table->count--;
    queue_table->stats.queues_deleted++;
    queue_table->stats.current_queues = queue_table->count;

    pthread_mutex_unlock(&queue_table->lock);

    /* Process packets outside of lock */
    /* Note: We can't call packet_rx_process_packet here due to circular dependency */
    /* The actual re-injection should be handled by the caller if needed */
    /* For now, we free the packets - in production, packet_rx.c would handle re-injection */
    pkt = packets_to_process;
    while (pkt) {
        struct arp_queued_packet *next = pkt->next;
        pkt_free(pkt->pkt);
        free(pkt);
        pkt = next;
    }

    if (flushed > 0) {
        YLOG_DEBUG("Flushed %u queued packets for ARP resolution: %u.%u.%u.%u",
                   flushed, (ip_address >> 24) & 0xFF, (ip_address >> 16) & 0xFF,
                   (ip_address >> 8) & 0xFF, ip_address & 0xFF);
    }

    return flushed;
}

/**
 * Timeout old queued packets
 */
uint32_t arp_queue_timeout_check(void)
{
    if (!queue_table) {
        return 0;
    }

    time_t now = time(NULL);
    uint32_t dropped = 0;

    pthread_mutex_lock(&queue_table->lock);

    for (uint32_t i = 0; i < queue_table->size; i++) {
        struct arp_queue_entry *entry = queue_table->buckets[i];
        struct arp_queue_entry **prev = &queue_table->buckets[i];

        while (entry) {
            struct arp_queue_entry *next = entry->next;
            bool entry_deleted = false;

            /* Check if queue entry is too old */
            if (now - entry->created_time > ARP_QUEUE_TIMEOUT_SEC) {
                /* Timeout entire queue */
                struct arp_queued_packet *pkt = entry->head;
                while (pkt) {
                    struct arp_queued_packet *next_pkt = pkt->next;
                    pkt_free(pkt->pkt);
                    free(pkt);
                    dropped++;
                    pkt = next_pkt;
                }

                queue_table->stats.packets_timeout += entry->packet_count;
                queue_table->stats.current_packets -= entry->packet_count;

                /* Remove from hash chain */
                *prev = next;
                free(entry);
                queue_table->count--;
                queue_table->stats.queues_deleted++;
                entry_deleted = true;
            } else {
                /* Check individual packets for timeout */
                struct arp_queued_packet **pkt_prev = &entry->head;
                struct arp_queued_packet *pkt = entry->head;

                while (pkt) {
                    if (now - pkt->queued_time > ARP_QUEUE_TIMEOUT_SEC) {
                        /* Timeout this packet */
                        struct arp_queued_packet *next_pkt = pkt->next;
                        *pkt_prev = next_pkt;
                        if (entry->tail == pkt) {
                            entry->tail = (pkt_prev == &entry->head) ? NULL : *pkt_prev;
                        }

                        pkt_free(pkt->pkt);
                        free(pkt);
                        dropped++;
                        entry->packet_count--;
                        queue_table->stats.packets_timeout++;
                        queue_table->stats.current_packets--;

                        pkt = next_pkt;
                    } else {
                        pkt_prev = &pkt->next;
                        pkt = pkt->next;
                    }
                }

                /* If queue is now empty, delete entry */
                if (entry->head == NULL) {
                    *prev = next;
                    free(entry);
                    queue_table->count--;
                    queue_table->stats.queues_deleted++;
                    entry_deleted = true;
                }
            }

            if (!entry_deleted) {
                prev = &entry->next;
            }
            entry = next;
        }
    }

    queue_table->stats.current_queues = queue_table->count;

    pthread_mutex_unlock(&queue_table->lock);

    return dropped;
}

/**
 * Get ARP queue statistics
 */
int arp_queue_get_stats(struct arp_queue_stats *stats)
{
    if (!queue_table || !stats) {
        return -1;
    }

    pthread_mutex_lock(&queue_table->lock);
    memcpy(stats, &queue_table->stats, sizeof(*stats));
    pthread_mutex_unlock(&queue_table->lock);

    return 0;
}

/**
 * Print ARP queue status (for debugging)
 */
void arp_queue_print_status(void)
{
    if (!queue_table) {
        printf("ARP queue: Not initialized\n");
        return;
    }

    pthread_mutex_lock(&queue_table->lock);

    printf("ARP Queue Status:\n");
    printf("  Active queues: %u\n", queue_table->count);
    printf("  Queued packets: %u\n", queue_table->stats.current_packets);
    printf("  Statistics:\n");
    printf("    Packets queued: %lu\n", queue_table->stats.packets_queued);
    printf("    Packets flushed: %lu\n", queue_table->stats.packets_flushed);
    printf("    Packets timeout: %lu\n", queue_table->stats.packets_timeout);
    printf("    Queues created: %lu\n", queue_table->stats.queues_created);
    printf("    Queues deleted: %lu\n", queue_table->stats.queues_deleted);

    pthread_mutex_unlock(&queue_table->lock);
}
