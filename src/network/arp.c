/**
 * @file arp.c
 * @brief ARP (Address Resolution Protocol) implementation
 */

#include "arp.h"
#include "arp_queue.h"
#include "interface.h"
#include "packet.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>

#ifdef HAVE_DPDK
#include <rte_ether.h>
#include <rte_arp.h>
#else
#include <net/ethernet.h>
#endif

/* ARP table structure */
struct arp_table {
    struct arp_entry **buckets;     /* Hash table buckets */
    uint32_t size;                  /* Current table size */
    uint32_t count;                 /* Current entry count */
    pthread_mutex_t lock;           /* Table lock */
    struct arp_stats stats;         /* Statistics */
};

static struct arp_table *arp_table = NULL;

/**
 * Hash function for IP addresses
 */
static uint32_t arp_hash(uint32_t ip_address)
{
    /* Simple hash function - can be improved */
    return (ip_address ^ (ip_address >> 16)) % arp_table->size;
}

/**
 * Initialize ARP subsystem
 */
int arp_init(void)
{
    arp_table = calloc(1, sizeof(*arp_table));
    if (!arp_table) {
        YLOG_ERROR("Failed to allocate ARP table");
        return -1;
    }

    arp_table->size = ARP_TABLE_SIZE;
    arp_table->buckets = calloc(arp_table->size, sizeof(struct arp_entry *));
    if (!arp_table->buckets) {
        YLOG_ERROR("Failed to allocate ARP table buckets");
        free(arp_table);
        arp_table = NULL;
        return -1;
    }

    if (pthread_mutex_init(&arp_table->lock, NULL) != 0) {
        YLOG_ERROR("Failed to initialize ARP table mutex");
        free(arp_table->buckets);
        free(arp_table);
        arp_table = NULL;
        return -1;
    }

    memset(&arp_table->stats, 0, sizeof(arp_table->stats));

    /* YLOG_INFO("ARP subsystem initialized (table size: %u)", arp_table->size); */
    return 0;
}

/**
 * Cleanup ARP subsystem
 */
void arp_cleanup(void)
{
    if (!arp_table) {
        return;
    }

    pthread_mutex_lock(&arp_table->lock);

    /* Free all entries */
    for (uint32_t i = 0; i < arp_table->size; i++) {
        struct arp_entry *entry = arp_table->buckets[i];
        while (entry) {
            struct arp_entry *next = entry->next;
            free(entry);
            entry = next;
        }
    }

    free(arp_table->buckets);

    pthread_mutex_unlock(&arp_table->lock);
    pthread_mutex_destroy(&arp_table->lock);

    free(arp_table);
    arp_table = NULL;

    YLOG_INFO("ARP subsystem cleaned up");
}

/**
 * Lookup ARP entry by IP address (internal, not thread-safe)
 */
static struct arp_entry *arp_table_lookup_internal(uint32_t ip_address)
{
    uint32_t hash = arp_hash(ip_address);
    struct arp_entry *entry = arp_table->buckets[hash];

    while (entry) {
        if (entry->ip_address == ip_address) {
            return entry;
        }
        entry = entry->next;
    }

    return NULL;
}

/**
 * Add or update ARP entry
 */
int arp_add_entry(uint32_t ip_address, const uint8_t *mac_address,
                  uint32_t ifindex, enum arp_state state)
{
    if (!arp_table || !mac_address) {
        return -1;
    }

    pthread_mutex_lock(&arp_table->lock);

    struct arp_entry *entry = arp_table_lookup_internal(ip_address);

    if (entry) {
        /* Update existing entry */
        memcpy(entry->mac_address, mac_address, 6);
        entry->state = state;
        entry->last_seen = time(NULL);
        entry->ifindex = ifindex;
        entry->retries = 0;
    } else {
        /* Create new entry */
        if (arp_table->count >= ARP_MAX_ENTRIES) {
            pthread_mutex_unlock(&arp_table->lock);
            YLOG_WARNING("ARP table full, cannot add entry");
            return -1;
        }

        entry = calloc(1, sizeof(*entry));
        if (!entry) {
            pthread_mutex_unlock(&arp_table->lock);
            return -1;
        }

        entry->ip_address = ip_address;
        memcpy(entry->mac_address, mac_address, 6);
        entry->state = state;
        entry->created = time(NULL);
        entry->last_seen = time(NULL);
        entry->ifindex = ifindex;
        entry->retries = 0;

        /* Insert into hash table */
        uint32_t hash = arp_hash(ip_address);
        entry->next = arp_table->buckets[hash];
        arp_table->buckets[hash] = entry;

        arp_table->count++;
        arp_table->stats.current_entries++;
        arp_table->stats.entries_created++;
    }

    pthread_mutex_unlock(&arp_table->lock);
    return 0;
}

/**
 * Lookup MAC address for IP address (LOCKED version - control plane)
 */
int arp_lookup(uint32_t ip_address, uint8_t *mac_address)
{
    if (!arp_table || !mac_address) {
        return -1;
    }

    pthread_mutex_lock(&arp_table->lock);
    arp_table->stats.lookups++;

    struct arp_entry *entry = arp_table_lookup_internal(ip_address);

    if (entry && entry->state == ARP_STATE_VALID) {
        memcpy(mac_address, entry->mac_address, 6);
        arp_table->stats.hits++;
        pthread_mutex_unlock(&arp_table->lock);
        return 0;
    }

    arp_table->stats.misses++;
    pthread_mutex_unlock(&arp_table->lock);
    return -1;
}

/**
 * LOCKLESS ARP lookup for fast path (VPP-style)
 * Uses relaxed memory ordering - safe because ARP entries are
 * rarely modified and worst case is a cache miss
 */
int arp_lookup_lockless(uint32_t ip_address, uint8_t *mac_address)
{
    if (!arp_table || !mac_address) {
        return -1;
    }

    /* Direct hash lookup without lock */
    uint32_t hash = (ip_address ^ (ip_address >> 16)) % arp_table->size;
    struct arp_entry *entry = arp_table->buckets[hash];

    /* Walk chain (usually short) */
    while (entry) {
        if (entry->ip_address == ip_address && entry->state == ARP_STATE_VALID) {
            /* Copy MAC atomically (6 bytes fits in cache line) */
            memcpy(mac_address, entry->mac_address, 6);
            __atomic_fetch_add(&arp_table->stats.hits, 1, __ATOMIC_RELAXED);
            return 0;
        }
        entry = entry->next;
    }

    __atomic_fetch_add(&arp_table->stats.misses, 1, __ATOMIC_RELAXED);
    return -1;
}

/**
 * LOCKLESS ARP entry update for fast path (VPP-style)
 * Only updates EXISTING entries - does NOT create new ones
 * Safe for concurrent access - uses atomic MAC copy
 */
int arp_update_lockless(uint32_t ip_address, const uint8_t *mac_address)
{
    if (!arp_table || !mac_address) {
        return -1;
    }

    /* Direct hash lookup without lock */
    uint32_t hash = (ip_address ^ (ip_address >> 16)) % arp_table->size;
    struct arp_entry *entry = arp_table->buckets[hash];

    /* Walk chain to find existing entry */
    while (entry) {
        if (entry->ip_address == ip_address) {
            /* Update existing entry atomically */
            /* 6-byte MAC fits in cache line - atomic on x86 */
            memcpy((void *)entry->mac_address, mac_address, 6);
            __atomic_store_n(&entry->state, ARP_STATE_VALID, __ATOMIC_RELEASE);
            return 0;
        }
        entry = entry->next;
    }

    return -1; /* Entry doesn't exist - caller should use slow path */
}

/**
 * Delete ARP entry
 */
int arp_delete_entry(uint32_t ip_address)
{
    if (!arp_table) {
        return -1;
    }

    pthread_mutex_lock(&arp_table->lock);

    uint32_t hash = arp_hash(ip_address);
    struct arp_entry *entry = arp_table->buckets[hash];
    struct arp_entry *prev = NULL;

    while (entry) {
        if (entry->ip_address == ip_address) {
            if (prev) {
                prev->next = entry->next;
            } else {
                arp_table->buckets[hash] = entry->next;
            }

            free(entry);
            arp_table->count--;
            arp_table->stats.current_entries--;
            arp_table->stats.entries_deleted++;
            pthread_mutex_unlock(&arp_table->lock);
            return 0;
        }
        prev = entry;
        entry = entry->next;
    }

    pthread_mutex_unlock(&arp_table->lock);
    return -1;
}

/**
 * Process incoming ARP packet
 */
int arp_process_packet(const uint8_t *pkt, uint16_t len, uint32_t ifindex)
{
    if (!arp_table || !pkt || len < sizeof(struct arp_hdr)) {
        return -1;
    }

    const struct arp_hdr *arp = (const struct arp_hdr *)pkt;

    /* Validate ARP packet */
    if (ntohs(arp->ar_hrd) != ARP_HTYPE_ETHERNET ||
        ntohs(arp->ar_pro) != ARP_PTYPE_IPV4 ||
        arp->ar_hln != ARP_HLEN_ETHERNET ||
        arp->ar_pln != ARP_PLEN_IPV4) {
        return -1;
    }

    uint16_t op = ntohs(arp->ar_op);
    uint32_t sender_ip = ntohl(arp->ar_sip);

    /* Update ARP table with sender information */
    if (sender_ip != 0) {
        /* Check if this is a new resolution (entry was INCOMPLETE or didn't exist) */
        bool was_incomplete = false;
        pthread_mutex_lock(&arp_table->lock);
        struct arp_entry *existing = arp_table_lookup_internal(sender_ip);
        if (existing && (existing->state == ARP_STATE_INCOMPLETE || existing->state == ARP_STATE_FAILED)) {
            was_incomplete = true;
        }
        pthread_mutex_unlock(&arp_table->lock);

        arp_add_entry(sender_ip, arp->ar_sha, ifindex, ARP_STATE_VALID);

        /* If ARP entry transitioned from INCOMPLETE to VALID, flush queued packets */
        if (was_incomplete) {
            arp_queue_flush(sender_ip);
        }
    }

    if (op == ARP_OP_REQUEST) {
        arp_table->stats.requests_received++;
        uint32_t target_ip = ntohl(arp->ar_tip);

        YLOG_DEBUG("ARP request received for IP %u.%u.%u.%u",
                   (target_ip >> 24) & 0xFF,
                   (target_ip >> 16) & 0xFF,
                   (target_ip >> 8) & 0xFF,
                   target_ip & 0xFF);

        /* Check if this is for one of our interfaces */
        struct interface *iface = interface_find_by_index(ifindex);
        if (iface && iface->config.ipv4_addr.s_addr != 0) {
            uint32_t our_ip = ntohl(iface->config.ipv4_addr.s_addr);
        if (target_ip == our_ip) {
                YLOG_INFO("ARP request received for us (IP %u.%u.%u.%u) - sending reply",
                    (target_ip >> 24) & 0xFF, (target_ip >> 16) & 0xFF,
                    (target_ip >> 8) & 0xFF, target_ip & 0xFF);
                int ret = arp_send_reply_on_interface(sender_ip, arp->ar_sha, our_ip, iface);
                if (ret != 0) {
                     YLOG_ERROR("ARP reply send failed: %d", ret);
                } else {
                     YLOG_INFO("ARP reply sent successfully to interface");
                }
            }
        }
    } else if (op == ARP_OP_REPLY) {
        arp_table->stats.replies_received++;
        YLOG_DEBUG("ARP reply received from IP %u.%u.%u.%u",
                   (sender_ip >> 24) & 0xFF,
                   (sender_ip >> 16) & 0xFF,
                   (sender_ip >> 8) & 0xFF,
                   sender_ip & 0xFF);
    }

    return 0;
}

/**
 * Send ARP request
 */
int arp_send_request(uint32_t target_ip, uint32_t source_ip,
                     const uint8_t *source_mac, uint32_t ifindex)
{
    if (!arp_table || !source_mac) {
        return -1;
    }

    struct interface *iface = interface_find_by_index(ifindex);
    if (!iface) {
        YLOG_ERROR("Interface %u not found for ARP request", ifindex);
        return -1;
    }

    /* Allocate packet buffer */
    struct pkt_buf *pkt = pkt_alloc();
    if (!pkt) {
        YLOG_ERROR("Failed to allocate packet for ARP request");
        return -1;
    }

#ifdef HAVE_DPDK
    /* Build Ethernet header - broadcast */
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt->data;
    memset(&eth->dst_addr, 0xFF, RTE_ETHER_ADDR_LEN);  /* Broadcast */
    memcpy(&eth->src_addr, source_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    /* Build ARP header */
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(pkt->data + sizeof(struct rte_ether_hdr));
    arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = 4;
    arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);

    memcpy(&arp->arp_data.arp_sha, source_mac, RTE_ETHER_ADDR_LEN);
    arp->arp_data.arp_sip = rte_cpu_to_be_32(source_ip);
    memset(&arp->arp_data.arp_tha, 0, RTE_ETHER_ADDR_LEN);  /* Unknown */
    arp->arp_data.arp_tip = rte_cpu_to_be_32(target_ip);

    pkt->len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
#else
    /* Non-DPDK fallback */
    struct ether_header *eth = (struct ether_header *)pkt->data;
    memset(eth->ether_dhost, 0xFF, 6);  /* Broadcast */
    memcpy(eth->ether_shost, source_mac, 6);
    eth->ether_type = htons(0x0806);

    struct arp_hdr *arp = (struct arp_hdr *)(pkt->data + sizeof(struct ether_header));
    arp->ar_hrd = htons(ARP_HTYPE_ETHERNET);
    arp->ar_pro = htons(ARP_PTYPE_IPV4);
    arp->ar_hln = ARP_HLEN_ETHERNET;
    arp->ar_pln = ARP_PLEN_IPV4;
    arp->ar_op = htons(ARP_OP_REQUEST);
    memcpy(arp->ar_sha, source_mac, 6);
    arp->ar_sip = htonl(source_ip);
    memset(arp->ar_tha, 0, 6);
    arp->ar_tip = htonl(target_ip);

    pkt->len = sizeof(struct ether_header) + sizeof(struct arp_hdr);
#endif

    /* Send via interface */
    int ret = interface_send(iface, pkt);
    pkt_free(pkt);

    if (ret == 0) {
        arp_table->stats.requests_sent++;
        YLOG_DEBUG("ARP request sent for IP %u.%u.%u.%u",
                   (target_ip >> 24) & 0xFF,
                   (target_ip >> 16) & 0xFF,
                   (target_ip >> 8) & 0xFF,
                   target_ip & 0xFF);
    } else {
        YLOG_ERROR("Failed to send ARP request");
    }

    return ret;
}

/**
 * Send ARP reply on a specific interface using DPDK structures
 * Reference: DPDK rte_arp.h
 */
int arp_send_reply_on_interface(uint32_t target_ip, const uint8_t *target_mac,
                                uint32_t source_ip, struct interface *iface)
{
    if (!arp_table || !target_mac || !iface) {
        return -1;
    }

    /* Allocate packet buffer */
    struct pkt_buf *pkt = pkt_alloc();
    if (!pkt) {
        YLOG_ERROR("Failed to allocate packet for ARP reply");
        return -1;
    }

#ifdef HAVE_DPDK
    /* Build Ethernet header using DPDK structures */
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt->data;
    memcpy(&eth->dst_addr, target_mac, RTE_ETHER_ADDR_LEN);
    memcpy(&eth->src_addr, iface->mac_addr, RTE_ETHER_ADDR_LEN);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    /* Build ARP header using DPDK rte_arp_hdr */
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(pkt->data + sizeof(struct rte_ether_hdr));
    arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = 4;
    arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

    memcpy(&arp->arp_data.arp_sha, iface->mac_addr, RTE_ETHER_ADDR_LEN);
    arp->arp_data.arp_sip = rte_cpu_to_be_32(source_ip);
    memcpy(&arp->arp_data.arp_tha, target_mac, RTE_ETHER_ADDR_LEN);
    arp->arp_data.arp_tip = rte_cpu_to_be_32(target_ip);

    pkt->len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
#else
    /* Non-DPDK fallback */
    struct ether_header *eth = (struct ether_header *)pkt->data;
    memcpy(eth->ether_dhost, target_mac, 6);
    memcpy(eth->ether_shost, iface->mac_addr, 6);
    eth->ether_type = htons(0x0806);

    struct arp_hdr *arp = (struct arp_hdr *)(pkt->data + sizeof(struct ether_header));
    arp->ar_hrd = htons(ARP_HTYPE_ETHERNET);
    arp->ar_pro = htons(ARP_PTYPE_IPV4);
    arp->ar_hln = ARP_HLEN_ETHERNET;
    arp->ar_pln = ARP_PLEN_IPV4;
    arp->ar_op = htons(ARP_OP_REPLY);
    memcpy(arp->ar_sha, iface->mac_addr, 6);
    arp->ar_sip = htonl(source_ip);
    memcpy(arp->ar_tha, target_mac, 6);
    arp->ar_tip = htonl(target_ip);

    pkt->len = sizeof(struct ether_header) + sizeof(struct arp_hdr);
#endif

    /* Send via interface */
    int ret = interface_send(iface, pkt);
    pkt_free(pkt);

    if (ret == 0) {
        arp_table->stats.replies_sent++;
        YLOG_INFO("ARP reply sent to %u.%u.%u.%u",
                  (target_ip >> 24) & 0xFF,
                  (target_ip >> 16) & 0xFF,
                  (target_ip >> 8) & 0xFF,
                  target_ip & 0xFF);
    } else {
        YLOG_ERROR("Failed to send ARP reply");
    }

    return ret;
}

/**
 * Send ARP reply (legacy)
 */
int arp_send_reply(uint32_t target_ip, const uint8_t *target_mac,
                   uint32_t source_ip, const uint8_t *source_mac,
                   uint32_t ifindex)
{
    struct interface *iface = interface_find_by_index(ifindex);
    if (!iface) {
        return -1;
    }
    (void)source_mac;
    return arp_send_reply_on_interface(target_ip, target_mac, source_ip, iface);
}

/**
 * Send gratuitous ARP
 */
int arp_send_gratuitous(uint32_t ip_address, const uint8_t *mac_address,
                        uint32_t ifindex)
{
    /* Gratuitous ARP is an ARP request where source and target IP are the same */
    return arp_send_request(ip_address, ip_address, mac_address, ifindex);
}

/**
 * Age out stale ARP entries
 */
uint32_t arp_timeout_check(void)
{
    if (!arp_table) {
        return 0;
    }

    time_t now = time(NULL);
    uint32_t deleted = 0;

    pthread_mutex_lock(&arp_table->lock);

    for (uint32_t i = 0; i < arp_table->size; i++) {
        struct arp_entry *entry = arp_table->buckets[i];
        struct arp_entry *prev = NULL;

        while (entry) {
            struct arp_entry *next = entry->next;
            bool should_delete = false;
            time_t age = now - entry->last_seen;

            switch (entry->state) {
                case ARP_STATE_VALID:
                    if (age > ARP_VALID_TIMEOUT) {
                        entry->state = ARP_STATE_STALE;
                    }
                    break;

                case ARP_STATE_STALE:
                    if (age > ARP_STALE_TIMEOUT) {
                        should_delete = true;
                    }
                    break;

                case ARP_STATE_INCOMPLETE:
                    if (age > ARP_INCOMPLETE_TIMEOUT) {
                        if (++entry->retries >= ARP_MAX_RETRIES) {
                            entry->state = ARP_STATE_FAILED;
                            should_delete = true;
                        }
                    }
                    break;

                case ARP_STATE_FAILED:
                    should_delete = true;
                    break;
            }

            if (should_delete) {
                if (prev) {
                    prev->next = next;
                } else {
                    arp_table->buckets[i] = next;
                }
                free(entry);
                arp_table->count--;
                arp_table->stats.current_entries--;
                arp_table->stats.entries_deleted++;
                arp_table->stats.timeouts++;
                deleted++;
            } else {
                prev = entry;
            }

            entry = next;
        }
    }

    pthread_mutex_unlock(&arp_table->lock);

    if (deleted > 0) {
        YLOG_DEBUG("ARP timeout check: deleted %u entries", deleted);
    }

    return deleted;
}

/**
 * Get ARP statistics
 */
int arp_get_stats(struct arp_stats *stats)
{
    if (!arp_table || !stats) {
        return -1;
    }

    pthread_mutex_lock(&arp_table->lock);
    memcpy(stats, &arp_table->stats, sizeof(*stats));
    pthread_mutex_unlock(&arp_table->lock);

    return 0;
}

/**
 * Print ARP table (for debugging)
 */
void arp_print_table(void)
{
    if (!arp_table) {
        printf("ARP table not initialized\n");
        return;
    }

    pthread_mutex_lock(&arp_table->lock);

    printf("\n========================================\n");
    printf("ARP Table (%u entries)\n", arp_table->count);
    printf("========================================\n");

    for (uint32_t i = 0; i < arp_table->size; i++) {
        struct arp_entry *entry = arp_table->buckets[i];
        while (entry) {
            uint32_t ip = entry->ip_address;
            printf("IP: %u.%u.%u.%u\n",
                   (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                   (ip >> 8) & 0xFF, ip & 0xFF);
            printf("  MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   entry->mac_address[0], entry->mac_address[1],
                   entry->mac_address[2], entry->mac_address[3],
                   entry->mac_address[4], entry->mac_address[5]);
            printf("  State: %s\n", arp_state_to_str(entry->state));
            printf("  Interface: %u\n", entry->ifindex);
            printf("  Age: %ld seconds\n", time(NULL) - entry->last_seen);
            printf("\n");
            entry = entry->next;
        }
    }

    printf("========================================\n");

    pthread_mutex_unlock(&arp_table->lock);
}

/**
 * Convert ARP state to string
 */
const char *arp_state_to_str(enum arp_state state)
{
    switch (state) {
        case ARP_STATE_INCOMPLETE: return "INCOMPLETE";
        case ARP_STATE_VALID:      return "VALID";
        case ARP_STATE_STALE:      return "STALE";
        case ARP_STATE_FAILED:     return "FAILED";
        default:                   return "UNKNOWN";
    }
}

#ifdef HAVE_DPDK
#include <rte_mbuf.h>
#include <rte_ethdev.h>

/**
 * Process ARP packet from DPDK mbuf - called from NAT fast path
 */
int arp_process_packet_dpdk(struct rte_mbuf *mbuf, uint16_t port_id)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);

    /* Validate ARP packet */
    if (rte_be_to_cpu_16(arp->arp_hardware) != RTE_ARP_HRD_ETHER ||
        rte_be_to_cpu_16(arp->arp_protocol) != RTE_ETHER_TYPE_IPV4) {
        rte_pktmbuf_free(mbuf);
        return -1;
    }

    uint16_t op = rte_be_to_cpu_16(arp->arp_opcode);
    uint32_t sender_ip = rte_be_to_cpu_32(arp->arp_data.arp_sip);
    uint32_t target_ip = rte_be_to_cpu_32(arp->arp_data.arp_tip);

    /* Find interface by DPDK port */
    struct interface *iface = interface_find_by_dpdk_port(port_id);
    if (!iface) {
        rte_pktmbuf_free(mbuf);
        return -1;
    }

    /* Update ARP table with sender */
    if (sender_ip != 0) {
        arp_add_entry(sender_ip, arp->arp_data.arp_sha.addr_bytes, iface->ifindex, ARP_STATE_VALID);
    }

    if (op == RTE_ARP_OP_REQUEST) {
        uint32_t our_ip = ntohl(iface->config.ipv4_addr.s_addr);

        if (target_ip == our_ip && our_ip != 0) {
            YLOG_INFO("ARP request for %u.%u.%u.%u - sending reply",
                     (target_ip >> 24) & 0xFF, (target_ip >> 16) & 0xFF,
                     (target_ip >> 8) & 0xFF, target_ip & 0xFF);

            /* Build ARP reply in-place */
            struct rte_ether_addr tmp_eth;
            rte_ether_addr_copy(&eth->src_addr, &tmp_eth);
            rte_ether_addr_copy(&eth->dst_addr, &eth->src_addr);
            rte_ether_addr_copy(&tmp_eth, &eth->dst_addr);

            /* Get our MAC */
            struct rte_ether_addr our_mac;
            rte_eth_macaddr_get(port_id, &our_mac);
            rte_ether_addr_copy(&our_mac, &eth->src_addr);

            /* Swap ARP addresses */
            arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
            rte_ether_addr_copy(&arp->arp_data.arp_sha, &arp->arp_data.arp_tha);
            arp->arp_data.arp_tip = arp->arp_data.arp_sip;
            rte_ether_addr_copy(&our_mac, &arp->arp_data.arp_sha);
            arp->arp_data.arp_sip = rte_cpu_to_be_32(our_ip);

            /* Send reply - try multiple queues if queue 0 fails */
            uint16_t nb_tx = rte_eth_tx_burst(port_id, 0, &mbuf, 1);
            if (nb_tx == 0) {
                /* Queue 0 failed, try queue 1 */
                nb_tx = rte_eth_tx_burst(port_id, 1, &mbuf, 1);
                if (nb_tx == 0) {
                    YLOG_WARNING("ARP reply TX failed on port %u", port_id);
                    rte_pktmbuf_free(mbuf);
                }
            }
            if (nb_tx > 0) {
                YLOG_INFO("ARP reply sent on port %u queue %d", port_id, nb_tx > 0 ? 0 : 1);
            }
            return 0;
        }
    }

    rte_pktmbuf_free(mbuf);
    return 0;
}
#endif
