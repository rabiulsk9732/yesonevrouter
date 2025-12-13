/**
 * @file arp_queue.h
 * @brief Packet queuing for ARP resolution
 * @details Queues packets waiting for ARP resolution to eliminate initial packet loss
 */

#ifndef ARP_QUEUE_H
#define ARP_QUEUE_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Forward declarations */
struct pkt_buf;
struct interface;

/* ARP queue configuration */
#define ARP_QUEUE_MAX_ENTRIES 1024      /* Maximum queued IPs */
#define ARP_QUEUE_MAX_PACKETS_PER_IP 32 /* Maximum packets per IP */
#define ARP_QUEUE_TIMEOUT_SEC 2         /* Timeout for queued packets (seconds) */

/**
 * @brief Queued packet entry
 */
struct arp_queued_packet {
    struct pkt_buf *pkt;              /* Packet buffer */
    struct interface *egress_iface;   /* Egress interface */
    struct interface *ingress_iface;  /* Ingress interface (for re-injection) */
    time_t queued_time;               /* Time when packet was queued */
    struct arp_queued_packet *next;   /* Next packet in queue */
};

/**
 * @brief ARP queue entry (per IP address)
 */
struct arp_queue_entry {
    uint32_t ip_address;              /* IP address being resolved */
    struct arp_queued_packet *head;   /* Head of packet queue */
    struct arp_queued_packet *tail;   /* Tail of packet queue */
    uint32_t packet_count;            /* Number of queued packets */
    time_t created_time;              /* Time when queue was created */
    struct arp_queue_entry *next;     /* Next entry in hash chain */
};

/**
 * @brief ARP queue statistics
 */
struct arp_queue_stats {
    uint64_t packets_queued;          /* Total packets queued */
    uint64_t packets_flushed;         /* Packets sent after ARP resolution */
    uint64_t packets_timeout;         /* Packets dropped due to timeout */
    uint64_t queues_created;          /* Queue entries created */
    uint64_t queues_deleted;          /* Queue entries deleted */
    uint32_t current_queues;          /* Current number of active queues */
    uint32_t current_packets;         /* Current number of queued packets */
};

/**
 * @brief Initialize ARP queue subsystem
 * @return 0 on success, -1 on error
 */
int arp_queue_init(void);

/**
 * @brief Cleanup ARP queue subsystem
 */
void arp_queue_cleanup(void);

/**
 * @brief Queue a packet waiting for ARP resolution
 * @param ip_address IP address being resolved
 * @param pkt Packet to queue
 * @param egress_iface Egress interface for the packet
 * @param ingress_iface Ingress interface (for re-injection after ARP resolution)
 * @return 0 on success, -1 on error (queue full, etc.)
 */
int arp_queue_packet(uint32_t ip_address, struct pkt_buf *pkt,
                     struct interface *egress_iface, struct interface *ingress_iface);

/**
 * @brief Flush queued packets for an IP address (called when ARP resolved)
 * @param ip_address IP address that was resolved
 * @param callback Optional callback function to process each flushed packet
 * @param callback_arg Argument to pass to callback
 * @return Number of packets flushed
 */
uint32_t arp_queue_flush(uint32_t ip_address);

/**
 * @brief Timeout old queued packets
 * @return Number of packets dropped due to timeout
 */
uint32_t arp_queue_timeout_check(void);

/**
 * @brief Get ARP queue statistics
 * @param stats Output buffer for statistics
 * @return 0 on success, -1 on error
 */
int arp_queue_get_stats(struct arp_queue_stats *stats);

/**
 * @brief Print ARP queue status (for debugging)
 */
void arp_queue_print_status(void);

#endif /* ARP_QUEUE_H */
