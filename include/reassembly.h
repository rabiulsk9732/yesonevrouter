/**
 * @file reassembly.h
 * @brief IP Packet Reassembly (RFC 791)
 */

#ifndef REASSEMBLY_H
#define REASSEMBLY_H

#include "packet.h"
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Reassembly configuration */
#define REASSEMBLY_TABLE_SIZE 256
#define REASSEMBLY_MAX_ENTRIES 1024
#define REASSEMBLY_TIMEOUT 60  /* 60 seconds per RFC 791 */
#define MAX_FRAGMENT_SIZE 65535

/* Fragment entry for tracking reassembly */
struct fragment_entry {
    /* Fragment identification tuple */
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t protocol;
    uint16_t id;

    /* Reassembly buffer */
    uint8_t *buffer;
    uint16_t buffer_size;
    uint16_t total_length;
    bool have_last_fragment;

    /* Fragment tracking bitmap (1 bit per 8 bytes) */
    uint8_t *bitmap;
    uint16_t bitmap_size;
    uint16_t received_bytes;

    /* Timestamps */
    time_t created;
    time_t last_update;

    /* Linked list */
    struct fragment_entry *next;
};

/* Reassembly statistics */
struct reassembly_stats {
    uint64_t fragments_received;
    uint64_t packets_reassembled;
    uint64_t reassembly_timeouts;
    uint64_t reassembly_failures;
    uint32_t current_entries;
};

/**
 * @brief Initialize reassembly subsystem
 * @return 0 on success, -1 on error
 */
int ip_reassembly_init(void);

/**
 * @brief Process received IP fragment
 * @param pkt Packet buffer (may be fragment)
 * @param reassembled Output for reassembled packet (if complete)
 * @return 1 if complete packet, 0 if waiting for more, -1 on error
 */
int ip_reassembly_process(struct pkt_buf *pkt, struct pkt_buf **reassembled);

/**
 * @brief Timeout old fragments (call periodically)
 * @return Number of timed-out entries
 */
uint32_t ip_reassembly_timeout(void);

/**
 * @brief Get reassembly statistics
 * @param stats Output buffer for statistics
 */
void ip_reassembly_get_stats(struct reassembly_stats *stats);

/**
 * @brief Cleanup reassembly subsystem
 */
void ip_reassembly_cleanup(void);

#endif /* REASSEMBLY_H */
