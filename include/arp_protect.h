/**
 * @file arp_protect.h
 * @brief ARP Protection API
 */

#ifndef ARP_PROTECT_H
#define ARP_PROTECT_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    ARP_RESULT_PASS,        /* Valid ARP */
    ARP_RESULT_SPOOF,       /* Spoofed - drop */
    ARP_RESULT_UNKNOWN      /* Unknown IP - may drop */
} arp_result_t;

/**
 * Initialize ARP protection
 */
int arp_protect_init(void);

/**
 * Cleanup ARP protection
 */
void arp_protect_cleanup(void);

/**
 * Add IP-MAC binding for session
 */
int arp_protect_add_binding(uint32_t ip, const uint8_t *mac, uint16_t session_id);

/**
 * Delete binding by IP
 */
void arp_protect_del_binding(uint32_t ip);

/**
 * Delete all bindings for session
 */
void arp_protect_del_by_session(uint16_t session_id);

/**
 * Validate ARP packet
 * @return ARP_RESULT_PASS if valid, ARP_RESULT_SPOOF if spoofed
 */
arp_result_t arp_protect_validate(uint32_t ip, const uint8_t *mac);

/**
 * Enable/disable ARP protection
 */
void arp_protect_enable(bool enable);

/**
 * Get ARP protection stats
 */
void arp_protect_stats(uint64_t *requests, uint64_t *replies, uint64_t *spoofs, uint64_t *dropped);

#endif /* ARP_PROTECT_H */
