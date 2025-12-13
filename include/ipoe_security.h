/**
 * @file ipoe_security.h
 * @brief IPoE Security - Rate Limiting and Anti-Spoof
 *
 * DHCP rate limiting, ARP rate limiting, rogue detection
 */

#ifndef IPOE_SECURITY_H
#define IPOE_SECURITY_H

#include <stdint.h>
#include <stdbool.h>

/*============================================================================
 * Rate Limit Configuration
 *============================================================================*/

#define IPOE_MAX_RATE_ENTRIES       65536   /* Per-MAC rate tracking */
#define IPOE_RATE_WINDOW_SEC        1       /* Rate limit window */

/*============================================================================
 * Per-MAC Rate Tracking
 *============================================================================*/

struct ipoe_rate_entry {
    uint8_t  mac[6];
    uint16_t pad;
    uint32_t dhcp_count;        /* DHCP packets in window */
    uint32_t arp_count;         /* ARP packets in window */
    uint64_t window_start;      /* Window start timestamp */
    struct ipoe_rate_entry *next;
};

/*============================================================================
 * Security Configuration
 *============================================================================*/

struct ipoe_security_config {
    bool     enabled;

    /* DHCP rate limiting */
    uint32_t dhcp_rate_per_mac;     /* Max DHCP/sec per MAC */
    uint32_t dhcp_rate_global;      /* Max DHCP/sec global */

    /* ARP rate limiting */
    uint32_t arp_rate_per_mac;
    uint32_t arp_rate_per_iface;

    /* Anti-spoof */
    bool     anti_spoof_enabled;
    bool     verify_mac_ip_binding;

    /* Rogue detection */
    bool     rogue_dhcp_detection;
    uint32_t trusted_dhcp_server;   /* Only allow from this server */

    /* Statistics */
    uint64_t dhcp_rate_limited;
    uint64_t arp_rate_limited;
    uint64_t spoof_detected;
    uint64_t rogue_detected;
};

/*============================================================================
 * Security API
 *============================================================================*/

/* Initialization */
int ipoe_security_init(void);
void ipoe_security_cleanup(void);
void ipoe_security_enable(bool enable);

/* Rate limiting */
bool ipoe_security_check_dhcp_rate(const uint8_t *mac);
bool ipoe_security_check_arp_rate(const uint8_t *mac, uint32_t ifindex);
void ipoe_security_set_dhcp_rate(uint32_t per_mac, uint32_t global);
void ipoe_security_set_arp_rate(uint32_t per_mac, uint32_t per_iface);

/* Anti-spoof */
bool ipoe_security_verify_packet(const uint8_t *mac, uint32_t src_ip,
                                  uint32_t ifindex);

/* Rogue detection */
bool ipoe_security_check_dhcp_server(uint32_t server_ip);
void ipoe_security_set_trusted_server(uint32_t server_ip);

/* Statistics */
void ipoe_security_get_stats(struct ipoe_security_config *stats);
void ipoe_security_print_stats(void);

#endif /* IPOE_SECURITY_H */
