/**
 * @file ipoe.h
 * @brief IPoE Main Header - Complete Module Integration
 *
 * Production-grade IPoE for YesRouter vBNG with BISON BNG feature parity
 * Features: L2/L3 modes, DHCP, RADIUS, profiles, pools, timer wheel, security
 */

#ifndef IPOE_H
#define IPOE_H

/* Core IPoE modules */
#include <ipoe_session.h>
#include <ipoe_dhcp.h>
#include <ipoe_radius.h>

/* BISON-style features */
#include <ipoe_profile.h>
#include <ipoe_timer.h>

/* Security and CoA */
#include <ipoe_security.h>
#include <ipoe_coa.h>

/* Existing YesRouter modules */
#include <arp.h>
#include <radius_lockless.h>

/*============================================================================
 * IPoE Global Configuration
 *============================================================================*/

struct ipoe_config {
    bool     enabled;
    uint8_t  mode;            /* IPOE_FLAG_L2_MODE or IPOE_FLAG_L3_MODE */
    uint32_t max_sessions;

    /* Authentication */
    bool     mac_auth_enabled;
    bool     radius_enabled;

    /* Security */
    bool     anti_spoof_enabled;
    bool     arp_inspect_enabled;
    bool     dhcp_snooping_enabled;

    /* Rate limits */
    uint32_t dhcp_rate_limit;     /* per MAC */
    uint32_t arp_rate_limit;      /* per interface */

    /* Timeouts */
    uint32_t default_lease_time;
    uint32_t session_timeout;
    uint32_t idle_timeout;
};

/*============================================================================
 * IPoE Module API
 *============================================================================*/

/* Module initialization */
int ipoe_init(struct ipoe_config *config);
void ipoe_cleanup(void);
void ipoe_enable(void);
void ipoe_disable(void);
bool ipoe_is_enabled(void);

/* Packet processing (called from fastpath) */
int ipoe_process_packet(const uint8_t *pkt, uint16_t len,
                         uint32_t ifindex, uint16_t svlan, uint16_t cvlan);

/* ARP integration (uses existing arp.c) */
int ipoe_arp_process(const uint8_t *pkt, uint16_t len, uint32_t ifindex);
int ipoe_arp_validate_session(struct ipoe_session *sess, uint32_t ip, const uint8_t *mac);

/* Statistics */
void ipoe_print_stats(void);
void ipoe_get_config(struct ipoe_config *config);

#endif /* IPOE_H */
