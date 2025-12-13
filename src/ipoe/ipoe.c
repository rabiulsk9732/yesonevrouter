/**
 * @file ipoe_main.c
 * @brief IPoE Main Integration - Wire IPoE to YesRouter main loop
 *
 * This file provides the integration points between IPoE and the main packet path
 */

#include <ipoe.h>
#include <ipoe_session.h>
#include <ipoe_dhcp.h>
#include <ipoe_profile.h>
#include <ipoe_timer.h>
#include <ipoe_security.h>
#include <ipoe_coa.h>

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

/*============================================================================
 * Constants
 *============================================================================*/

#define ETH_HLEN        14
#define ETH_P_IP        0x0800
#define ETH_P_ARP       0x0806
#define ETH_P_8021Q     0x8100
#define ETH_P_8021AD    0x88A8

#ifndef IPPROTO_UDP
#define IPPROTO_UDP     17
#endif
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

/*============================================================================
 * Global State
 *============================================================================*/

static struct ipoe_config g_ipoe_config = {0};
static bool g_ipoe_enabled = false;

/* External: pool allocator initialization */
extern int ipoe_pool_alloc_init(const char *name, uint32_t start_ip, uint32_t end_ip);

/* Forward declaration */
uint64_t ipoe_get_timestamp_ns(void);

/*============================================================================
 * Timer Callback
 *============================================================================*/

static void ipoe_timer_callback(uint32_t session_id, uint8_t timer_type)
{
    struct ipoe_session *sess = ipoe_session_find_by_id(session_id);
    if (!sess) return;

    switch (timer_type) {
        case IPOE_TIMER_LEASE:
            printf("ipoe: session %u lease expired\n", session_id);
            ipoe_session_destroy(sess, IPOE_TERM_LEASE_EXPIRE);
            break;

        case IPOE_TIMER_IDLE:
            printf("ipoe: session %u idle timeout\n", session_id);
            ipoe_session_destroy(sess, IPOE_TERM_IDLE_TIMEOUT);
            break;

        case IPOE_TIMER_SESSION:
            printf("ipoe: session %u session timeout\n", session_id);
            ipoe_session_destroy(sess, IPOE_TERM_SESSION_TIMEOUT);
            break;

        default:
            break;
    }
}

/*============================================================================
 * Initialization
 *============================================================================*/

int ipoe_init(struct ipoe_config *config)
{
    if (config) {
        memcpy(&g_ipoe_config, config, sizeof(g_ipoe_config));
    } else {
        /* Default configuration */
        g_ipoe_config.enabled = true;
        g_ipoe_config.mode = IPOE_FLAG_L2_MODE;
        g_ipoe_config.max_sessions = IPOE_MAX_SESSIONS;
        g_ipoe_config.mac_auth_enabled = true;
        g_ipoe_config.anti_spoof_enabled = true;
        g_ipoe_config.dhcp_rate_limit = 10;
        g_ipoe_config.default_lease_time = 3600;
    }

    /* Initialize all sub-modules */
    if (ipoe_session_mgr_init(g_ipoe_config.max_sessions) < 0) {
        fprintf(stderr, "ipoe: failed to init session manager\n");
        return -1;
    }

    if (ipoe_profile_init() < 0) {
        fprintf(stderr, "ipoe: failed to init profiles\n");
        return -1;
    }

    if (ipoe_timer_init(ipoe_timer_callback) < 0) {
        fprintf(stderr, "ipoe: failed to init timer wheel\n");
        return -1;
    }

    if (ipoe_security_init() < 0) {
        fprintf(stderr, "ipoe: failed to init security\n");
        return -1;
    }

    if (ipoe_coa_init() < 0) {
        fprintf(stderr, "ipoe: failed to init CoA\n");
        return -1;
    }

    g_ipoe_enabled = g_ipoe_config.enabled;

    printf("ipoe: initialized (mode=%s, max_sessions=%u)\n",
           (g_ipoe_config.mode == IPOE_FLAG_L2_MODE) ? "L2" : "L3",
           g_ipoe_config.max_sessions);

    return 0;
}

void ipoe_cleanup(void)
{
    g_ipoe_enabled = false;
    ipoe_timer_cleanup();
    ipoe_security_cleanup();
    ipoe_coa_cleanup();
    ipoe_profile_cleanup();
    ipoe_session_mgr_cleanup();
}

void ipoe_enable(void)
{
    g_ipoe_enabled = true;
}

void ipoe_disable(void)
{
    g_ipoe_enabled = false;
}

bool ipoe_is_enabled(void)
{
    return g_ipoe_enabled;
}

/*============================================================================
 * Packet Classification
 *============================================================================*/

/**
 * Check if packet is DHCP
 * Returns: 1 if DHCP, 0 otherwise
 */
static int is_dhcp_packet(const uint8_t *pkt, uint16_t len)
{
    if (len < ETH_HLEN + 28) return 0;  /* Min IP + UDP header */

    const uint8_t *eth = pkt;
    uint16_t ethertype = (eth[12] << 8) | eth[13];

    /* Skip VLAN tags */
    int offset = ETH_HLEN;
    if (ethertype == ETH_P_8021Q || ethertype == ETH_P_8021AD) {
        offset += 4;
        ethertype = (pkt[offset - 2] << 8) | pkt[offset - 1];

        /* Double-tagged (QinQ) */
        if (ethertype == ETH_P_8021Q) {
            offset += 4;
            ethertype = (pkt[offset - 2] << 8) | pkt[offset - 1];
        }
    }

    if (ethertype != ETH_P_IP) return 0;

    /* Check IP header */
    const uint8_t *ip = pkt + offset;
    if ((ip[0] >> 4) != 4) return 0;  /* IPv4 */
    if (ip[9] != IPPROTO_UDP) return 0;

    /* Check UDP ports */
    int ip_hlen = (ip[0] & 0x0F) * 4;
    const uint8_t *udp = ip + ip_hlen;
    uint16_t dst_port = (udp[2] << 8) | udp[3];

    return (dst_port == DHCP_SERVER_PORT || dst_port == DHCP_CLIENT_PORT);
}

/**
 * Extract VLAN info from packet
 */
static void extract_vlan(const uint8_t *pkt, uint16_t *svlan, uint16_t *cvlan)
{
    *svlan = 0;
    *cvlan = 0;

    uint16_t ethertype = (pkt[12] << 8) | pkt[13];

    if (ethertype == ETH_P_8021AD || ethertype == ETH_P_8021Q) {
        *svlan = ((pkt[14] & 0x0F) << 8) | pkt[15];

        uint16_t inner_type = (pkt[16] << 8) | pkt[17];
        if (inner_type == ETH_P_8021Q) {
            *cvlan = ((pkt[18] & 0x0F) << 8) | pkt[19];
        }
    }
}

/*============================================================================
 * Main Packet Processing Entry Point
 *============================================================================*/

/**
 * Process incoming packet on IPoE-enabled interface
 *
 * Called from DPDK RX path for subscriber-facing interfaces
 * Returns: 0 = packet consumed, 1 = forward normally, -1 = drop
 */
int ipoe_process_packet(const uint8_t *pkt, uint16_t len,
                         uint32_t ifindex, uint16_t svlan, uint16_t cvlan)
{
    if (!g_ipoe_enabled) return 1;  /* Forward normally */
    if (!pkt || len < ETH_HLEN) return -1;

    /* Extract source MAC */
    const uint8_t *src_mac = pkt + 6;

    /* Check rate limiting */
    if (!ipoe_security_check_dhcp_rate(src_mac)) {
        return -1;  /* Rate limited, drop */
    }

    /* Extract VLANs if not provided */
    if (svlan == 0 && cvlan == 0) {
        extract_vlan(pkt, &svlan, &cvlan);
    }

    /* Look up or create session */
    struct ipoe_session *sess;

    if (g_ipoe_config.mode == IPOE_FLAG_L2_MODE) {
        sess = ipoe_session_find_by_mac(src_mac);
    } else {
        sess = ipoe_session_find_by_vlan_mac(svlan, cvlan, src_mac);
    }

    /* Check if DHCP packet */
    if (is_dhcp_packet(pkt, len)) {
        if (!sess) {
            /* New subscriber - create session */
            sess = ipoe_session_create(src_mac, svlan, cvlan);
            if (!sess) {
                return -1;  /* Failed to create session */
            }
            sess->ifindex = ifindex;

            /* Match profile */
            struct ipoe_service_profile *profile = ipoe_profile_match(svlan, cvlan, ifindex);
            if (profile) {
                strncpy(sess->pool_name, profile->pool_name, IPOE_MAX_POOL_NAME_LEN - 1);
                sess->rate_limit_up = profile->rate_limit_up;
                sess->rate_limit_down = profile->rate_limit_down;
            }
        }

        /* Process DHCP - this returns response packet */
        /* TODO: Call ipoe_dhcp_process_packet() and TX response */
        return 0;  /* Packet consumed */
    }

    /* Regular data packet */
    if (!sess) {
        return -1;  /* No session, drop */
    }

    /* Anti-spoof check */
    if (g_ipoe_config.anti_spoof_enabled && sess->ip_addr != 0) {
        /* Extract source IP from packet */
        /* TODO: Verify source IP matches session */
    }

    /* Update activity timestamp */
    sess->last_activity = ipoe_get_timestamp_ns();

    return 1;  /* Forward normally */
}

/*============================================================================
 * Timer Tick (called from main loop)
 *============================================================================*/

void ipoe_periodic_tick(void)
{
    if (!g_ipoe_enabled) return;

    ipoe_timer_tick();
}

/*============================================================================
 * Statistics
 *============================================================================*/

void ipoe_print_stats(void)
{
    printf("\n=== IPoE Statistics ===\n");
    printf("Enabled: %s\n", g_ipoe_enabled ? "yes" : "no");
    printf("Mode: %s\n", (g_ipoe_config.mode == IPOE_FLAG_L2_MODE) ? "L2" : "L3");

    ipoe_session_print_stats();
    ipoe_timer_print_stats();
    ipoe_security_print_stats();
    ipoe_coa_print_stats();
}

void ipoe_get_config(struct ipoe_config *config)
{
    if (config) {
        memcpy(config, &g_ipoe_config, sizeof(*config));
    }
}

/*============================================================================
 * Utility Functions
 *============================================================================*/

uint64_t ipoe_get_timestamp_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
