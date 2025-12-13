/**
 * @file ipoe_security.c
 * @brief IPoE Security - Rate Limiting and Anti-Spoof Implementation
 */

#include <ipoe_security.h>
#include <ipoe_session.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_DPDK
#include <rte_hash.h>
#include <rte_jhash.h>
#endif

/*============================================================================
 * Global Security Context
 *============================================================================*/

static struct {
    struct ipoe_security_config config;

#ifdef HAVE_DPDK
    struct rte_hash *rate_table;    /* Lockless rate tracking */
#else
    struct ipoe_rate_entry *rate_table[4096];
#endif

    /* Global counters */
    uint64_t global_dhcp_count;
    uint64_t global_dhcp_window_start;
} g_security = {0};

/*============================================================================
 * Helper Functions
 *============================================================================*/

static uint64_t get_timestamp_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static uint32_t mac_hash(const uint8_t *mac)
{
    return (mac[0] ^ mac[1] ^ mac[2] ^ mac[3] ^ mac[4] ^ mac[5]) & 0xFFF;
}

/*============================================================================
 * Initialization
 *============================================================================*/

int ipoe_security_init(void)
{
    memset(&g_security, 0, sizeof(g_security));

    /* Default rate limits */
    g_security.config.enabled = true;
    g_security.config.dhcp_rate_per_mac = 10;     /* 10 DHCP/sec per MAC */
    g_security.config.dhcp_rate_global = 50000;   /* 50K DHCP/sec global */
    g_security.config.arp_rate_per_mac = 100;     /* 100 ARP/sec per MAC */
    g_security.config.arp_rate_per_iface = 10000; /* 10K ARP/sec per interface */
    g_security.config.anti_spoof_enabled = true;

#ifdef HAVE_DPDK
    struct rte_hash_parameters params = {
        .name = "ipoe_rate_table",
        .entries = IPOE_MAX_RATE_ENTRIES,
        .key_len = 6,  /* MAC address */
        .hash_func = rte_jhash,
        .socket_id = 0,
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY
    };
    g_security.rate_table = rte_hash_create(&params);
    if (!g_security.rate_table) {
        fprintf(stderr, "ipoe_security: failed to create rate table\n");
        return -1;
    }
#endif

    printf("ipoe_security: initialized (DHCP rate: %u/mac, %u/global)\n",
           g_security.config.dhcp_rate_per_mac,
           g_security.config.dhcp_rate_global);

    return 0;
}

void ipoe_security_cleanup(void)
{
#ifndef HAVE_DPDK
    for (int i = 0; i < 4096; i++) {
        struct ipoe_rate_entry *e = g_security.rate_table[i];
        while (e) {
            struct ipoe_rate_entry *next = e->next;
            free(e);
            e = next;
        }
    }
#endif
}

void ipoe_security_enable(bool enable)
{
    g_security.config.enabled = enable;
}

/*============================================================================
 * Rate Limiting
 *============================================================================*/

static struct ipoe_rate_entry *find_or_create_rate_entry(const uint8_t *mac)
{
#ifdef HAVE_DPDK
    void *data = NULL;
    int ret = rte_hash_lookup_data(g_security.rate_table, mac, &data);
    if (ret >= 0) {
        return (struct ipoe_rate_entry *)data;
    }

    /* Create new entry */
    struct ipoe_rate_entry *entry = calloc(1, sizeof(*entry));
    if (!entry) return NULL;

    memcpy(entry->mac, mac, 6);
    entry->window_start = get_timestamp_ns();

    rte_hash_add_key_data(g_security.rate_table, mac, entry);
    return entry;
#else
    uint32_t hash = mac_hash(mac);
    struct ipoe_rate_entry *e = g_security.rate_table[hash];

    while (e) {
        if (memcmp(e->mac, mac, 6) == 0) {
            return e;
        }
        e = e->next;
    }

    /* Create new */
    e = calloc(1, sizeof(*e));
    if (!e) return NULL;

    memcpy(e->mac, mac, 6);
    e->window_start = get_timestamp_ns();
    e->next = g_security.rate_table[hash];
    g_security.rate_table[hash] = e;

    return e;
#endif
}

bool ipoe_security_check_dhcp_rate(const uint8_t *mac)
{
    if (!g_security.config.enabled) return true;

    uint64_t now = get_timestamp_ns();
    uint64_t window_ns = (uint64_t)IPOE_RATE_WINDOW_SEC * 1000000000ULL;

    /* Check global rate */
    if (now - g_security.global_dhcp_window_start > window_ns) {
        g_security.global_dhcp_count = 0;
        g_security.global_dhcp_window_start = now;
    }

    if (g_security.global_dhcp_count >= g_security.config.dhcp_rate_global) {
        g_security.config.dhcp_rate_limited++;
        return false;
    }

    /* Check per-MAC rate */
    struct ipoe_rate_entry *entry = find_or_create_rate_entry(mac);
    if (!entry) return true;

    if (now - entry->window_start > window_ns) {
        entry->dhcp_count = 0;
        entry->window_start = now;
    }

    if (entry->dhcp_count >= g_security.config.dhcp_rate_per_mac) {
        g_security.config.dhcp_rate_limited++;
        return false;
    }

    /* Allow packet */
    entry->dhcp_count++;
    g_security.global_dhcp_count++;
    return true;
}

bool ipoe_security_check_arp_rate(const uint8_t *mac, uint32_t ifindex)
{
    (void)ifindex;

    if (!g_security.config.enabled) return true;

    struct ipoe_rate_entry *entry = find_or_create_rate_entry(mac);
    if (!entry) return true;

    uint64_t now = get_timestamp_ns();
    uint64_t window_ns = (uint64_t)IPOE_RATE_WINDOW_SEC * 1000000000ULL;

    if (now - entry->window_start > window_ns) {
        entry->arp_count = 0;
        entry->window_start = now;
    }

    if (entry->arp_count >= g_security.config.arp_rate_per_mac) {
        g_security.config.arp_rate_limited++;
        return false;
    }

    entry->arp_count++;
    return true;
}

void ipoe_security_set_dhcp_rate(uint32_t per_mac, uint32_t global)
{
    g_security.config.dhcp_rate_per_mac = per_mac;
    g_security.config.dhcp_rate_global = global;
}

void ipoe_security_set_arp_rate(uint32_t per_mac, uint32_t per_iface)
{
    g_security.config.arp_rate_per_mac = per_mac;
    g_security.config.arp_rate_per_iface = per_iface;
}

/*============================================================================
 * Anti-Spoof
 *============================================================================*/

bool ipoe_security_verify_packet(const uint8_t *mac, uint32_t src_ip,
                                  uint32_t ifindex)
{
    if (!g_security.config.anti_spoof_enabled) return true;
    if (src_ip == 0) return true;  /* DHCP packets have 0 src IP */

    /* Find session by MAC */
    struct ipoe_session *sess = ipoe_session_find_by_mac(mac);
    if (!sess) {
        /* No session - could be new subscriber, allow initial packets */
        return true;
    }

    /* Check if IP matches bound IP */
    if (sess->ip_addr != 0 && sess->ip_addr != src_ip) {
        g_security.config.spoof_detected++;
        return false;
    }

    /* Check interface */
    if (sess->ifindex != 0 && sess->ifindex != ifindex) {
        g_security.config.spoof_detected++;
        return false;
    }

    return true;
}

/*============================================================================
 * Rogue DHCP Detection
 *============================================================================*/

bool ipoe_security_check_dhcp_server(uint32_t server_ip)
{
    if (!g_security.config.rogue_dhcp_detection) return true;
    if (g_security.config.trusted_dhcp_server == 0) return true;

    if (server_ip != g_security.config.trusted_dhcp_server) {
        g_security.config.rogue_detected++;
        return false;
    }

    return true;
}

void ipoe_security_set_trusted_server(uint32_t server_ip)
{
    g_security.config.trusted_dhcp_server = server_ip;
    g_security.config.rogue_dhcp_detection = (server_ip != 0);
}

/*============================================================================
 * Statistics
 *============================================================================*/

void ipoe_security_get_stats(struct ipoe_security_config *stats)
{
    if (stats) {
        memcpy(stats, &g_security.config, sizeof(*stats));
    }
}

void ipoe_security_print_stats(void)
{
    printf("\nIPoE Security Statistics:\n");
    printf("  Enabled:           %s\n", g_security.config.enabled ? "yes" : "no");
    printf("  DHCP rate/MAC:     %u/sec\n", g_security.config.dhcp_rate_per_mac);
    printf("  DHCP rate/global:  %u/sec\n", g_security.config.dhcp_rate_global);
    printf("  ARP rate/MAC:      %u/sec\n", g_security.config.arp_rate_per_mac);
    printf("  Anti-spoof:        %s\n", g_security.config.anti_spoof_enabled ? "yes" : "no");
    printf("  DHCP rate limited: %lu\n", g_security.config.dhcp_rate_limited);
    printf("  ARP rate limited:  %lu\n", g_security.config.arp_rate_limited);
    printf("  Spoof detected:    %lu\n", g_security.config.spoof_detected);
    printf("  Rogue detected:    %lu\n", g_security.config.rogue_detected);
    printf("\n");
}
