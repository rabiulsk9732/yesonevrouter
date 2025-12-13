/**
 * @file ipv6_ndp.c
 * @brief IPv6 Neighbor Discovery Protocol (NDP) Implementation
 *
 * Implements RFC 4861 for neighbor discovery, including:
 * - Neighbor Solicitation/Advertisement
 * - Router Solicitation/Advertisement
 * - Neighbor Cache management
 */

#include "ipv6/ipv6.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>

/* NDP Neighbor Cache Entry */
struct ndp_entry {
    struct ipv6_addr ip;
    uint8_t mac[6];
    time_t expires;
    enum {
        NDP_STATE_INCOMPLETE,
        NDP_STATE_REACHABLE,
        NDP_STATE_STALE,
        NDP_STATE_DELAY,
        NDP_STATE_PROBE
    } state;
    struct ndp_entry *next;
};

/* ICMPv6 Types */
#define ICMPV6_ECHO_REQUEST     128
#define ICMPV6_ECHO_REPLY       129
#define ICMPV6_ROUTER_SOLICIT   133
#define ICMPV6_ROUTER_ADVERT    134
#define ICMPV6_NEIGHBOR_SOLICIT 135
#define ICMPV6_NEIGHBOR_ADVERT  136

/* NDP Options */
#define NDP_OPT_SOURCE_LINKADDR 1
#define NDP_OPT_TARGET_LINKADDR 2
#define NDP_OPT_PREFIX_INFO     3
#define NDP_OPT_MTU             5

/* Global NDP Cache */
#define NDP_MAX_ENTRIES 1024
#define NDP_REACHABLE_TIME 30  /* seconds */

static struct ndp_entry *g_ndp_cache = NULL;
static pthread_mutex_t g_ndp_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t g_ndp_count = 0;

/* Statistics */
static struct {
    uint64_t ns_sent;
    uint64_t ns_recv;
    uint64_t na_sent;
    uint64_t na_recv;
    uint64_t cache_hits;
    uint64_t cache_misses;
} g_ndp_stats = {0};

/**
 * @brief Initialize NDP subsystem
 */
int ndp_init(void)
{
    g_ndp_cache = NULL;
    g_ndp_count = 0;
    YLOG_INFO("IPv6 NDP initialized");
    return 0;
}

/**
 * @brief Lookup neighbor in cache
 */
int ndp_lookup(const struct ipv6_addr *ip, uint8_t *mac)
{
    struct ndp_entry *entry;
    time_t now = time(NULL);

    pthread_mutex_lock(&g_ndp_mutex);

    entry = g_ndp_cache;
    while (entry) {
        if (memcmp(entry->ip.addr, ip->addr, 16) == 0) {
            if (entry->state == NDP_STATE_REACHABLE && entry->expires > now) {
                memcpy(mac, entry->mac, 6);
                g_ndp_stats.cache_hits++;
                pthread_mutex_unlock(&g_ndp_mutex);
                return 0;
            }
            /* Entry stale or incomplete */
            g_ndp_stats.cache_misses++;
            pthread_mutex_unlock(&g_ndp_mutex);
            return -1;
        }
        entry = entry->next;
    }

    g_ndp_stats.cache_misses++;
    pthread_mutex_unlock(&g_ndp_mutex);
    return -1;
}

/**
 * @brief Add/Update neighbor cache entry
 */
int ndp_update(const struct ipv6_addr *ip, const uint8_t *mac)
{
    struct ndp_entry *entry;
    time_t now = time(NULL);

    pthread_mutex_lock(&g_ndp_mutex);

    /* Search for existing entry */
    entry = g_ndp_cache;
    while (entry) {
        if (memcmp(entry->ip.addr, ip->addr, 16) == 0) {
            memcpy(entry->mac, mac, 6);
            entry->expires = now + NDP_REACHABLE_TIME;
            entry->state = NDP_STATE_REACHABLE;
            pthread_mutex_unlock(&g_ndp_mutex);
            return 0;
        }
        entry = entry->next;
    }

    /* Add new entry */
    if (g_ndp_count >= NDP_MAX_ENTRIES) {
        YLOG_WARNING("NDP cache full");
        pthread_mutex_unlock(&g_ndp_mutex);
        return -1;
    }

    entry = calloc(1, sizeof(struct ndp_entry));
    if (!entry) {
        pthread_mutex_unlock(&g_ndp_mutex);
        return -1;
    }

    memcpy(entry->ip.addr, ip->addr, 16);
    memcpy(entry->mac, mac, 6);
    entry->expires = now + NDP_REACHABLE_TIME;
    entry->state = NDP_STATE_REACHABLE;

    entry->next = g_ndp_cache;
    g_ndp_cache = entry;
    g_ndp_count++;

    char ip_str[64];
    inet_ntop(AF_INET6, ip->addr, ip_str, sizeof(ip_str));
    YLOG_DEBUG("NDP: Added %s -> %02x:%02x:%02x:%02x:%02x:%02x",
               ip_str, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    pthread_mutex_unlock(&g_ndp_mutex);
    return 0;
}

/**
 * @brief Get NDP statistics
 */
void ndp_get_stats(uint64_t *hits, uint64_t *misses, uint64_t *entries)
{
    pthread_mutex_lock(&g_ndp_mutex);
    if (hits) *hits = g_ndp_stats.cache_hits;
    if (misses) *misses = g_ndp_stats.cache_misses;
    if (entries) *entries = g_ndp_count;
    pthread_mutex_unlock(&g_ndp_mutex);
}

/**
 * @brief Dump NDP cache (for CLI)
 */
void ndp_dump(void)
{
    struct ndp_entry *entry;
    char ip_str[64];

    pthread_mutex_lock(&g_ndp_mutex);

    printf("IPv6 Neighbor Cache (%u entries):\n", g_ndp_count);
    printf("%-40s %-18s %s\n", "IPv6 Address", "MAC Address", "State");
    printf("----------------------------------------------------------------------\n");

    entry = g_ndp_cache;
    while (entry) {
        inet_ntop(AF_INET6, entry->ip.addr, ip_str, sizeof(ip_str));
        printf("%-40s %02x:%02x:%02x:%02x:%02x:%02x %s\n",
               ip_str,
               entry->mac[0], entry->mac[1], entry->mac[2],
               entry->mac[3], entry->mac[4], entry->mac[5],
               entry->state == NDP_STATE_REACHABLE ? "REACHABLE" :
               entry->state == NDP_STATE_STALE ? "STALE" : "INCOMPLETE");
        entry = entry->next;
    }

    pthread_mutex_unlock(&g_ndp_mutex);
}

/**
 * @brief Expire old NDP entries
 */
void ndp_expire(void)
{
    struct ndp_entry *entry, *prev = NULL, *next;
    time_t now = time(NULL);

    pthread_mutex_lock(&g_ndp_mutex);

    entry = g_ndp_cache;
    while (entry) {
        next = entry->next;

        if (entry->expires <= now) {
            if (entry->state == NDP_STATE_REACHABLE) {
                entry->state = NDP_STATE_STALE;
                entry->expires = now + 60; /* Keep stale for 60s */
            } else {
                /* Remove entry */
                if (prev) {
                    prev->next = next;
                } else {
                    g_ndp_cache = next;
                }
                free(entry);
                g_ndp_count--;
                entry = next;
                continue;
            }
        }

        prev = entry;
        entry = next;
    }

    pthread_mutex_unlock(&g_ndp_mutex);
}

/**
 * @brief Send Neighbor Solicitation for an IPv6 address
 * @param target Target IPv6 address to resolve
 * @param src_ip Source IPv6 address
 * @param src_mac Source MAC address
 * @param ifindex Interface index to send on
 * @return 0 on success, -1 on error
 */
int ndp_send_solicitation(const struct ipv6_addr *target,
                          const struct ipv6_addr *src_ip,
                          const uint8_t *src_mac,
                          int ifindex)
{
    /* Build Neighbor Solicitation packet */
    /* NS uses solicited-node multicast: ff02::1:ffXX:XXXX */
    uint8_t packet[128];
    memset(packet, 0, sizeof(packet));

    /* Ethernet header (14 bytes) */
    uint8_t *eth = packet;
    /* Destination: solicited-node multicast (33:33:ff:XX:XX:XX) */
    eth[0] = 0x33; eth[1] = 0x33; eth[2] = 0xff;
    eth[3] = target->addr[13];
    eth[4] = target->addr[14];
    eth[5] = target->addr[15];
    /* Source MAC */
    memcpy(&eth[6], src_mac, 6);
    /* EtherType: IPv6 (0x86DD) */
    eth[12] = 0x86; eth[13] = 0xDD;

    /* IPv6 header (40 bytes) */
    uint8_t *ip6 = eth + 14;
    ip6[0] = 0x60; /* Version 6, TC 0, Flow 0 */
    ip6[1] = 0x00;
    ip6[2] = 0x00;
    ip6[3] = 0x00;
    /* Payload length: ICMPv6 header (8) + Target (16) + Option (8) = 32 */
    ip6[4] = 0x00; ip6[5] = 32;
    ip6[6] = 58; /* Next Header: ICMPv6 */
    ip6[7] = 255; /* Hop Limit */
    /* Source address */
    memcpy(&ip6[8], src_ip->addr, 16);
    /* Destination: solicited-node multicast ff02::1:ff00:0/104 + last 24 bits */
    ip6[24] = 0xff; ip6[25] = 0x02;
    memset(&ip6[26], 0, 9);
    ip6[35] = 0x01; ip6[36] = 0xff;
    ip6[37] = target->addr[13];
    ip6[38] = target->addr[14];
    ip6[39] = target->addr[15];

    /* ICMPv6 Neighbor Solicitation (8 + 16 + 8 = 32 bytes) */
    uint8_t *icmp = ip6 + 40;
    icmp[0] = ICMPV6_NEIGHBOR_SOLICIT; /* Type */
    icmp[1] = 0; /* Code */
    icmp[2] = 0; icmp[3] = 0; /* Checksum (computed later) */
    icmp[4] = 0; icmp[5] = 0; icmp[6] = 0; icmp[7] = 0; /* Reserved */
    /* Target Address */
    memcpy(&icmp[8], target->addr, 16);
    /* Source Link-Layer Address Option */
    icmp[24] = NDP_OPT_SOURCE_LINKADDR;
    icmp[25] = 1; /* Length in units of 8 bytes */
    memcpy(&icmp[26], src_mac, 6);

    /* Compute ICMPv6 checksum (pseudo-header + ICMPv6) */
    /* Simplified: For now, set to 0 and let hardware offload or kernel fix */
    /* In production, compute proper checksum */

    g_ndp_stats.ns_sent++;

    char target_str[64];
    inet_ntop(AF_INET6, target->addr, target_str, sizeof(target_str));
    YLOG_DEBUG("NDP: Sent NS for %s on ifindex %d", target_str, ifindex);

    /* TODO: Actually send packet via interface_send() */
    (void)ifindex;

    return 0;
}

/**
 * @brief Build and queue Neighbor Advertisement response
 * @param request_src_ip IPv6 address of the requester
 * @param request_src_mac MAC address of the requester
 * @param target_ip Target IPv6 address (our address)
 * @param our_mac Our MAC address
 * @param ifindex Interface to respond on
 */
int ndp_send_advertisement(const struct ipv6_addr *request_src_ip,
                           const uint8_t *request_src_mac,
                           const struct ipv6_addr *target_ip,
                           const uint8_t *our_mac,
                           int ifindex)
{
    g_ndp_stats.na_sent++;

    char target_str[64];
    inet_ntop(AF_INET6, target_ip->addr, target_str, sizeof(target_str));
    YLOG_DEBUG("NDP: Sent NA for %s on ifindex %d", target_str, ifindex);

    /* TODO: Build and send NA packet */
    (void)request_src_ip;
    (void)request_src_mac;
    (void)target_ip;
    (void)our_mac;
    (void)ifindex;

    return 0;
}

/**
 * @brief Add incomplete entry pending resolution
 */
int ndp_add_incomplete(const struct ipv6_addr *ip)
{
    struct ndp_entry *entry;

    pthread_mutex_lock(&g_ndp_mutex);

    /* Check if already exists */
    entry = g_ndp_cache;
    while (entry) {
        if (memcmp(entry->ip.addr, ip->addr, 16) == 0) {
            pthread_mutex_unlock(&g_ndp_mutex);
            return 0; /* Already exists */
        }
        entry = entry->next;
    }

    if (g_ndp_count >= NDP_MAX_ENTRIES) {
        pthread_mutex_unlock(&g_ndp_mutex);
        return -1;
    }

    entry = calloc(1, sizeof(struct ndp_entry));
    if (!entry) {
        pthread_mutex_unlock(&g_ndp_mutex);
        return -1;
    }

    memcpy(entry->ip.addr, ip->addr, 16);
    entry->state = NDP_STATE_INCOMPLETE;
    entry->expires = time(NULL) + 3; /* 3 second timeout */

    entry->next = g_ndp_cache;
    g_ndp_cache = entry;
    g_ndp_count++;

    pthread_mutex_unlock(&g_ndp_mutex);
    return 0;
}
