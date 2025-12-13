/**
 * @file ipv6_dhcpv6pd.c
 * @brief DHCPv6 Prefix Delegation Server
 *
 * Implements RFC 8415 DHCPv6-PD for delegating IPv6 prefixes to subscribers.
 * Supports SOLICIT, ADVERTISE, REQUEST, REPLY message flow.
 */

#include "ipv6/ipv6.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>

/* DHCPv6 Message Types */
#define DHCPV6_SOLICIT      1
#define DHCPV6_ADVERTISE    2
#define DHCPV6_REQUEST      3
#define DHCPV6_CONFIRM      4
#define DHCPV6_RENEW        5
#define DHCPV6_REBIND       6
#define DHCPV6_REPLY        7
#define DHCPV6_RELEASE      8
#define DHCPV6_DECLINE      9
#define DHCPV6_RECONFIGURE  10
#define DHCPV6_INFO_REQUEST 11
#define DHCPV6_RELAY_FORW   12
#define DHCPV6_RELAY_REPL   13

/* DHCPv6 Option Types */
#define DHCPV6_OPT_CLIENTID     1
#define DHCPV6_OPT_SERVERID     2
#define DHCPV6_OPT_IA_NA        3
#define DHCPV6_OPT_IA_TA        4
#define DHCPV6_OPT_IAADDR       5
#define DHCPV6_OPT_ORO          6
#define DHCPV6_OPT_PREFERENCE   7
#define DHCPV6_OPT_ELAPSED_TIME 8
#define DHCPV6_OPT_RELAY_MSG    9
#define DHCPV6_OPT_STATUS_CODE  13
#define DHCPV6_OPT_RAPID_COMMIT 14
#define DHCPV6_OPT_DNS_SERVERS  23
#define DHCPV6_OPT_DOMAIN_LIST  24
#define DHCPV6_OPT_IA_PD        25
#define DHCPV6_OPT_IAPREFIX     26

/* Status Codes */
#define DHCPV6_STATUS_SUCCESS   0
#define DHCPV6_STATUS_NOADDRS   2
#define DHCPV6_STATUS_NOBINDING 3
#define DHCPV6_STATUS_NOPREFIXAVAIL 6

/* DHCPv6-PD Lease Entry */
struct dhcpv6pd_lease {
    uint8_t client_duid[128];
    int client_duid_len;
    uint32_t iaid;
    struct ipv6_addr prefix;
    uint8_t prefix_len;
    time_t valid_lifetime;
    time_t preferred_lifetime;
    time_t created;
    int ifindex;
    struct dhcpv6pd_lease *next;
};

/* Server Configuration */
static struct {
    bool enabled;
    struct ipv6_addr server_duid;
    int server_duid_len;
    char pool_name[64];
    uint32_t preferred_lifetime;
    uint32_t valid_lifetime;
    struct ipv6_addr dns_servers[3];
    int dns_server_count;
} g_dhcpv6pd_config = {
    .enabled = false,
    .preferred_lifetime = 3600,
    .valid_lifetime = 7200,
    .dns_server_count = 0
};

static struct dhcpv6pd_lease *g_dhcpv6pd_leases = NULL;
static pthread_mutex_t g_dhcpv6pd_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t g_lease_count = 0;

/* Statistics */
static struct {
    uint64_t solicit_recv;
    uint64_t advertise_sent;
    uint64_t request_recv;
    uint64_t reply_sent;
    uint64_t renew_recv;
    uint64_t release_recv;
    uint64_t prefixes_delegated;
} g_dhcpv6pd_stats = {0};

/**
 * @brief Initialize DHCPv6-PD server
 */
int dhcpv6pd_init(void)
{
    /* Generate Server DUID (Type 3 = DUID-LL) */
    g_dhcpv6pd_config.server_duid.addr[0] = 0x00;
    g_dhcpv6pd_config.server_duid.addr[1] = 0x03; /* DUID-LL */
    g_dhcpv6pd_config.server_duid.addr[2] = 0x00;
    g_dhcpv6pd_config.server_duid.addr[3] = 0x01; /* Ethernet */
    /* MAC-like identifier */
    g_dhcpv6pd_config.server_duid.addr[4] = 0xDE;
    g_dhcpv6pd_config.server_duid.addr[5] = 0xAD;
    g_dhcpv6pd_config.server_duid.addr[6] = 0xBE;
    g_dhcpv6pd_config.server_duid.addr[7] = 0xEF;
    g_dhcpv6pd_config.server_duid.addr[8] = 0xCA;
    g_dhcpv6pd_config.server_duid.addr[9] = 0xFE;
    g_dhcpv6pd_config.server_duid_len = 10;

    YLOG_INFO("DHCPv6-PD server initialized");
    return 0;
}

/**
 * @brief Enable/disable DHCPv6-PD server
 */
void dhcpv6pd_enable(bool enable)
{
    g_dhcpv6pd_config.enabled = enable;
    YLOG_INFO("DHCPv6-PD server %s", enable ? "enabled" : "disabled");
}

/**
 * @brief Check if DHCPv6-PD is enabled
 */
bool dhcpv6pd_is_enabled(void)
{
    return g_dhcpv6pd_config.enabled;
}

/**
 * @brief Set the pool to use for prefix delegation
 */
int dhcpv6pd_set_pool(const char *pool_name)
{
    if (!pool_name) return -1;
    strncpy(g_dhcpv6pd_config.pool_name, pool_name, sizeof(g_dhcpv6pd_config.pool_name) - 1);
    YLOG_INFO("DHCPv6-PD using pool: %s", pool_name);
    return 0;
}

/**
 * @brief Set DNS servers for delegation
 */
int dhcpv6pd_set_dns(const struct ipv6_addr *dns, int count)
{
    if (count > 3) count = 3;
    for (int i = 0; i < count; i++) {
        memcpy(&g_dhcpv6pd_config.dns_servers[i], &dns[i], sizeof(struct ipv6_addr));
    }
    g_dhcpv6pd_config.dns_server_count = count;
    return 0;
}

#if 0 /* TODO: Enable when DHCPv6 packet handler is implemented */
/**
 * @brief Allocate a prefix for a client
 * Note: Will be used by DHCPv6 packet handler when fully implemented
 */
static struct dhcpv6pd_lease *dhcpv6pd_allocate_prefix(
    const uint8_t *client_duid, int duid_len, uint32_t iaid, int ifindex)
{
    struct dhcpv6pd_lease *lease;
    struct ipv6_addr prefix;
    uint8_t prefix_len = 64; /* Default allocation length */

    /* Allocate from pool */
    if (ipv6_pool_alloc(g_dhcpv6pd_config.pool_name, &prefix) != 0) {
        YLOG_WARNING("DHCPv6-PD: No prefix available from pool %s",
                     g_dhcpv6pd_config.pool_name);
        return NULL;
    }

    /* Create lease entry */
    lease = calloc(1, sizeof(struct dhcpv6pd_lease));
    if (!lease) {
        ipv6_pool_free(g_dhcpv6pd_config.pool_name, &prefix);
        return NULL;
    }

    memcpy(lease->client_duid, client_duid, duid_len);
    lease->client_duid_len = duid_len;
    lease->iaid = iaid;
    memcpy(&lease->prefix, &prefix, sizeof(prefix));
    lease->prefix_len = prefix_len;
    lease->valid_lifetime = time(NULL) + g_dhcpv6pd_config.valid_lifetime;
    lease->preferred_lifetime = time(NULL) + g_dhcpv6pd_config.preferred_lifetime;
    lease->created = time(NULL);
    lease->ifindex = ifindex;

    pthread_mutex_lock(&g_dhcpv6pd_mutex);
    lease->next = g_dhcpv6pd_leases;
    g_dhcpv6pd_leases = lease;
    g_lease_count++;
    g_dhcpv6pd_stats.prefixes_delegated++;
    pthread_mutex_unlock(&g_dhcpv6pd_mutex);

    char prefix_str[64];
    inet_ntop(AF_INET6, prefix.addr, prefix_str, sizeof(prefix_str));
    YLOG_INFO("DHCPv6-PD: Delegated %s/%d to client", prefix_str, prefix_len);

    return lease;
}

/**
 * @brief Find existing lease for client
 * Note: Will be used by DHCPv6 packet handler when fully implemented
 */
static struct dhcpv6pd_lease *dhcpv6pd_find_lease(
    const uint8_t *client_duid, int duid_len, uint32_t iaid)
{
    struct dhcpv6pd_lease *lease;

    pthread_mutex_lock(&g_dhcpv6pd_mutex);
    lease = g_dhcpv6pd_leases;
    while (lease) {
        if (lease->client_duid_len == duid_len &&
            memcmp(lease->client_duid, client_duid, duid_len) == 0 &&
            lease->iaid == iaid) {
            pthread_mutex_unlock(&g_dhcpv6pd_mutex);
            return lease;
        }
        lease = lease->next;
    }
    pthread_mutex_unlock(&g_dhcpv6pd_mutex);
    return NULL;
}
#endif /* TODO */

/**
 * @brief Release a prefix delegation
 */
int dhcpv6pd_release(const uint8_t *client_duid, int duid_len, uint32_t iaid)
{
    struct dhcpv6pd_lease *lease, *prev = NULL;

    pthread_mutex_lock(&g_dhcpv6pd_mutex);
    lease = g_dhcpv6pd_leases;
    while (lease) {
        if (lease->client_duid_len == duid_len &&
            memcmp(lease->client_duid, client_duid, duid_len) == 0 &&
            lease->iaid == iaid) {
            /* Remove from list */
            if (prev) {
                prev->next = lease->next;
            } else {
                g_dhcpv6pd_leases = lease->next;
            }

            /* Return prefix to pool */
            ipv6_pool_free(g_dhcpv6pd_config.pool_name,
                          &lease->prefix);

            char prefix_str[64];
            inet_ntop(AF_INET6, lease->prefix.addr, prefix_str, sizeof(prefix_str));
            YLOG_INFO("DHCPv6-PD: Released %s/%d", prefix_str, lease->prefix_len);

            free(lease);
            g_lease_count--;
            g_dhcpv6pd_stats.release_recv++;
            pthread_mutex_unlock(&g_dhcpv6pd_mutex);
            return 0;
        }
        prev = lease;
        lease = lease->next;
    }
    pthread_mutex_unlock(&g_dhcpv6pd_mutex);
    return -1;
}

/**
 * @brief Get DHCPv6-PD statistics
 */
void dhcpv6pd_get_stats(uint64_t *delegated, uint64_t *active)
{
    pthread_mutex_lock(&g_dhcpv6pd_mutex);
    if (delegated) *delegated = g_dhcpv6pd_stats.prefixes_delegated;
    if (active) *active = g_lease_count;
    pthread_mutex_unlock(&g_dhcpv6pd_mutex);
}

/**
 * @brief Dump active DHCPv6-PD leases (for CLI)
 */
void dhcpv6pd_dump_leases(void)
{
    struct dhcpv6pd_lease *lease;
    char prefix_str[64];
    time_t now = time(NULL);

    pthread_mutex_lock(&g_dhcpv6pd_mutex);

    printf("DHCPv6-PD Active Leases (%u):\n", g_lease_count);
    printf("%-40s %-6s %-10s %-10s\n", "Prefix", "Len", "Valid(s)", "Pref(s)");
    printf("----------------------------------------------------------------------\n");

    lease = g_dhcpv6pd_leases;
    while (lease) {
        inet_ntop(AF_INET6, lease->prefix.addr, prefix_str, sizeof(prefix_str));
        printf("%-40s /%-5d %-10ld %-10ld\n",
               prefix_str, lease->prefix_len,
               (long)(lease->valid_lifetime - now),
               (long)(lease->preferred_lifetime - now));
        lease = lease->next;
    }

    pthread_mutex_unlock(&g_dhcpv6pd_mutex);
}

/**
 * @brief Expire old leases
 */
void dhcpv6pd_expire(void)
{
    struct dhcpv6pd_lease *lease, *prev = NULL, *next;
    time_t now = time(NULL);

    pthread_mutex_lock(&g_dhcpv6pd_mutex);

    lease = g_dhcpv6pd_leases;
    while (lease) {
        next = lease->next;

        if (lease->valid_lifetime <= now) {
            /* Lease expired */
            if (prev) {
                prev->next = next;
            } else {
                g_dhcpv6pd_leases = next;
            }

            ipv6_pool_free(g_dhcpv6pd_config.pool_name,
                          &lease->prefix);

            char prefix_str[64];
            inet_ntop(AF_INET6, lease->prefix.addr, prefix_str, sizeof(prefix_str));
            YLOG_DEBUG("DHCPv6-PD: Lease expired %s/%d", prefix_str, lease->prefix_len);

            free(lease);
            g_lease_count--;
            lease = next;
            continue;
        }

        prev = lease;
        lease = next;
    }

    pthread_mutex_unlock(&g_dhcpv6pd_mutex);
}
