/**
 * @file ipv6.h
 * @brief IPv6 Subsystem Core Definitions
 */

#ifndef IPV6_H
#define IPV6_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

/* IPv6 Address definitions */
struct ipv6_addr {
    uint8_t addr[16];
};

/* Constants */
#define IPV6_PREFIX_LEN_DEFAULT 64
#define IPV6_MAX_POOLS 64
#define IPV6_MIN_MTU 1280

/* Initialization */
int ipv6_init(void);
void ipv6_cleanup(void);

/* Feature checks */
bool ipv6_is_enabled(void);
void ipv6_enable(bool enable);

/* IPv6 Fetcher (DHCPv6 Client) */
/* Structure Config for Fetcher */
struct ipv6_fetcher_config {
    char interface[16];
    bool enabled;
    uint8_t requested_prefix_len; /* e.g. 48, 56 */
};

/* Fetcher API */
int ipv6_fetcher_init(void);
int ipv6_fetcher_start(const char *interface);
int ipv6_fetcher_stop(void);
int ipv6_fetcher_get_prefix(struct ipv6_addr *prefix, uint8_t *len);

/* IPv6 Pool Management */
#define IPV6_POOL_NAME_LEN 32

struct ipv6_pool {
    char name[IPV6_POOL_NAME_LEN];
    struct ipv6_addr base_prefix;
    uint8_t prefix_len;
    uint8_t alloc_len; /* Length of prefixes to allocate (e.g. 64) */

    struct ipv6_pool *next; /* Linked list */

    /* Allocation bitmap/tracking would go here */
    /* For now, simple counter/list approach */
    uint32_t total_prefixes;
    uint32_t used_prefixes;
};

/* Pool API */
int ipv6_pool_init(void);
int ipv6_pool_create(const char *name, struct ipv6_addr *prefix, uint8_t len, uint8_t alloc_len);
int ipv6_pool_delete(const char *name);
int ipv6_pool_alloc(const char *pool_name, struct ipv6_addr *allocated_prefix);
void ipv6_pool_free(const char *pool_name, struct ipv6_addr *prefix);
struct ipv6_pool *ipv6_pool_get(const char *name);

/* IPv6 Routing */
struct ipv6_route {
    struct ipv6_addr dest_prefix;
    uint8_t prefix_len;
    struct ipv6_addr next_hop; /* :: if directly connected */
    char interface[16];        /* Outgoing interface */
    uint32_t metric;

    struct ipv6_route *next;   /* Linked list for simple implementation */
};

/* Routing API */
int ipv6_route_init(void);
int ipv6_route_add(const struct ipv6_addr *dest, uint8_t len, const struct ipv6_addr *next_hop, const char *iface, uint32_t metric);
int ipv6_route_del(const struct ipv6_addr *dest, uint8_t len);
struct ipv6_route *ipv6_route_lookup(const struct ipv6_addr *dest);
void ipv6_route_dump(void); /* For debugging/CLI */

/* IPv6 Neighbor Discovery Protocol (NDP) */
int ndp_init(void);
int ndp_lookup(const struct ipv6_addr *ip, uint8_t *mac);
int ndp_update(const struct ipv6_addr *ip, const uint8_t *mac);
void ndp_expire(void);
void ndp_dump(void);
void ndp_get_stats(uint64_t *hits, uint64_t *misses, uint64_t *entries);
int ndp_send_solicitation(const struct ipv6_addr *target,
                          const struct ipv6_addr *src_ip,
                          const uint8_t *src_mac,
                          int ifindex);
int ndp_send_advertisement(const struct ipv6_addr *request_src_ip,
                           const uint8_t *request_src_mac,
                           const struct ipv6_addr *target_ip,
                           const uint8_t *our_mac,
                           int ifindex);
int ndp_add_incomplete(const struct ipv6_addr *ip);

/* ICMPv6 */
#define ICMPV6_ECHO_REQUEST     128
#define ICMPV6_ECHO_REPLY       129
#define ICMPV6_NEIGHBOR_SOLICIT 135
#define ICMPV6_NEIGHBOR_ADVERT  136

/* DHCPv6-PD Server */
int dhcpv6pd_init(void);
void dhcpv6pd_enable(bool enable);
bool dhcpv6pd_is_enabled(void);
int dhcpv6pd_set_pool(const char *pool_name);
int dhcpv6pd_set_dns(const struct ipv6_addr *dns, int count);
int dhcpv6pd_release(const uint8_t *client_duid, int duid_len, uint32_t iaid);
void dhcpv6pd_get_stats(uint64_t *delegated, uint64_t *active);
void dhcpv6pd_dump_leases(void);
void dhcpv6pd_expire(void);

#endif /* IPV6_H */
