/**
 * @file dns.h
 * @brief DNS Resolver/Proxy Interface
 */

#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

/* DNS Configuration */
#define DNS_MAX_SERVERS     4
#define DNS_DEFAULT_PORT    53
#define DNS_MAX_CACHE       1024

/* DNS Statistics */
struct dns_stats {
    uint64_t queries;
    uint64_t queries_sent;
    uint64_t responses;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t timeouts;
    uint64_t errors;
};

/**
 * Initialize DNS subsystem
 * @return 0 on success, -1 on error
 */
int dns_init(void);

/**
 * Cleanup DNS subsystem
 */
void dns_cleanup(void);

/**
 * Add DNS server
 * @param server DNS server address
 * @return 0 on success, -1 on error
 */
int dns_add_server(const struct in_addr *server);

/**
 * Clear all DNS servers
 */
void dns_clear_servers(void);

/**
 * Resolve hostname to IP address
 * @param hostname Hostname to resolve
 * @param result Pointer to store result
 * @return 0 on success, -1 on error
 */
int dns_resolve(const char *hostname, struct in_addr *result);

/**
 * Get DNS statistics
 * @param stats Pointer to store statistics
 * @return 0 on success, -1 on error
 */
int dns_get_stats(struct dns_stats *stats);

/**
 * Print DNS configuration
 */
void dns_print_config(void);

#endif /* DNS_H */
