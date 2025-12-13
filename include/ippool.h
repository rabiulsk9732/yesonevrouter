/**
 * @file ippool.h
 * @brief IP Address Pool Management
 */

#ifndef YESROUTER_IPPOOL_H
#define YESROUTER_IPPOOL_H

#include <stdint.h>
#include <stdbool.h>

#define IPPOOL_MAX_POOLS 16
#define IPPOOL_NAME_LEN 32

struct ip_reservation {
    uint8_t mac[6];
    uint64_t last_seen;
    bool active;
};

struct ip_pool {
    char name[IPPOOL_NAME_LEN];
    uint32_t start_ip;      /* Host order */
    uint32_t end_ip;        /* Host order */
    uint32_t total_ips;
    uint32_t used_ips;

    uint32_t next_alloc_idx; /* Optimization for next allocation */
    uint32_t *bitmap;       /* 1 bit per IP */
    struct ip_reservation *reservations; /* Array of reservations */
    bool active;
};

/**
 * Initialize IP pool subsystem
 */
int ippool_init(void);

/**
 * Create a new IP pool
 * @param name Pool name
 * @param start_ip Start IP address (host order)
 * @param end_ip End IP address (host order)
 * @return 0 on success, -1 on error
 */
int ippool_create(const char *name, uint32_t start_ip, uint32_t end_ip);

/**
 * Delete an IP pool
 */
int ippool_delete(const char *name);

/**
 * Allocate an IP from the pool
 * @param pool_name Name of the pool
 * @param mac Client MAC address (optional, for sticky IP)
 * @return Allocated IP (host order) or 0 if failed
 */
uint32_t ippool_alloc_ip(const char *pool_name, const uint8_t *mac);

/**
 * Free an allocated IP
 * @param pool_name Name of the pool
 * @param ip IP to free (host order)
 */
void ippool_free_ip(const char *pool_name, uint32_t ip);

/**
 * Get pool statistics
 */
struct ip_pool *ippool_get_by_name(const char *name);

/**
 * Print all pools
 */
void ippool_print_all(void);

#endif /* YESROUTER_IPPOOL_H */
