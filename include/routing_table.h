/**
 * @file routing_table.h
 * @brief Routing Table with Longest Prefix Match (LPM)
 *
 * Implements efficient routing table using Radix Tree (Trie) for LPM lookups.
 * Supports RIB/FIB separation, admin distance, and ECMP.
 */

#ifndef ROUTING_TABLE_H
#define ROUTING_TABLE_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <time.h>

/* Maximum number of ECMP paths per route */
#define ROUTE_MAX_ECMP_PATHS    8
#define ROUTE_MAX_SOURCE_LEN    32

/* Admin distance values (lower = higher priority) */
#define ADMIN_DISTANCE_CONNECTED    0
#define ADMIN_DISTANCE_STATIC       1
#define ADMIN_DISTANCE_EBGP         20
#define ADMIN_DISTANCE_IBGP         200
#define ADMIN_DISTANCE_OSPF         110
#define ADMIN_DISTANCE_ISIS         115
#define ADMIN_DISTANCE_RIP          120
#define ADMIN_DISTANCE_MAX          255

/* Route source types */
enum route_source {
    ROUTE_SOURCE_CONNECTED = 0,
    ROUTE_SOURCE_STATIC,
    ROUTE_SOURCE_BGP,
    ROUTE_SOURCE_OSPF,
    ROUTE_SOURCE_ISIS,
    ROUTE_SOURCE_RIP,
    ROUTE_SOURCE_UNKNOWN
};

/* ECMP path entry */
struct ecmp_path {
    struct in_addr next_hop;
    uint32_t egress_ifindex;
    uint32_t weight;              /* For weighted ECMP */
    uint64_t packets;             /* Statistics */
    uint64_t bytes;
};

/* Route entry structure */
struct route_entry {
    struct in_addr prefix;
    uint8_t prefix_len;           /* 0-32 for IPv4 */

    /* Next hop information */
    struct in_addr next_hop;
    uint32_t egress_ifindex;

    /* Route attributes */
    uint8_t admin_distance;
    enum route_source source;
    char source_name[ROUTE_MAX_SOURCE_LEN];

    /* ECMP support */
    uint32_t num_paths;
    struct ecmp_path paths[ROUTE_MAX_ECMP_PATHS];
    uint32_t ecmp_hash_seed;      /* For consistent hashing */

    /* Statistics */
    uint64_t packets;
    uint64_t bytes;
    time_t created_time;
    time_t last_used;

    /* Internal use */
    bool in_fib;                  /* Is this route in FIB? */
    struct route_entry *next;     /* For RIB list */
};

/* Radix tree node */
struct radix_node {
    struct in_addr prefix;
    uint8_t prefix_len;

    /* Child nodes (0 = left, 1 = right) */
    struct radix_node *left;
    struct radix_node *right;

    /* Route data (NULL if intermediate node) */
    struct route_entry *route;

    /* Reference count */
    uint32_t refcnt;
};

/* Routing table structure */
struct routing_table {
    /* RIB (Routing Information Base) - all routes */
    struct radix_node *rib_root;
    uint32_t rib_count;

    /* FIB (Forwarding Information Base) - best routes only */
    struct radix_node *fib_root;
    uint32_t fib_count;

    /* Statistics */
    uint64_t lookups;
    uint64_t hits;
    uint64_t misses;
    uint64_t inserts;
    uint64_t deletes;

    /* Lock for thread safety */
    void *lock;                   /* pthread_rwlock_t or similar */
};

/* Route update notification callback */
typedef void (*route_update_callback_t)(struct route_entry *route,
                                        bool added,
                                        void *user_data);

/* Route update notification context */
struct route_notification {
    route_update_callback_t callback;
    void *user_data;
    struct route_notification *next;
};

/**
 * Initialize routing table
 * @return Pointer to routing table or NULL on failure
 */
struct routing_table *routing_table_init(void);
struct routing_table *routing_table_get_instance(void);

/**
 * Cleanup and free routing table
 * @param table Routing table to cleanup
 */
void routing_table_cleanup(struct routing_table *table);

/**
 * Add route to routing table
 * @param table Routing table
 * @param prefix Network prefix
 * @param prefix_len Prefix length (0-32)
 * @param next_hop Next hop IP address
 * @param egress_ifindex Egress interface index
 * @param admin_distance Administrative distance
 * @param source Route source type
 * @param source_name Source name/identifier
 * @return 0 on success, -1 on failure
 */
int routing_table_add(struct routing_table *table,
                      const struct in_addr *prefix,
                      uint8_t prefix_len,
                      const struct in_addr *next_hop,
                      uint32_t egress_ifindex,
                      uint8_t admin_distance,
                      enum route_source source,
                      const char *source_name);

/**
 * Delete route from routing table
 * @param table Routing table
 * @param prefix Network prefix
 * @param prefix_len Prefix length
 * @param source Route source (for disambiguation)
 * @return 0 on success, -1 if route not found
 */
int routing_table_delete(struct routing_table *table,
                         const struct in_addr *prefix,
                         uint8_t prefix_len,
                         enum route_source source);

/**
 * Lookup route using Longest Prefix Match
 * @param table Routing table
 * @param ip IP address to lookup
 * @return Route entry or NULL if no route found
 */
struct route_entry *routing_table_lookup(struct routing_table *table,
                                         const struct in_addr *ip);

/**
 * Add ECMP path to existing route
 * @param table Routing table
 * @param prefix Network prefix
 * @param prefix_len Prefix length
 * @param next_hop Next hop IP address
 * @param egress_ifindex Egress interface index
 * @param weight Path weight (for weighted ECMP)
 * @return 0 on success, -1 on failure
 */
int routing_table_add_ecmp_path(struct routing_table *table,
                                const struct in_addr *prefix,
                                uint8_t prefix_len,
                                const struct in_addr *next_hop,
                                uint32_t egress_ifindex,
                                uint32_t weight);

/**
 * Select ECMP path for packet (consistent hashing)
 * @param route Route entry with ECMP paths
 * @param flow_hash Flow hash (5-tuple hash)
 * @return Pointer to selected ECMP path or NULL
 */
struct ecmp_path *routing_table_select_ecmp_path(struct route_entry *route,
                                                  uint32_t flow_hash);

/**
 * Register route update notification callback
 * @param table Routing table
 * @param callback Callback function
 * @param user_data User data passed to callback
 * @return 0 on success, -1 on failure
 */
int routing_table_register_notification(struct routing_table *table,
                                        route_update_callback_t callback,
                                        void *user_data);

/**
 * Get routing table statistics
 * @param table Routing table
 * @param lookups Number of lookups (output)
 * @param hits Number of successful lookups (output)
 * @param misses Number of failed lookups (output)
 * @param rib_count Number of routes in RIB (output)
 * @param fib_count Number of routes in FIB (output)
 */
void routing_table_get_stats(struct routing_table *table,
                             uint64_t *lookups,
                             uint64_t *hits,
                             uint64_t *misses,
                             uint64_t *rib_count,
                             uint64_t *fib_count);

/**
 * Print routing table (for debugging)
 * @param table Routing table
 */
void routing_table_print(struct routing_table *table);

/**
 * Print route entry (for debugging)
 * @param route Route entry to print
 */
void routing_table_print_route(struct route_entry *route);

/**
 * Convert route source to string
 * @param source Route source type
 * @return String representation
 */
const char *routing_table_source_to_str(enum route_source source);

#endif /* ROUTING_TABLE_H */
