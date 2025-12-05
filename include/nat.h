/**
 * @file nat.h
 * @brief NAT (Network Address Translation) Engine
 *
 * Carrier-Grade NAT implementation supporting:
 * - SNAT44/DNAT44
 * - Deterministic NAT (RFC 7422)
 * - Dynamic NAT with Port Block Allocation
 * - Endpoint Independent Mapping (EIM)
 * - Hairpinning
 */

#ifndef NAT_H
#define NAT_H

#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

/* NAT Configuration */
#define NAT_SESSION_TABLE_SIZE (64 * 1024 * 1024) /* 64M sessions (reduces collisions) */
#define NAT_SESSION_HASH_MASK (NAT_SESSION_TABLE_SIZE - 1)
#define NAT_NUM_PARTITIONS 1024 /* 1024 Lock Partitions */
#define NAT_PARTITION_MASK (NAT_NUM_PARTITIONS - 1)
#define NAT_MAX_POOLS 16
#define PORTS_PER_BLOCK 64   /* Ports per subscriber */
#define NAT_TCP_TIMEOUT 7200 /* TCP session timeout (2 hours) */
#define NAT_UDP_TIMEOUT 300  /* UDP session timeout (5 minutes) */
#define NAT_ICMP_TIMEOUT 60  /* ICMP session timeout (1 minute) */

/* Per-Worker Session Tables */
#define NAT_MAX_WORKERS 16
#define NAT_WORKER_TABLE_SIZE 65536 /* 64K per worker */
#define NAT_WORKER_TABLE_MASK (NAT_WORKER_TABLE_SIZE - 1)
#define NAT_SESSION_CACHE_SIZE 256 /* Per-worker cache for hot sessions */

/* Forward declaration */
struct nat_session;

/**
 * Per-worker session cache entry (packed for cache efficiency)
 * Stores frequently accessed session mappings to avoid hash table lookup
 */
struct nat_session_cache_entry {
    uint32_t inside_ip;
    uint16_t inside_port;
    uint16_t outside_port;
    uint32_t outside_ip;
    uint8_t protocol;
    uint8_t valid;
    uint16_t pad;
} __attribute__((packed));

/**
 * Per-worker NAT session table and statistics
 * Cache-line aligned to prevent false sharing between workers
 */
struct nat_worker_data {
    /* Per-core session tables (lockless within worker) */
    struct nat_session *in2out_table[NAT_WORKER_TABLE_SIZE];
    struct nat_session *out2in_table[NAT_WORKER_TABLE_SIZE];

    /* Per-core statistics */
    uint64_t in2out_hits;
    uint64_t in2out_misses;
    uint64_t out2in_hits;
    uint64_t out2in_misses;
    uint64_t sessions_created;
    uint64_t sessions_deleted;
    uint64_t cache_hits;   /* Fast cache hits */
    uint64_t cache_misses; /* Cache misses - fell through to hash */

    /* Per-worker session cache (L1-resident hot path) */
    struct nat_session_cache_entry session_cache[NAT_SESSION_CACHE_SIZE];
    uint32_t cache_count;
    uint32_t cache_head; /* Circular buffer head for LRU-like eviction */

    uint8_t pad[64]; /* Avoid false sharing */
} __attribute__((aligned(64)));

/* NAT Event Types defined in nat_log.h */

/* Forward declarations */
struct pkt_buf;
struct interface;

/**
 * NAT Session Entry
 * Represents a single NAT translation mapping
 */
struct nat_session {
    /* 5-tuple for session identification */
    uint32_t inside_ip;    /* Private IP address */
    uint32_t outside_ip;   /* Public IP address */
    uint16_t inside_port;  /* Private port */
    uint16_t outside_port; /* Public port */
    uint8_t protocol;      /* IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP */
    uint8_t pad1;

    /* Session metadata */
    uint64_t session_id;    /* Unique session identifier */
    uint32_t subscriber_id; /* Subscriber identifier (hash of inside_ip) */
    uint16_t port_block_id; /* Port block assignment */
    uint16_t pad2;

    /* Timers */
    uint64_t created_ts;   /* Session creation timestamp (ns) */
    uint64_t last_used_ts; /* Last packet timestamp (ns) */
    uint32_t timeout;      /* Session timeout (seconds) */
    uint32_t pad3;

    /* Statistics */
    uint64_t packets_in;  /* Packets LAN→WAN */
    uint64_t packets_out; /* Packets WAN→LAN */
    uint64_t bytes_in;    /* Bytes LAN→WAN */
    uint64_t bytes_out;   /* Bytes WAN→LAN */

    /* Flags */
    uint8_t eim : 1;           /* Endpoint Independent Mapping */
    uint8_t hairpin : 1;       /* Hairpinning enabled */
    uint8_t deterministic : 1; /* Deterministic NAT */
    uint8_t logged : 1;        /* Event logged */
    uint8_t alg_active : 1;    /* ALG processing active */
    uint8_t is_static : 1;     /* Static mapping */
    uint8_t reserved : 2;
    uint8_t pad4[7];

    /* Hash table linkage */
    struct nat_session *next;
    struct nat_session *next_outside; /* Linkage for outside-to-inside lookup table */
} __attribute__((aligned(64)));       /* Cache line aligned */

/**
 * Port Block Allocation
 */
struct port_block {
    uint32_t public_ip;     /* Public IP address */
    uint16_t block_start;   /* Starting port number */
    uint16_t block_size;    /* Block size (e.g., 64) */
    uint32_t subscriber_id; /* Assigned subscriber */
    uint64_t allocated_ts;  /* Allocation timestamp */
    uint64_t port_bitmap;   /* Bitmap of used ports (64 bits) */
};

/**
 * NAT Pool - Range of public IP addresses
 */
struct nat_pool {
    char name[32];
    uint32_t start_ip; /* First IP in pool */
    uint32_t end_ip;   /* Last IP in pool */
    uint32_t netmask;
    uint32_t current_ip; /* Current IP for round-robin */
    uint32_t total_ips;  /* Total IPs in pool */
    uint32_t used_ips;   /* IPs currently in use */
    bool active;
};

/**
 * NAT Statistics
 */
struct nat_stats {
    /* Session statistics */
    uint64_t total_sessions;   /* Total sessions created */
    uint64_t active_sessions;  /* Currently active sessions */
    uint64_t sessions_created; /* Sessions created (counter) */
    uint64_t sessions_deleted; /* Sessions deleted (counter) */
    uint64_t sessions_timeout; /* Sessions timed out */

    /* Translation statistics */
    uint64_t packets_translated; /* Total packets translated */
    uint64_t bytes_translated;   /* Total bytes translated */
    uint64_t snat_packets;       /* SNAT packets */
    uint64_t dnat_packets;       /* DNAT packets */

    /* Error statistics */
    uint64_t no_port_available; /* Port exhaustion */
    uint64_t no_ip_available;   /* IP pool exhaustion */
    uint64_t session_not_found; /* Reverse lookup failed */
    uint64_t invalid_packet;    /* Invalid packet for NAT */

    /* Port block statistics */
    uint64_t port_blocks_allocated;
    uint64_t port_blocks_released;
    uint64_t ports_allocated;
    uint64_t ports_released;

    /* ALG statistics */
    uint64_t alg_icmp_packets;
    uint64_t alg_pptp_packets;

    /* Debug/Performance counters */
    uint64_t in2out_hits;
    uint64_t in2out_misses;
    uint64_t out2in_hits;
    uint64_t out2in_misses;

    /* ICMP-specific statistics */
    uint64_t icmp_echo_requests;         /* ICMP echo requests processed */
    uint64_t icmp_echo_replies;          /* ICMP echo replies processed */
    uint64_t icmp_identifier_mismatches; /* ICMP identifier lookup failures */
    uint64_t icmp_session_race_failures; /* Session creation/lookup race failures */

    /* Diagnostic counters */
    uint64_t snat_function_calls; /* Total SNAT function invocations */
    uint64_t snat_early_returns;  /* SNAT early returns (disabled/null mbuf) */
};

/**
 * NAT Rule (Policy Based NAT)
 * Maps an ACL to a NAT Pool
 */
struct nat_rule {
    char acl_name[32];
    char pool_name[32];
    uint32_t priority; /* Lower is higher priority (execution order) */
    bool active;
};

/**
 * NAT Configuration
 */
struct nat_config {
    bool enabled;
    bool hairpinning_enabled;
    bool eim_enabled; /* Endpoint Independent Mapping */
    bool deterministic_enabled;

/* Pools */
#define NAT_MAX_POOLS 16
    struct nat_pool pools[NAT_MAX_POOLS];
    int num_pools;

/* NAT Rules (Policy Based NAT) */
#define NAT_MAX_RULES 64
    struct nat_rule rules[NAT_MAX_RULES];
    int num_rules;

    /* Statistics */
    struct nat_stats stats;

    /* Logging */
    bool ipfix_enabled;
    bool netflow_enabled;
    struct in_addr ipfix_collector;
    uint16_t ipfix_collector_port;
    struct in_addr netflow_collector;
    uint16_t netflow_collector_port;
};

/**
 * Initialize NAT subsystem
 * @return 0 on success, -1 on error
 */
int nat_init(void);

/**
 * Initialize NAT session table locks
 * @return 0 on success, -1 on error
 */
int nat_session_init(void);

/**
 * Cleanup NAT subsystem
 */
void nat_cleanup(void);

/**
 * Check if NAT is enabled
 * @return true if NAT is enabled, false otherwise
 */
bool nat_is_enabled(void);

/**
 * Enable or disable NAT globally
 * @param enable true to enable, false to disable
 */
void nat_enable(bool enable);

/**
 * Create a NAT pool
 * @param name Pool name
 * @param start_ip First IP in pool
 * @param end_ip Last IP in pool
 * @param netmask Netmask
 * @return 0 on success, -1 on error
 */
int nat_pool_create(const char *name, uint32_t start_ip, uint32_t end_ip, uint32_t netmask);

/**
 * Delete a NAT pool
 * @param name Pool name
 * @return 0 on success, -1 on error
 */
int nat_pool_delete(const char *name);

/**
 * Allocate public IP from NAT pool
 * @param pool NAT pool
 * @return Public IP (host byte order), 0 on error
 */
uint32_t nat_pool_allocate_ip(struct nat_pool *pool);

/**
 * Release public IP back to NAT pool
 * @param pool NAT pool
 * @param ip Public IP to release (host byte order)
 */
void nat_pool_release_ip(struct nat_pool *pool, uint32_t ip);

/**
 * Allocate public port
 * @param public_ip Public IP address
 * @param protocol Protocol
 * @return Port number, 0 on error
 */
uint16_t nat_allocate_port(uint32_t public_ip, uint8_t protocol);

/**
 * Process packet for NAT (SNAT - inside to outside)
 * @param pkt Packet buffer
 * @param iface Ingress interface
 * @return 0 on success, -1 on error
 */
int nat_translate_snat(struct pkt_buf *pkt, struct interface *iface);

/**
 * Process packet for reverse NAT (DNAT - outside to inside)
 * @param pkt Packet buffer
 * @param iface Ingress interface
 * @return 0 on success, -1 on error
 */
int nat_translate_dnat(struct pkt_buf *pkt, struct interface *iface);

/**
 * Create a NAT session
 * @param inside_ip Private IP
 * @param inside_port Private port
 * @param outside_ip Public IP
 * @param outside_port Public port
 * @param protocol Protocol (TCP/UDP/ICMP)
 * @return NAT session pointer, NULL on error
 */
struct nat_session *nat_session_create(uint32_t inside_ip, uint16_t inside_port,
                                       uint32_t outside_ip, uint16_t outside_port,
                                       uint8_t protocol);

/**
 * Lookup NAT session by inside (private) 5-tuple
 * @param inside_ip Private IP
 * @param inside_port Private port
 * @param protocol Protocol
 * @return NAT session pointer, NULL if not found
 */
struct nat_session *nat_session_lookup_inside(uint32_t inside_ip, uint16_t inside_port,
                                              uint8_t protocol);

/**
 * Lookup NAT session by outside (public) 5-tuple
 * @param outside_ip Public IP
 * @param outside_port Public port
 * @param protocol Protocol
 * @return NAT session pointer, NULL if not found
 */
struct nat_session *nat_session_lookup_outside(uint32_t outside_ip, uint16_t outside_port,
                                               uint8_t protocol);

/**
 * Delete a NAT session
 * @param session Session to delete
 */
void nat_session_delete(struct nat_session *session);

/**
 * Timeout expired sessions
 * @return Number of sessions deleted
 */
int nat_session_timeout_check(void);

/**
 * Get NAT statistics
 * @param stats Pointer to store statistics
 * @return 0 on success, -1 on error
 */
int nat_get_stats(struct nat_stats *stats);

/**
 * Print NAT configuration
 */
void nat_print_config(void);

/**
 * Print NAT sessions
 */
void nat_print_sessions(void);

/**
 * Clear all NAT sessions
 */
void nat_clear_sessions(void);

/**
 * Initialize port block pool
 * @param max_blocks Maximum number of port blocks
 * @return 0 on success, -1 on error
 */
int nat_portblock_init(uint32_t max_blocks);

/**
 * Cleanup port block pool
 */
void nat_portblock_cleanup(void);

/**
 * Allocate port block for subscriber
 * @param subscriber_id Subscriber ID
 * @param public_ip Public IP (host byte order)
 * @param block_size Block size (e.g., 64)
 * @return Block ID or -1 on error
 */
int nat_portblock_allocate(uint32_t subscriber_id, uint32_t public_ip, uint16_t block_size);

/**
 * Allocate port from subscriber's port block
 * @param subscriber_id Subscriber ID
 * @param public_ip Public IP (host byte order)
 * @param protocol Protocol
 * @return Port number or 0 on error
 */
uint16_t nat_portblock_allocate_port(uint32_t subscriber_id, uint32_t public_ip, uint8_t protocol);

/**
 * Release port back to pool
 * @param subscriber_id Subscriber ID
 * @param public_ip Public IP (host byte order)
 * @param port Port number
 */
void nat_portblock_release_port(uint32_t subscriber_id, uint32_t public_ip, uint16_t port);

/**
 * Get port block info for subscriber
 * @param subscriber_id Subscriber ID
 * @param public_ip Public IP (host byte order)
 * @param block_out Output buffer
 * @return 0 on success, -1 on error
 */
int nat_portblock_get_info(uint32_t subscriber_id, uint32_t public_ip,
                           struct port_block *block_out);

/**
 * Print port block statistics
 */
void nat_portblock_print_stats(void);

/**
 * Set number of NAT workers (for per-worker session tables)
 * @param num_workers Number of worker threads
 */
void nat_set_num_workers(uint32_t num_workers);

/**
 * Get number of NAT workers
 * @return Number of active workers
 */
uint32_t nat_get_num_workers(void);

/**
 * Get pointer to per-worker statistics (for internal use)
 * @param worker_id Worker ID (0 to NAT_MAX_WORKERS-1)
 * @return Pointer to worker data, or NULL if invalid
 */
struct nat_worker_data *nat_get_worker_stats_ptr(uint32_t worker_id);

#endif /* NAT_H */
