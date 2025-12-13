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
#define NAT_MAX_WORKERS 64    /* Supports up to 64 worker cores */
#define NAT_WORKER_TABLE_SIZE 65536 /* 64K per worker */
#define NAT_WORKER_TABLE_MASK (NAT_WORKER_TABLE_SIZE - 1)
#define NAT_SESSION_CACHE_SIZE 256 /* Per-worker cache for hot sessions */

/* Forward declaration */
/* Forward declaration */
struct nat_session;
struct rte_ip_frag_tbl;
struct rte_ip_frag_death_row;

/**
 * Per-worker session cache entry (packed for cache efficiency)
 * Stores frequently accessed session mappings to avoid hash table lookup
 */
struct nat_session_cache_entry {
    uint32_t inside_ip;
    uint16_t inside_port;
    uint32_t session_index; /* Index in global slab */
    uint8_t protocol;
    uint8_t valid;
    uint8_t pad[4]; /* Pad to 16 bytes */
} __attribute__((packed));

/**
 * Open Addressing Hash Bucket
 * Stores 32-bit signature (hash fragment) and 32-bit session index.
 * Packed into 64-bit for atomic ops (optional) or efficient storage.
 */
struct nat_hash_bucket {
    uint32_t sig; /* Hash signature for quick check */
    uint32_t idx; /* Session Index (0 = Empty) */
};

/**
 * Per-worker NAT session table and statistics
 * Cache-line aligned to prevent false sharing between workers
 */
struct nat_worker_data {
    /* Per-core Open Addressing Hash Tables */
    /* Size: NAT_WORKER_TABLE_SIZE * 2 (Load Factor 0.5) */
    struct nat_hash_bucket *in2out_hash;
    struct nat_hash_bucket *out2in_hash;
    uint32_t hash_mask; /* Size - 1 */

    /* Per-core statistics */
    uint64_t in2out_hits;
    uint64_t in2out_misses;
    uint64_t out2in_hits;
    uint64_t out2in_misses;
    uint64_t sessions_created;
    uint64_t sessions_deleted;
    uint64_t sessions_failed;     /* Session creation failures */
    uint64_t port_alloc_failed;   /* Port allocation failures */
    uint64_t cache_hits;   /* Fast cache hits */
    uint64_t cache_misses; /* Cache misses - fell through to hash */

    /* Packet Translation Stats (Per-Worker) */
    uint64_t packets_translated;
    uint64_t snat_packets;
    uint64_t dnat_packets;

    /* Per-worker session cache (L1-resident hot path) */
    struct nat_session_cache_entry session_cache[NAT_SESSION_CACHE_SIZE];
    uint32_t cache_count;
    uint32_t cache_head; /* Circular buffer head for LRU-like eviction */

    /* IPv4 Reassembly Table (Per-Worker) */
    struct rte_ip_frag_tbl *frag_tbl;
    struct rte_ip_frag_death_row *death_row;

    /* Per-worker port pool for LOCKLESS port allocation */
    struct {
        uint32_t nat_ip;               /* NAT IP assigned to this worker */
        uint32_t port_bitmap[2048];    /* 64K ports / 32 bits = 2048 words */
        uint16_t next_hint;            /* Next port to try (for cache locality) */
        uint16_t ports_allocated;      /* Count of allocated ports */
        uint16_t port_min;             /* Minimum port (default: 1024) */
        uint16_t port_max;             /* Maximum port (default: 65535) */
        uint64_t alloc_success;        /* Allocation success counter */
        uint64_t alloc_fail;           /* Allocation failure counter */
    } port_pool;

    /* Per-worker session pool for LOCKLESS session allocation */
    struct {
        uint32_t *free_stack;          /* Stack of free session indices */
        uint32_t free_top;             /* Top of free stack */
        uint32_t capacity;             /* Total sessions in this worker's pool */
        uint64_t alloc_success;        /* Allocation success counter */
        uint64_t alloc_fail;           /* Allocation failure counter */
    } session_pool;

    /* VPP-STYLE: Worker handoff ring for lockless cross-worker packet routing */
    struct rte_ring *handoff_ring;     /* Incoming packets from other workers */
    uint64_t handoff_enqueue;          /* Packets sent to other workers */
    uint64_t handoff_dequeue;          /* Packets received from other workers */

    uint8_t pad[40]; /* Avoid false sharing (adjusted for new fields) */
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
    /* Cacheline 0: Hot Fields (Query & Translation) */
    uint32_t inside_ip;    /* 4 */
    uint32_t outside_ip;   /* 8 */
    uint16_t inside_port;  /* 10 */
    uint16_t outside_port; /* 12 */
    uint8_t protocol;      /* 13 */
    uint8_t flags;         /* 14 (consolidated bitfields) */
    uint16_t _pad1;        /* 16 */

    /* Hot Write Fields (Timestamp) */
    uint64_t last_used_ts; /* 24 */
    uint32_t timeout;      /* 28 */
    uint32_t session_index;/* 32: Index in Slab (0 = invalid) */

    /* Hash Table Linkage (Hot for lookup) */
    struct nat_session *next;         /* 40: Next in In2Out bucket */
    struct nat_session *next_outside; /* 48: Next in Out2In bucket */

    /* Metadata needed for flow tracking */
    uint32_t subscriber_id; /* 52 */
    uint16_t port_block_id; /* 54 */
    uint16_t _pad2;         /* 56 */
    uint64_t _pad3;         /* 64: End of CL 0 */

    /* Cacheline 1: Cold / Stats / Management */
    uint64_t created_ts;
    uint32_t dest_ip;       /* For NetFlow */
    uint16_t dest_port;
    uint16_t _pad4;

    uint64_t session_id;

    /* Statistics (Atomic or per-worker in V2? Kept atomic for now) */
    uint64_t packets_in;
    uint64_t packets_out;
    uint64_t bytes_in;
    uint64_t bytes_out;

    /* Flow Export */
    uint64_t last_export_ts;
    uint64_t exported_pkts_in;
    uint64_t exported_pkts_out;
    uint64_t exported_bytes_in;
    uint64_t exported_bytes_out;
    uint8_t exported;
    uint8_t alg_active;
    uint8_t alg_type;
    uint8_t _pad5[5];
} __attribute__((aligned(64)));

/* Flags definitions */
#define NAT_SESSION_FLAG_EIM           (1 << 0)
#define NAT_SESSION_FLAG_HAIRPIN       (1 << 1)
#define NAT_SESSION_FLAG_DETERMINISTIC (1 << 2)
#define NAT_SESSION_FLAG_STATIC        (1 << 3)
#define NAT_SESSION_FLAG_LOGGED        (1 << 4)

/* Global Session Slab */
extern struct nat_session *g_session_slab;
extern uint32_t g_max_sessions;

int nat_session_slab_init(uint32_t max_sessions);
struct nat_session *nat_session_alloc_slab(void);
void nat_session_free_slab(struct nat_session *s);

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

    /* Port Allocation Logic (Thread-Safe via Atomic Bitmaps) */
    /* pthread_spinlock_t lock; REMOVED in V2 */
    uint64_t *port_bitmap;        /* Bitmap for port tracking (1 bit per port) */
    /* Note: We allocate this dynamically. 65536 bits = 8KB per IP?
       Wait, if pool has multiple IPs, do we need one bitmap PER IP?
       Yes. Or we alloc (Pool_Size * 65536) bits.
       For simplicity in Phase 2, let's assume we map (IP, Port) -> Global Bitmap?
       No, standard NAT uses Per-IP port usage.
       Let's add a pointer `void *ip_bitmaps` and manage it in nat_core.c.
    */
    void *ip_port_bitmaps; /* Array of bitmaps, one per IP */
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
 * Find NAT pool by public IP
 * @param ip Public IP address (host byte order)
 * @return NAT pool or NULL if not found
 */
struct nat_pool *nat_pool_get_by_ip(uint32_t ip);

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
uint16_t nat_allocate_port(struct nat_pool *pool, uint32_t public_ip, uint8_t protocol);

/**
 * Allocate public port with parity preference (RFC 6888 REQ-1)
 * @param pool NAT pool
 * @param public_ip Public IP address
 * @param protocol Protocol
 * @param preferred_port Preferred port (usually the internal port)
 * @return Port number (same as preferred if available), 0 on error
 */
uint16_t nat_allocate_port_with_parity(struct nat_pool *pool, uint32_t public_ip,
                                       uint8_t protocol, uint16_t preferred_port);

/**
 * Release public port
 * @param pool NAT pool
 * @param public_ip Public IP address
 * @param port Port number
 * @param protocol Protocol
 */
void nat_release_port(struct nat_pool *pool, uint32_t public_ip, uint16_t port, uint8_t protocol);

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
 * @param dest_ip Destination IP (for NetFlow logging)
 * @param dest_port Destination port (for NetFlow logging)
 * @return NAT session pointer, NULL on error
 */
struct nat_session *nat_session_create(uint32_t inside_ip, uint16_t inside_port,
                                       uint32_t outside_ip, uint16_t outside_port,
                                       uint8_t protocol, uint32_t dest_ip, uint16_t dest_port);

/**
 * Create NAT session - LOCKLESS PATH
 * Bypasses global locks when worker ID is valid and multi-worker mode active.
 * @param worker_id Current worker thread ID
 * @param inside_ip Private IP
 * @param inside_port Private port
 * @param outside_ip Public IP (NAT)
 * @param outside_port Public port (NAT)
 * @param protocol Protocol (TCP/UDP/ICMP)
 * @param dest_ip Destination IP
 * @param dest_port Destination port
 * @return NAT session pointer, NULL on error
 */
struct nat_session *nat_session_create_lockless(uint32_t worker_id,
                                                 uint32_t inside_ip, uint16_t inside_port,
                                                 uint32_t outside_ip, uint16_t outside_port,
                                                 uint8_t protocol, uint32_t dest_ip, uint16_t dest_port);

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
 * PURE LOCKLESS session lookup - never falls back to global locks (VPP-style)
 * Use when RSS guarantees flow affinity to current worker
 * @param inside_ip Private IP
 * @param inside_port Private port
 * @param protocol Protocol
 * @param worker_id Worker ID (must be valid)
 * @return NAT session pointer, NULL if not found
 */
struct nat_session *nat_session_lookup_lockless(uint32_t inside_ip, uint16_t inside_port,
                                                uint8_t protocol, uint32_t worker_id);

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
 * Initialize per-worker port pool (LOCKLESS)
 * @param worker_id Worker ID
 * @param nat_ip NAT IP assigned to this worker
 * @param port_min Minimum port (typically 1024)
 * @param port_max Maximum port (typically 65535)
 */
void nat_worker_port_pool_init(uint32_t worker_id, uint32_t nat_ip,
                               uint16_t port_min, uint16_t port_max);

/**
 * Allocate port from worker's pool (LOCKLESS - no locks!)
 * @param worker_id Worker ID
 * @param preferred_port Preferred port for parity preservation (0 = no preference)
 * @return Port number, 0 on failure
 */
uint16_t nat_worker_alloc_port_lockless(uint32_t worker_id, uint16_t preferred_port);

/**
 * Free port back to worker's pool (LOCKLESS)
 * @param worker_id Worker ID
 * @param port Port number to free
 */
void nat_worker_free_port_lockless(uint32_t worker_id, uint16_t port);

/**
 * Initialize per-worker session pool (LOCKLESS)
 * Pre-allocates session indices for fast allocation
 * @param worker_id Worker ID
 * @param start_index Starting session index in global slab
 * @param count Number of sessions to assign to this worker
 */
void nat_worker_session_pool_init(uint32_t worker_id, uint32_t start_index, uint32_t count);

/**
 * Allocate session from worker's pool (LOCKLESS - no locks!)
 * @param worker_id Worker ID
 * @return Session pointer, NULL on failure
 */
struct nat_session *nat_worker_alloc_session_lockless(uint32_t worker_id);

/**
 * Free session back to worker's pool (LOCKLESS)
 * @param worker_id Worker ID
 * @param session Session to free
 */
void nat_worker_free_session_lockless(uint32_t worker_id, struct nat_session *session);

/**
 * Get pointer to per-worker statistics (for internal use)
 * @param worker_id Worker ID (0 to NAT_MAX_WORKERS-1)
 * @return Pointer to worker data, or NULL if invalid
 */
struct nat_worker_data *nat_get_worker_stats_ptr(uint32_t worker_id);

/* VPP-STYLE Worker Handoff API (for lockless 10M PPS) */
#ifdef HAVE_DPDK
struct rte_mbuf;

/**
 * Initialize worker handoff rings (call once at startup)
 * @param num_workers Number of worker threads
 * @return 0 on success, -1 on error
 */
int nat_worker_handoff_init(uint32_t num_workers);

/**
 * Map flow to worker ID (deterministic - same flow always maps to same worker)
 * @return Worker ID that should handle this flow
 */
uint32_t nat_flow_to_worker(uint32_t src_ip, uint16_t src_port,
                            uint32_t dst_ip, uint16_t dst_port,
                            uint8_t proto);

/**
 * Enqueue packet to target worker's handoff ring
 * @return 0 on success, -1 if ring full
 */
int nat_worker_handoff_enqueue(uint32_t target_worker, struct rte_mbuf *pkt);

/**
 * Dequeue packets from this worker's handoff ring
 * @return Number of packets dequeued
 */
uint16_t nat_worker_handoff_dequeue(uint32_t worker_id, struct rte_mbuf **pkts, uint16_t max_pkts);
#endif /* HAVE_DPDK */

/* NAT64 API (RFC 6146/6145) */
int nat64_init(void);
void nat64_enable(bool enable);
bool nat64_is_enabled(void);
int nat64_set_prefix(const uint8_t *prefix, uint8_t prefix_len);
bool nat64_is_nat64_address(const uint8_t *ipv6_addr);
uint32_t nat64_extract_ipv4(const uint8_t *ipv6_addr);
void nat64_construct_ipv6(uint8_t *ipv6_out, uint32_t ipv4_addr);
void nat64_get_stats(uint64_t *pkts_6to4, uint64_t *pkts_4to6, uint64_t *errors);
void nat64_print_config(void);

/* NAT RSS API (Receive Side Scaling for lockless operation) */
int nat_rss_configure(uint16_t port_id, uint16_t num_workers);
uint32_t nat_rss_get_worker_id(uint32_t src_ip, uint32_t dst_ip,
                               uint16_t src_port, uint16_t dst_port,
                               uint8_t protocol);
bool nat_rss_is_enabled(void);
uint16_t nat_rss_get_num_queues(void);
void nat_rss_print_config(void);

/* NAT HA API (High Availability) */
int nat_ha_init(void);
int nat_ha_set_peer(const char *peer_ip, uint16_t port);
int nat_ha_enable(bool enable, uint16_t local_port);
void nat_ha_set_role(bool is_active);
bool nat_ha_is_enabled(void);
bool nat_ha_is_active(void);
int nat_ha_sync_session(struct nat_session *session, uint8_t msg_type);
int nat_ha_send_heartbeat(void);
bool nat_ha_peer_alive(void);
void nat_ha_trigger_failover(void);
void nat_ha_get_stats(uint64_t *sessions_synced, uint64_t *heartbeats_sent,
                      uint64_t *heartbeats_received, uint64_t *sync_errors);
void nat_ha_print_status(void);
void nat_ha_cleanup(void);

#endif /* NAT_H */
