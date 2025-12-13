/**
 * @file env_config.h
 * @brief Bison-Style Environment Configuration Parser
 *
 * Single authoritative .env file drives ALL runtime parameters.
 * No hardcoded values. All parameters validated at startup.
 */

#ifndef ENV_CONFIG_H
#define ENV_CONFIG_H

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

#define ENV_MAX_PORTS 8
#define ENV_MAX_LCORES 32
#define ENV_MAX_PATH 256

/**
 * DPDK Configuration (from .env)
 */
struct env_dpdk_config {
    /* Core assignment */
    int main_lcore;
    int worker_lcores[ENV_MAX_LCORES];
    int num_workers;
    int numa_node;

    /* Memory */
    int socket_mem_mb;
    int mbuf_count;
    int mbuf_cache_size;
    int hugepages;

    /* Ports */
    char ports[ENV_MAX_PORTS][32];  /* PCI addresses */
    int num_ports;
    char driver[64];
    int port_mtu;

    /* Queues */
    int rx_queues;
    int tx_queues;
    int rx_desc;
    int tx_desc;

    /* Burst sizes */
    int rx_burst_size;
    int tx_burst_size;

    /* RSS */
    bool rss_enable;
};

/**
 * Worker Configuration (from .env)
 */
struct env_worker_config {
    int rx_count;
    int nat_count;
};

/**
 * NAT44 Performance Tuning (from .env - hardware level)
 * Runtime config (pools, timeouts, enable) is in startup.json
 */
struct env_nat44_config {
    uint32_t max_sessions;       /* Session table size */
    bool lockless_enable;        /* Per-core lockless mode */
    int session_cache_size;      /* Per-worker L1 cache */
    int prefetch_lookahead;      /* Prefetch depth */
};

/**
 * Logging Configuration (from .env)
 */
struct env_log_config {
    int level;  /* 0=emerg, 7=debug */
};

/**
 * Global Environment Configuration
 * Populated by env_config_load() from /etc/yesrouter/yesrouter.env
 */
struct env_config {
    struct env_dpdk_config dpdk;
    struct env_worker_config workers;
    struct env_nat44_config nat44;
    struct env_log_config log;

    bool validated;  /* Set true after successful parse */
    char env_path[ENV_MAX_PATH];
};

/* Global config instance */
extern struct env_config g_env_config;

/**
 * Load and validate .env configuration
 * @param path Path to .env file (default: /etc/yesrouter/yesrouter.env)
 * @return 0 on success, -1 on error
 */
int env_config_load(const char *path);

/**
 * Print current configuration (debug)
 */
void env_config_print(void);

/**
 * Getters for dataplane components (thread-safe after load)
 */
int env_get_rx_queues(void);
int env_get_tx_queues(void);
int env_get_rx_burst_size(void);
int env_get_tx_burst_size(void);
int env_get_rx_desc(void);
int env_get_tx_desc(void);
int env_get_num_workers(void);
int env_get_numa_node(void);
bool env_get_rss_enable(void);
bool env_get_nat44_lockless(void);
uint32_t env_get_nat44_max_sessions(void);
int env_get_nat44_cache_size(void);
int env_get_nat44_prefetch(void);

#endif /* ENV_CONFIG_H */
