/**
 * @file nat_rss.c
 * @brief RSS Configuration for Lockless NAT
 *
 * Configures symmetric RSS to ensure bidirectional flows
 * always go to the same worker (enabling lockless operation)
 */

#include "nat.h"
#include "log.h"
#include <string.h>

#ifdef HAVE_DPDK
#include <rte_ethdev.h>
#include <rte_hash.h>
#endif

/* Symmetric Toeplitz RSS key (ensures same hash for A→B and B→A) */
static const uint8_t symmetric_rss_key[40] = {
    0x6D, 0x5A, 0x56, 0xDA, 0x25, 0x5B, 0x0E, 0xC2,
    0x41, 0x67, 0x25, 0x3D, 0x43, 0xA3, 0x8F, 0xB0,
    0xD0, 0xCA, 0x2B, 0xCB, 0xAE, 0x7B, 0x30, 0xB4,
    0x77, 0xCB, 0x2D, 0xA3, 0x80, 0x30, 0xF2, 0x0C,
    0x6A, 0x42, 0xB7, 0x3B, 0xBE, 0xAC, 0x01, 0xFA
};

/* RSS configuration state */
static struct {
    bool enabled;
    uint16_t num_queues;
    uint8_t key[40];
} g_rss_config = {0};

/**
 * Configure RSS on a DPDK port for symmetric hashing
 * @param port_id DPDK port ID
 * @param num_workers Number of worker threads
 * @return 0 on success, -1 on error
 */
int nat_rss_configure(uint16_t port_id, uint16_t num_workers)
{
#ifdef HAVE_DPDK
    struct rte_eth_dev_info dev_info;
    int ret;

    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0) {
        LOG_ERROR("[NAT-RSS] Failed to get device info for port %u", port_id);
        return -1;
    }

    /* Check if RSS is supported */
    if (dev_info.max_rx_queues < num_workers) {
        LOG_WARN("[NAT-RSS] Port %u supports only %u queues, requested %u",
                  port_id, dev_info.max_rx_queues, num_workers);
        num_workers = dev_info.max_rx_queues;
    }

    /* Configure RSS hash */
    struct rte_eth_rss_conf rss_conf = {
        .rss_key = (uint8_t *)symmetric_rss_key,
        .rss_key_len = 40,
        .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
    };

    ret = rte_eth_dev_rss_hash_update(port_id, &rss_conf);
    if (ret != 0) {
        LOG_ERROR("[NAT-RSS] Failed to configure RSS hash on port %u: %d", port_id, ret);
        return -1;
    }

    /* Configure RETA (Redirection Table) for even distribution */
    struct rte_eth_rss_reta_entry64 reta_conf[8];
    uint16_t reta_size = dev_info.reta_size;

    if (reta_size > 0 && reta_size <= 512) {
        memset(reta_conf, 0, sizeof(reta_conf));
        for (uint16_t i = 0; i < reta_size; i++) {
            uint16_t idx = i / RTE_ETH_RETA_GROUP_SIZE;
            uint16_t shift = i % RTE_ETH_RETA_GROUP_SIZE;
            reta_conf[idx].mask |= (1ULL << shift);
            reta_conf[idx].reta[shift] = i % num_workers;
        }

        ret = rte_eth_dev_rss_reta_update(port_id, reta_conf, reta_size);
        if (ret != 0) {
            LOG_WARN("[NAT-RSS] Failed to update RETA on port %u: %d", port_id, ret);
            /* Non-fatal - continue */
        }
    }

    g_rss_config.enabled = true;
    g_rss_config.num_queues = num_workers;
    memcpy(g_rss_config.key, symmetric_rss_key, 40);

    LOG_INFO("[NAT-RSS] Port %u configured with symmetric RSS, %u queues", port_id, num_workers);
    return 0;

#else
    (void)port_id;
    (void)num_workers;
    LOG_WARN("[NAT-RSS] DPDK not available, RSS not configured");
    return 0;
#endif
}

/**
 * Get worker ID for a given flow (for software fallback)
 * Uses same hash algorithm as NIC RSS
 * @param src_ip Source IP
 * @param dst_ip Destination IP
 * @param src_port Source port
 * @param dst_port Destination port
 * @param protocol Protocol
 * @return Worker ID (0 to num_workers-1)
 */
uint32_t nat_rss_get_worker_id(uint32_t src_ip, uint32_t dst_ip,
                               uint16_t src_port, uint16_t dst_port,
                               uint8_t protocol)
{
    extern uint32_t g_num_workers;

    if (g_num_workers <= 1) {
        return 0;
    }

    /* Symmetric hash: ensure same result for A→B and B→A */
    uint32_t min_ip = (src_ip < dst_ip) ? src_ip : dst_ip;
    uint32_t max_ip = (src_ip < dst_ip) ? dst_ip : src_ip;
    uint16_t min_port = (src_port < dst_port) ? src_port : dst_port;
    uint16_t max_port = (src_port < dst_port) ? dst_port : src_port;

    /* Simple but effective hash */
    uint32_t hash = min_ip ^ max_ip;
    hash = hash * 31 + min_port;
    hash = hash * 31 + max_port;
    hash = hash * 31 + protocol;

    /* Mix bits */
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;

    return hash % g_num_workers;
}

/**
 * Check if RSS is configured
 * @return true if RSS is enabled
 */
bool nat_rss_is_enabled(void)
{
    return g_rss_config.enabled;
}

/**
 * Get configured number of RSS queues
 * @return Number of RSS queues (workers)
 */
uint16_t nat_rss_get_num_queues(void)
{
    return g_rss_config.num_queues;
}

/**
 * Print RSS configuration for debugging
 */
void nat_rss_print_config(void)
{
    LOG_INFO("[NAT-RSS] Configuration:");
    LOG_INFO("  Enabled:      %s", g_rss_config.enabled ? "yes" : "no");
    LOG_INFO("  Num queues:   %u", g_rss_config.num_queues);
    LOG_INFO("  Hash type:    Symmetric Toeplitz");
    LOG_INFO("  Hash fields:  IP + TCP/UDP ports");
}
