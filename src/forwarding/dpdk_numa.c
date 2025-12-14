/**
 * @file dpdk_numa.c
 * @brief NUMA-Aware Memory Pools and Multi-Queue NIC Configuration
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_DPDK
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#endif

#include "dpdk_numa.h"
#include "log.h"

#ifdef HAVE_DPDK

#define NUM_MBUFS           8191
#define MBUF_CACHE_SIZE     250
#define RX_RING_SIZE        1024
#define TX_RING_SIZE        1024
#define JUMBO_FRAME_SIZE    9000
#define MAX_NUMA_NODES      8
#define MAX_QUEUES_PER_PORT 16

/* Per-NUMA mempool */
static struct rte_mempool *g_pktmbuf_pool[MAX_NUMA_NODES];
static int g_numa_count = 0;

/* External symmetric RSS key (defined in interfaces/physical.c) */
extern uint8_t symmetric_rss_key[52];

/* Multi-queue configuration */
static struct {
    uint16_t port_id;
    uint16_t num_rx_queues;
    uint16_t num_tx_queues;
    bool configured;
} g_port_config[RTE_MAX_ETHPORTS];

int dpdk_numa_init(void)
{
    memset(g_pktmbuf_pool, 0, sizeof(g_pktmbuf_pool));
    memset(g_port_config, 0, sizeof(g_port_config));

    /* Get the number of NUMA nodes */
    g_numa_count = rte_socket_count();
    if (g_numa_count == 0) g_numa_count = 1;

    YLOG_INFO("DPDK NUMA: %d NUMA nodes detected", g_numa_count);
    return 0;
}

struct rte_mempool *dpdk_numa_create_mempool(int numa_node, const char *name,
                                              uint32_t num_mbufs, uint16_t mbuf_size)
{
    if (numa_node < 0 || numa_node >= MAX_NUMA_NODES) {
        numa_node = 0;
    }

    char pool_name[64];
    snprintf(pool_name, sizeof(pool_name), "%s_numa%d", name, numa_node);

    uint16_t data_room = mbuf_size;
    if (data_room == 0) {
        data_room = RTE_MBUF_DEFAULT_BUF_SIZE;
    }

    struct rte_mempool *pool = rte_pktmbuf_pool_create(
        pool_name,
        num_mbufs,
        MBUF_CACHE_SIZE,
        0,
        data_room,
        numa_node
    );

    if (!pool) {
        YLOG_ERROR("DPDK NUMA: Failed to create mempool '%s' on NUMA %d",
                   pool_name, numa_node);
        return NULL;
    }

    g_pktmbuf_pool[numa_node] = pool;
    YLOG_INFO("DPDK NUMA: Created mempool '%s' (%u mbufs, %u bytes) on NUMA %d",
              pool_name, num_mbufs, data_room, numa_node);
    return pool;
}

struct rte_mempool *dpdk_numa_create_jumbo_mempool(int numa_node, const char *name)
{
    return dpdk_numa_create_mempool(numa_node, name, NUM_MBUFS, JUMBO_FRAME_SIZE);
}

struct rte_mempool *dpdk_numa_get_mempool(int numa_node)
{
    if (numa_node < 0 || numa_node >= MAX_NUMA_NODES) {
        numa_node = 0;
    }
    return g_pktmbuf_pool[numa_node];
}

int dpdk_numa_get_socket_for_lcore(unsigned int lcore_id)
{
    return rte_lcore_to_socket_id(lcore_id);
}

int dpdk_multiqueue_configure_port(uint16_t port_id, uint16_t num_rx_queues,
                                    uint16_t num_tx_queues, struct rte_mempool *pool)
{
    struct rte_eth_dev_info dev_info;
    int ret;

    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0) {
        YLOG_ERROR("DPDK Multiqueue: Failed to get device info for port %u", port_id);
        return -1;
    }

    /* Limit to hardware capabilities */
    if (num_rx_queues > dev_info.max_rx_queues) {
        num_rx_queues = dev_info.max_rx_queues;
    }
    if (num_tx_queues > dev_info.max_tx_queues) {
        num_tx_queues = dev_info.max_tx_queues;
    }

    /* Determine RSS key length based on device capability */
    uint8_t rss_key_len = dev_info.hash_key_size;
    if (rss_key_len == 0 || rss_key_len > 52) {
        rss_key_len = 40;  /* Default for Intel ixgbe, i40e */
    }

    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode = RTE_ETH_MQ_RX_RSS,
            .max_lro_pkt_size = JUMBO_FRAME_SIZE,
        },
        .txmode = {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = symmetric_rss_key,  /* CRITICAL: Enable symmetric RSS */
                .rss_key_len = rss_key_len,
                .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
            },
        },
    };

    /* Adjust based on hardware */
    port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;

    YLOG_INFO("DPDK RSS: Applying symmetric key (len=%u) for port %u", rss_key_len, port_id);

    ret = rte_eth_dev_configure(port_id, num_rx_queues, num_tx_queues, &port_conf);
    if (ret != 0) {
        YLOG_ERROR("DPDK Multiqueue: Failed to configure port %u: %d", port_id, ret);
        return -1;
    }

    /* Configure RSS Redirection Table (RETA) for flow affinity */
    if (num_rx_queues > 1 && dev_info.reta_size > 0) {
        struct rte_eth_rss_reta_entry64 reta_conf[RTE_ETH_RSS_RETA_SIZE_512 / RTE_ETH_RETA_GROUP_SIZE];
        memset(reta_conf, 0, sizeof(reta_conf));

        /* Distribute hash values evenly across queues */
        for (uint16_t i = 0; i < dev_info.reta_size; i++) {
            uint16_t idx = i / RTE_ETH_RETA_GROUP_SIZE;
            uint16_t shift = i % RTE_ETH_RETA_GROUP_SIZE;
            reta_conf[idx].mask |= (1ULL << shift);
            reta_conf[idx].reta[shift] = i % num_rx_queues;
        }

        ret = rte_eth_dev_rss_reta_update(port_id, reta_conf, dev_info.reta_size);
        if (ret == 0) {
            YLOG_INFO("DPDK RSS RETA: Configured %u entries across %u queues for port %u",
                      dev_info.reta_size, num_rx_queues, port_id);
        } else {
            YLOG_WARNING("DPDK RSS RETA: Config failed for port %u (non-critical): %s",
                         port_id, rte_strerror(-ret));
        }
    }

    /* Setup RX queues */
    for (uint16_t q = 0; q < num_rx_queues; q++) {
        ret = rte_eth_rx_queue_setup(port_id, q, RX_RING_SIZE,
                                     rte_eth_dev_socket_id(port_id), NULL, pool);
        if (ret < 0) {
            YLOG_ERROR("DPDK Multiqueue: RX queue %u setup failed on port %u", q, port_id);
            return -1;
        }
    }

    /* Setup TX queues */
    for (uint16_t q = 0; q < num_tx_queues; q++) {
        ret = rte_eth_tx_queue_setup(port_id, q, TX_RING_SIZE,
                                     rte_eth_dev_socket_id(port_id), NULL);
        if (ret < 0) {
            YLOG_ERROR("DPDK Multiqueue: TX queue %u setup failed on port %u", q, port_id);
            return -1;
        }
    }

    g_port_config[port_id].port_id = port_id;
    g_port_config[port_id].num_rx_queues = num_rx_queues;
    g_port_config[port_id].num_tx_queues = num_tx_queues;
    g_port_config[port_id].configured = true;

    YLOG_INFO("DPDK Multiqueue: Port %u configured with %u RX, %u TX queues",
              port_id, num_rx_queues, num_tx_queues);
    return 0;
}

int dpdk_multiqueue_get_queue_count(uint16_t port_id, uint16_t *rx_queues, uint16_t *tx_queues)
{
    if (port_id >= RTE_MAX_ETHPORTS || !g_port_config[port_id].configured) {
        return -1;
    }

    if (rx_queues) *rx_queues = g_port_config[port_id].num_rx_queues;
    if (tx_queues) *tx_queues = g_port_config[port_id].num_tx_queues;
    return 0;
}

int dpdk_jumbo_frame_enable(uint16_t port_id, uint16_t max_frame_size)
{
    struct rte_eth_dev_info dev_info;
    int ret;

    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0) return -1;

    if (max_frame_size > dev_info.max_rx_pktlen) {
        max_frame_size = dev_info.max_rx_pktlen;
    }

    ret = rte_eth_dev_set_mtu(port_id, max_frame_size - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN);
    if (ret != 0) {
        YLOG_WARNING("DPDK Jumbo: Failed to set MTU on port %u: %d", port_id, ret);
        return -1;
    }

    YLOG_INFO("DPDK Jumbo: Port %u MTU set to support %u byte frames",
              port_id, max_frame_size);
    return 0;
}

void dpdk_numa_cleanup(void)
{
    for (int i = 0; i < MAX_NUMA_NODES; i++) {
        if (g_pktmbuf_pool[i]) {
            rte_mempool_free(g_pktmbuf_pool[i]);
            g_pktmbuf_pool[i] = NULL;
        }
    }
    YLOG_INFO("DPDK NUMA: Cleanup complete");
}

#else /* !HAVE_DPDK */

int dpdk_numa_init(void) { return 0; }
void dpdk_numa_cleanup(void) {}
void *dpdk_numa_create_mempool(int numa_node, const char *name,
                               uint32_t num_mbufs, uint16_t mbuf_size) {
    (void)numa_node; (void)name; (void)num_mbufs; (void)mbuf_size;
    return NULL;
}
void *dpdk_numa_create_jumbo_mempool(int numa_node, const char *name) {
    (void)numa_node; (void)name;
    return NULL;
}
void *dpdk_numa_get_mempool(int numa_node) {
    (void)numa_node;
    return NULL;
}
int dpdk_numa_get_socket_for_lcore(unsigned int lcore_id) {
    (void)lcore_id;
    return 0;
}
int dpdk_multiqueue_configure_port(uint16_t port_id, uint16_t num_rx_queues,
                                    uint16_t num_tx_queues, void *pool) {
    (void)port_id; (void)num_rx_queues; (void)num_tx_queues; (void)pool;
    return 0;
}
int dpdk_multiqueue_get_queue_count(uint16_t port_id, uint16_t *rx_queues, uint16_t *tx_queues) {
    (void)port_id; (void)rx_queues; (void)tx_queues;
    return -1;
}
int dpdk_jumbo_frame_enable(uint16_t port_id, uint16_t max_frame_size) {
    (void)port_id; (void)max_frame_size;
    return 0;
}

#endif /* HAVE_DPDK */
