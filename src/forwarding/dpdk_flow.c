/**
 * @file dpdk_flow.c
 * @brief DPDK Flow API Classification and RSS Configuration
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_DPDK
#include <rte_flow.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#endif

#include "dpdk_flow.h"
#include "log.h"

#ifdef HAVE_DPDK

#define MAX_FLOW_RULES 1024

/* Flow rule storage */
static struct {
    struct rte_flow *flows[MAX_FLOW_RULES];
    int count;
    uint16_t port_id;
} g_flow_ctx;

int dpdk_flow_init(uint16_t port_id)
{
    memset(&g_flow_ctx, 0, sizeof(g_flow_ctx));
    g_flow_ctx.port_id = port_id;

    YLOG_INFO("DPDK Flow: Initialized for port %u", port_id);
    return 0;
}

/**
 * Create flow rule to classify PPPoE Discovery to queue
 */
int dpdk_flow_pppoe_discovery_queue(uint16_t port_id, uint16_t queue_id)
{
    struct rte_flow_attr attr = {
        .group = 0,
        .priority = 0,
        .ingress = 1,
        .egress = 0,
    };

    /* Match: ETH_TYPE = ETH_P_PPPOE_DISC (0x8863) */
    struct rte_flow_item_eth eth_spec = {
        .type = rte_cpu_to_be_16(0x8863),
    };
    struct rte_flow_item_eth eth_mask = {
        .type = 0xFFFF,
    };

    struct rte_flow_item pattern[] = {
        {
            .type = RTE_FLOW_ITEM_TYPE_ETH,
            .spec = &eth_spec,
            .mask = &eth_mask,
        },
        {
            .type = RTE_FLOW_ITEM_TYPE_END,
        },
    };

    /* Action: Direct to specific queue */
    struct rte_flow_action_queue queue_action = {
        .index = queue_id,
    };

    struct rte_flow_action actions[] = {
        {
            .type = RTE_FLOW_ACTION_TYPE_QUEUE,
            .conf = &queue_action,
        },
        {
            .type = RTE_FLOW_ACTION_TYPE_END,
        },
    };

    struct rte_flow_error error;
    struct rte_flow *flow = rte_flow_create(port_id, &attr, pattern, actions, &error);

    if (!flow) {
        YLOG_ERROR("DPDK Flow: Failed to create PPPoE Discovery rule: %s",
                   error.message ? error.message : "unknown");
        return -1;
    }

    if (g_flow_ctx.count < MAX_FLOW_RULES) {
        g_flow_ctx.flows[g_flow_ctx.count++] = flow;
    }

    YLOG_INFO("DPDK Flow: PPPoE Discovery -> queue %u", queue_id);
    return 0;
}

/**
 * Create flow rule to classify PPPoE Session to queue
 */
int dpdk_flow_pppoe_session_queue(uint16_t port_id, uint16_t queue_id)
{
    struct rte_flow_attr attr = {
        .group = 0,
        .priority = 0,
        .ingress = 1,
        .egress = 0,
    };

    /* Match: ETH_TYPE = ETH_P_PPPOE_SESS (0x8864) */
    struct rte_flow_item_eth eth_spec = {
        .type = rte_cpu_to_be_16(0x8864),
    };
    struct rte_flow_item_eth eth_mask = {
        .type = 0xFFFF,
    };

    struct rte_flow_item pattern[] = {
        {
            .type = RTE_FLOW_ITEM_TYPE_ETH,
            .spec = &eth_spec,
            .mask = &eth_mask,
        },
        {
            .type = RTE_FLOW_ITEM_TYPE_END,
        },
    };

    /* Action: RSS to spread across queues */
    struct rte_flow_action_queue queue_action = {
        .index = queue_id,
    };

    struct rte_flow_action actions[] = {
        {
            .type = RTE_FLOW_ACTION_TYPE_QUEUE,
            .conf = &queue_action,
        },
        {
            .type = RTE_FLOW_ACTION_TYPE_END,
        },
    };

    struct rte_flow_error error;
    struct rte_flow *flow = rte_flow_create(port_id, &attr, pattern, actions, &error);

    if (!flow) {
        YLOG_ERROR("DPDK Flow: Failed to create PPPoE Session rule: %s",
                   error.message ? error.message : "unknown");
        return -1;
    }

    if (g_flow_ctx.count < MAX_FLOW_RULES) {
        g_flow_ctx.flows[g_flow_ctx.count++] = flow;
    }

    YLOG_INFO("DPDK Flow: PPPoE Session -> queue %u", queue_id);
    return 0;
}

/**
 * Configure RSS for PPPoE traffic distribution
 */
int dpdk_flow_configure_rss(uint16_t port_id, uint16_t *queues, uint16_t num_queues)
{
    struct rte_eth_rss_conf rss_conf = {
        .rss_key = NULL,  /* Use default key */
        .rss_key_len = 0,
        .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
    };

    /* Configure RSS on all queues */
    struct rte_eth_rss_reta_entry64 reta_conf[8];
    uint16_t reta_size = 128; /* Common RETA size */

    memset(reta_conf, 0, sizeof(reta_conf));

    for (uint16_t i = 0; i < reta_size; i++) {
        uint16_t idx = i / RTE_ETH_RETA_GROUP_SIZE;
        uint16_t shift = i % RTE_ETH_RETA_GROUP_SIZE;

        reta_conf[idx].mask |= (1ULL << shift);
        reta_conf[idx].reta[shift] = queues[i % num_queues];
    }

    int ret = rte_eth_dev_rss_reta_update(port_id, reta_conf, reta_size);
    if (ret < 0) {
        YLOG_WARNING("DPDK Flow: RSS RETA update failed: %d", ret);
        /* Non-fatal, some NICs may not support this */
    }

    ret = rte_eth_dev_rss_hash_update(port_id, &rss_conf);
    if (ret < 0) {
        YLOG_WARNING("DPDK Flow: RSS hash update failed: %d", ret);
    }

    YLOG_INFO("DPDK Flow: RSS configured with %u queues", num_queues);
    return 0;
}

void dpdk_flow_flush(uint16_t port_id)
{
    struct rte_flow_error error;

    rte_flow_flush(port_id, &error);

    memset(g_flow_ctx.flows, 0, sizeof(g_flow_ctx.flows));
    g_flow_ctx.count = 0;

    YLOG_INFO("DPDK Flow: Flushed all rules on port %u", port_id);
}

void dpdk_flow_cleanup(void)
{
    if (g_flow_ctx.count > 0) {
        dpdk_flow_flush(g_flow_ctx.port_id);
    }
}

#else /* !HAVE_DPDK */

int dpdk_flow_init(uint16_t port_id) { (void)port_id; return 0; }
int dpdk_flow_pppoe_discovery_queue(uint16_t port_id, uint16_t queue_id) {
    (void)port_id; (void)queue_id; return 0;
}
int dpdk_flow_pppoe_session_queue(uint16_t port_id, uint16_t queue_id) {
    (void)port_id; (void)queue_id; return 0;
}
int dpdk_flow_configure_rss(uint16_t port_id, uint16_t *queues, uint16_t num_queues) {
    (void)port_id; (void)queues; (void)num_queues; return 0;
}
void dpdk_flow_flush(uint16_t port_id) { (void)port_id; }
void dpdk_flow_cleanup(void) {}

#endif /* HAVE_DPDK */
