/**
 * @file lcore_ctx.h
 * @brief Per-Lcore Context for Lockless Operation
 *
 * Each DPDK lcore has its own context with:
 * - Local session cache
 * - Per-core statistics
 * - SPSC rings for inter-core communication
 * - Local mempool cache
 */

#ifndef _LCORE_CTX_H
#define _LCORE_CTX_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_hash.h>

#define MAX_LCORES          32
#define LCORE_RING_SIZE     4096
#define LCORE_BATCH_SIZE    32

/* Per-lcore statistics (cache-line aligned to avoid false sharing) */
struct lcore_stats {
    /* Packet counters */
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_dropped;
    uint64_t tx_dropped;

    /* PPPoE counters */
    uint64_t pppoe_padi;
    uint64_t pppoe_pado;
    uint64_t pppoe_padr;
    uint64_t pppoe_pads;
    uint64_t pppoe_padt;
    uint64_t pppoe_session_rx;
    uint64_t pppoe_session_tx;

    /* Session counters */
    uint64_t sessions_created;
    uint64_t sessions_destroyed;
    uint64_t auth_requests;
    uint64_t auth_success;
    uint64_t auth_failures;

    /* Timing */
    uint64_t last_rx_tsc;
    uint64_t busy_cycles;
    uint64_t idle_cycles;

    uint8_t _pad[64 - ((sizeof(uint64_t) * 19) % 64)];
} __attribute__((aligned(64)));

/* Message types for inter-core communication */
typedef enum {
    LCORE_MSG_SESSION_CREATE,
    LCORE_MSG_SESSION_DESTROY,
    LCORE_MSG_AUTH_RESPONSE,
    LCORE_MSG_CONFIG_UPDATE,
    LCORE_MSG_STATS_REQUEST,
    LCORE_MSG_SHUTDOWN
} lcore_msg_type_t;

/* Inter-core message */
struct lcore_msg {
    lcore_msg_type_t type;
    uint32_t session_id;
    uint32_t src_lcore;
    void *data;
    uint64_t timestamp;
};

/* Per-lcore context */
struct lcore_ctx {
    uint32_t lcore_id;
    uint32_t socket_id;
    bool initialized;
    bool running;

    /* Port assignment */
    uint16_t port_id;
    uint16_t queue_id;

    /* Statistics */
    struct lcore_stats stats;

    /* SPSC rings for inter-core messaging */
    struct rte_ring *msg_ring;          /* Incoming messages */
    struct rte_ring *response_ring;     /* Outgoing responses */

    /* Local session cache (sessions owned by this lcore) */
    struct rte_hash *local_sessions;    /* session_id -> session* */
    uint32_t local_session_count;
    uint32_t max_local_sessions;

    /* Packet batch buffers */
    struct rte_mbuf *rx_batch[LCORE_BATCH_SIZE];
    struct rte_mbuf *tx_batch[LCORE_BATCH_SIZE];
    uint16_t tx_batch_count;

    /* Timing */
    uint64_t tsc_hz;
    uint64_t last_stats_tsc;

    /* Padding to cache line */
    uint8_t _pad[64];
} __attribute__((aligned(64)));

/* Global array of per-lcore contexts */
extern struct lcore_ctx g_lcore_ctx[MAX_LCORES];

/* Initialization */
int lcore_ctx_init(uint32_t lcore_id, uint16_t port_id, uint16_t queue_id);
void lcore_ctx_cleanup(uint32_t lcore_id);
int lcore_ctx_init_all(void);
void lcore_ctx_cleanup_all(void);

/* Get current lcore context (fast path - no function call in hot path) */
static inline struct lcore_ctx *lcore_ctx_get(void)
{
    return &g_lcore_ctx[rte_lcore_id()];
}

/* Get specific lcore context */
static inline struct lcore_ctx *lcore_ctx_get_by_id(uint32_t lcore_id)
{
    return &g_lcore_ctx[lcore_id];
}

/* Inter-core messaging */
int lcore_send_msg(uint32_t dst_lcore, struct lcore_msg *msg);
int lcore_recv_msg(struct lcore_msg *msg);
int lcore_process_messages(void);

/* Statistics */
void lcore_stats_aggregate(struct lcore_stats *total);
void lcore_stats_reset(uint32_t lcore_id);
void lcore_stats_dump(uint32_t lcore_id);

/* TX batching */
static inline void lcore_tx_batch_add(struct lcore_ctx *ctx, struct rte_mbuf *m)
{
    ctx->tx_batch[ctx->tx_batch_count++] = m;

    if (ctx->tx_batch_count >= LCORE_BATCH_SIZE) {
        uint16_t sent = rte_eth_tx_burst(ctx->port_id, ctx->queue_id,
                                          ctx->tx_batch, ctx->tx_batch_count);
        ctx->stats.tx_packets += sent;

        /* Free unsent packets */
        for (uint16_t i = sent; i < ctx->tx_batch_count; i++) {
            rte_pktmbuf_free(ctx->tx_batch[i]);
            ctx->stats.tx_dropped++;
        }
        ctx->tx_batch_count = 0;
    }
}

static inline void lcore_tx_batch_flush(struct lcore_ctx *ctx)
{
    if (ctx->tx_batch_count > 0) {
        uint16_t sent = rte_eth_tx_burst(ctx->port_id, ctx->queue_id,
                                          ctx->tx_batch, ctx->tx_batch_count);
        ctx->stats.tx_packets += sent;

        for (uint16_t i = sent; i < ctx->tx_batch_count; i++) {
            rte_pktmbuf_free(ctx->tx_batch[i]);
            ctx->stats.tx_dropped++;
        }
        ctx->tx_batch_count = 0;
    }
}

#endif /* _LCORE_CTX_H */
