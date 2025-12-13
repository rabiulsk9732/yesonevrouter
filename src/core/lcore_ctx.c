/**
 * @file lcore_ctx.c
 * @brief Per-Lcore Context Implementation
 */

#include <stdio.h>
#include <string.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cycles.h>

#include "lcore_ctx.h"

/* Global per-lcore contexts */
struct lcore_ctx g_lcore_ctx[MAX_LCORES] __attribute__((aligned(64)));

/*============================================================================
 * Initialization
 *============================================================================*/

int lcore_ctx_init(uint32_t lcore_id, uint16_t port_id, uint16_t queue_id)
{
    if (lcore_id >= MAX_LCORES) {
        return -1;
    }

    struct lcore_ctx *ctx = &g_lcore_ctx[lcore_id];

    if (ctx->initialized) {
        return 0;  /* Already initialized */
    }

    memset(ctx, 0, sizeof(*ctx));

    ctx->lcore_id = lcore_id;
    ctx->socket_id = rte_lcore_to_socket_id(lcore_id);
    ctx->port_id = port_id;
    ctx->queue_id = queue_id;
    ctx->tsc_hz = rte_get_tsc_hz();
    ctx->max_local_sessions = 65536;  /* Per-core session limit */

    /* Create message ring (SPSC) */
    char ring_name[64];
    snprintf(ring_name, sizeof(ring_name), "lcore_msg_%u", lcore_id);

    ctx->msg_ring = rte_ring_create(ring_name, LCORE_RING_SIZE,
                                     ctx->socket_id,
                                     RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!ctx->msg_ring) {
        fprintf(stderr, "Failed to create message ring for lcore %u\n", lcore_id);
        return -1;
    }

    /* Create response ring */
    snprintf(ring_name, sizeof(ring_name), "lcore_resp_%u", lcore_id);
    ctx->response_ring = rte_ring_create(ring_name, LCORE_RING_SIZE,
                                          ctx->socket_id,
                                          RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!ctx->response_ring) {
        rte_ring_free(ctx->msg_ring);
        return -1;
    }

    /* Create local session hash table */
    struct rte_hash_parameters hash_params = {
        .name = ring_name,  /* Reuse buffer */
        .entries = ctx->max_local_sessions,
        .key_len = sizeof(uint32_t),
        .hash_func = rte_jhash,
        .socket_id = ctx->socket_id,
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
    };
    snprintf(hash_params.name, sizeof(ring_name), "lcore_sess_%u", lcore_id);

    ctx->local_sessions = rte_hash_create(&hash_params);
    if (!ctx->local_sessions) {
        rte_ring_free(ctx->msg_ring);
        rte_ring_free(ctx->response_ring);
        return -1;
    }

    ctx->initialized = true;
    ctx->running = false;

    printf("lcore_ctx: Initialized lcore %u (socket %u, port %u, queue %u)\n",
           lcore_id, ctx->socket_id, port_id, queue_id);

    return 0;
}

void lcore_ctx_cleanup(uint32_t lcore_id)
{
    if (lcore_id >= MAX_LCORES) return;

    struct lcore_ctx *ctx = &g_lcore_ctx[lcore_id];

    if (!ctx->initialized) return;

    ctx->running = false;

    if (ctx->msg_ring) {
        rte_ring_free(ctx->msg_ring);
        ctx->msg_ring = NULL;
    }

    if (ctx->response_ring) {
        rte_ring_free(ctx->response_ring);
        ctx->response_ring = NULL;
    }

    if (ctx->local_sessions) {
        rte_hash_free(ctx->local_sessions);
        ctx->local_sessions = NULL;
    }

    ctx->initialized = false;

    printf("lcore_ctx: Cleaned up lcore %u\n", lcore_id);
}

int lcore_ctx_init_all(void)
{
    uint32_t lcore_id;
    uint16_t queue_id = 0;

    RTE_LCORE_FOREACH(lcore_id) {
        /* Skip main lcore for now - it handles control plane */
        if (lcore_id == rte_get_main_lcore()) {
            continue;
        }

        /* Initialize with port 0, incrementing queue IDs */
        if (lcore_ctx_init(lcore_id, 0, queue_id++) < 0) {
            fprintf(stderr, "Failed to initialize lcore %u\n", lcore_id);
            return -1;
        }
    }

    return 0;
}

void lcore_ctx_cleanup_all(void)
{
    for (uint32_t i = 0; i < MAX_LCORES; i++) {
        lcore_ctx_cleanup(i);
    }
}

/*============================================================================
 * Inter-core Messaging
 *============================================================================*/

int lcore_send_msg(uint32_t dst_lcore, struct lcore_msg *msg)
{
    if (dst_lcore >= MAX_LCORES) return -1;

    struct lcore_ctx *dst_ctx = &g_lcore_ctx[dst_lcore];

    if (!dst_ctx->initialized || !dst_ctx->msg_ring) {
        return -1;
    }

    msg->src_lcore = rte_lcore_id();
    msg->timestamp = rte_rdtsc();

    if (rte_ring_enqueue(dst_ctx->msg_ring, msg) < 0) {
        return -1;  /* Ring full */
    }

    return 0;
}

int lcore_recv_msg(struct lcore_msg *msg)
{
    struct lcore_ctx *ctx = lcore_ctx_get();

    if (!ctx->initialized || !ctx->msg_ring) {
        return -1;
    }

    void *ptr;
    if (rte_ring_dequeue(ctx->msg_ring, &ptr) < 0) {
        return -1;  /* No messages */
    }

    memcpy(msg, ptr, sizeof(*msg));
    return 0;
}

int lcore_process_messages(void)
{
    struct lcore_ctx *ctx = lcore_ctx_get();
    struct lcore_msg msg;
    int processed = 0;

    /* Process up to 16 messages per call to avoid starvation */
    for (int i = 0; i < 16; i++) {
        if (lcore_recv_msg(&msg) < 0) {
            break;
        }

        switch (msg.type) {
        case LCORE_MSG_SESSION_CREATE:
            /* Handle session creation on this lcore */
            break;

        case LCORE_MSG_SESSION_DESTROY:
            /* Handle session destruction */
            break;

        case LCORE_MSG_AUTH_RESPONSE:
            /* Handle authentication response from control plane */
            break;

        case LCORE_MSG_CONFIG_UPDATE:
            /* Handle configuration update */
            break;

        case LCORE_MSG_STATS_REQUEST:
            /* Send stats to requester */
            break;

        case LCORE_MSG_SHUTDOWN:
            ctx->running = false;
            break;
        }

        processed++;
    }

    return processed;
}

/*============================================================================
 * Statistics
 *============================================================================*/

void lcore_stats_aggregate(struct lcore_stats *total)
{
    memset(total, 0, sizeof(*total));

    for (uint32_t i = 0; i < MAX_LCORES; i++) {
        struct lcore_ctx *ctx = &g_lcore_ctx[i];

        if (!ctx->initialized) continue;

        total->rx_packets += ctx->stats.rx_packets;
        total->tx_packets += ctx->stats.tx_packets;
        total->rx_bytes += ctx->stats.rx_bytes;
        total->tx_bytes += ctx->stats.tx_bytes;
        total->rx_dropped += ctx->stats.rx_dropped;
        total->tx_dropped += ctx->stats.tx_dropped;

        total->pppoe_padi += ctx->stats.pppoe_padi;
        total->pppoe_pado += ctx->stats.pppoe_pado;
        total->pppoe_padr += ctx->stats.pppoe_padr;
        total->pppoe_pads += ctx->stats.pppoe_pads;
        total->pppoe_padt += ctx->stats.pppoe_padt;
        total->pppoe_session_rx += ctx->stats.pppoe_session_rx;
        total->pppoe_session_tx += ctx->stats.pppoe_session_tx;

        total->sessions_created += ctx->stats.sessions_created;
        total->sessions_destroyed += ctx->stats.sessions_destroyed;
        total->auth_requests += ctx->stats.auth_requests;
        total->auth_success += ctx->stats.auth_success;
        total->auth_failures += ctx->stats.auth_failures;
    }
}

void lcore_stats_reset(uint32_t lcore_id)
{
    if (lcore_id >= MAX_LCORES) return;

    struct lcore_ctx *ctx = &g_lcore_ctx[lcore_id];
    memset(&ctx->stats, 0, sizeof(ctx->stats));
}

void lcore_stats_dump(uint32_t lcore_id)
{
    if (lcore_id >= MAX_LCORES) return;

    struct lcore_ctx *ctx = &g_lcore_ctx[lcore_id];
    struct lcore_stats *s = &ctx->stats;

    printf("\n=== Lcore %u Statistics ===\n", lcore_id);
    printf("  RX packets: %lu, TX packets: %lu\n", s->rx_packets, s->tx_packets);
    printf("  RX bytes: %lu, TX bytes: %lu\n", s->rx_bytes, s->tx_bytes);
    printf("  RX dropped: %lu, TX dropped: %lu\n", s->rx_dropped, s->tx_dropped);
    printf("  PPPoE: PADI=%lu PADO=%lu PADR=%lu PADS=%lu PADT=%lu\n",
           s->pppoe_padi, s->pppoe_pado, s->pppoe_padr, s->pppoe_pads, s->pppoe_padt);
    printf("  Sessions: created=%lu destroyed=%lu\n",
           s->sessions_created, s->sessions_destroyed);
    printf("  Auth: requests=%lu success=%lu failures=%lu\n",
           s->auth_requests, s->auth_success, s->auth_failures);
}
