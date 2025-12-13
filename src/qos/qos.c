/**
 * @file qos.c
 * @brief QoS Implementation - Token Bucket, CIR/MIR, Policing
 */

#include <string.h>
#include <stdlib.h>
#include "qos.h"
#include "log.h"
#include <time.h>

#define MAX_QOS_SESSIONS 65535

/* Session table */
static struct qos_session *g_qos_sessions[MAX_QOS_SESSIONS];

#ifdef HAVE_DPDK
#include <rte_cycles.h>
static inline uint64_t get_time_rc(void)
{
    return rte_get_timer_cycles();
}
static inline uint64_t get_hz(void)
{
    return rte_get_timer_hz();
}
#else
static inline uint64_t get_time_rc(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
static inline uint64_t get_hz(void)
{
    return 1000000000ULL; /* NS per sec */
}
#endif

int qos_init(void)
{
    memset(g_qos_sessions, 0, sizeof(g_qos_sessions));
    YLOG_INFO("QoS subsystem initialized (CIR/MIR, trTCM policing)");
    return 0;
}

void qos_cleanup(void)
{
    for (int i = 0; i < MAX_QOS_SESSIONS; i++) {
        if (g_qos_sessions[i]) {
            free(g_qos_sessions[i]);
            g_qos_sessions[i] = NULL;
        }
    }
    YLOG_INFO("QoS cleanup complete");
}

void qos_tb_init(struct token_bucket *tb, uint64_t rate_bps, uint64_t burst_bytes)
{
    tb->rate = rate_bps / 8; /* Convert to Bytes/sec */
    tb->burst = burst_bytes;
    tb->tokens = burst_bytes; /* Start full */
    tb->last_update = get_time_rc();
}

int qos_tb_conform(struct token_bucket *tb, uint32_t pkt_len)
{
    uint64_t now = get_time_rc();
    uint64_t elapsed = now - tb->last_update;
    tb->last_update = now;

    /* Refill tokens: (Bytes/sec * cycles) / cycles/sec */
    uint64_t new_tokens = (tb->rate * elapsed) / get_hz();

    tb->tokens += new_tokens;
    if (tb->tokens > tb->burst) {
        tb->tokens = tb->burst;
    }

    /* Consume */
    if (tb->tokens >= pkt_len) {
        tb->tokens -= pkt_len;
        return 1; /* Pass */
    }

    return 0; /* Drop */
}

int qos_tb_check(struct token_bucket *tb, uint32_t pkt_len)
{
    uint64_t now = get_time_rc();
    uint64_t elapsed = now - tb->last_update;
    /* Do not update last_update here */

    uint64_t new_tokens = (tb->rate * elapsed) / get_hz();
    uint64_t projected_tokens = tb->tokens + new_tokens;
    if (projected_tokens > tb->burst) projected_tokens = tb->burst;

    if (projected_tokens >= pkt_len) return 1;
    return 0;
}

void qos_tb_consume(struct token_bucket *tb, uint32_t pkt_len)
{
    if (tb->tokens >= pkt_len) {
        tb->tokens -= pkt_len;
    } else {
        /* Should not happen if check passed, but handle underflow/borrow */
        tb->tokens = 0;
    }
}


void qos_meter_init(struct qos_meter *meter, uint64_t cir, uint64_t cbs,
                    uint64_t pir, uint64_t pbs)
{
    meter->cir = cir / 8;  /* Convert bps to Bps */
    meter->cbs = cbs;
    meter->c_tokens = cbs;

    meter->pir = pir / 8;
    meter->pbs = pbs;
    meter->p_tokens = pbs;

    meter->last_update = get_time_rc();
    meter->exceed_action = QOS_ACTION_MARK_YELLOW;
    meter->violate_action = QOS_ACTION_DROP;
}

qos_action_t qos_meter_packet(struct qos_meter *meter, uint32_t pkt_len)
{
    uint64_t now = get_time_rc();
    uint64_t elapsed = now - meter->last_update;
    meter->last_update = now;

    /* Refill committed bucket (CIR) */
    uint64_t c_refill = (meter->cir * elapsed) / get_hz();
    meter->c_tokens += c_refill;
    if (meter->c_tokens > meter->cbs) {
        meter->c_tokens = meter->cbs;
    }

    /* Refill peak bucket (PIR) */
    uint64_t p_refill = (meter->pir * elapsed) / get_hz();
    meter->p_tokens += p_refill;
    if (meter->p_tokens > meter->pbs) {
        meter->p_tokens = meter->pbs;
    }

    /* trTCM color decision */
    if (meter->p_tokens < pkt_len) {
        /* RED: Violates PIR */
        return meter->violate_action;
    } else if (meter->c_tokens < pkt_len) {
        /* YELLOW: Exceeds CIR but within PIR */
        meter->p_tokens -= pkt_len;
        return meter->exceed_action;
    } else {
        /* GREEN: Within CIR */
        meter->c_tokens -= pkt_len;
        meter->p_tokens -= pkt_len;
        return QOS_ACTION_PASS;
    }
}



int __attribute__((unused)) qos_session_create(uint16_t session_id, uint64_t cir_up, uint64_t cir_down,
                       uint64_t mir_up, uint64_t mir_down)
{
    if (session_id >= MAX_QOS_SESSIONS) return -1;
    if (g_qos_sessions[session_id]) {
        YLOG_WARNING("QoS: Session %u already exists", session_id);
        return -1;
    }

    struct qos_session *session = calloc(1, sizeof(*session));
    if (!session) return -1;

    session->session_id = session_id;
    session->enabled = true;

    /* Default burst = 1 second worth */
    uint64_t cbs_up = cir_up / 8;   /* 1 second of CIR */
    uint64_t pbs_up = mir_up / 8;
    uint64_t cbs_down = cir_down / 8;
    uint64_t pbs_down = mir_down / 8;

    /* Minimum burst of 1500 bytes (1 MTU) */
    if (cbs_up < 1500) cbs_up = 1500;
    if (pbs_up < 1500) pbs_up = 1500;
    if (cbs_down < 1500) cbs_down = 1500;
    if (pbs_down < 1500) pbs_down = 1500;

    qos_meter_init(&session->uplink, cir_up, cbs_up, mir_up, pbs_up);
    qos_meter_init(&session->downlink, cir_down, cbs_down, mir_down, pbs_down);

    g_qos_sessions[session_id] = session;

    YLOG_DEBUG("QoS: Created session %u (CIR up/down: %lu/%lu, MIR: %lu/%lu)",
               session_id, cir_up, cir_down, mir_up, mir_down);
    return 0;
}

void __attribute__((unused)) qos_session_delete(uint16_t session_id)
{
    if (session_id >= MAX_QOS_SESSIONS) return;
    if (g_qos_sessions[session_id]) {
        free(g_qos_sessions[session_id]);
        g_qos_sessions[session_id] = NULL;
    }
}

qos_action_t __attribute__((unused)) qos_apply_uplink(uint16_t session_id, uint32_t pkt_len)
{
    if (session_id >= (uint16_t)MAX_QOS_SESSIONS) return QOS_ACTION_PASS;
    struct qos_session *session = g_qos_sessions[session_id];
    if (!session || !session->enabled) return QOS_ACTION_PASS;

    qos_action_t action = qos_meter_packet(&session->uplink, pkt_len);

    switch (action) {
    case QOS_ACTION_PASS:       session->green_packets++;  break;
    case QOS_ACTION_MARK_YELLOW: session->yellow_packets++; break;
    case QOS_ACTION_MARK_RED:   session->red_packets++;    break;
    case QOS_ACTION_DROP:       session->dropped_packets++; break;
    }

    return action;
}

qos_action_t __attribute__((unused)) qos_apply_downlink(uint16_t session_id, uint32_t pkt_len)
{
    struct qos_session *session = g_qos_sessions[session_id];
    if (!session || !session->enabled) return QOS_ACTION_PASS;

    qos_action_t action = qos_meter_packet(&session->downlink, pkt_len);

    switch (action) {
    case QOS_ACTION_PASS:       session->green_packets++;  break;
    case QOS_ACTION_MARK_YELLOW: session->yellow_packets++; break;
    case QOS_ACTION_MARK_RED:   session->red_packets++;    break;
    case QOS_ACTION_DROP:       session->dropped_packets++; break;
    }

    return action;
}

void __attribute__((unused)) qos_session_update_rates(uint16_t session_id, uint64_t cir_down, uint64_t mir_down)
{
    struct qos_session *session = g_qos_sessions[session_id];
    if (!session) return;

    uint64_t cbs = cir_down / 8;
    uint64_t pbs = mir_down / 8;
    if (cbs < 1500) cbs = 1500;
    if (pbs < 1500) pbs = 1500;

    qos_meter_init(&session->downlink, cir_down, cbs, mir_down, pbs);

    YLOG_INFO("QoS: Updated session %u downlink (CIR: %lu, MIR: %lu)",
              session_id, cir_down, mir_down);
}
