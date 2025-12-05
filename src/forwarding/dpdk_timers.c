/**
 * @file dpdk_timers.c
 * @brief DPDK Timer Subsystem for High-Precision Scheduling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_DPDK
#include <rte_timer.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#endif

#include "dpdk_timers.h"
#include "log.h"

#ifdef HAVE_DPDK

#define MAX_TIMERS 256

/* Timer management */
static struct {
    struct rte_timer timers[MAX_TIMERS];
    dpdk_timer_cb_t callbacks[MAX_TIMERS];
    void *contexts[MAX_TIMERS];
    int used[MAX_TIMERS];
    int count;
    uint64_t hz;
} g_timer_ctx;

static void timer_callback_wrapper(struct rte_timer *timer, void *arg)
{
    (void)timer;
    int idx = (int)(uintptr_t)arg;

    if (idx >= 0 && idx < MAX_TIMERS && g_timer_ctx.used[idx]) {
        if (g_timer_ctx.callbacks[idx]) {
            g_timer_ctx.callbacks[idx](g_timer_ctx.contexts[idx]);
        }
    }
}

int dpdk_timers_init(void)
{
    memset(&g_timer_ctx, 0, sizeof(g_timer_ctx));

    rte_timer_subsystem_init();
    g_timer_ctx.hz = rte_get_timer_hz();

    for (int i = 0; i < MAX_TIMERS; i++) {
        rte_timer_init(&g_timer_ctx.timers[i]);
    }

    YLOG_INFO("DPDK Timers: Initialized (freq: %lu Hz)", g_timer_ctx.hz);
    return 0;
}

int dpdk_timer_create(uint64_t period_ms, bool periodic, dpdk_timer_cb_t cb, void *ctx)
{
    /* Find free slot */
    int idx = -1;
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (!g_timer_ctx.used[i]) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        YLOG_ERROR("DPDK Timers: No free timer slots");
        return -1;
    }

    g_timer_ctx.callbacks[idx] = cb;
    g_timer_ctx.contexts[idx] = ctx;
    g_timer_ctx.used[idx] = 1;

    uint64_t ticks = (period_ms * g_timer_ctx.hz) / 1000;

    enum rte_timer_type type = periodic ? PERIODICAL : SINGLE;

    int ret = rte_timer_reset(&g_timer_ctx.timers[idx], ticks, type,
                               rte_lcore_id(), timer_callback_wrapper,
                               (void *)(uintptr_t)idx);
    if (ret < 0) {
        g_timer_ctx.used[idx] = 0;
        YLOG_ERROR("DPDK Timers: Failed to start timer");
        return -1;
    }

    g_timer_ctx.count++;
    YLOG_DEBUG("DPDK Timers: Created timer %d (%lu ms, %s)",
               idx, period_ms, periodic ? "periodic" : "oneshot");
    return idx;
}

void dpdk_timer_cancel(int timer_id)
{
    if (timer_id < 0 || timer_id >= MAX_TIMERS) return;
    if (!g_timer_ctx.used[timer_id]) return;

    rte_timer_stop(&g_timer_ctx.timers[timer_id]);
    g_timer_ctx.used[timer_id] = 0;
    g_timer_ctx.callbacks[timer_id] = NULL;
    g_timer_ctx.contexts[timer_id] = NULL;
    g_timer_ctx.count--;
}

void dpdk_timers_process(void)
{
    rte_timer_manage();
}

uint64_t dpdk_timer_get_cycles(void)
{
    return rte_get_timer_cycles();
}

uint64_t dpdk_timer_cycles_to_us(uint64_t cycles)
{
    return (cycles * 1000000) / g_timer_ctx.hz;
}

/* Keepalive timer - sends Echo-Request every interval */
static int g_keepalive_timer = -1;
static dpdk_timer_cb_t g_keepalive_cb = NULL;
static void *g_keepalive_ctx = NULL;

static void keepalive_callback(void *ctx)
{
    if (g_keepalive_cb) {
        g_keepalive_cb(ctx);
    }
}

int dpdk_timer_start_keepalive(uint32_t interval_ms, dpdk_timer_cb_t cb, void *ctx)
{
    if (g_keepalive_timer >= 0) {
        dpdk_timer_cancel(g_keepalive_timer);
    }

    g_keepalive_cb = cb;
    g_keepalive_ctx = ctx;
    g_keepalive_timer = dpdk_timer_create(interval_ms, true, keepalive_callback, ctx);

    if (g_keepalive_timer < 0) {
        YLOG_ERROR("DPDK Timers: Failed to start keepalive timer");
        return -1;
    }

    YLOG_INFO("DPDK Timers: Keepalive timer started (%u ms)", interval_ms);
    return 0;
}

void dpdk_timer_stop_keepalive(void)
{
    if (g_keepalive_timer >= 0) {
        dpdk_timer_cancel(g_keepalive_timer);
        g_keepalive_timer = -1;
        g_keepalive_cb = NULL;
        g_keepalive_ctx = NULL;
    }
}

/* Accounting timer - sends interim updates */
static int g_accounting_timer = -1;

int dpdk_timer_start_accounting(uint32_t interval_ms, dpdk_timer_cb_t cb, void *ctx)
{
    if (g_accounting_timer >= 0) {
        dpdk_timer_cancel(g_accounting_timer);
    }

    g_accounting_timer = dpdk_timer_create(interval_ms, true, cb, ctx);

    if (g_accounting_timer < 0) {
        YLOG_ERROR("DPDK Timers: Failed to start accounting timer");
        return -1;
    }

    YLOG_INFO("DPDK Timers: Accounting timer started (%u ms)", interval_ms);
    return 0;
}

void dpdk_timer_stop_accounting(void)
{
    if (g_accounting_timer >= 0) {
        dpdk_timer_cancel(g_accounting_timer);
        g_accounting_timer = -1;
    }
}

void dpdk_timers_cleanup(void)
{
    dpdk_timer_stop_keepalive();
    dpdk_timer_stop_accounting();

    for (int i = 0; i < MAX_TIMERS; i++) {
        if (g_timer_ctx.used[i]) {
            rte_timer_stop(&g_timer_ctx.timers[i]);
            g_timer_ctx.used[i] = 0;
        }
    }

    g_timer_ctx.count = 0;
    YLOG_INFO("DPDK Timers: Cleanup complete");
}

#else /* !HAVE_DPDK */

int dpdk_timers_init(void) { return 0; }
void dpdk_timers_cleanup(void) {}
int dpdk_timer_create(uint64_t period_ms, bool periodic, dpdk_timer_cb_t cb, void *ctx) {
    (void)period_ms; (void)periodic; (void)cb; (void)ctx;
    return -1;
}
void dpdk_timer_cancel(int timer_id) { (void)timer_id; }
void dpdk_timers_process(void) {}
uint64_t dpdk_timer_get_cycles(void) { return 0; }
uint64_t dpdk_timer_cycles_to_us(uint64_t cycles) { (void)cycles; return 0; }
int dpdk_timer_start_keepalive(uint32_t interval_ms, dpdk_timer_cb_t cb, void *ctx) {
    (void)interval_ms; (void)cb; (void)ctx;
    return 0;
}
void dpdk_timer_stop_keepalive(void) {}
int dpdk_timer_start_accounting(uint32_t interval_ms, dpdk_timer_cb_t cb, void *ctx) {
    (void)interval_ms; (void)cb; (void)ctx;
    return 0;
}
void dpdk_timer_stop_accounting(void) {}

#endif /* HAVE_DPDK */
