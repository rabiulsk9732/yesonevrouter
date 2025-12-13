/**
 * @file qos_red.c
 * @brief RED/WRED (Random Early Detection) Implementation
 * @details RFC 2309, RFC 2597 (Assured Forwarding)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "qos.h"
#include "log.h"

/*============================================================================
 * RED Constants
 *============================================================================*/

#define RED_WQ_SHIFT        9           /* Weight for EWMA: 1/512 */
#define RED_MAX_PROB        255         /* Max probability (100%) */
#define RED_SCALE           1024        /* Scaling factor for calculations */

/*============================================================================
 * RED Configuration
 *============================================================================*/

struct red_config {
    uint32_t min_th;        /* Minimum threshold (packets) */
    uint32_t max_th;        /* Maximum threshold (packets) */
    uint32_t max_prob;      /* Max drop probability (0-255) */
    uint32_t wq;            /* Queue weight for EWMA (shift value) */
    bool     enabled;
};

struct red_state {
    uint64_t avg_queue;     /* EWMA of queue length (scaled) */
    int64_t  count;         /* Packets since last drop */
    uint64_t prng_state;    /* PRNG state for random drops */

    /* Statistics */
    uint64_t packets_in;
    uint64_t packets_dropped;
    uint64_t early_drops;   /* Drops due to RED, not full queue */
};

struct wred_config {
    struct red_config green;    /* DSCP EF, AF1x */
    struct red_config yellow;   /* DSCP AF2x, AF3x */
    struct red_config red;      /* DSCP AF4x, BE */
};

/*============================================================================
 * Per-Queue RED State
 *============================================================================*/

#define MAX_RED_QUEUES 64

static struct {
    struct red_config config[MAX_RED_QUEUES];
    struct red_state state[MAX_RED_QUEUES];
    int num_queues;
    bool initialized;
} g_red = {0};

/*============================================================================
 * Utility Functions
 *============================================================================*/

/* Simple xorshift PRNG for random drop decisions */
static uint64_t red_random(struct red_state *state)
{
    uint64_t x = state->prng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    state->prng_state = x;
    return x;
}

/*============================================================================
 * RED Functions
 *============================================================================*/

/**
 * @brief Initialize RED subsystem
 */
int red_init(void)
{
    memset(&g_red, 0, sizeof(g_red));
    g_red.initialized = true;
    YLOG_INFO("RED/WRED subsystem initialized");
    return 0;
}

/**
 * @brief Configure RED for a queue
 */
int red_configure(uint16_t queue_id, uint32_t min_th, uint32_t max_th,
                  uint32_t max_prob, uint32_t wq)
{
    if (queue_id >= MAX_RED_QUEUES) return -1;

    struct red_config *cfg = &g_red.config[queue_id];
    cfg->min_th = min_th;
    cfg->max_th = max_th;
    cfg->max_prob = max_prob;
    cfg->wq = wq > 0 ? wq : RED_WQ_SHIFT;
    cfg->enabled = true;

    /* Initialize state */
    struct red_state *st = &g_red.state[queue_id];
    st->avg_queue = 0;
    st->count = -1;
    st->prng_state = (uint64_t)time(NULL) ^ (queue_id << 16);

    if (queue_id >= g_red.num_queues) {
        g_red.num_queues = queue_id + 1;
    }

    YLOG_INFO("RED: Queue %u configured (min=%u, max=%u, prob=%u%%)",
              queue_id, min_th, max_th, (max_prob * 100) / 255);

    return 0;
}

/**
 * @brief Update average queue length (EWMA)
 */
static void red_update_avg(struct red_state *st, struct red_config *cfg,
                           uint32_t queue_len)
{
    /*
     * EWMA formula:
     * avg = avg + wq * (queue_len - avg)
     *
     * Using shift for wq (e.g., wq=9 means 1/512):
     * avg = avg + ((queue_len - avg) >> wq)
     */
    int64_t diff = ((int64_t)queue_len * RED_SCALE) - (int64_t)st->avg_queue;
    st->avg_queue += diff >> cfg->wq;

    if (st->avg_queue < 0) st->avg_queue = 0;
}

/**
 * @brief Check if packet should be dropped (RED algorithm)
 * @return true if packet should be dropped, false otherwise
 */
bool red_drop(uint16_t queue_id, uint32_t queue_len)
{
    if (queue_id >= MAX_RED_QUEUES) return false;

    struct red_config *cfg = &g_red.config[queue_id];
    struct red_state *st = &g_red.state[queue_id];

    if (!cfg->enabled) return false;

    st->packets_in++;

    /* Update average queue length */
    red_update_avg(st, cfg, queue_len);

    uint32_t avg = st->avg_queue / RED_SCALE;

    if (avg < cfg->min_th) {
        /* Below minimum: no drops */
        st->count = -1;
        return false;
    }

    if (avg >= cfg->max_th) {
        /* Above maximum: always drop */
        st->count = -1;
        st->packets_dropped++;
        st->early_drops++;
        return true;
    }

    /* Between min and max: probabilistic drop */
    st->count++;

    /*
     * Calculate drop probability:
     * pb = max_prob * (avg - min_th) / (max_th - min_th)
     * pa = pb / (1 - count * pb)
     */
    uint32_t range = cfg->max_th - cfg->min_th;
    uint32_t pb = (cfg->max_prob * (avg - cfg->min_th)) / range;

    /* Increase probability based on count */
    uint32_t pa;
    if (st->count > 0 && pb > 0) {
        uint32_t denom = RED_MAX_PROB - (st->count * pb);
        if (denom > 0) {
            pa = (pb * RED_MAX_PROB) / denom;
        } else {
            pa = RED_MAX_PROB;
        }
    } else {
        pa = pb;
    }

    /* Random drop decision */
    uint64_t rand = red_random(st) % 256;

    if (rand < pa) {
        st->count = 0;
        st->packets_dropped++;
        st->early_drops++;
        return true;
    }

    return false;
}

/**
 * @brief WRED drop decision based on DSCP/color
 */
bool wred_drop(uint16_t queue_id, uint32_t queue_len, uint8_t dscp)
{
    /* Map DSCP to color */
    uint8_t color;

    switch (dscp >> 3) {
        case 5:  /* EF */
        case 4:  /* AF4x */
            color = 0;  /* Green - lowest drop probability */
            break;
        case 3:  /* AF3x */
        case 2:  /* AF2x */
            color = 1;  /* Yellow */
            break;
        default: /* AF1x, BE */
            color = 2;  /* Red - highest drop probability */
            break;
    }

    /* Use different queue IDs for different colors */
    uint16_t effective_queue = queue_id * 3 + color;
    return red_drop(effective_queue, queue_len);
}

/**
 * @brief Configure WRED (three thresholds per queue)
 */
int wred_configure(uint16_t queue_id,
                   uint32_t green_min, uint32_t green_max, uint32_t green_prob,
                   uint32_t yellow_min, uint32_t yellow_max, uint32_t yellow_prob,
                   uint32_t red_min, uint32_t red_max, uint32_t red_prob)
{
    uint16_t base = queue_id * 3;

    red_configure(base + 0, green_min, green_max, green_prob, RED_WQ_SHIFT);
    red_configure(base + 1, yellow_min, yellow_max, yellow_prob, RED_WQ_SHIFT);
    red_configure(base + 2, red_min, red_max, red_prob, RED_WQ_SHIFT);

    YLOG_INFO("WRED: Queue %u configured with 3-color thresholds", queue_id);
    return 0;
}

/**
 * @brief Get RED statistics
 */
void red_get_stats(uint16_t queue_id, uint64_t *packets_in,
                   uint64_t *packets_dropped, uint64_t *early_drops)
{
    if (queue_id >= MAX_RED_QUEUES) return;

    struct red_state *st = &g_red.state[queue_id];

    if (packets_in) *packets_in = st->packets_in;
    if (packets_dropped) *packets_dropped = st->packets_dropped;
    if (early_drops) *early_drops = st->early_drops;
}

/**
 * @brief Print RED configuration and statistics
 */
void red_print(void)
{
    printf("RED/WRED Status\n");
    printf("===============\n\n");

    for (int i = 0; i < g_red.num_queues; i++) {
        struct red_config *cfg = &g_red.config[i];
        struct red_state *st = &g_red.state[i];

        if (!cfg->enabled) continue;

        uint32_t avg = st->avg_queue / RED_SCALE;

        printf("Queue %d:\n", i);
        printf("  Thresholds: min=%u, max=%u, prob=%u%%\n",
               cfg->min_th, cfg->max_th, (cfg->max_prob * 100) / 255);
        printf("  Avg queue:  %u packets\n", avg);
        printf("  Packets in: %lu\n", st->packets_in);
        printf("  Dropped:    %lu (early: %lu)\n",
               st->packets_dropped, st->early_drops);
        printf("\n");
    }
}

/**
 * @brief Cleanup RED subsystem
 */
void red_cleanup(void)
{
    memset(&g_red, 0, sizeof(g_red));
    YLOG_INFO("RED/WRED cleanup complete");
}
