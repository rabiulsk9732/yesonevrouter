/**
 * @file dpdk_timers.h
 * @brief DPDK Timer Subsystem API
 */

#ifndef DPDK_TIMERS_H
#define DPDK_TIMERS_H

#include <stdint.h>
#include <stdbool.h>

/* Timer callback function type */
typedef void (*dpdk_timer_cb_t)(void *ctx);

/**
 * Initialize timer subsystem
 */
int dpdk_timers_init(void);

/**
 * Cleanup timer subsystem
 */
void dpdk_timers_cleanup(void);

/**
 * Create a timer
 * @param period_ms Timer period in milliseconds
 * @param periodic True for repeating timer
 * @param cb Callback function
 * @param ctx User context
 * @return Timer ID on success, -1 on failure
 */
int dpdk_timer_create(uint64_t period_ms, bool periodic, dpdk_timer_cb_t cb, void *ctx);

/**
 * Cancel a timer
 */
void dpdk_timer_cancel(int timer_id);

/**
 * Process timer events (call from main loop)
 */
void dpdk_timers_process(void);

/**
 * Get current cycle count
 */
uint64_t dpdk_timer_get_cycles(void);

/**
 * Convert cycles to microseconds
 */
uint64_t dpdk_timer_cycles_to_us(uint64_t cycles);

/**
 * Start keepalive timer (Echo-Request)
 */
int dpdk_timer_start_keepalive(uint32_t interval_ms, dpdk_timer_cb_t cb, void *ctx);

/**
 * Stop keepalive timer
 */
void dpdk_timer_stop_keepalive(void);

/**
 * Start accounting timer (Interim-Update)
 */
int dpdk_timer_start_accounting(uint32_t interval_ms, dpdk_timer_cb_t cb, void *ctx);

/**
 * Stop accounting timer
 */
void dpdk_timer_stop_accounting(void);

#endif /* DPDK_TIMERS_H */
