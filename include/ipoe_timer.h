/**
 * @file ipoe_timer.h
 * @brief IPoE Lease Timer Wheel
 *
 * DPDK-optimized timer wheel for DHCP lease management
 */

#ifndef IPOE_TIMER_H
#define IPOE_TIMER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef HAVE_DPDK
#include <rte_timer.h>
#endif

/*============================================================================
 * Timer Configuration
 *============================================================================*/

#define IPOE_TIMER_WHEEL_SLOTS      4096    /* 4K slots = 68 min at 1s resolution */
#define IPOE_TIMER_RESOLUTION_MS    1000    /* 1 second resolution */

/*============================================================================
 * Timer Entry
 *============================================================================*/

struct ipoe_timer_entry {
    uint32_t session_id;
    uint64_t expire_ns;
    uint8_t  timer_type;
    struct ipoe_timer_entry *next;
};

/* Timer types */
#define IPOE_TIMER_LEASE            1       /* DHCP lease expiry */
#define IPOE_TIMER_RENEW            2       /* T1 renewal */
#define IPOE_TIMER_REBIND           3       /* T2 rebind */
#define IPOE_TIMER_IDLE             4       /* Idle timeout */
#define IPOE_TIMER_SESSION          5       /* Session timeout */

/*============================================================================
 * Timer Wheel
 *============================================================================*/

struct ipoe_timer_wheel {
    struct ipoe_timer_entry *slots[IPOE_TIMER_WHEEL_SLOTS];
    uint32_t current_slot;
    uint64_t last_tick_ns;
    uint64_t resolution_ns;

#ifdef HAVE_DPDK
    struct rte_timer tick_timer;
#endif

    /* Callback for expired timers */
    void (*expire_callback)(uint32_t session_id, uint8_t timer_type);

    /* Statistics */
    uint64_t timers_added;
    uint64_t timers_expired;
    uint64_t timers_cancelled;
};

/*============================================================================
 * Timer API
 *============================================================================*/

/* Initialization */
int ipoe_timer_init(void (*callback)(uint32_t session_id, uint8_t timer_type));
void ipoe_timer_cleanup(void);

/* Timer management */
int ipoe_timer_add(uint32_t session_id, uint8_t timer_type, uint32_t timeout_sec);
int ipoe_timer_cancel(uint32_t session_id, uint8_t timer_type);
int ipoe_timer_cancel_all(uint32_t session_id);

/* Timer tick (called periodically) */
void ipoe_timer_tick(void);

/* Statistics */
void ipoe_timer_print_stats(void);

#endif /* IPOE_TIMER_H */
