/**
 * @file ipoe_timer.c
 * @brief IPoE Lease Timer Wheel Implementation
 */

#include <ipoe_timer.h>
#include <ipoe_session.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*============================================================================
 * Global Timer Wheel
 *============================================================================*/

static struct ipoe_timer_wheel g_timer_wheel = {0};

/*============================================================================
 * Helper Functions
 *============================================================================*/

static uint64_t get_timestamp_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static uint32_t time_to_slot(uint64_t expire_ns)
{
    uint64_t now = get_timestamp_ns();
    if (expire_ns <= now) {
        return g_timer_wheel.current_slot;
    }

    uint64_t delta_ns = expire_ns - now;
    uint64_t slots = delta_ns / g_timer_wheel.resolution_ns;

    return (g_timer_wheel.current_slot + slots) % IPOE_TIMER_WHEEL_SLOTS;
}

/*============================================================================
 * Initialization
 *============================================================================*/

int ipoe_timer_init(void (*callback)(uint32_t session_id, uint8_t timer_type))
{
    memset(&g_timer_wheel, 0, sizeof(g_timer_wheel));
    g_timer_wheel.resolution_ns = IPOE_TIMER_RESOLUTION_MS * 1000000ULL;
    g_timer_wheel.last_tick_ns = get_timestamp_ns();
    g_timer_wheel.expire_callback = callback;

    printf("ipoe_timer: wheel initialized (%u slots, %ums resolution)\n",
           IPOE_TIMER_WHEEL_SLOTS, IPOE_TIMER_RESOLUTION_MS);

    return 0;
}

void ipoe_timer_cleanup(void)
{
    /* Free all timer entries */
    for (uint32_t i = 0; i < IPOE_TIMER_WHEEL_SLOTS; i++) {
        struct ipoe_timer_entry *e = g_timer_wheel.slots[i];
        while (e) {
            struct ipoe_timer_entry *next = e->next;
            free(e);
            e = next;
        }
        g_timer_wheel.slots[i] = NULL;
    }
}

/*============================================================================
 * Timer Management
 *============================================================================*/

int ipoe_timer_add(uint32_t session_id, uint8_t timer_type, uint32_t timeout_sec)
{
    if (timeout_sec == 0) return -1;

    struct ipoe_timer_entry *entry = calloc(1, sizeof(*entry));
    if (!entry) return -1;

    entry->session_id = session_id;
    entry->timer_type = timer_type;
    entry->expire_ns = get_timestamp_ns() + (uint64_t)timeout_sec * 1000000000ULL;

    uint32_t slot = time_to_slot(entry->expire_ns);

    /* Insert at head of slot list */
    entry->next = g_timer_wheel.slots[slot];
    g_timer_wheel.slots[slot] = entry;

    g_timer_wheel.timers_added++;

    return 0;
}

int ipoe_timer_cancel(uint32_t session_id, uint8_t timer_type)
{
    for (uint32_t i = 0; i < IPOE_TIMER_WHEEL_SLOTS; i++) {
        struct ipoe_timer_entry **pp = &g_timer_wheel.slots[i];

        while (*pp) {
            if ((*pp)->session_id == session_id &&
                (*pp)->timer_type == timer_type) {
                struct ipoe_timer_entry *old = *pp;
                *pp = (*pp)->next;
                free(old);
                g_timer_wheel.timers_cancelled++;
                return 0;
            }
            pp = &(*pp)->next;
        }
    }

    return -1;  /* Not found */
}

int ipoe_timer_cancel_all(uint32_t session_id)
{
    int count = 0;

    for (uint32_t i = 0; i < IPOE_TIMER_WHEEL_SLOTS; i++) {
        struct ipoe_timer_entry **pp = &g_timer_wheel.slots[i];

        while (*pp) {
            if ((*pp)->session_id == session_id) {
                struct ipoe_timer_entry *old = *pp;
                *pp = (*pp)->next;
                free(old);
                g_timer_wheel.timers_cancelled++;
                count++;
            } else {
                pp = &(*pp)->next;
            }
        }
    }

    return count;
}

/*============================================================================
 * Timer Tick (called from main loop or DPDK timer)
 *============================================================================*/

void ipoe_timer_tick(void)
{
    uint64_t now = get_timestamp_ns();
    uint64_t elapsed = now - g_timer_wheel.last_tick_ns;

    /* Advance slots based on elapsed time */
    uint32_t slots_to_advance = elapsed / g_timer_wheel.resolution_ns;
    if (slots_to_advance == 0) return;

    for (uint32_t i = 0; i < slots_to_advance && i < IPOE_TIMER_WHEEL_SLOTS; i++) {
        g_timer_wheel.current_slot =
            (g_timer_wheel.current_slot + 1) % IPOE_TIMER_WHEEL_SLOTS;

        /* Process expired timers in this slot */
        struct ipoe_timer_entry *e = g_timer_wheel.slots[g_timer_wheel.current_slot];
        g_timer_wheel.slots[g_timer_wheel.current_slot] = NULL;

        while (e) {
            struct ipoe_timer_entry *next = e->next;

            if (e->expire_ns <= now) {
                /* Timer expired */
                g_timer_wheel.timers_expired++;

                if (g_timer_wheel.expire_callback) {
                    g_timer_wheel.expire_callback(e->session_id, e->timer_type);
                }

                free(e);
            } else {
                /* Re-insert (wrapped around) */
                uint32_t new_slot = time_to_slot(e->expire_ns);
                e->next = g_timer_wheel.slots[new_slot];
                g_timer_wheel.slots[new_slot] = e;
            }

            e = next;
        }
    }

    g_timer_wheel.last_tick_ns = now;
}

/*============================================================================
 * Statistics
 *============================================================================*/

void ipoe_timer_print_stats(void)
{
    printf("\nIPoE Timer Wheel Statistics:\n");
    printf("  Timers added:     %lu\n", g_timer_wheel.timers_added);
    printf("  Timers expired:   %lu\n", g_timer_wheel.timers_expired);
    printf("  Timers cancelled: %lu\n", g_timer_wheel.timers_cancelled);
    printf("  Current slot:     %u\n", g_timer_wheel.current_slot);
    printf("\n");
}
