/**
 * @file neighbor.c
 * @brief Neighbor state machine for ARP
 */

#include "arp.h"
#include "log.h"
#include <stdio.h>
#include <string.h>

/**
 * @brief Transition neighbor state
 * @param entry ARP entry
 * @param new_state New state
 */
static void neighbor_transition(struct arp_entry *entry, enum arp_state new_state)
{
    if (!entry) {
        return;
    }

    __attribute__((unused)) enum arp_state old_state = entry->state;
    entry->state = new_state;

    YLOG_DEBUG("Neighbor state transition: %s -> %s for IP %u.%u.%u.%u",
               arp_state_to_str(old_state),
               arp_state_to_str(new_state),
               (entry->ip_address >> 24) & 0xFF,
               (entry->ip_address >> 16) & 0xFF,
               (entry->ip_address >> 8) & 0xFF,
               entry->ip_address & 0xFF);
}

/**
 * @brief Process neighbor state machine
 * @param entry ARP entry
 * @return 0 on success, -1 on error
 */
int neighbor_process(struct arp_entry *entry)
{
    if (!entry) {
        return -1;
    }

    time_t now = time(NULL);
    time_t age = now - entry->last_seen;

    switch (entry->state) {
        case ARP_STATE_INCOMPLETE:
            /* Waiting for ARP reply */
            if (age > ARP_INCOMPLETE_TIMEOUT) {
                if (entry->retries < ARP_MAX_RETRIES) {
                    /* Retry ARP request */
                    entry->retries++;
                    entry->last_seen = now;
                    /* TODO: Resend ARP request */
                    YLOG_DEBUG("Neighbor retry ARP request (%d/%d)",
                               entry->retries, ARP_MAX_RETRIES);
                } else {
                    /* Max retries exceeded */
                    neighbor_transition(entry, ARP_STATE_FAILED);
                    return -1;
                }
            }
            break;

        case ARP_STATE_VALID:
            /* Entry is valid */
            if (age > ARP_VALID_TIMEOUT) {
                neighbor_transition(entry, ARP_STATE_STALE);
            }
            break;

        case ARP_STATE_STALE:
            /* Entry needs revalidation */
            /* Could send ARP probe here */
            break;

        case ARP_STATE_FAILED:
            /* Entry failed, will be removed */
            break;
    }

    return 0;
}

/**
 * @brief Validate neighbor entry
 * @param entry ARP entry
 * @param mac_address MAC address from ARP reply
 */
void neighbor_validate(struct arp_entry *entry, const uint8_t *mac_address)
{
    if (!entry || !mac_address) {
        return;
    }

    memcpy(entry->mac_address, mac_address, 6);
    entry->last_seen = time(NULL);
    entry->retries = 0;
    neighbor_transition(entry, ARP_STATE_VALID);
}

/**
 * @brief Mark neighbor as stale
 * @param entry ARP entry
 */
void neighbor_mark_stale(struct arp_entry *entry)
{
    if (!entry) {
        return;
    }

    neighbor_transition(entry, ARP_STATE_STALE);
}

/**
 * @brief Check if neighbor is reachable
 * @param entry ARP entry
 * @return true if reachable, false otherwise
 */
bool neighbor_is_reachable(const struct arp_entry *entry)
{
    if (!entry) {
        return false;
    }

    return entry->state == ARP_STATE_VALID;
}
