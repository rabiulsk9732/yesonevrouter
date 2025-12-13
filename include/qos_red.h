/**
 * @file qos_red.h
 * @brief RED/WRED (Random Early Detection) Header
 */

#ifndef QOS_RED_H
#define QOS_RED_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Initialize RED subsystem
 */
int red_init(void);

/**
 * @brief Configure RED for a queue
 * @param queue_id Queue identifier
 * @param min_th Minimum threshold (packets)
 * @param max_th Maximum threshold (packets)
 * @param max_prob Maximum drop probability (0-255, 255=100%)
 * @param wq Queue weight for EWMA (shift value, e.g., 9 = 1/512)
 */
int red_configure(uint16_t queue_id, uint32_t min_th, uint32_t max_th,
                  uint32_t max_prob, uint32_t wq);

/**
 * @brief Check if packet should be dropped (RED algorithm)
 * @param queue_id Queue identifier
 * @param queue_len Current queue length in packets
 * @return true if packet should be dropped
 */
bool red_drop(uint16_t queue_id, uint32_t queue_len);

/**
 * @brief WRED drop decision based on DSCP/color
 * @param queue_id Queue identifier
 * @param queue_len Current queue length
 * @param dscp DSCP value (0-63)
 * @return true if packet should be dropped
 */
bool wred_drop(uint16_t queue_id, uint32_t queue_len, uint8_t dscp);

/**
 * @brief Configure WRED with three thresholds per queue
 */
int wred_configure(uint16_t queue_id,
                   uint32_t green_min, uint32_t green_max, uint32_t green_prob,
                   uint32_t yellow_min, uint32_t yellow_max, uint32_t yellow_prob,
                   uint32_t red_min, uint32_t red_max, uint32_t red_prob);

/**
 * @brief Get RED statistics
 */
void red_get_stats(uint16_t queue_id, uint64_t *packets_in,
                   uint64_t *packets_dropped, uint64_t *early_drops);

/**
 * @brief Print RED configuration and statistics
 */
void red_print(void);

/**
 * @brief Cleanup RED subsystem
 */
void red_cleanup(void);

#endif /* QOS_RED_H */
