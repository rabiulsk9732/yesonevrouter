/**
 * @file pcap_tap.h
 * @brief PCAP Packet Capture API
 */

#ifndef PCAP_TAP_H
#define PCAP_TAP_H

#include <stdint.h>
#include <stdbool.h>

/**
 * Start capturing packets to PCAP file
 * @param filename Output file path
 * @param snaplen Maximum bytes to capture per packet (0 for unlimited)
 */
int pcap_tap_start(const char *filename, uint32_t snaplen);

/**
 * Stop capturing
 */
void pcap_tap_stop(void);

/**
 * Write raw packet to PCAP
 * @return 1 if written, 0 if filtered/disabled
 */
int pcap_tap_write(const uint8_t *data, uint32_t len);

/**
 * Write PPPoE session packet (with filter support)
 */
int pcap_tap_write_pppoe(uint16_t session_id, const uint8_t *data, uint32_t len);

/**
 * Set capture filter
 * @param session_id Filter by session ID (0 for all)
 * @param ip Filter by IP (0 for all)
 */
void pcap_tap_set_filter(uint16_t session_id, uint32_t ip);

/**
 * Clear filter (capture all)
 */
void pcap_tap_clear_filter(void);

/**
 * Get capture statistics
 */
void pcap_tap_stats(uint64_t *packets, uint64_t *bytes);

/**
 * Check if capture is running
 */
bool pcap_tap_is_running(void);

#endif /* PCAP_TAP_H */
