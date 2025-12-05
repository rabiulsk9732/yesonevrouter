/**
 * @file metrics.h
 * @brief Prometheus Metrics API
 */

#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>
#include <stddef.h>

/**
 * Initialize metrics subsystem
 */
int metrics_init(void);

/**
 * Cleanup metrics subsystem
 */
void metrics_cleanup(void);

/* Increment functions (thread-safe) */
void metrics_inc_sessions_total(void);
void metrics_inc_sessions_active(void);
void metrics_dec_sessions_active(void);
void metrics_inc_auth_success(void);
void metrics_inc_auth_failed(void);
void metrics_add_packets_rx(uint64_t n);
void metrics_add_packets_tx(uint64_t n);
void metrics_add_bytes_rx(uint64_t n);
void metrics_add_bytes_tx(uint64_t n);
void metrics_inc_padi(void);
void metrics_inc_pado(void);
void metrics_inc_padr(void);
void metrics_inc_pads(void);
void metrics_inc_padt_sent(void);
void metrics_inc_padt_recv(void);
void metrics_inc_dropped(void);

/**
 * Export metrics in Prometheus text format
 * @return Number of bytes written
 */
int metrics_export_prometheus(char *buf, size_t buf_size);

/**
 * Start HTTP server for /metrics endpoint
 * @param port TCP port (default: 9100)
 */
int metrics_start_http_server(uint16_t port);

/**
 * Stop HTTP server
 */
void metrics_stop_http_server(void);

#endif /* METRICS_H */
