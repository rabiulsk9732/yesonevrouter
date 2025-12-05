#ifndef EXPORTER_CORE_H
#define EXPORTER_CORE_H

#include "export_common.h"

/**
 * @brief Initialize exporter subsystem (rings, thread)
 * @return 0 on success
 */
int exporter_init(void);

/**
 * @brief Enqueue message to exporter
 * @param lcore_id Source Core ID
 * @param msg Message to export
 * @return 0 on success, <0 if ring full
 */
int exporter_enqueue(unsigned int lcore_id, struct exporter_msg *msg);

/**
 * @brief Main loop for exporter thread
 */
int exporter_thread_func(void *arg);

/**
 * @brief Set collector configuration
 * @param idx Collector index (0-MAX_EXPORTERS)
 * @param ip IP address
 * @param port Port
 */
void export_config_set_collector(int idx, uint32_t ip, uint16_t port);

#endif /* EXPORTER_CORE_H */
