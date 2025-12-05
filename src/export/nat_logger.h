#ifndef NAT_LOGGER_H
#define NAT_LOGGER_H

#include "export_common.h"

/**
 * @brief Initialize NAT logger
 */
int nat_logger_init(void);

/**
 * @brief Log a NAT event
 * @param event_type Event type (Create, Delete, Quota)
 * @param original_ip Original Source IP
 * @param original_port Original Source Port
 * @param translated_ip Translated Source IP
 * @param translated_port Translated Source Port
 * @param dest_ip Destination IP
 * @param dest_port Destination Port
 * @param protocol Protocol ID
 */
void nat_logger_log_event(uint8_t event_type, uint32_t original_ip, uint16_t original_port,
                          uint32_t translated_ip, uint16_t translated_port, uint32_t dest_ip,
                          uint16_t dest_port, uint8_t protocol);

#endif /* NAT_LOGGER_H */
