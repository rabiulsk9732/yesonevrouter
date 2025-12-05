/**
 * @file nat_logger.c
 * @brief NAT Event Logger Subsystem
 */

#include "nat_logger.h"
#include "exporter_core.h"
#include "log.h"
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <sys/time.h>
#include <unistd.h>

int nat_logger_init(void)
{
    /* No specific init needed per core, exporter rings handled centrally */
    return 0;
}

void nat_logger_log_event(uint8_t event_type, uint32_t original_ip, uint16_t original_port,
                          uint32_t translated_ip, uint16_t translated_port, uint32_t dest_ip,
                          uint16_t dest_port, uint8_t protocol)
{
    struct exporter_msg msg;
    msg.type = MSG_TYPE_NAT_EVENT;

    struct nat_event_record *rec = &msg.data.nat;
    rec->event_type = event_type;
    rec->original_ip = original_ip;
    rec->original_port = original_port;
    rec->translated_ip = translated_ip;
    rec->translated_port = translated_port;
    rec->destination_ip = dest_ip;
    rec->destination_port = dest_port;
    rec->protocol = protocol;

    /* Timestamp logic: gettimeofday is heavy but NAT events are rarer than packets */
    /* Only do this for events, packets use cycles */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    rec->timestamp_ms = (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;

    rec->bytes_in = 0; /* Populate on delete if available from session */
    rec->bytes_out = 0;

    /* Push to ring */
    /* Note: rte_lcore_id() works in dataplane threads. */
    exporter_enqueue(rte_lcore_id(), &msg);
}
