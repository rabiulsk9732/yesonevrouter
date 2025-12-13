/**
 * @file conntrack.h
 * @brief Connection Tracking Header
 */

#ifndef CONNTRACK_H
#define CONNTRACK_H

#include <stdint.h>
#include <stdbool.h>

/* Forward declaration */
struct ct_entry;

enum ct_status {
    CT_STATUS_NEW,
    CT_STATUS_ESTABLISHED,
    CT_STATUS_RELATED,
    CT_STATUS_INVALID
};

enum tcp_state {
    TCP_STATE_NONE = 0,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECV,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_LAST_ACK,
    TCP_STATE_TIME_WAIT,
    TCP_STATE_CLOSE
};

int conntrack_init(void);
void conntrack_enable(bool enable);

struct ct_entry *conntrack_lookup(uint8_t protocol,
                                  uint32_t src_ip, uint16_t src_port,
                                  uint32_t dst_ip, uint16_t dst_port,
                                  bool *is_reply);

struct ct_entry *conntrack_create(uint8_t protocol,
                                  uint32_t src_ip, uint16_t src_port,
                                  uint32_t dst_ip, uint16_t dst_port);

void conntrack_update(struct ct_entry *entry, uint32_t pkt_len,
                      uint8_t tcp_flags, bool is_reply);

void conntrack_delete(struct ct_entry *entry);
void conntrack_expire(void);
void conntrack_print_stats(void);
void conntrack_cleanup(void);

#endif /* CONNTRACK_H */
