/**
 * @file pbr.h
 * @brief Policy-Based Routing Header
 */

#ifndef PBR_H
#define PBR_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

struct pbr_match {
    uint32_t src_ip, src_mask;
    uint16_t src_port_min, src_port_max;
    uint32_t dst_ip, dst_mask;
    uint16_t dst_port_min, dst_port_max;
    uint8_t  protocol;
    uint8_t  dscp, dscp_mask;
    uint32_t in_ifindex;
    char acl_name[32];
};

enum pbr_action_type {
    PBR_ACTION_NEXTHOP,
    PBR_ACTION_INTERFACE,
    PBR_ACTION_VRF,
    PBR_ACTION_DROP,
    PBR_ACTION_PERMIT
};

struct pbr_action {
    enum pbr_action_type type;
    union {
        struct in_addr next_hop;
        uint32_t ifindex;
        uint32_t vrf_id;
    };
    uint8_t set_dscp;
};

int pbr_init(void);
int pbr_create_policy(const char *name);
int pbr_add_rule(const char *policy_name, uint32_t seq,
                 const struct pbr_match *match,
                 const struct pbr_action *action);
struct pbr_action *pbr_lookup(const char *policy_name,
                              uint8_t protocol, uint32_t src_ip, uint16_t src_port,
                              uint32_t dst_ip, uint16_t dst_port, uint32_t in_ifindex);
void pbr_print(const char *policy_name);
void pbr_cleanup(void);

#endif /* PBR_H */
