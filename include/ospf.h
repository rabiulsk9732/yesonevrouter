/**
 * @file ospf.h
 * @brief OSPF Version 2 Header (RFC 2328)
 */

#ifndef OSPF_H
#define OSPF_H

#include <stdint.h>
#include <stdbool.h>

/* OSPF Neighbor States (RFC 2328) */
enum ospf_neighbor_state {
    OSPF_NBR_DOWN = 0,
    OSPF_NBR_ATTEMPT,
    OSPF_NBR_INIT,
    OSPF_NBR_2WAY,
    OSPF_NBR_EXSTART,
    OSPF_NBR_EXCHANGE,
    OSPF_NBR_LOADING,
    OSPF_NBR_FULL
};

/* OSPF Interface States (RFC 2328) */
enum ospf_iface_state {
    OSPF_IFACE_DOWN = 0,
    OSPF_IFACE_LOOPBACK,
    OSPF_IFACE_WAITING,
    OSPF_IFACE_POINT_TO_POINT,
    OSPF_IFACE_DR_OTHER,
    OSPF_IFACE_BACKUP,
    OSPF_IFACE_DR
};

/* Initialize OSPF */
int ospf_init(uint32_t router_id);

/* Router configuration */
int ospf_router_id(uint32_t router_id);

/* Area configuration */
int ospf_area(uint32_t area_id);
int ospf_area_stub(uint32_t area_id, bool no_summary);
int ospf_area_nssa(uint32_t area_id, bool no_summary);

/* Network configuration */
int ospf_network(uint32_t network, uint32_t wildcard, uint32_t area_id);

/* Interface configuration */
int ospf_interface(uint32_t ifindex, uint32_t ip_addr, uint32_t ip_mask, uint32_t area_id);
int ospf_interface_cost(uint32_t ifindex, uint32_t cost);
int ospf_interface_priority(uint32_t ifindex, uint8_t priority);
int ospf_interface_passive(uint32_t ifindex, bool passive);

/* Show commands (Cisco-style) */
void ospf_show(void);
void ospf_show_interface(void);
void ospf_show_neighbor(void);
void ospf_show_database(void);

/* Cleanup */
void ospf_cleanup(void);

#endif /* OSPF_H */
