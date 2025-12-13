/**
 * @file bgp.h
 * @brief BGP-4 Header (RFC 4271)
 */

#ifndef BGP_H
#define BGP_H

#include <stdint.h>
#include <stdbool.h>

/* BGP States (RFC 4271) */
enum bgp_state {
    BGP_STATE_IDLE = 1,
    BGP_STATE_CONNECT,
    BGP_STATE_ACTIVE,
    BGP_STATE_OPEN_SENT,
    BGP_STATE_OPEN_CONFIRM,
    BGP_STATE_ESTABLISHED
};

/* BGP Origin (RFC 4271) */
#define BGP_ORIGIN_IGP          0
#define BGP_ORIGIN_EGP          1
#define BGP_ORIGIN_INCOMPLETE   2

/* Well-known Communities (RFC 1997) */
#define BGP_COMMUNITY_NO_EXPORT         0xFFFFFF01
#define BGP_COMMUNITY_NO_ADVERTISE      0xFFFFFF02

/* Initialize BGP */
int bgp_init(uint32_t router_id, uint32_t local_as);

/* Neighbor management */
int bgp_neighbor(uint32_t remote_ip, uint32_t remote_as);
int bgp_neighbor_description(uint32_t remote_ip, const char *desc);
int bgp_neighbor_next_hop_self(uint32_t remote_ip, bool enable);
int bgp_neighbor_route_reflector_client(uint32_t remote_ip, bool enable);

/* Network advertisement */
int bgp_network(uint32_t prefix, uint8_t prefix_len);

/* Show commands (Cisco-style) */
void bgp_show_summary(void);
void bgp_show_neighbors(void);
void bgp_show_routes(void);

/* Cleanup */
void bgp_cleanup(void);

#endif /* BGP_H */
