/**
 * @file interface.h
 * @brief Interface Abstraction Layer
 *
 * Provides hardware-independent interface abstraction for physical and virtual interfaces.
 */

#ifndef INTERFACE_H
#define INTERFACE_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <net/if.h>
#include "packet.h"

#define IF_NAME_MAX         32  /* Extended for Cisco-style names like GigabitEthernet0/0 */
#define IF_MAX_INTERFACES   256
#define IF_MAX_VLAN_MEMBERS 16

#include "interface_types.h"

/* Interface states */
enum interface_state {
    IF_STATE_DOWN = 0,
    IF_STATE_UP,
    IF_STATE_ADMIN_DOWN,
    IF_STATE_ERROR
};

/* Link states */
enum link_state {
    LINK_STATE_UNKNOWN = 0,
    LINK_STATE_DOWN,
    LINK_STATE_UP
};

/* Interface statistics */
struct interface_stats {
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t rx_errors;
    uint64_t rx_dropped;
    uint64_t rx_multicast;
    uint64_t rx_broadcast;

    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_errors;
    uint64_t tx_dropped;
    uint64_t tx_multicast;
    uint64_t tx_broadcast;

    uint64_t collisions;
    uint64_t carrier_errors;

    /* Timestamps */
    uint64_t last_rx_time;
    uint64_t last_tx_time;
    uint64_t last_link_change;
};

/* Interface configuration */
struct interface_config_data {
    uint32_t mtu;
    uint32_t speed;                 /* Mbps, 0 = auto */
    bool promiscuous;
    bool multicast;
    bool auto_negotiate;
    uint8_t duplex;                 /* 0 = half, 1 = full */

    /* IP configuration */
    struct in_addr ipv4_addr;
    struct in_addr ipv4_mask;
    struct in_addr ipv4_gateway;

    /* VLAN configuration (for VLAN interfaces) */
    uint16_t vlan_id;
    uint32_t parent_ifindex;

    /* LAG configuration (for LAG interfaces) */
    uint32_t num_members;
    uint32_t member_ifindexes[IF_MAX_VLAN_MEMBERS];
    uint8_t lag_mode;               /* 0 = active-backup, 1 = balance-rr, etc. */

    /* NAT interface role (dynamic - not hardcoded to port numbers) */
    bool nat_inside;                /* true = LAN side, source of SNAT traffic */
    bool nat_outside;               /* true = WAN side, destination of SNAT traffic */
};

/* Forward declaration */
struct interface;

/* Interface operations structure */
struct interface_ops {
    /**
     * Initialize interface
     * @param iface Interface structure
     * @return 0 on success, -1 on failure
     */
    int (*init)(struct interface *iface);

    /**
     * Bring interface up
     * @param iface Interface structure
     * @return 0 on success, -1 on failure
     */
    int (*up)(struct interface *iface);

    /**
     * Bring interface down
     * @param iface Interface structure
     * @return 0 on success, -1 on failure
     */
    int (*down)(struct interface *iface);

    /**
     * Send packet on interface
     * @param iface Interface structure
     * @param pkt Packet buffer
     * @return 0 on success, -1 on failure
     */
    int (*send)(struct interface *iface, struct pkt_buf *pkt);

    /**
     * Receive packet from interface
     * @param iface Interface structure
     * @param pkt Packet buffer (output)
     * @return 0 on success, -1 on failure, >0 for number of packets
     */
    int (*recv)(struct interface *iface, struct pkt_buf **pkt);

    /**
     * Get link state
     * @param iface Interface structure
     * @return Link state
     */
    enum link_state (*get_link_state)(struct interface *iface);

    /**
     * Get interface statistics
     * @param iface Interface structure
     * @param stats Statistics structure (output)
     * @return 0 on success, -1 on failure
     */
    int (*get_stats)(struct interface *iface, struct interface_stats *stats);

    /**
     * Configure interface
     * @param iface Interface structure
     * @param config Configuration data
     * @return 0 on success, -1 on failure
     */
    int (*configure)(struct interface *iface, const struct interface_config_data *config);

    /**
     * Cleanup interface
     * @param iface Interface structure
     */
    void (*cleanup)(struct interface *iface);
};

/* Main interface structure */
struct interface {
    /* Basic information */
    uint32_t ifindex;               /* Interface index */
    char name[IF_NAME_MAX];         /* Interface name (e.g., "eth0", "vlan100") */
    enum interface_type type;       /* Interface type */
    enum interface_state state;     /* Current state */
    enum link_state link;           /* Link state */

    /* MAC address */
    uint8_t mac_addr[6];

    /* Configuration */
    struct interface_config_data config;

    /* Statistics */
    struct interface_stats stats;

    /* Operations */
    const struct interface_ops *ops;

    /* Private data (type-specific) */
    void *priv_data;

    /* Flags */
    uint32_t flags;

    /* Timestamps */
    uint64_t created_time;
    uint64_t last_state_change;

    /* Reference counting */
    uint32_t refcnt;
};

/* Interface manager */
struct interface_manager {
    struct interface *interfaces[IF_MAX_INTERFACES];
    uint32_t num_interfaces;
    uint32_t next_ifindex;
    bool initialized;
};

/* Global interface manager */
extern struct interface_manager g_if_mgr;

/**
 * Initialize interface subsystem
 * @return 0 on success, -1 on failure
 */
int interface_init(void);

/**
 * Create a new interface
 * @param name Interface name
 * @param type Interface type
 * @return Pointer to interface or NULL on failure
 */
struct interface *interface_create(const char *name, enum interface_type type);

/**
 * Create a new interface with flags (VPP-style for DPDK)
 * @param name Interface name
 * @param type Interface type
 * @param flags Interface flags (high bit = DPDK, lower bits = port_id)
 * @return Pointer to interface or NULL on failure
 */
struct interface *interface_create_with_flags(const char *name, enum interface_type type, uint32_t flags);

/**
 * Create a VLAN sub-interface
 * @param parent_name Parent interface name (e.g., "eth0")
 * @param vlan_id VLAN ID (1-4094)
 * @return Pointer to interface (named "parent.vlan_id") or NULL on failure
 */
struct interface *interface_create_vlan(const char *parent_name, uint16_t vlan_id);

/**
 * Find interface by name
 * @param name Interface name
 * @return Pointer to interface or NULL if not found
 */
struct interface *interface_find_by_name(const char *name);

/**
 * Find interface by index
 * @param ifindex Interface index
 * @return Pointer to interface or NULL if not found
 */
struct interface *interface_find_by_index(uint32_t ifindex);

/**
 * Find interface by DPDK port ID
 * @param port_id DPDK port ID
 * @return Pointer to interface or NULL if not found
 */
struct interface *interface_find_by_dpdk_port(uint16_t port_id);

/**
 * Register interface for O(1) fast lookup (call at interface init)
 * @param iface Interface structure
 * @param port_id DPDK port ID
 */
void interface_register_fast_lookup(struct interface *iface, uint16_t port_id);

/**
 * Find interface by IP address within its configured subnet
 * @param addr IP address to search for
 * @return Pointer to interface or NULL if not found
 */
struct interface *interface_find_by_subnet(const struct in_addr *addr);

/**
 * Bring interface up
 * @param iface Interface structure
 * @return 0 on success, -1 on failure
 */
int interface_up(struct interface *iface);

/**
 * Bring interface down
 * @param iface Interface structure
 * @return 0 on success, -1 on failure
 */
int interface_down(struct interface *iface);

/**
 * Send packet on interface
 * @param iface Interface structure
 * @param pkt Packet buffer
 * @return 0 on success, -1 on failure
 */
int interface_send(struct interface *iface, struct pkt_buf *pkt);

/**
 * Receive packet from interface
 * @param iface Interface structure
 * @param pkt Packet buffer (output)
 * @return 0 on success, -1 on failure, >0 for number of packets
 */
int interface_recv(struct interface *iface, struct pkt_buf **pkt);

/**
 * Get link state
 * @param iface Interface structure
 * @return Link state
 */
enum link_state interface_get_link_state(struct interface *iface);

/**
 * Get interface statistics
 * @param iface Interface structure
 * @param stats Statistics structure (output)
 * @return 0 on success, -1 on failure
 */
int interface_get_stats(struct interface *iface, struct interface_stats *stats);

/**
 * Configure interface
 * @param iface Interface structure
 * @param config Configuration data
 * @return 0 on success, -1 on failure
 */
int interface_configure(struct interface *iface, const struct interface_config_data *config);

/**
 * Delete interface
 * @param iface Interface structure
 * @return 0 on success, -1 on failure
 */
int interface_delete(struct interface *iface);

/**
 * Print interface information
 * @param iface Interface structure
 */
void interface_print(const struct interface *iface);

/**
 * Print all interfaces
 */
void interface_print_all(void);

/**
 * Get interface count
 * @return Number of interfaces
 */
uint32_t interface_count(void);

/**
 * @brief Discover system interfaces (Linux only)
 * @return Number of interfaces discovered, or -1 on error
 */
int interface_discover_system(void);

/**
 * @brief Discover DPDK ports
 * @return Number of DPDK ports discovered, or -1 on error
 */
int interface_discover_dpdk_ports(void);

/**
 * Cleanup interface subsystem
 */
void interface_cleanup(void);

/* Helper functions */
const char *interface_type_to_str(enum interface_type type);
const char *interface_state_to_str(enum interface_state state);
const char *link_state_to_str(enum link_state state);

#endif /* INTERFACE_H */
