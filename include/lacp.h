/**
 * @file lacp.h
 * @brief Link Aggregation Control Protocol (802.3ad) Support
 */

#ifndef LACP_H
#define LACP_H

#include <stdint.h>
#include <stdbool.h>
#include "packet.h"
#include "interface.h"

/* LACP EtherType (Slow Protocols) */
#define ETHERTYPE_SLOW_PROTOCOLS  0x8809

/* LACP Multicast MAC address */
#define LACP_MULTICAST_MAC { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x02 }

/* LACP Protocol Subtype */
#define LACP_SUBTYPE  0x01

/* LACP Version */
#define LACP_VERSION  0x01

/* LACP Timers (in milliseconds) */
#define LACP_FAST_PERIODIC_TIME    1000   /* 1 second */
#define LACP_SLOW_PERIODIC_TIME   30000   /* 30 seconds */
#define LACP_SHORT_TIMEOUT_TIME    3000   /* 3 seconds */
#define LACP_LONG_TIMEOUT_TIME    90000   /* 90 seconds */

/* LACP State flags */
#define LACP_STATE_ACTIVITY       (1 << 0)  /* LACP activity */
#define LACP_STATE_TIMEOUT        (1 << 1)  /* LACP timeout (0=long, 1=short) */
#define LACP_STATE_AGGREGATION    (1 << 2)  /* Aggregation capable */
#define LACP_STATE_SYNCHRONIZATION (1 << 3) /* In sync */
#define LACP_STATE_COLLECTING     (1 << 4)  /* Collecting (receiving) */
#define LACP_STATE_DISTRIBUTING   (1 << 5)  /* Distributing (transmitting) */
#define LACP_STATE_DEFAULTED      (1 << 6)  /* Using default partner info */
#define LACP_STATE_EXPIRED        (1 << 7)  /* Partner info expired */

/**
 * @brief Bonding modes
 */
enum bond_mode {
    BOND_MODE_ACTIVE_BACKUP = 0,  /* Active-backup (failover only) */
    BOND_MODE_BALANCE_RR,         /* Balance round-robin */
    BOND_MODE_BALANCE_XOR,        /* Balance XOR (hash-based) */
    BOND_MODE_802_3AD,            /* IEEE 802.3ad LACP */
    BOND_MODE_BALANCE_TLB,        /* Adaptive transmit load balancing */
    BOND_MODE_BALANCE_ALB         /* Adaptive load balancing */
};

/**
 * @brief Load balancing hash types
 */
enum bond_xmit_hash_policy {
    BOND_XMIT_POLICY_LAYER2 = 0,      /* Source/Dest MAC */
    BOND_XMIT_POLICY_LAYER34,         /* Source/Dest IP + Port */
    BOND_XMIT_POLICY_LAYER23,         /* MAC + IP */
    BOND_XMIT_POLICY_ENCAP23,         /* Encapsulated L2/L3 */
    BOND_XMIT_POLICY_ENCAP34          /* Encapsulated L3/L4 */
};

/**
 * @brief LACP TLV structure (Type-Length-Value)
 */
struct lacp_tlv {
    uint8_t type;
    uint8_t length;
    uint8_t data[0];
} __attribute__((packed));

/**
 * @brief LACP Actor/Partner information
 */
struct lacp_actor_partner_info {
    uint8_t  tlv_type;
    uint8_t  tlv_length;
    uint16_t system_priority;
    uint8_t  system[6];           /* MAC address */
    uint16_t key;
    uint16_t port_priority;
    uint16_t port;
    uint8_t  state;
    uint8_t  reserved[3];
} __attribute__((packed));

/**
 * @brief LACP Collector information
 */
struct lacp_collector_info {
    uint8_t  tlv_type;
    uint8_t  tlv_length;
    uint16_t max_delay;
    uint8_t  reserved[12];
} __attribute__((packed));

/**
 * @brief LACP PDU (Protocol Data Unit)
 */
struct lacp_pdu {
    uint8_t subtype;              /* LACP subtype (0x01) */
    uint8_t version;              /* Version number (0x01) */

    /* Actor information */
    struct lacp_actor_partner_info actor;

    /* Partner information */
    struct lacp_actor_partner_info partner;

    /* Collector information */
    struct lacp_collector_info collector;

    /* Terminator */
    uint8_t terminator_type;
    uint8_t terminator_length;
    uint8_t reserved[50];
} __attribute__((packed));

/**
 * @brief LACP state machine states
 */
enum lacp_sm_state {
    LACP_SM_DETACHED = 0,
    LACP_SM_ATTACHED,
    LACP_SM_COLLECTING,
    LACP_SM_DISTRIBUTING,
    LACP_SM_DISABLED
};

/**
 * @brief LACP port structure
 */
struct lacp_port {
    struct interface *iface;
    uint16_t port_priority;
    uint16_t port_number;
    uint8_t  state;
    enum lacp_sm_state sm_state;

    /* Actor information */
    struct lacp_actor_partner_info actor_info;

    /* Partner information */
    struct lacp_actor_partner_info partner_info;

    /* Timers */
    uint64_t current_while_timer;
    uint64_t periodic_timer;

    /* Statistics */
    uint64_t lacpdu_tx;
    uint64_t lacpdu_rx;
    uint64_t lacpdu_errors;
};

/**
 * @brief LAG/Bond interface structure
 */
struct bond_interface {
    struct interface *iface;
    enum bond_mode mode;
    enum bond_xmit_hash_policy xmit_hash_policy;

    /* LACP parameters */
    uint16_t system_priority;
    uint8_t  system_mac[6];
    uint16_t key;
    bool     lacp_active;
    bool     lacp_fast;

    /* Member ports */
    struct lacp_port *ports[IF_MAX_VLAN_MEMBERS];
    uint32_t num_ports;
    uint32_t active_member;  /* For active-backup mode */

    /* Statistics */
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t rx_bytes;
};

/**
 * @brief Initialize LACP subsystem
 * @return 0 on success, -1 on failure
 */
int lacp_init(void);

/**
 * @brief Create a bonded interface
 * @param name Interface name (e.g., "Port-channel1")
 * @param mode Bonding mode
 * @return Pointer to bond interface or NULL on failure
 */
struct bond_interface *bond_create(const char *name, enum bond_mode mode);

/**
 * @brief Add a member port to a bond
 * @param bond Bond interface
 * @param iface Member interface
 * @return 0 on success, -1 on failure
 */
int bond_add_member(struct bond_interface *bond, struct interface *iface);

/**
 * @brief Remove a member port from a bond
 * @param bond Bond interface
 * @param iface Member interface
 * @return 0 on success, -1 on failure
 */
int bond_remove_member(struct bond_interface *bond, struct interface *iface);

/**
 * @brief Select a member for transmitting a packet
 * @param bond Bond interface
 * @param pkt Packet buffer
 * @return Pointer to selected member interface or NULL
 */
struct interface *bond_select_tx_member(struct bond_interface *bond, struct pkt_buf *pkt);

/**
 * @brief Process received LACP PDU
 * @param iface Receiving interface
 * @param pkt Packet buffer containing LACP PDU
 * @return 0 on success, -1 on failure
 */
int lacp_rx_pdu(struct interface *iface, struct pkt_buf *pkt);

/**
 * @brief Transmit LACP PDU
 * @param port LACP port
 * @return 0 on success, -1 on failure
 */
int lacp_tx_pdu(struct lacp_port *port);

/**
 * @brief LACP periodic timer tick (called every 1 second)
 */
void lacp_periodic_tick(void);

/**
 * @brief Hash packet for load balancing
 * @param pkt Packet buffer
 * @param policy Hash policy
 * @return Hash value
 */
uint32_t bond_hash_packet(struct pkt_buf *pkt, enum bond_xmit_hash_policy policy);

/**
 * @brief Cleanup LACP subsystem
 */
void lacp_cleanup(void);

#endif /* LACP_H */
