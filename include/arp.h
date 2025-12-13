/**
 * @file arp.h
 * @brief ARP (Address Resolution Protocol) implementation
 * @details RFC 826 - Address Resolution Protocol
 */

#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>

/* ARP constants */
#define ARP_HTYPE_ETHERNET      1
#define ARP_PTYPE_IPV4          0x0800
#define ARP_HLEN_ETHERNET       6
#define ARP_PLEN_IPV4           4

#define ARP_OP_REQUEST          1
#define ARP_OP_REPLY            2

#define ARP_TABLE_SIZE          256         /* Initial hash table size */
#define ARP_MAX_ENTRIES         100000      /* Maximum ARP entries */
#define ARP_VALID_TIMEOUT       300         /* 5 minutes */
#define ARP_STALE_TIMEOUT       60          /* 1 minute */
#define ARP_INCOMPLETE_TIMEOUT  3           /* 3 seconds */
#define ARP_MAX_RETRIES         3           /* Max ARP request retries */

/**
 * @brief ARP packet header (RFC 826)
 */
struct arp_hdr {
    uint16_t ar_hrd;                /* Hardware type (1 = Ethernet) */
    uint16_t ar_pro;                /* Protocol type (0x0800 = IPv4) */
    uint8_t  ar_hln;                /* Hardware address length (6) */
    uint8_t  ar_pln;                /* Protocol address length (4) */
    uint16_t ar_op;                 /* Operation (1=request, 2=reply) */
    uint8_t  ar_sha[6];             /* Sender hardware address */
    uint32_t ar_sip;                /* Sender IP address */
    uint8_t  ar_tha[6];             /* Target hardware address */
    uint32_t ar_tip;                /* Target IP address */
} __attribute__((packed));

/**
 * @brief ARP entry states
 */
enum arp_state {
    ARP_STATE_INCOMPLETE = 0,       /* ARP request sent, awaiting reply */
    ARP_STATE_VALID,                /* Entry is valid and usable */
    ARP_STATE_STALE,                /* Entry is old, needs revalidation */
    ARP_STATE_FAILED                /* ARP resolution failed */
};

/**
 * @brief ARP table entry
 */
struct arp_entry {
    uint32_t ip_address;            /* IPv4 address */
    uint8_t mac_address[6];         /* MAC address */
    enum arp_state state;           /* Entry state */
    time_t created;                 /* Creation time */
    time_t last_seen;               /* Last activity time */
    uint32_t ifindex;               /* Interface index */
    uint8_t retries;                /* Number of ARP request retries */

    struct arp_entry *next;         /* Next entry in hash chain */
};

/**
 * @brief ARP table statistics
 */
struct arp_stats {
    uint64_t requests_sent;         /* ARP requests sent */
    uint64_t requests_received;     /* ARP requests received */
    uint64_t replies_sent;          /* ARP replies sent */
    uint64_t replies_received;      /* ARP replies received */
    uint64_t gratuitous_received;   /* Gratuitous ARP received */
    uint64_t lookups;               /* Table lookups */
    uint64_t hits;                  /* Successful lookups */
    uint64_t misses;                /* Failed lookups */
    uint64_t timeouts;              /* Entries timed out */
    uint64_t entries_created;       /* Entries created */
    uint64_t entries_deleted;       /* Entries deleted */
    uint32_t current_entries;       /* Current entry count */
};

/**
 * @brief Initialize ARP subsystem
 * @return 0 on success, -1 on error
 */
int arp_init(void);

/**
 * @brief Cleanup ARP subsystem
 */
void arp_cleanup(void);

/**
 * @brief Process incoming ARP packet
 * @param pkt Pointer to packet buffer
 * @param ifindex Interface index
 * @return 0 on success, -1 on error
 */
int arp_process_packet(const uint8_t *pkt, uint16_t len, uint32_t ifindex);

/**
 * @brief Send ARP request
 * @param target_ip Target IP address
 * @param source_ip Source IP address
 * @param source_mac Source MAC address
 * @param ifindex Interface index
 * @return 0 on success, -1 on error
 */
int arp_send_request(uint32_t target_ip, uint32_t source_ip,
                     const uint8_t *source_mac, uint32_t ifindex);

/* Forward declaration */
struct interface;

/**
 * @brief Send ARP reply on interface
 * @param target_ip Target IP address
 * @param target_mac Target MAC address
 * @param source_ip Source IP address
 * @param iface Interface to send on
 * @return 0 on success, -1 on error
 */
int arp_send_reply_on_interface(uint32_t target_ip, const uint8_t *target_mac,
                                uint32_t source_ip, struct interface *iface);

/**
 * @brief Send ARP reply
 * @param target_ip Target IP address
 * @param target_mac Target MAC address
 * @param source_ip Source IP address
 * @param source_mac Source MAC address
 * @param ifindex Interface index
 * @return 0 on success, -1 on error
 */
int arp_send_reply(uint32_t target_ip, const uint8_t *target_mac,
                   uint32_t source_ip, const uint8_t *source_mac,
                   uint32_t ifindex);

/**
 * @brief Send gratuitous ARP
 * @param ip_address IP address to announce
 * @param mac_address MAC address
 * @param ifindex Interface index
 * @return 0 on success, -1 on error
 */
int arp_send_gratuitous(uint32_t ip_address, const uint8_t *mac_address,
                        uint32_t ifindex);

/**
 * @brief Lookup MAC address for IP address
 * @param ip_address IP address to lookup
 * @param mac_address Output buffer for MAC address (6 bytes)
 * @return 0 if found, -1 if not found
 */
int arp_lookup(uint32_t ip_address, uint8_t *mac_address);

/**
 * @brief LOCKLESS ARP lookup for fast path (VPP-style)
 * @param ip_address IP address to lookup
 * @param mac_address Output buffer for MAC address (6 bytes)
 * @return 0 if found, -1 if not found
 */
int arp_lookup_lockless(uint32_t ip_address, uint8_t *mac_address);

/**
 * @brief Add or update ARP entry
 * @param ip_address IP address
 * @param mac_address MAC address
 * @param ifindex Interface index
 * @param state Entry state
 * @return 0 on success, -1 on error
 */
int arp_add_entry(uint32_t ip_address, const uint8_t *mac_address,
                  uint32_t ifindex, enum arp_state state);

/**
 * @brief Delete ARP entry
 * @param ip_address IP address
 * @return 0 on success, -1 if not found
 */
int arp_delete_entry(uint32_t ip_address);

/**
 * @brief Age out stale ARP entries
 * @return Number of entries deleted
 */
uint32_t arp_timeout_check(void);

/**
 * @brief Get ARP statistics
 * @param stats Output buffer for statistics
 * @return 0 on success, -1 on error
 */
int arp_get_stats(struct arp_stats *stats);

/**
 * @brief Print ARP table (for debugging)
 */
void arp_print_table(void);

/**
 * @brief Convert ARP state to string
 * @param state ARP state
 * @return String representation
 */
const char *arp_state_to_str(enum arp_state state);

#endif /* ARP_H */
