/**
 * @file interface.c
 * @brief Interface Abstraction Layer Implementation
 */

#define _GNU_SOURCE
#include "interface.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <errno.h>

/* Global interface manager */
struct interface_manager g_if_mgr = {
    .interfaces = {0},
    .num_interfaces = 0,
    .next_ifindex = 1,
    .initialized = false
};

/* O(1) LOCKLESS lookup tables (VPP-style) */
#define MAX_DPDK_PORTS 16
static struct interface *g_port_to_iface[MAX_DPDK_PORTS];
static struct interface *g_ifindex_to_iface[IF_MAX_INTERFACES];

/* Forward declarations for driver implementations */
extern const struct interface_ops physical_interface_ops;
extern const struct interface_ops vlan_interface_ops;
extern const struct interface_ops lag_interface_ops;
extern const struct interface_ops loopback_interface_ops;
extern const struct interface_ops dummy_interface_ops;

static const struct interface_ops *get_ops_for_type(enum interface_type type)
{
    switch (type) {
    case IF_TYPE_PHYSICAL:
        return &physical_interface_ops;
    case IF_TYPE_VLAN:
        return &vlan_interface_ops;
    case IF_TYPE_LAG:
        return &lag_interface_ops;
    case IF_TYPE_LOOPBACK:
        return &loopback_interface_ops;
    case IF_TYPE_DUMMY:
        return &dummy_interface_ops;
    default:
        return NULL;
    }
}

int interface_init(void)
{
    if (g_if_mgr.initialized) {
        return 0;
    }

    memset(&g_if_mgr, 0, sizeof(g_if_mgr));
    g_if_mgr.next_ifindex = 1;
    g_if_mgr.initialized = true;

    printf("Interface subsystem initialized\n");
    return 0;
}

struct interface *interface_create_with_flags(const char *name, enum interface_type type, uint32_t flags)
{
    struct interface *iface;
    const struct interface_ops *ops;
    uint32_t i;

    if (!g_if_mgr.initialized) {
        fprintf(stderr, "Interface subsystem not initialized\n");
        return NULL;
    }

    if (!name || strlen(name) == 0 || strlen(name) >= IF_NAME_MAX) {
        fprintf(stderr, "Invalid interface name\n");
        return NULL;
    }

    /* Check if interface already exists */
    if (interface_find_by_name(name)) {
        fprintf(stderr, "Interface %s already exists\n", name);
        return NULL;
    }

    /* Check if we have space */
    if (g_if_mgr.num_interfaces >= IF_MAX_INTERFACES) {
        fprintf(stderr, "Maximum number of interfaces reached\n");
        return NULL;
    }

    /* Get operations for this interface type */
    ops = get_ops_for_type(type);
    if (!ops) {
        fprintf(stderr, "Unsupported interface type: %d\n", type);
        return NULL;
    }

    /* Allocate interface structure */
    iface = calloc(1, sizeof(*iface));
    if (!iface) {
        fprintf(stderr, "Failed to allocate interface structure\n");
        return NULL;
    }

    /* Initialize basic fields */
    iface->ifindex = g_if_mgr.next_ifindex++;
    strncpy(iface->name, name, IF_NAME_MAX - 1);
    iface->type = type;
    iface->state = IF_STATE_DOWN;
    iface->link = LINK_STATE_UNKNOWN;
    iface->ops = ops;
    iface->refcnt = 1;
    iface->created_time = (uint64_t)time(NULL);
    iface->last_state_change = iface->created_time;
    iface->flags = flags;  /* Set flags BEFORE init - VPP style */

    /* Set default configuration */
    iface->config.mtu = 1500;
    iface->config.speed = 0;  /* Auto */
    iface->config.promiscuous = false;
    iface->config.multicast = true;
    iface->config.auto_negotiate = true;
    iface->config.duplex = 1;  /* Full duplex */

    /* Initialize interface using driver */
    if (ops->init && ops->init(iface) < 0) {
        fprintf(stderr, "Failed to initialize interface %s\n", name);
        free(iface);
        return NULL;
    }

    /* Add to manager */
    for (i = 0; i < IF_MAX_INTERFACES; i++) {
        if (g_if_mgr.interfaces[i] == NULL) {
            g_if_mgr.interfaces[i] = iface;
            g_if_mgr.num_interfaces++;
            break;
        }
    }

    printf("Created interface %s (index %u, type %s)\n",
           name, iface->ifindex, interface_type_to_str(type));

    return iface;
}

/* Wrapper for backward compatibility */
struct interface *interface_create(const char *name, enum interface_type type)
{
    return interface_create_with_flags(name, type, 0);
}

/* Create a VLAN sub-interface */
struct interface *interface_create_vlan(const char *parent_name, uint16_t vlan_id)
{
    if (!parent_name || vlan_id == 0 || vlan_id > 4094) {
        printf("Error: Invalid parent name or VLAN ID (1-4094)\n");
        return NULL;
    }

    /* Find parent interface */
    struct interface *parent = interface_find_by_name(parent_name);
    if (!parent) {
        printf("Error: Parent interface '%s' not found\n", parent_name);
        return NULL;
    }

    /* Build VLAN interface name: parent.vlan_id */
    char vlan_name[IF_NAME_MAX];
    snprintf(vlan_name, sizeof(vlan_name), "%s.%u", parent_name, vlan_id);

    /* Check if already exists */
    if (interface_find_by_name(vlan_name)) {
        printf("Error: Interface '%s' already exists\n", vlan_name);
        return NULL;
    }

    /* Create VLAN interface */
    struct interface *vlan_iface = interface_create_with_flags(vlan_name, IF_TYPE_VLAN, 0);
    if (!vlan_iface) {
        printf("Error: Failed to create VLAN interface '%s'\n", vlan_name);
        return NULL;
    }

    /* Configure VLAN settings */
    vlan_iface->config.vlan_id = vlan_id;
    vlan_iface->config.parent_ifindex = parent->ifindex;

    /* Copy MAC from parent */
    memcpy(vlan_iface->mac_addr, parent->mac_addr, 6);

    /* Copy MTU from parent */
    vlan_iface->config.mtu = parent->config.mtu;

    printf("Created VLAN interface %s (parent: %s, vlan: %u)\n",
           vlan_name, parent_name, vlan_id);
    return vlan_iface;
}

struct interface *interface_find_by_name(const char *name)
{
    uint32_t i;

    if (!name) {
        return NULL;
    }

    for (i = 0; i < IF_MAX_INTERFACES; i++) {
        if (g_if_mgr.interfaces[i] &&
            strcmp(g_if_mgr.interfaces[i]->name, name) == 0) {
            return g_if_mgr.interfaces[i];
        }
    }

    return NULL;
}

struct interface *interface_find_by_index(uint32_t ifindex)
{
    uint32_t i;

    for (i = 0; i < IF_MAX_INTERFACES; i++) {
        if (g_if_mgr.interfaces[i] &&
            g_if_mgr.interfaces[i]->ifindex == ifindex) {
            return g_if_mgr.interfaces[i];
        }
    }

    return NULL;
}

struct interface *interface_find_by_dpdk_port(uint16_t port_id)
{
    /* O(1) LOCKLESS lookup - VPP style */
    if (likely(port_id < MAX_DPDK_PORTS)) {
        return g_port_to_iface[port_id];
    }
    return NULL;
}

/* Register interface for O(1) fast lookup */
void interface_register_fast_lookup(struct interface *iface, uint16_t port_id)
{
    if (port_id < MAX_DPDK_PORTS) {
        __atomic_store_n(&g_port_to_iface[port_id], iface, __ATOMIC_RELEASE);
    }
    if (iface && iface->ifindex < IF_MAX_INTERFACES) {
        __atomic_store_n(&g_ifindex_to_iface[iface->ifindex], iface, __ATOMIC_RELEASE);
    }
}

struct interface *interface_find_by_subnet(const struct in_addr *addr)
{
    uint32_t i;
    uint32_t ip = ntohl(addr->s_addr);

    for (i = 0; i < IF_MAX_INTERFACES; i++) {
        struct interface *iface = g_if_mgr.interfaces[i];
        if (iface && iface->config.ipv4_addr.s_addr != 0) {
            uint32_t if_ip = ntohl(iface->config.ipv4_addr.s_addr);
            uint32_t if_mask = ntohl(iface->config.ipv4_mask.s_addr);

            if ((ip & if_mask) == (if_ip & if_mask)) {
                return iface;
            }
        }
    }

    return NULL;
}

int interface_up(struct interface *iface)
{
    if (!iface) {
        return -1;
    }

    if (iface->state == IF_STATE_UP) {
        return 0;  /* Already up */
    }

    if (iface->ops->up && iface->ops->up(iface) < 0) {
        fprintf(stderr, "Failed to bring interface %s up\n", iface->name);
        return -1;
    }

    iface->state = IF_STATE_UP;
    iface->last_state_change = (uint64_t)time(NULL);

    printf("Interface %s is now UP\n", iface->name);
    return 0;
}

int interface_down(struct interface *iface)
{
    if (!iface) {
        return -1;
    }

    if (iface->state == IF_STATE_DOWN) {
        return 0;  /* Already down */
    }

    if (iface->ops->down && iface->ops->down(iface) < 0) {
        fprintf(stderr, "Failed to bring interface %s down\n", iface->name);
        return -1;
    }

    iface->state = IF_STATE_DOWN;
    iface->last_state_change = (uint64_t)time(NULL);

    printf("Interface %s is now DOWN\n", iface->name);
    return 0;
}

int interface_send(struct interface *iface, struct pkt_buf *pkt)
{
    if (!iface || !pkt) {
        return -1;
    }

    if (iface->state != IF_STATE_UP) {
        return -1;
    }

    if (!iface->ops->send) {
        return -1;
    }

    int ret = iface->ops->send(iface, pkt);

    /* Statistics are updated by the driver (physical.c) to avoid duplicate time() syscalls */
    if (ret != 0) {
        __atomic_add_fetch(&iface->stats.tx_errors, 1, __ATOMIC_RELAXED);
    }

    return ret;
}

int interface_recv(struct interface *iface, struct pkt_buf **pkt)
{
    if (!iface || !pkt) {
        return -1;
    }

    if (iface->state != IF_STATE_UP) {
        return -1;
    }

    if (!iface->ops->recv) {
        return -1;
    }

    int ret = iface->ops->recv(iface, pkt);

    /* Statistics are updated by the driver (physical.c) to avoid duplicate time() syscalls */
    if (ret < 0) {
        __atomic_add_fetch(&iface->stats.rx_errors, 1, __ATOMIC_RELAXED);
    }

    return ret;
}

enum link_state interface_get_link_state(struct interface *iface)
{
    if (!iface || !iface->ops->get_link_state) {
        return LINK_STATE_UNKNOWN;
    }

    enum link_state link = iface->ops->get_link_state(iface);

    /* Update cached link state */
    if (link != iface->link) {
        iface->link = link;
        iface->stats.last_link_change = (uint64_t)time(NULL);
    }

    return link;
}

int interface_get_stats(struct interface *iface, struct interface_stats *stats)
{
    if (!iface || !stats) {
        return -1;
    }

    /* Update link state */
    interface_get_link_state(iface);

    /* Get driver-specific statistics if available */
    if (iface->ops->get_stats) {
        iface->ops->get_stats(iface, &iface->stats);
    }

    /* Copy statistics */
    memcpy(stats, &iface->stats, sizeof(*stats));

    return 0;
}

int interface_configure(struct interface *iface, const struct interface_config_data *config)
{
    if (!iface || !config) {
        return -1;
    }

    if (iface->ops->configure) {
        int ret = iface->ops->configure(iface, config);
        if (ret == 0) {
            /* Update cached configuration */
            memcpy(&iface->config, config, sizeof(*config));
        }
        return ret;
    }

    /* Fallback: just update cached configuration */
    memcpy(&iface->config, config, sizeof(*config));
    return 0;
}

int interface_delete(struct interface *iface)
{
    uint32_t i;

    if (!iface) {
        return -1;
    }

    /* Bring interface down first */
    if (iface->state == IF_STATE_UP) {
        interface_down(iface);
    }

    /* Cleanup driver-specific data */
    if (iface->ops->cleanup) {
        iface->ops->cleanup(iface);
    }

    /* Free private data */
    if (iface->priv_data) {
        free(iface->priv_data);
    }

    /* Remove from manager */
    for (i = 0; i < IF_MAX_INTERFACES; i++) {
        if (g_if_mgr.interfaces[i] == iface) {
            g_if_mgr.interfaces[i] = NULL;
            g_if_mgr.num_interfaces--;
            break;
        }
    }

    printf("Deleted interface %s\n", iface->name);
    free(iface);

    return 0;
}

void interface_print(const struct interface *iface)
{
    if (!iface) {
        return;
    }

    printf("\nInterface: %s\n", iface->name);
    printf("  Index: %u\n", iface->ifindex);
    printf("  Type: %s\n", interface_type_to_str(iface->type));
    printf("  State: %s\n", interface_state_to_str(iface->state));
    printf("  Link: %s\n", link_state_to_str(iface->link));
    printf("  MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           iface->mac_addr[0], iface->mac_addr[1], iface->mac_addr[2],
           iface->mac_addr[3], iface->mac_addr[4], iface->mac_addr[5]);

    /* Show IP address if configured */
    if (iface->config.ipv4_addr.s_addr != 0) {
        char ip_str[INET_ADDRSTRLEN];
        char mask_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iface->config.ipv4_addr, ip_str, sizeof(ip_str));
        inet_ntop(AF_INET, &iface->config.ipv4_mask, mask_str, sizeof(mask_str));
        printf("  IP Address: %s / %s\n", ip_str, mask_str);
    }

    printf("  MTU: %u\n", iface->config.mtu);
    printf("  Speed: %s\n", iface->config.speed > 0 ?
           (char[32]){0} : "Auto");
    if (iface->config.speed > 0) {
        printf("    %u Mbps\n", iface->config.speed);
    }
    printf("  Statistics:\n");
    printf("    RX: %lu packets, %lu bytes, %lu errors, %lu dropped\n",
           iface->stats.rx_packets, iface->stats.rx_bytes,
           iface->stats.rx_errors, iface->stats.rx_dropped);
    printf("    TX: %lu packets, %lu bytes, %lu errors, %lu dropped\n",
           iface->stats.tx_packets, iface->stats.tx_bytes,
           iface->stats.tx_errors, iface->stats.tx_dropped);
}

void interface_print_all(void)
{
    uint32_t i;

    printf("\n========================================\n");
    printf("Interface List (%u interfaces)\n", g_if_mgr.num_interfaces);
    printf("========================================\n");

    for (i = 0; i < IF_MAX_INTERFACES; i++) {
        if (g_if_mgr.interfaces[i]) {
            interface_print(g_if_mgr.interfaces[i]);
        }
    }

    printf("\n");
}

#include <ifaddrs.h>
#include "dpdk_init.h"

#ifdef HAVE_DPDK
#include <rte_ethdev.h>
#endif

int interface_discover_dpdk_ports(void)
{
#ifdef HAVE_DPDK
    uint16_t port_id;
    int count = 0;
    char name[IF_NAME_MAX];

    if (!dpdk_is_enabled()) {
        printf("DPDK not enabled, skipping DPDK port discovery\n");
        return 0;
    }

    printf("Discovering DPDK ports...\n");

    RTE_ETH_FOREACH_DEV(port_id) {
        struct rte_eth_dev_info dev_info;
        struct rte_ether_addr mac_addr;
        struct interface *iface;
        (void)0; /* placeholder */

        /* Get device info */
        if (rte_eth_dev_info_get(port_id, &dev_info) != 0) {
            fprintf(stderr, "Failed to get device info for port %u\n", port_id);
            continue;
        }

        /* Simple Cisco-style naming: Gi0/1, Gi0/2, etc. */
        snprintf(name, sizeof(name), "Gi0/%u", port_id + 1);

        /* Check if already exists */
        if (interface_find_by_name(name)) {
            continue;
        }

        /* Create interface with DPDK flags set BEFORE init (VPP-style) */
        /* High bit (0x80000000) indicates DPDK port, lower bits are port_id */
        uint32_t dpdk_flags = (uint32_t)port_id | 0x80000000;
        iface = interface_create_with_flags(name, IF_TYPE_PHYSICAL, dpdk_flags);
        if (!iface) {
            fprintf(stderr, "Failed to create interface for DPDK port %u\n", port_id);
            continue;
        }

        /* Get and set MAC address (already done in physical_init, but update here too) */
        if (rte_eth_macaddr_get(port_id, &mac_addr) == 0) {
            memcpy(iface->mac_addr, mac_addr.addr_bytes, 6);
        }

        printf("  Interface %s: DPDK port %u (MAC: %02x:%02x:%02x:%02x:%02x:%02x, driver: %s)\n",
               name, port_id,
               iface->mac_addr[0], iface->mac_addr[1], iface->mac_addr[2],
               iface->mac_addr[3], iface->mac_addr[4], iface->mac_addr[5],
               dev_info.driver_name ? dev_info.driver_name : "unknown");

        /* Bring interface UP to configure and start the DPDK port */
        if (interface_up(iface) != 0) {
            fprintf(stderr, "  Warning: Failed to bring up interface %s\n", name);
        }

        count++;
    }

    printf("Discovered %d DPDK ports\n", count);
    return count;
#else
    return 0;
#endif
}

#include <netpacket/packet.h>
#include <net/if.h>

int interface_discover_system(void)
{
    struct ifaddrs *ifaddr, *ifa;
    int count = 0;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    /* Walk through linked list, maintaining head pointer so we can free list later */
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        /* Only check AF_PACKET to avoid duplicates (one per interface) */
        if (ifa->ifa_addr->sa_family != AF_PACKET)
            continue;

        /* Skip loopback */
        if (strcmp(ifa->ifa_name, "lo") == 0)
            continue;

        /* Check if already exists */
        if (interface_find_by_name(ifa->ifa_name))
            continue;

        /* Create interface */
        struct interface *iface = interface_create(ifa->ifa_name, IF_TYPE_PHYSICAL);
        if (iface) {
            /* Extract MAC address */
            struct sockaddr_ll *sll = (struct sockaddr_ll *)ifa->ifa_addr;
            if (sll->sll_halen == 6) {
                memcpy(iface->mac_addr, sll->sll_addr, 6);
            }

            /* Set state */
            if (ifa->ifa_flags & IFF_UP) {
                iface->state = IF_STATE_UP;
                iface->link = LINK_STATE_UP;
            }

            count++;
        }
    }

    freeifaddrs(ifaddr);
    printf("Discovered %d system interfaces\n", count);
    return count;
}

uint32_t interface_count(void)
{
    return g_if_mgr.num_interfaces;
}

void interface_cleanup(void)
{
    uint32_t i;

    printf("Cleaning up interface subsystem...\n");

    /* Delete all interfaces */
    for (i = 0; i < IF_MAX_INTERFACES; i++) {
        if (g_if_mgr.interfaces[i]) {
            interface_delete(g_if_mgr.interfaces[i]);
        }
    }

    memset(&g_if_mgr, 0, sizeof(g_if_mgr));
    printf("Interface subsystem cleanup complete\n");
}

const char *interface_type_to_str(enum interface_type type)
{
    switch (type) {
    case IF_TYPE_PHYSICAL: return "Physical";
    case IF_TYPE_VLAN: return "VLAN";
    case IF_TYPE_LAG: return "LAG";
    case IF_TYPE_LOOPBACK: return "Loopback";
    case IF_TYPE_DUMMY: return "Dummy";
    default: return "Unknown";
    }
}

const char *interface_state_to_str(enum interface_state state)
{
    switch (state) {
    case IF_STATE_DOWN: return "DOWN";
    case IF_STATE_UP: return "UP";
    case IF_STATE_ADMIN_DOWN: return "ADMIN_DOWN";
    case IF_STATE_ERROR: return "ERROR";
    default: return "UNKNOWN";
    }
}

const char *link_state_to_str(enum link_state state)
{
    switch (state) {
    case LINK_STATE_UP: return "UP";
    case LINK_STATE_DOWN: return "DOWN";
    default: return "UNKNOWN";
    }
}
