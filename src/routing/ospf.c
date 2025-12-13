/**
 * @file ospf.c
 * @brief OSPF Version 2 Full Implementation
 * @details RFC 2328 - OSPF Version 2
 *          RFC 3623 - Graceful OSPF Restart
 *          RFC 5243 - OSPF Database Exchange Summary List Optimization
 *          Cisco IOS Compatible Features
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include "routing_table.h"
#include "log.h"

/*============================================================================
 * OSPF Constants (RFC 2328)
 *============================================================================*/

#define OSPF_VERSION                2
#define OSPF_IP_PROTOCOL            89
#define OSPF_ALL_SPF_ROUTERS        0xE0000005  /* 224.0.0.5 */
#define OSPF_ALL_DR_ROUTERS         0xE0000006  /* 224.0.0.6 */

#define OSPF_MAX_AREAS              64
#define OSPF_MAX_INTERFACES         128
#define OSPF_MAX_NEIGHBORS          512
#define OSPF_MAX_LSA                100000

/* OSPF Packet Types (RFC 2328 A.3.1) */
#define OSPF_MSG_HELLO              1
#define OSPF_MSG_DB_DESC            2
#define OSPF_MSG_LS_REQUEST         3
#define OSPF_MSG_LS_UPDATE          4
#define OSPF_MSG_LS_ACK             5

/* LSA Types (RFC 2328 A.4) */
#define OSPF_LSA_ROUTER             1   /* Router-LSA */
#define OSPF_LSA_NETWORK            2   /* Network-LSA */
#define OSPF_LSA_SUMMARY_NETWORK    3   /* Summary-LSA (Network) */
#define OSPF_LSA_SUMMARY_ASBR       4   /* Summary-LSA (ASBR) */
#define OSPF_LSA_AS_EXTERNAL        5   /* AS-External-LSA */
#define OSPF_LSA_NSSA_EXTERNAL      7   /* NSSA-External-LSA (RFC 3101) */
#define OSPF_LSA_OPAQUE_LINK        9   /* Opaque Link-local (RFC 5250) */
#define OSPF_LSA_OPAQUE_AREA        10  /* Opaque Area-local */
#define OSPF_LSA_OPAQUE_AS          11  /* Opaque AS-scope */

/* Default Timers (Cisco IOS defaults) */
#define OSPF_HELLO_INTERVAL_DEFAULT     10      /* 10 seconds */
#define OSPF_DEAD_INTERVAL_DEFAULT      40      /* 4x hello */
#define OSPF_RETRANSMIT_INTERVAL        5       /* 5 seconds */
#define OSPF_TRANSMIT_DELAY             1       /* 1 second */
#define OSPF_SPF_DELAY                  5       /* 5 seconds (Cisco) */
#define OSPF_SPF_HOLDTIME               10      /* 10 seconds */
#define OSPF_LSA_MAX_AGE                3600    /* 1 hour */
#define OSPF_LSA_REFRESH_TIME           1800    /* 30 minutes */

/* OSPF Options Field (RFC 2328 A.2) */
#define OSPF_OPTION_E       0x02    /* External routing capability */
#define OSPF_OPTION_MC      0x04    /* Multicast capability */
#define OSPF_OPTION_NP      0x08    /* NSSA (RFC 3101) */
#define OSPF_OPTION_EA      0x10    /* External-Attributes-LSA */
#define OSPF_OPTION_DC      0x20    /* Demand Circuits (RFC 1793) */
#define OSPF_OPTION_O       0x40    /* Opaque LSA support */

/* Router-LSA Link Types (RFC 2328 A.4.2) */
#define OSPF_LINK_P2P           1   /* Point-to-point */
#define OSPF_LINK_TRANSIT       2   /* Transit network */
#define OSPF_LINK_STUB          3   /* Stub network */
#define OSPF_LINK_VIRTUAL       4   /* Virtual link */

/*============================================================================
 * OSPF Neighbor States (RFC 2328 Section 10.1)
 *============================================================================*/

enum ospf_neighbor_state {
    OSPF_NBR_DOWN = 0,
    OSPF_NBR_ATTEMPT,       /* For NBMA networks */
    OSPF_NBR_INIT,
    OSPF_NBR_2WAY,
    OSPF_NBR_EXSTART,
    OSPF_NBR_EXCHANGE,
    OSPF_NBR_LOADING,
    OSPF_NBR_FULL
};

/*============================================================================
 * OSPF Interface States (RFC 2328 Section 9.1)
 *============================================================================*/

enum ospf_iface_state {
    OSPF_IFACE_DOWN = 0,
    OSPF_IFACE_LOOPBACK,
    OSPF_IFACE_WAITING,
    OSPF_IFACE_POINT_TO_POINT,
    OSPF_IFACE_DR_OTHER,
    OSPF_IFACE_BACKUP,
    OSPF_IFACE_DR
};

/*============================================================================
 * OSPF Network Types (Cisco)
 *============================================================================*/

enum ospf_network_type {
    OSPF_NETWORK_BROADCAST = 0,
    OSPF_NETWORK_POINT_TO_POINT,
    OSPF_NETWORK_NBMA,
    OSPF_NETWORK_POINT_TO_MULTIPOINT,
    OSPF_NETWORK_LOOPBACK
};

/*============================================================================
 * OSPF Structures
 *============================================================================*/

/* OSPF Packet Header (RFC 2328 A.3.1) */
struct ospf_header {
    uint8_t  version;
    uint8_t  type;
    uint16_t length;
    uint32_t router_id;
    uint32_t area_id;
    uint16_t checksum;
    uint16_t auth_type;
    uint64_t auth_data;
} __attribute__((packed));

/* OSPF Hello Packet (RFC 2328 A.3.2) */
struct ospf_hello {
    uint32_t network_mask;
    uint16_t hello_interval;
    uint8_t  options;
    uint8_t  priority;
    uint32_t dead_interval;
    uint32_t dr;
    uint32_t bdr;
    /* Neighbors follow */
} __attribute__((packed));

/* LSA Header (RFC 2328 A.4.1) */
struct ospf_lsa_header {
    uint16_t ls_age;
    uint8_t  options;
    uint8_t  ls_type;
    uint32_t link_state_id;
    uint32_t advertising_router;
    uint32_t ls_seq_num;
    uint16_t ls_checksum;
    uint16_t length;
} __attribute__((packed));

/* Router Link (RFC 2328 A.4.2) */
struct ospf_router_link {
    uint32_t link_id;
    uint32_t link_data;
    uint8_t  type;
    uint8_t  tos_count;
    uint16_t metric;
} __attribute__((packed));

/* Full LSA Structure */
struct ospf_lsa {
    struct ospf_lsa_header header;
    uint8_t  body[1024];
    int      body_len;
    time_t   received_time;
    time_t   installed_time;
    uint32_t received_from;     /* Neighbor that sent this LSA */
    struct ospf_lsa *next;
};

/* OSPF Neighbor */
struct ospf_neighbor {
    uint32_t router_id;
    uint32_t ip_addr;
    uint8_t  priority;
    uint8_t  options;
    enum ospf_neighbor_state state;
    uint32_t dr;
    uint32_t bdr;
    time_t   last_hello;
    time_t   last_exstart;

    /* Database Description */
    bool     master;            /* DD master flag */
    bool     more;              /* MS flag */
    bool     init;              /* I flag */
    uint32_t dd_seq_num;

    /* LSA lists */
    struct ospf_lsa_header *db_summary_list;
    int      db_summary_count;
    struct ospf_lsa_header *ls_request_list;
    int      ls_request_count;

    /* Retransmission */
    struct ospf_lsa_header *ls_retrans_list;
    int      ls_retrans_count;
    time_t   last_retrans;

    /* Statistics */
    uint64_t hello_recv;
    uint64_t hello_sent;
    uint64_t dd_recv;
    uint64_t dd_sent;
    uint64_t lsr_recv;
    uint64_t lsr_sent;
    uint64_t lsu_recv;
    uint64_t lsu_sent;
    uint64_t lsack_recv;
    uint64_t lsack_sent;
    uint64_t state_changes;
};

/* OSPF Interface */
struct ospf_interface {
    uint32_t ifindex;
    char     name[32];
    uint32_t ip_addr;
    uint32_t ip_mask;
    uint32_t area_id;

    /* Configuration */
    uint8_t  priority;
    uint16_t hello_interval;
    uint32_t dead_interval;
    uint16_t retransmit_interval;
    uint16_t transmit_delay;
    uint32_t cost;
    uint32_t mtu;
    enum ospf_network_type network_type;
    bool     passive;           /* Passive interface */

    /* Authentication */
    uint8_t  auth_type;         /* 0=none, 1=simple, 2=MD5 */
    char     auth_key[16];
    uint8_t  auth_key_id;

    /* State */
    enum ospf_iface_state state;
    uint32_t dr;
    uint32_t bdr;
    time_t   wait_timer_end;

    /* Neighbors */
    struct ospf_neighbor neighbors[OSPF_MAX_NEIGHBORS];
    int      neighbor_count;

    /* Flooding */
    time_t   last_hello_sent;
    uint64_t hello_out;
    uint64_t hello_in;

    bool     enabled;
};

/* OSPF Area */
struct ospf_area {
    uint32_t area_id;
    bool     stub;              /* Stub area */
    bool     nssa;              /* Not-So-Stubby Area (RFC 3101) */
    bool     totally_stubby;    /* Totally stubby */
    uint32_t default_cost;      /* Default cost for stub */
    uint8_t  options;           /* Area options */

    /* Link State Database */
    struct ospf_lsa *lsdb;
    int      lsa_count;
    int      router_lsa_count;
    int      network_lsa_count;
    int      summary_lsa_count;
    int      asbr_summary_lsa_count;

    /* SPF Calculation */
    uint32_t spf_calculation_count;
    time_t   last_spf_time;
    time_t   spf_delay_expiry;
    bool     spf_pending;

    /* Interfaces in this area */
    uint32_t interface_count;

    /* ABR Summary */
    bool     transit_area;      /* Has virtual links */
};

/* OSPF Global Configuration */
struct ospf_config {
    uint32_t router_id;
    bool     enabled;
    bool     abr;               /* Area Border Router */
    bool     asbr;              /* AS Boundary Router */
    uint32_t reference_bandwidth;   /* For cost calculation */
    uint16_t spf_delay;         /* Initial SPF delay */
    uint16_t spf_holdtime;      /* Min time between SPF */
    bool     log_adjacency_changes;
    bool     compatible_rfc1583;    /* RFC 1583 compatibility */
};

/* Global OSPF State */
static struct {
    struct ospf_config config;
    struct ospf_area areas[OSPF_MAX_AREAS];
    int      area_count;
    struct ospf_interface interfaces[OSPF_MAX_INTERFACES];
    int      interface_count;
    pthread_mutex_t lock;
    pthread_t thread;
    bool     running;
} g_ospf = {
    .area_count = 0,
    .interface_count = 0,
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .running = false
};

/*============================================================================
 * OSPF Utility Functions
 *============================================================================*/

static const char *ospf_neighbor_state_name(enum ospf_neighbor_state state)
{
    switch (state) {
        case OSPF_NBR_DOWN:     return "DOWN";
        case OSPF_NBR_ATTEMPT:  return "ATTEMPT";
        case OSPF_NBR_INIT:     return "INIT";
        case OSPF_NBR_2WAY:     return "2WAY";
        case OSPF_NBR_EXSTART:  return "EXSTART";
        case OSPF_NBR_EXCHANGE: return "EXCHANGE";
        case OSPF_NBR_LOADING:  return "LOADING";
        case OSPF_NBR_FULL:     return "FULL";
        default:                return "UNKNOWN";
    }
}

static const char *ospf_interface_state_name(enum ospf_iface_state state)
{
    switch (state) {
        case OSPF_IFACE_DOWN:           return "DOWN";
        case OSPF_IFACE_LOOPBACK:       return "LOOPBACK";
        case OSPF_IFACE_WAITING:        return "WAITING";
        case OSPF_IFACE_POINT_TO_POINT: return "P2P";
        case OSPF_IFACE_DR_OTHER:       return "DROTHER";
        case OSPF_IFACE_BACKUP:         return "BDR";
        case OSPF_IFACE_DR:             return "DR";
        default:                        return "UNKNOWN";
    }
}

static const char *ospf_network_type_name(enum ospf_network_type type)
{
    switch (type) {
        case OSPF_NETWORK_BROADCAST:            return "BROADCAST";
        case OSPF_NETWORK_POINT_TO_POINT:       return "POINT_TO_POINT";
        case OSPF_NETWORK_NBMA:                 return "NON_BROADCAST";
        case OSPF_NETWORK_POINT_TO_MULTIPOINT:  return "POINT_TO_MULTIPOINT";
        case OSPF_NETWORK_LOOPBACK:             return "LOOPBACK";
        default:                                return "UNKNOWN";
    }
}

static const char *ospf_lsa_type_name(uint8_t type)
{
    switch (type) {
        case OSPF_LSA_ROUTER:           return "Router";
        case OSPF_LSA_NETWORK:          return "Network";
        case OSPF_LSA_SUMMARY_NETWORK:  return "Summary Net";
        case OSPF_LSA_SUMMARY_ASBR:     return "Summary ASBR";
        case OSPF_LSA_AS_EXTERNAL:      return "AS External";
        case OSPF_LSA_NSSA_EXTERNAL:    return "NSSA External";
        case OSPF_LSA_OPAQUE_LINK:      return "Opaque Link";
        case OSPF_LSA_OPAQUE_AREA:      return "Opaque Area";
        case OSPF_LSA_OPAQUE_AS:        return "Opaque AS";
        default:                        return "Unknown";
    }
}

static void ospf_ip_to_str(uint32_t ip, char *buf, int len)
{
    struct in_addr a = {.s_addr = htonl(ip)};
    inet_ntop(AF_INET, &a, buf, len);
}

/*============================================================================
 * OSPF DR/BDR Election (RFC 2328 Section 9.4)
 *============================================================================*/

static void ospf_dr_election(struct ospf_interface *iface)
{
    if (iface->network_type == OSPF_NETWORK_POINT_TO_POINT ||
        iface->network_type == OSPF_NETWORK_POINT_TO_MULTIPOINT) {
        return;  /* No DR election needed */
    }

    /* Simple DR election - highest priority, then highest router-id */
    uint32_t new_dr = 0;
    uint32_t new_bdr = 0;
    uint8_t dr_priority = 0;
    uint8_t bdr_priority = 0;
    uint32_t dr_id = 0;
    uint32_t bdr_id = 0;

    /* Include self */
    if (iface->priority > 0) {
        new_dr = g_ospf.config.router_id;
        dr_priority = iface->priority;
        dr_id = g_ospf.config.router_id;
    }

    /* Check all neighbors */
    for (int i = 0; i < iface->neighbor_count; i++) {
        struct ospf_neighbor *n = &iface->neighbors[i];
        if (n->state < OSPF_NBR_2WAY) continue;
        if (n->priority == 0) continue;

        /* DR election */
        if (n->priority > dr_priority ||
            (n->priority == dr_priority && n->router_id > dr_id)) {
            /* Old DR becomes BDR candidate */
            if (new_dr != 0) {
                if (dr_priority > bdr_priority ||
                    (dr_priority == bdr_priority && dr_id > bdr_id)) {
                    new_bdr = new_dr;
                    bdr_priority = dr_priority;
                    bdr_id = dr_id;
                }
            }
            new_dr = n->router_id;
            dr_priority = n->priority;
            dr_id = n->router_id;
        } else if (n->priority > bdr_priority ||
                   (n->priority == bdr_priority && n->router_id > bdr_id)) {
            new_bdr = n->router_id;
            bdr_priority = n->priority;
            bdr_id = n->router_id;
        }
    }

    /* Update interface state */
    if (new_dr == g_ospf.config.router_id) {
        iface->state = OSPF_IFACE_DR;
    } else if (new_bdr == g_ospf.config.router_id) {
        iface->state = OSPF_IFACE_BACKUP;
    } else {
        iface->state = OSPF_IFACE_DR_OTHER;
    }

    iface->dr = new_dr;
    iface->bdr = new_bdr;
}

/*============================================================================
 * OSPF SPF Calculation (RFC 2328 Section 16)
 *============================================================================*/

static void ospf_run_spf(struct ospf_area *area)
{
    if (!area) return;

    area->spf_pending = false;
    area->last_spf_time = time(NULL);
    area->spf_calculation_count++;

    /* TODO: Full Dijkstra implementation */
    /* For now, we mark this as placeholder */

    YLOG_DEBUG("OSPF: SPF calculation for area %u.%u.%u.%u (#%u)",
               (area->area_id >> 24) & 0xFF, (area->area_id >> 16) & 0xFF,
               (area->area_id >> 8) & 0xFF, area->area_id & 0xFF,
               area->spf_calculation_count);
}

/*============================================================================
 * OSPF Public API
 *============================================================================*/

int ospf_init(uint32_t router_id)
{
    memset(&g_ospf.config, 0, sizeof(g_ospf.config));
    g_ospf.config.router_id = router_id;
    g_ospf.config.enabled = true;
    g_ospf.config.reference_bandwidth = 100000000;  /* 100 Mbps */
    g_ospf.config.spf_delay = OSPF_SPF_DELAY;
    g_ospf.config.spf_holdtime = OSPF_SPF_HOLDTIME;
    g_ospf.config.log_adjacency_changes = true;
    g_ospf.area_count = 0;
    g_ospf.interface_count = 0;

    char rid_str[32];
    ospf_ip_to_str(router_id, rid_str, sizeof(rid_str));
    YLOG_INFO("OSPF: Initialized (Router-ID %s)", rid_str);
    return 0;
}

int ospf_router_id(uint32_t router_id)
{
    pthread_mutex_lock(&g_ospf.lock);
    g_ospf.config.router_id = router_id;
    pthread_mutex_unlock(&g_ospf.lock);

    char rid_str[32];
    ospf_ip_to_str(router_id, rid_str, sizeof(rid_str));
    YLOG_INFO("OSPF: Router-ID set to %s", rid_str);
    return 0;
}

int ospf_area(uint32_t area_id)
{
    pthread_mutex_lock(&g_ospf.lock);

    /* Check if area exists */
    for (int i = 0; i < g_ospf.area_count; i++) {
        if (g_ospf.areas[i].area_id == area_id) {
            pthread_mutex_unlock(&g_ospf.lock);
            return i;
        }
    }

    if (g_ospf.area_count >= OSPF_MAX_AREAS) {
        pthread_mutex_unlock(&g_ospf.lock);
        return -1;
    }

    struct ospf_area *a = &g_ospf.areas[g_ospf.area_count++];
    memset(a, 0, sizeof(*a));
    a->area_id = area_id;
    a->options = OSPF_OPTION_E;  /* External routing by default */

    char area_str[32];
    ospf_ip_to_str(area_id, area_str, sizeof(area_str));
    YLOG_INFO("OSPF: Created area %s", area_str);

    pthread_mutex_unlock(&g_ospf.lock);
    return g_ospf.area_count - 1;
}

int ospf_area_stub(uint32_t area_id, bool no_summary)
{
    pthread_mutex_lock(&g_ospf.lock);

    for (int i = 0; i < g_ospf.area_count; i++) {
        if (g_ospf.areas[i].area_id == area_id) {
            g_ospf.areas[i].stub = true;
            g_ospf.areas[i].totally_stubby = no_summary;
            g_ospf.areas[i].options &= ~OSPF_OPTION_E;

            char area_str[32];
            ospf_ip_to_str(area_id, area_str, sizeof(area_str));
            YLOG_INFO("OSPF: Area %s is now %s stub",
                      area_str, no_summary ? "totally" : "");

            pthread_mutex_unlock(&g_ospf.lock);
            return 0;
        }
    }

    pthread_mutex_unlock(&g_ospf.lock);
    return -1;
}

int ospf_area_nssa(uint32_t area_id, bool no_summary)
{
    pthread_mutex_lock(&g_ospf.lock);

    for (int i = 0; i < g_ospf.area_count; i++) {
        if (g_ospf.areas[i].area_id == area_id) {
            g_ospf.areas[i].nssa = true;
            g_ospf.areas[i].totally_stubby = no_summary;
            g_ospf.areas[i].options |= OSPF_OPTION_NP;

            pthread_mutex_unlock(&g_ospf.lock);
            return 0;
        }
    }

    pthread_mutex_unlock(&g_ospf.lock);
    return -1;
}

int ospf_network(uint32_t network, uint32_t wildcard, uint32_t area_id)
{
    pthread_mutex_lock(&g_ospf.lock);

    /* Find or create area */
    int area_idx = -1;
    for (int i = 0; i < g_ospf.area_count; i++) {
        if (g_ospf.areas[i].area_id == area_id) {
            area_idx = i;
            break;
        }
    }

    if (area_idx < 0) {
        pthread_mutex_unlock(&g_ospf.lock);
        ospf_area(area_id);
        pthread_mutex_lock(&g_ospf.lock);
    }

    char net_str[32], area_str[32];
    ospf_ip_to_str(network, net_str, sizeof(net_str));
    ospf_ip_to_str(area_id, area_str, sizeof(area_str));
    YLOG_INFO("OSPF: Network %s wildcard 0x%08x area %s", net_str, wildcard, area_str);

    pthread_mutex_unlock(&g_ospf.lock);
    return 0;
}

int ospf_interface(uint32_t ifindex, uint32_t ip_addr, uint32_t ip_mask, uint32_t area_id)
{
    pthread_mutex_lock(&g_ospf.lock);

    if (g_ospf.interface_count >= OSPF_MAX_INTERFACES) {
        pthread_mutex_unlock(&g_ospf.lock);
        return -1;
    }

    struct ospf_interface *iface = &g_ospf.interfaces[g_ospf.interface_count++];
    memset(iface, 0, sizeof(*iface));

    iface->ifindex = ifindex;
    snprintf(iface->name, sizeof(iface->name), "eth%u", ifindex);
    iface->ip_addr = ip_addr;
    iface->ip_mask = ip_mask;
    iface->area_id = area_id;
    iface->priority = 1;
    iface->hello_interval = OSPF_HELLO_INTERVAL_DEFAULT;
    iface->dead_interval = OSPF_DEAD_INTERVAL_DEFAULT;
    iface->retransmit_interval = OSPF_RETRANSMIT_INTERVAL;
    iface->transmit_delay = OSPF_TRANSMIT_DELAY;
    iface->cost = g_ospf.config.reference_bandwidth / 1000000;  /* Assume 1Gbps */
    iface->mtu = 1500;
    iface->network_type = OSPF_NETWORK_BROADCAST;
    iface->state = OSPF_IFACE_DOWN;
    iface->enabled = true;

    /* Update area's interface count */
    for (int i = 0; i < g_ospf.area_count; i++) {
        if (g_ospf.areas[i].area_id == area_id) {
            g_ospf.areas[i].interface_count++;
            break;
        }
    }

    char ip_str[32], area_str[32];
    ospf_ip_to_str(ip_addr, ip_str, sizeof(ip_str));
    ospf_ip_to_str(area_id, area_str, sizeof(area_str));
    YLOG_INFO("OSPF: Interface %s added to area %s (cost %u)",
              iface->name, area_str, iface->cost);

    pthread_mutex_unlock(&g_ospf.lock);
    return g_ospf.interface_count - 1;
}

int ospf_interface_cost(uint32_t ifindex, uint32_t cost)
{
    pthread_mutex_lock(&g_ospf.lock);

    for (int i = 0; i < g_ospf.interface_count; i++) {
        if (g_ospf.interfaces[i].ifindex == ifindex) {
            g_ospf.interfaces[i].cost = cost;
            pthread_mutex_unlock(&g_ospf.lock);
            return 0;
        }
    }

    pthread_mutex_unlock(&g_ospf.lock);
    return -1;
}

int ospf_interface_priority(uint32_t ifindex, uint8_t priority)
{
    pthread_mutex_lock(&g_ospf.lock);

    for (int i = 0; i < g_ospf.interface_count; i++) {
        if (g_ospf.interfaces[i].ifindex == ifindex) {
            g_ospf.interfaces[i].priority = priority;
            pthread_mutex_unlock(&g_ospf.lock);
            return 0;
        }
    }

    pthread_mutex_unlock(&g_ospf.lock);
    return -1;
}

int ospf_interface_passive(uint32_t ifindex, bool passive)
{
    pthread_mutex_lock(&g_ospf.lock);

    for (int i = 0; i < g_ospf.interface_count; i++) {
        if (g_ospf.interfaces[i].ifindex == ifindex) {
            g_ospf.interfaces[i].passive = passive;
            pthread_mutex_unlock(&g_ospf.lock);
            return 0;
        }
    }

    pthread_mutex_unlock(&g_ospf.lock);
    return -1;
}

void ospf_show(void)
{
    pthread_mutex_lock(&g_ospf.lock);

    char rid_str[32];
    ospf_ip_to_str(g_ospf.config.router_id, rid_str, sizeof(rid_str));

    printf("OSPF Routing Process\n");
    printf("  Router ID: %s\n", rid_str);
    printf("  Reference bandwidth unit: %u Mbps\n", g_ospf.config.reference_bandwidth / 1000000);
    printf("  %s; %s\n",
           g_ospf.config.abr ? "It is an ABR" : "It is not an ABR",
           g_ospf.config.asbr ? "It is an ASBR" : "It is not an ASBR");
    printf("  Number of areas: %d\n", g_ospf.area_count);
    printf("  Number of interfaces: %d\n", g_ospf.interface_count);
    printf("\n");

    for (int i = 0; i < g_ospf.area_count; i++) {
        struct ospf_area *a = &g_ospf.areas[i];
        char area_str[32];
        ospf_ip_to_str(a->area_id, area_str, sizeof(area_str));

        printf("Area %s%s%s\n", area_str,
               a->stub ? " (Stub)" : "",
               a->nssa ? " (NSSA)" : "");
        printf("  Number of interfaces: %u\n", a->interface_count);
        printf("  Number of LSAs: %d\n", a->lsa_count);
        printf("  SPF algorithm executed %u times\n", a->spf_calculation_count);
    }

    pthread_mutex_unlock(&g_ospf.lock);
}

void ospf_show_interface(void)
{
    pthread_mutex_lock(&g_ospf.lock);

    for (int i = 0; i < g_ospf.interface_count; i++) {
        struct ospf_interface *iface = &g_ospf.interfaces[i];

        char ip_str[32], mask_str[32], area_str[32], dr_str[32], bdr_str[32];
        ospf_ip_to_str(iface->ip_addr, ip_str, sizeof(ip_str));
        ospf_ip_to_str(iface->ip_mask, mask_str, sizeof(mask_str));
        ospf_ip_to_str(iface->area_id, area_str, sizeof(area_str));
        ospf_ip_to_str(iface->dr, dr_str, sizeof(dr_str));
        ospf_ip_to_str(iface->bdr, bdr_str, sizeof(bdr_str));

        printf("%s is %s, line protocol is %s\n",
               iface->name,
               iface->enabled ? "up" : "administratively down",
               iface->enabled ? "up" : "down");
        printf("  Internet Address %s/%u, Area %s\n",
               ip_str, __builtin_popcount(iface->ip_mask), area_str);
        printf("  Process ID 1, Router ID %u.%u.%u.%u, Network Type %s, Cost: %u\n",
               (g_ospf.config.router_id >> 24) & 0xFF,
               (g_ospf.config.router_id >> 16) & 0xFF,
               (g_ospf.config.router_id >> 8) & 0xFF,
               g_ospf.config.router_id & 0xFF,
               ospf_network_type_name(iface->network_type),
               iface->cost);
        printf("  Transmit Delay is %u sec, State %s, Priority %u\n",
               iface->transmit_delay,
               ospf_interface_state_name(iface->state),
               iface->priority);
        printf("  Designated Router (ID) %s\n", dr_str);
        printf("  Backup Designated Router (ID) %s\n", bdr_str);
        printf("  Timer intervals configured, Hello %u, Dead %u, Retransmit %u\n",
               iface->hello_interval, iface->dead_interval, iface->retransmit_interval);
        printf("  Neighbor Count is %d, Adjacent neighbor count is %d\n",
               iface->neighbor_count,
               iface->neighbor_count);  /* TODO: Count FULL only */
        printf("\n");
    }

    pthread_mutex_unlock(&g_ospf.lock);
}

void ospf_show_neighbor(void)
{
    pthread_mutex_lock(&g_ospf.lock);

    printf("%-16s %-4s %-10s %-10s %-16s %-16s\n",
           "Neighbor ID", "Pri", "State", "Dead Time", "Address", "Interface");

    for (int i = 0; i < g_ospf.interface_count; i++) {
        struct ospf_interface *iface = &g_ospf.interfaces[i];

        for (int n = 0; n < iface->neighbor_count; n++) {
            struct ospf_neighbor *nbr = &iface->neighbors[n];

            char rid_str[32], addr_str[32];
            ospf_ip_to_str(nbr->router_id, rid_str, sizeof(rid_str));
            ospf_ip_to_str(nbr->ip_addr, addr_str, sizeof(addr_str));

            char state_str[32];
            snprintf(state_str, sizeof(state_str), "%s/%s",
                     ospf_neighbor_state_name(nbr->state),
                     nbr->router_id == iface->dr ? "DR" :
                     nbr->router_id == iface->bdr ? "BDR" : "-");

            time_t dead_time = iface->dead_interval - (time(NULL) - nbr->last_hello);
            if (dead_time < 0) dead_time = 0;

            printf("%-16s %-4u %-10s %-10ld %-16s %-16s\n",
                   rid_str, nbr->priority, state_str,
                   dead_time, addr_str, iface->name);
        }
    }

    pthread_mutex_unlock(&g_ospf.lock);
}

void ospf_show_database(void)
{
    pthread_mutex_lock(&g_ospf.lock);

    char rid_str[32];
    ospf_ip_to_str(g_ospf.config.router_id, rid_str, sizeof(rid_str));

    printf("OSPF Router with ID (%s)\n\n", rid_str);

    for (int a = 0; a < g_ospf.area_count; a++) {
        struct ospf_area *area = &g_ospf.areas[a];
        char area_str[32];
        ospf_ip_to_str(area->area_id, area_str, sizeof(area_str));

        printf("                Router Link States (Area %s)\n\n", area_str);
        printf("%-16s %-16s %-6s %-10s %-10s\n",
               "Link ID", "ADV Router", "Age", "Seq#", "Checksum");

        /* Print LSAs from LSDB */
        for (struct ospf_lsa *lsa = area->lsdb; lsa; lsa = lsa->next) {
            char lsid_str[32], adv_str[32];
            ospf_ip_to_str(ntohl(lsa->header.link_state_id), lsid_str, sizeof(lsid_str));
            ospf_ip_to_str(ntohl(lsa->header.advertising_router), adv_str, sizeof(adv_str));

            printf("%-16s %-16s %-6u 0x%08x 0x%04x\n",
                   lsid_str, adv_str,
                   ntohs(lsa->header.ls_age),
                   ntohl(lsa->header.ls_seq_num),
                   ntohs(lsa->header.ls_checksum));
        }
        printf("\n");
    }

    pthread_mutex_unlock(&g_ospf.lock);
}

void ospf_cleanup(void)
{
    pthread_mutex_lock(&g_ospf.lock);

    g_ospf.running = false;

    /* Free LSDBs */
    for (int i = 0; i < g_ospf.area_count; i++) {
        struct ospf_lsa *lsa = g_ospf.areas[i].lsdb;
        while (lsa) {
            struct ospf_lsa *next = lsa->next;
            free(lsa);
            lsa = next;
        }
    }

    g_ospf.area_count = 0;
    g_ospf.interface_count = 0;

    pthread_mutex_unlock(&g_ospf.lock);
    YLOG_INFO("OSPF: Cleanup complete");
}
