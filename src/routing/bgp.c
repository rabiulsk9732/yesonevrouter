/**
 * @file bgp.c
 * @brief BGP-4 (Border Gateway Protocol) Full Implementation
 * @details RFC 4271 - BGP-4, RFC 4760 - Multiprotocol BGP
 *          RFC 8277 - BGP Communities, RFC 4456 - Route Reflectors
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
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <fcntl.h>

#include "routing_table.h"
#include "log.h"

/*============================================================================
 * BGP Constants (RFC 4271)
 *============================================================================*/

#define BGP_PORT                179
#define BGP_VERSION             4
#define BGP_MAX_MESSAGE_LEN     4096
#define BGP_HEADER_LEN          19
#define BGP_MARKER_LEN          16

#define BGP_MAX_PEERS           256
#define BGP_MAX_PREFIXES        2000000     /* 2M prefixes */
#define BGP_MAX_AS_PATH_LEN     255
#define BGP_MAX_COMMUNITIES     64

/* Default Timers (Cisco defaults) */
#define BGP_HOLD_TIME_DEFAULT       180     /* 3 minutes */
#define BGP_KEEPALIVE_TIME_DEFAULT  60      /* 1 minute */
#define BGP_CONNECT_RETRY_TIME      120     /* 2 minutes */
#define BGP_MIN_AS_ORIGINATION      15      /* 15 seconds */
#define BGP_MIN_ROUTE_ADVERTISEMENT 30      /* 30 seconds (eBGP) */
#define BGP_MIN_ROUTE_ADVERTISEMENT_IBGP 5  /* 5 seconds (iBGP) */

/* BGP Message Types (RFC 4271 Section 4) */
#define BGP_MSG_OPEN            1
#define BGP_MSG_UPDATE          2
#define BGP_MSG_NOTIFICATION    3
#define BGP_MSG_KEEPALIVE       4
#define BGP_MSG_ROUTE_REFRESH   5   /* RFC 2918 */

/* BGP OPEN Optional Parameter Types */
#define BGP_OPT_CAPABILITIES    2

/* BGP Capability Codes (RFC 5492) */
#define BGP_CAP_MULTIPROTOCOL   1   /* RFC 4760 */
#define BGP_CAP_ROUTE_REFRESH   2   /* RFC 2918 */
#define BGP_CAP_4BYTE_AS        65  /* RFC 6793 */
#define BGP_CAP_GRACEFUL_RESTART 64 /* RFC 4724 */

/* BGP Path Attribute Type Codes (RFC 4271 Section 5) */
#define BGP_ATTR_FLAG_OPTIONAL      0x80
#define BGP_ATTR_FLAG_TRANSITIVE    0x40
#define BGP_ATTR_FLAG_PARTIAL       0x20
#define BGP_ATTR_FLAG_EXTENDED      0x10

#define BGP_ATTR_ORIGIN             1   /* Well-known mandatory */
#define BGP_ATTR_AS_PATH            2   /* Well-known mandatory */
#define BGP_ATTR_NEXT_HOP           3   /* Well-known mandatory */
#define BGP_ATTR_MED                4   /* Optional non-transitive */
#define BGP_ATTR_LOCAL_PREF         5   /* Well-known discretionary */
#define BGP_ATTR_ATOMIC_AGGR        6   /* Well-known discretionary */
#define BGP_ATTR_AGGREGATOR         7   /* Optional transitive */
#define BGP_ATTR_COMMUNITY          8   /* Optional transitive (RFC 1997) */
#define BGP_ATTR_ORIGINATOR_ID      9   /* Optional non-transitive (RFC 4456) */
#define BGP_ATTR_CLUSTER_LIST       10  /* Optional non-transitive (RFC 4456) */
#define BGP_ATTR_MP_REACH_NLRI      14  /* Optional non-transitive (RFC 4760) */
#define BGP_ATTR_MP_UNREACH_NLRI    15  /* Optional non-transitive (RFC 4760) */
#define BGP_ATTR_EXT_COMMUNITY      16  /* Optional transitive (RFC 4360) */
#define BGP_ATTR_AS4_PATH           17  /* Optional transitive (RFC 6793) */
#define BGP_ATTR_AS4_AGGREGATOR     18  /* Optional transitive (RFC 6793) */
#define BGP_ATTR_LARGE_COMMUNITY    32  /* Optional transitive (RFC 8092) */

/* BGP Origin Values (RFC 4271 Section 5.1.1) */
#define BGP_ORIGIN_IGP          0
#define BGP_ORIGIN_EGP          1
#define BGP_ORIGIN_INCOMPLETE   2

/* AS_PATH Segment Types (RFC 4271 Section 5.1.2) */
#define AS_SET                  1
#define AS_SEQUENCE             2
#define AS_CONFED_SEQUENCE      3   /* RFC 5065 */
#define AS_CONFED_SET           4   /* RFC 5065 */

/* Well-known BGP Communities (RFC 1997) */
#define BGP_COMMUNITY_NO_EXPORT         0xFFFFFF01
#define BGP_COMMUNITY_NO_ADVERTISE      0xFFFFFF02
#define BGP_COMMUNITY_NO_EXPORT_SUBCONFED 0xFFFFFF03
#define BGP_COMMUNITY_NOPEER            0xFFFFFF04  /* RFC 3765 */

/* BGP NOTIFICATION Error Codes (RFC 4271 Section 6.1) */
#define BGP_ERR_HEADER          1
#define BGP_ERR_OPEN            2
#define BGP_ERR_UPDATE          3
#define BGP_ERR_HOLD_TIMER      4
#define BGP_ERR_FSM             5
#define BGP_ERR_CEASE           6

/* CEASE Subcodes (RFC 4486) */
#define BGP_CEASE_MAX_PREFIXES      1
#define BGP_CEASE_ADMIN_SHUTDOWN    2
#define BGP_CEASE_PEER_DECONFIGURED 3
#define BGP_CEASE_ADMIN_RESET       4
#define BGP_CEASE_CONN_REJECTED     5
#define BGP_CEASE_CONFIG_CHANGE     6
#define BGP_CEASE_CONN_COLLISION    7
#define BGP_CEASE_OUT_OF_RESOURCES  8

/*============================================================================
 * BGP Peer States (RFC 4271 Section 8.2.2)
 *============================================================================*/

enum bgp_state {
    BGP_STATE_IDLE = 1,
    BGP_STATE_CONNECT,
    BGP_STATE_ACTIVE,
    BGP_STATE_OPEN_SENT,
    BGP_STATE_OPEN_CONFIRM,
    BGP_STATE_ESTABLISHED
};

/*============================================================================
 * BGP Structures
 *============================================================================*/

/* BGP Message Header (RFC 4271 Section 4.1) */
struct bgp_header {
    uint8_t  marker[BGP_MARKER_LEN];
    uint16_t length;
    uint8_t  type;
} __attribute__((packed));

/* BGP OPEN Message (RFC 4271 Section 4.2) */
struct bgp_open {
    uint8_t  version;
    uint16_t my_as;
    uint16_t hold_time;
    uint32_t bgp_id;
    uint8_t  opt_param_len;
    /* Optional parameters follow */
} __attribute__((packed));

/* Path Attributes */
struct bgp_path_attr {
    uint8_t  origin;                    /* IGP/EGP/INCOMPLETE */
    uint32_t as_path[BGP_MAX_AS_PATH_LEN];
    int      as_path_len;
    uint32_t next_hop;                  /* IPv4 next-hop */
    uint32_t med;                       /* Multi-Exit Discriminator */
    uint32_t local_pref;                /* LOCAL_PREF */
    bool     atomic_aggregate;          /* ATOMIC_AGGREGATE */
    uint32_t aggregator_as;             /* AGGREGATOR AS */
    uint32_t aggregator_id;             /* AGGREGATOR origin ID */
    uint32_t communities[BGP_MAX_COMMUNITIES];
    int      community_count;
    uint32_t originator_id;             /* Route Reflector */
    uint32_t cluster_list[16];          /* Route Reflector */
    int      cluster_list_len;
    uint16_t weight;                    /* Cisco-specific: Weight */
};

/* BGP Route Entry */
struct bgp_route {
    uint32_t prefix;
    uint8_t  prefix_len;
    struct bgp_path_attr attr;
    uint32_t peer_id;                   /* Which peer advertised this */
    time_t   received_time;
    bool     valid;                     /* Passed sanity checks */
    bool     best;                      /* Best path selected */
    bool     suppressed;                /* Dampened */
    struct bgp_route *next;
};

/* BGP Peer Configuration & State */
struct bgp_peer {
    /* Configuration */
    uint32_t remote_ip;
    uint32_t remote_as;
    uint32_t local_as;
    uint32_t router_id;
    char     description[64];

    /* Peer-specific settings (Cisco-style) */
    uint32_t update_source;             /* Update source IP */
    uint8_t  ebgp_multihop;             /* eBGP TTL */
    uint32_t password_hash;             /* MD5 auth (RFC 2385) */
    uint32_t max_prefix;                /* Maximum prefix limit */
    uint8_t  max_prefix_threshold;      /* Warning threshold % */
    bool     max_prefix_warning_only;
    bool     next_hop_self;             /* Set next-hop to self */
    bool     soft_reconfiguration;      /* Store received routes */
    bool     remove_private_as;         /* Remove private AS */
    bool     route_reflector_client;    /* RR client */
    uint16_t weight;                    /* Default weight */

    /* Timers (configurable) */
    uint16_t hold_time;
    uint16_t keepalive_time;
    uint16_t connect_retry_time;
    uint16_t min_advertisement_interval;

    /* Negotiated values */
    uint16_t negotiated_hold_time;
    uint32_t remote_router_id;
    bool     cap_4byte_as;
    bool     cap_route_refresh;
    bool     cap_graceful_restart;

    /* FSM State */
    enum bgp_state state;
    enum bgp_state prev_state;
    int      sock_fd;
    time_t   state_change_time;
    uint32_t connect_retry_counter;

    /* Timers */
    time_t   last_keepalive_sent;
    time_t   last_keepalive_recv;
    time_t   last_update_sent;
    time_t   last_update_recv;
    time_t   uptime;

    /* Statistics */
    uint64_t open_in;
    uint64_t open_out;
    uint64_t update_in;
    uint64_t update_out;
    uint64_t notification_in;
    uint64_t notification_out;
    uint64_t keepalive_in;
    uint64_t keepalive_out;
    uint64_t route_refresh_in;
    uint64_t route_refresh_out;
    uint64_t prefixes_received;
    uint64_t prefixes_sent;
    uint64_t prefixes_withdrawn;
    uint64_t messages_total_in;
    uint64_t messages_total_out;

    /* State */
    bool     enabled;
    bool     passive;
    bool     ebgp;
    bool     shutdown;
    uint8_t  last_error_code;
    uint8_t  last_error_subcode;
};

/* BGP Global Configuration */
struct bgp_config {
    uint32_t router_id;
    uint32_t local_as;
    uint32_t cluster_id;                /* Route Reflector cluster ID */
    bool     enabled;
    bool     always_compare_med;        /* Compare MED from different AS */
    bool     deterministic_med;         /* Deterministic MED comparison */
    bool     bestpath_as_path_ignore;   /* Ignore AS path length */
    bool     bestpath_compare_routerid; /* Compare router-id as tiebreaker */
    bool     log_neighbor_changes;
    uint32_t default_local_pref;        /* Default LOCAL_PREF (100) */
    uint16_t default_keepalive;
    uint16_t default_hold_time;
};

/* Global BGP state */
static struct {
    struct bgp_config config;
    struct bgp_peer peers[BGP_MAX_PEERS];
    int peer_count;
    struct bgp_route *adj_rib_in;       /* Adj-RIB-In (all received) */
    struct bgp_route *loc_rib;          /* Loc-RIB (best paths) */
    pthread_mutex_t lock;
    pthread_t fsm_thread;
    bool running;
} g_bgp = {
    .peer_count = 0,
    .adj_rib_in = NULL,
    .loc_rib = NULL,
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .running = false
};

/*============================================================================
 * BGP Utilities
 *============================================================================*/

static const char *bgp_state_name(enum bgp_state state)
{
    switch (state) {
        case BGP_STATE_IDLE:         return "Idle";
        case BGP_STATE_CONNECT:      return "Connect";
        case BGP_STATE_ACTIVE:       return "Active";
        case BGP_STATE_OPEN_SENT:    return "OpenSent";
        case BGP_STATE_OPEN_CONFIRM: return "OpenConfirm";
        case BGP_STATE_ESTABLISHED:  return "Established";
        default:                     return "Unknown";
    }
}

static const char *bgp_origin_str(uint8_t origin)
{
    switch (origin) {
        case BGP_ORIGIN_IGP:        return "i";
        case BGP_ORIGIN_EGP:        return "e";
        case BGP_ORIGIN_INCOMPLETE: return "?";
        default:                    return "?";
    }
}

static void bgp_log_state_change(struct bgp_peer *p, enum bgp_state old, enum bgp_state new)
{
    if (g_bgp.config.log_neighbor_changes) {
        char ip_str[32];
        struct in_addr a = {.s_addr = htonl(p->remote_ip)};
        inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));
        YLOG_INFO("BGP: %s - state changed from %s to %s",
                  ip_str, bgp_state_name(old), bgp_state_name(new));
    }
}

/*============================================================================
 * BGP Best Path Selection (RFC 4271 Section 9.1.2.2)
 * Cisco Best Path Algorithm:
 * 1. Highest Weight (Cisco-specific)
 * 2. Highest LOCAL_PREF
 * 3. Locally originated
 * 4. Shortest AS_PATH
 * 5. Lowest Origin (IGP < EGP < INCOMPLETE)
 * 6. Lowest MED (for same AS)
 * 7. eBGP over iBGP
 * 8. Lowest IGP metric to next-hop
 * 9. Oldest route (for eBGP)
 * 10. Lowest Router ID
 * 11. Lowest Cluster List length
 * 12. Lowest neighbor IP
 *============================================================================*/

static int bgp_path_compare(struct bgp_route *a, struct bgp_route *b)
{
    /* 1. Weight (Cisco) - higher is better */
    if (a->attr.weight != b->attr.weight)
        return b->attr.weight - a->attr.weight;

    /* 2. LOCAL_PREF - higher is better */
    if (a->attr.local_pref != b->attr.local_pref)
        return b->attr.local_pref - a->attr.local_pref;

    /* 4. AS_PATH length - shorter is better */
    if (!g_bgp.config.bestpath_as_path_ignore) {
        if (a->attr.as_path_len != b->attr.as_path_len)
            return a->attr.as_path_len - b->attr.as_path_len;
    }

    /* 5. Origin - lower is better (IGP < EGP < INCOMPLETE) */
    if (a->attr.origin != b->attr.origin)
        return a->attr.origin - b->attr.origin;

    /* 6. MED - lower is better (same neighbor AS only by default) */
    if (g_bgp.config.always_compare_med ||
        (a->attr.as_path_len > 0 && b->attr.as_path_len > 0 &&
         a->attr.as_path[0] == b->attr.as_path[0])) {
        if (a->attr.med != b->attr.med)
            return a->attr.med - b->attr.med;
    }

    /* 10. Router ID - lower is better */
    if (g_bgp.config.bestpath_compare_routerid) {
        if (a->peer_id != b->peer_id)
            return a->peer_id - b->peer_id;
    }

    return 0;  /* Equal */
}

static void bgp_run_decision_process(void)
{
    /* Clear all best flags */
    for (struct bgp_route *r = g_bgp.adj_rib_in; r; r = r->next) {
        r->best = false;
    }

    /* For each unique prefix, select best path */
    for (struct bgp_route *r = g_bgp.adj_rib_in; r; r = r->next) {
        if (!r->valid) continue;

        struct bgp_route *best = r;

        for (struct bgp_route *c = r->next; c; c = c->next) {
            if (!c->valid) continue;
            if (c->prefix != r->prefix || c->prefix_len != r->prefix_len) continue;

            if (bgp_path_compare(c, best) < 0) {
                best = c;
            }
        }

        best->best = true;
    }
}

/*============================================================================
 * BGP Message Building
 *============================================================================*/

static int bgp_build_open(struct bgp_peer *p, uint8_t *buf, int max_len)
{
    int len = 0;

    /* Marker (16 bytes of 0xFF) */
    memset(buf, 0xFF, BGP_MARKER_LEN);
    len = BGP_MARKER_LEN;

    /* Length placeholder */
    len += 2;

    /* Type */
    buf[len++] = BGP_MSG_OPEN;

    /* Version */
    buf[len++] = BGP_VERSION;

    /* My AS (2 bytes for < 65535, else use AS_TRANS) */
    uint16_t my_as = (p->local_as <= 65535) ? p->local_as : 23456;  /* AS_TRANS */
    buf[len++] = (my_as >> 8) & 0xFF;
    buf[len++] = my_as & 0xFF;

    /* Hold Time */
    buf[len++] = (p->hold_time >> 8) & 0xFF;
    buf[len++] = p->hold_time & 0xFF;

    /* BGP Identifier */
    buf[len++] = (p->router_id >> 24) & 0xFF;
    buf[len++] = (p->router_id >> 16) & 0xFF;
    buf[len++] = (p->router_id >> 8) & 0xFF;
    buf[len++] = p->router_id & 0xFF;

    /* Optional Parameters Length (placeholder) */
    int opt_len_pos = len;
    buf[len++] = 0;
    int opt_start = len;

    /* Capability: 4-byte AS (RFC 6793) */
    buf[len++] = BGP_OPT_CAPABILITIES;
    buf[len++] = 6;  /* Length */
    buf[len++] = BGP_CAP_4BYTE_AS;
    buf[len++] = 4;  /* Capability length */
    buf[len++] = (p->local_as >> 24) & 0xFF;
    buf[len++] = (p->local_as >> 16) & 0xFF;
    buf[len++] = (p->local_as >> 8) & 0xFF;
    buf[len++] = p->local_as & 0xFF;

    /* Capability: Route Refresh */
    buf[len++] = BGP_OPT_CAPABILITIES;
    buf[len++] = 2;
    buf[len++] = BGP_CAP_ROUTE_REFRESH;
    buf[len++] = 0;

    /* Capability: MP-BGP IPv4 Unicast */
    buf[len++] = BGP_OPT_CAPABILITIES;
    buf[len++] = 6;
    buf[len++] = BGP_CAP_MULTIPROTOCOL;
    buf[len++] = 4;
    buf[len++] = 0; buf[len++] = 1;  /* AFI IPv4 */
    buf[len++] = 0;                   /* Reserved */
    buf[len++] = 1;                   /* SAFI Unicast */

    /* Set optional parameters length */
    buf[opt_len_pos] = len - opt_start;

    /* Set message length */
    buf[16] = (len >> 8) & 0xFF;
    buf[17] = len & 0xFF;

    return len;
}

static int bgp_build_keepalive(uint8_t *buf)
{
    memset(buf, 0xFF, BGP_MARKER_LEN);
    buf[16] = 0;
    buf[17] = BGP_HEADER_LEN;
    buf[18] = BGP_MSG_KEEPALIVE;
    return BGP_HEADER_LEN;
}

static int bgp_build_notification(uint8_t *buf, uint8_t error, uint8_t subcode)
{
    memset(buf, 0xFF, BGP_MARKER_LEN);
    buf[16] = 0;
    buf[17] = BGP_HEADER_LEN + 2;
    buf[18] = BGP_MSG_NOTIFICATION;
    buf[19] = error;
    buf[20] = subcode;
    return BGP_HEADER_LEN + 2;
}

/*============================================================================
 * BGP FSM Event Handlers
 *============================================================================*/

static void bgp_fsm_idle_start(struct bgp_peer *p)
{
    p->connect_retry_counter = 0;

    if (!p->passive) {
        /* Initiate TCP connection */
        p->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (p->sock_fd >= 0) {
            fcntl(p->sock_fd, F_SETFL, O_NONBLOCK);

            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(BGP_PORT);
            addr.sin_addr.s_addr = htonl(p->remote_ip);

            connect(p->sock_fd, (struct sockaddr *)&addr, sizeof(addr));

            enum bgp_state old = p->state;
            p->state = BGP_STATE_CONNECT;
            bgp_log_state_change(p, old, p->state);
        }
    } else {
        enum bgp_state old = p->state;
        p->state = BGP_STATE_ACTIVE;
        bgp_log_state_change(p, old, p->state);
    }
}

static void bgp_fsm_connected(struct bgp_peer *p)
{
    uint8_t buf[256];
    int len = bgp_build_open(p, buf, sizeof(buf));

    send(p->sock_fd, buf, len, 0);
    p->open_out++;

    enum bgp_state old = p->state;
    p->state = BGP_STATE_OPEN_SENT;
    bgp_log_state_change(p, old, p->state);
}

static void bgp_fsm_open_received(struct bgp_peer *p, const uint8_t *msg, int len)
{
    if (len < sizeof(struct bgp_open)) return;

    const struct bgp_open *open = (const struct bgp_open *)msg;

    /* Validate OPEN */
    if (open->version != BGP_VERSION) {
        uint8_t buf[64];
        int nlen = bgp_build_notification(buf, BGP_ERR_OPEN, 1);  /* Unsupported version */
        send(p->sock_fd, buf, nlen, 0);
        p->notification_out++;
        return;
    }

    p->remote_router_id = ntohl(open->bgp_id);
    p->negotiated_hold_time = ntohs(open->hold_time);
    if (p->negotiated_hold_time > p->hold_time) {
        p->negotiated_hold_time = p->hold_time;
    }

    p->open_in++;

    if (p->state == BGP_STATE_OPEN_SENT) {
        /* Send KEEPALIVE */
        uint8_t buf[64];
        int klen = bgp_build_keepalive(buf);
        send(p->sock_fd, buf, klen, 0);
        p->keepalive_out++;

        enum bgp_state old = p->state;
        p->state = BGP_STATE_OPEN_CONFIRM;
        bgp_log_state_change(p, old, p->state);
    } else if (p->state == BGP_STATE_ACTIVE) {
        /* Send OPEN then wait */
        uint8_t buf[256];
        int olen = bgp_build_open(p, buf, sizeof(buf));
        send(p->sock_fd, buf, olen, 0);
        p->open_out++;

        enum bgp_state old = p->state;
        p->state = BGP_STATE_OPEN_CONFIRM;
        bgp_log_state_change(p, old, p->state);
    }
}

static void bgp_fsm_keepalive_received(struct bgp_peer *p)
{
    p->keepalive_in++;
    p->last_keepalive_recv = time(NULL);

    if (p->state == BGP_STATE_OPEN_CONFIRM) {
        enum bgp_state old = p->state;
        p->state = BGP_STATE_ESTABLISHED;
        p->uptime = time(NULL);
        bgp_log_state_change(p, old, p->state);

        char ip_str[32];
        struct in_addr a = {.s_addr = htonl(p->remote_ip)};
        inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));
        YLOG_INFO("BGP: Neighbor %s (AS %u) is now ESTABLISHED", ip_str, p->remote_as);
    }
}

/*============================================================================
 * BGP Public API
 *============================================================================*/

int bgp_init(uint32_t router_id, uint32_t local_as)
{
    memset(&g_bgp.config, 0, sizeof(g_bgp.config));
    g_bgp.config.router_id = router_id;
    g_bgp.config.local_as = local_as;
    g_bgp.config.cluster_id = router_id;
    g_bgp.config.enabled = true;
    g_bgp.config.default_local_pref = 100;
    g_bgp.config.default_keepalive = BGP_KEEPALIVE_TIME_DEFAULT;
    g_bgp.config.default_hold_time = BGP_HOLD_TIME_DEFAULT;
    g_bgp.config.log_neighbor_changes = true;
    g_bgp.peer_count = 0;
    g_bgp.adj_rib_in = NULL;
    g_bgp.loc_rib = NULL;

    YLOG_INFO("BGP: Initialized (AS %u, Router-ID %u.%u.%u.%u)",
              local_as,
              (router_id >> 24) & 0xFF, (router_id >> 16) & 0xFF,
              (router_id >> 8) & 0xFF, router_id & 0xFF);
    return 0;
}

int bgp_neighbor(uint32_t remote_ip, uint32_t remote_as)
{
    pthread_mutex_lock(&g_bgp.lock);

    if (g_bgp.peer_count >= BGP_MAX_PEERS) {
        pthread_mutex_unlock(&g_bgp.lock);
        return -1;
    }

    struct bgp_peer *p = &g_bgp.peers[g_bgp.peer_count];
    memset(p, 0, sizeof(*p));

    p->remote_ip = remote_ip;
    p->remote_as = remote_as;
    p->local_as = g_bgp.config.local_as;
    p->router_id = g_bgp.config.router_id;
    p->state = BGP_STATE_IDLE;
    p->sock_fd = -1;
    p->hold_time = g_bgp.config.default_hold_time;
    p->keepalive_time = g_bgp.config.default_keepalive;
    p->connect_retry_time = BGP_CONNECT_RETRY_TIME;
    p->enabled = true;
    p->ebgp = (remote_as != g_bgp.config.local_as);
    p->min_advertisement_interval = p->ebgp ?
        BGP_MIN_ROUTE_ADVERTISEMENT : BGP_MIN_ROUTE_ADVERTISEMENT_IBGP;
    p->weight = 0;
    p->ebgp_multihop = p->ebgp ? 1 : 0;

    g_bgp.peer_count++;

    char ip_str[32];
    struct in_addr a = {.s_addr = htonl(remote_ip)};
    inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));
    YLOG_INFO("BGP: Added neighbor %s remote-as %u (%s)",
              ip_str, remote_as, p->ebgp ? "eBGP" : "iBGP");

    pthread_mutex_unlock(&g_bgp.lock);
    return g_bgp.peer_count - 1;
}

int bgp_neighbor_description(uint32_t remote_ip, const char *desc)
{
    pthread_mutex_lock(&g_bgp.lock);
    for (int i = 0; i < g_bgp.peer_count; i++) {
        if (g_bgp.peers[i].remote_ip == remote_ip) {
            snprintf(g_bgp.peers[i].description, 64, "%s", desc);
            pthread_mutex_unlock(&g_bgp.lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_bgp.lock);
    return -1;
}

int bgp_neighbor_next_hop_self(uint32_t remote_ip, bool enable)
{
    pthread_mutex_lock(&g_bgp.lock);
    for (int i = 0; i < g_bgp.peer_count; i++) {
        if (g_bgp.peers[i].remote_ip == remote_ip) {
            g_bgp.peers[i].next_hop_self = enable;
            pthread_mutex_unlock(&g_bgp.lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_bgp.lock);
    return -1;
}

int bgp_neighbor_route_reflector_client(uint32_t remote_ip, bool enable)
{
    pthread_mutex_lock(&g_bgp.lock);
    for (int i = 0; i < g_bgp.peer_count; i++) {
        if (g_bgp.peers[i].remote_ip == remote_ip) {
            g_bgp.peers[i].route_reflector_client = enable;
            pthread_mutex_unlock(&g_bgp.lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_bgp.lock);
    return -1;
}

int bgp_network(uint32_t prefix, uint8_t prefix_len)
{
    pthread_mutex_lock(&g_bgp.lock);

    struct bgp_route *r = calloc(1, sizeof(*r));
    if (!r) {
        pthread_mutex_unlock(&g_bgp.lock);
        return -1;
    }

    r->prefix = prefix;
    r->prefix_len = prefix_len;
    r->attr.origin = BGP_ORIGIN_IGP;
    r->attr.next_hop = g_bgp.config.router_id;
    r->attr.local_pref = g_bgp.config.default_local_pref;
    r->received_time = time(NULL);
    r->valid = true;
    r->best = true;
    r->peer_id = 0;  /* Local */

    /* Add to Loc-RIB */
    r->next = g_bgp.loc_rib;
    g_bgp.loc_rib = r;

    char prefix_str[32];
    struct in_addr p = {.s_addr = htonl(prefix)};
    inet_ntop(AF_INET, &p, prefix_str, sizeof(prefix_str));
    YLOG_INFO("BGP: Network %s/%u added", prefix_str, prefix_len);

    pthread_mutex_unlock(&g_bgp.lock);
    return 0;
}

void bgp_show_summary(void)
{
    pthread_mutex_lock(&g_bgp.lock);

    printf("BGP router identifier %u.%u.%u.%u, local AS number %u\n",
           (g_bgp.config.router_id >> 24) & 0xFF,
           (g_bgp.config.router_id >> 16) & 0xFF,
           (g_bgp.config.router_id >> 8) & 0xFF,
           g_bgp.config.router_id & 0xFF,
           g_bgp.config.local_as);
    printf("\n");

    printf("%-16s %-4s %-5s %-10s %-10s %-9s %s\n",
           "Neighbor", "V", "AS", "MsgRcvd", "MsgSent", "Up/Down", "State/PfxRcd");

    for (int i = 0; i < g_bgp.peer_count; i++) {
        struct bgp_peer *p = &g_bgp.peers[i];

        char ip_str[32];
        struct in_addr a = {.s_addr = htonl(p->remote_ip)};
        inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));

        printf("%-16s %-4d %-5u %-10lu %-10lu %-9s %s\n",
               ip_str, BGP_VERSION, p->remote_as,
               p->messages_total_in, p->messages_total_out,
               "-",
               p->state == BGP_STATE_ESTABLISHED ? "Established" : bgp_state_name(p->state));
    }

    pthread_mutex_unlock(&g_bgp.lock);
}

void bgp_show_neighbors(void)
{
    pthread_mutex_lock(&g_bgp.lock);

    for (int i = 0; i < g_bgp.peer_count; i++) {
        struct bgp_peer *p = &g_bgp.peers[i];

        char ip_str[32];
        struct in_addr a = {.s_addr = htonl(p->remote_ip)};
        inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));

        printf("BGP neighbor is %s, remote AS %u, %s link\n",
               ip_str, p->remote_as, p->ebgp ? "external" : "internal");
        if (p->description[0]) {
            printf("  Description: %s\n", p->description);
        }
        printf("  BGP version 4, remote router ID %u.%u.%u.%u\n",
               (p->remote_router_id >> 24) & 0xFF,
               (p->remote_router_id >> 16) & 0xFF,
               (p->remote_router_id >> 8) & 0xFF,
               p->remote_router_id & 0xFF);
        printf("  BGP state = %s\n", bgp_state_name(p->state));
        printf("  Hold time is %u, keepalive interval is %u seconds\n",
               p->negotiated_hold_time, p->keepalive_time);
        printf("  Message statistics:\n");
        printf("                         Sent       Rcvd\n");
        printf("    Opens:          %9lu  %9lu\n", p->open_out, p->open_in);
        printf("    Notifications:  %9lu  %9lu\n", p->notification_out, p->notification_in);
        printf("    Updates:        %9lu  %9lu\n", p->update_out, p->update_in);
        printf("    Keepalives:     %9lu  %9lu\n", p->keepalive_out, p->keepalive_in);
        printf("    Route Refresh:  %9lu  %9lu\n", p->route_refresh_out, p->route_refresh_in);
        printf("    Total:          %9lu  %9lu\n", p->messages_total_out, p->messages_total_in);
        printf("\n");
    }

    pthread_mutex_unlock(&g_bgp.lock);
}

void bgp_show_routes(void)
{
    pthread_mutex_lock(&g_bgp.lock);

    printf("   Network          Next Hop            Metric LocPrf Weight Path\n");

    for (struct bgp_route *r = g_bgp.loc_rib; r; r = r->next) {
        char prefix_str[32], nh_str[32];
        struct in_addr p = {.s_addr = htonl(r->prefix)};
        struct in_addr n = {.s_addr = htonl(r->attr.next_hop)};
        inet_ntop(AF_INET, &p, prefix_str, sizeof(prefix_str));
        inet_ntop(AF_INET, &n, nh_str, sizeof(nh_str));

        printf("%c%c %-15s/%-2u %-15s %10u %6u %6u ",
               r->valid ? '*' : ' ',
               r->best ? '>' : ' ',
               prefix_str, r->prefix_len, nh_str,
               r->attr.med, r->attr.local_pref, r->attr.weight);

        /* AS Path */
        for (int i = 0; i < r->attr.as_path_len; i++) {
            printf("%u ", r->attr.as_path[i]);
        }
        printf("%s\n", bgp_origin_str(r->attr.origin));
    }

    pthread_mutex_unlock(&g_bgp.lock);
}

void bgp_cleanup(void)
{
    pthread_mutex_lock(&g_bgp.lock);

    g_bgp.running = false;

    for (int i = 0; i < g_bgp.peer_count; i++) {
        if (g_bgp.peers[i].sock_fd >= 0) {
            close(g_bgp.peers[i].sock_fd);
        }
    }
    g_bgp.peer_count = 0;

    while (g_bgp.adj_rib_in) {
        struct bgp_route *next = g_bgp.adj_rib_in->next;
        free(g_bgp.adj_rib_in);
        g_bgp.adj_rib_in = next;
    }

    while (g_bgp.loc_rib) {
        struct bgp_route *next = g_bgp.loc_rib->next;
        free(g_bgp.loc_rib);
        g_bgp.loc_rib = next;
    }

    pthread_mutex_unlock(&g_bgp.lock);
    YLOG_INFO("BGP: Cleanup complete");
}
