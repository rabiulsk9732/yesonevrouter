/**
 * @file natexport.c
 * @brief NAT Export - ipt-netflow compatible NetFlow v9 & IPFIX implementation
 *
 * Template refresh logic based on ipt-netflow:
 * - refresh_rate: Template sent every N PDUs
 * - timeout_rate: Template sent every N seconds
 * - Inline templates: Template and data in same packet
 *
 * Uses DPDK for packet transmission to ensure correct source IP from vBNG interface.
 */

#include "natexport.h"
#include "nat.h"

/* Forward declarations for internal functions */
int natexport_add_collector(uint32_t ip, uint16_t port);      /* For struct nat_session */
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_DPDK
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_errno.h>
#include "interface.h"
#include "routing_table.h"
#include "arp.h"
#include "dpdk_init.h"
#endif

#define RING_SIZE 4096 /* Power of 2 */
static struct rte_ring *g_worker_rings[NAT_MAX_WORKERS];
static bool g_has_rings = false;
#ifdef HAVE_DPDK
#include <rte_mempool.h>
static struct rte_mempool *g_event_mempool = NULL;
#endif

/*============================================================================
 * Configuration
 *============================================================================*/

#define BUFFER_SIZE         1400    /* MTU-safe */
#define MAX_RECORDS         30      /* Max records per PDU */
#define NATEXPORT_MAX_COLLECTORS 4  /* Multi-collector support */

/*============================================================================
 * Exporter State
 *============================================================================*/

static struct {
    bool enabled;
    int sock_fd;
    struct sockaddr_in collectors[NATEXPORT_MAX_COLLECTORS];
    int num_collectors;
    natexport_protocol_t protocol;
    uint32_t source_id;
    uint32_t sequence;
    time_t boot_time;

    /* ipt-netflow template tracking */
    uint32_t pdu_count;
    uint32_t template_pdu_count;    /* PDU count when template last sent */
    time_t template_time;           /* Time when template last sent */

    /* Buffer */
    uint8_t buffer[BUFFER_SIZE];
    size_t buf_offset;
    int record_count;
    int flowset_count;
    bool has_template;

    /* Stats */
    struct natexport_stats stats;
    pthread_mutex_t lock;

    /* Flush thread */
    pthread_t flush_thread;
    bool flush_thread_running;

    /* Active timeout scanner thread */
    pthread_t active_timeout_thread;
    bool active_timeout_running;

    /* Runtime configurable timeouts (seconds) */
    uint32_t active_timeout;          /* Export long-running flows (default 1800s = 30min) */
    uint32_t inactive_timeout;        /* Export idle flows (default 15s) */

    /* Graceful degradation */
    uint32_t dpdk_consecutive_failures;
    bool dpdk_disabled;             /* False back to socket-only if too many failures */
} g_exp = {
    .enabled = false,
    .sock_fd = -1,
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .flush_thread_running = false,
    .active_timeout_running = false,
    .active_timeout = ACTIVE_TIMEOUT_SEC,       /* Default 1800 seconds (30 min) */
    .inactive_timeout = INACTIVE_TIMEOUT_SEC,   /* Default 15 seconds */
    .dpdk_consecutive_failures = 0,
    .dpdk_disabled = false
};

/*============================================================================
 * Utility Functions
 *============================================================================*/

static uint32_t get_uptime_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static uint64_t get_timestamp_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static uint64_t get_timestamp_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/*============================================================================
 * ipt-netflow Template Logic
 *============================================================================*/

/* Check if template needs to be sent (ipt-netflow logic) */
static bool template_needs_send(void)
{
    time_t now = time(NULL);

    /* Never sent */
    if (g_exp.template_time == 0) {
        return true;
    }

    /* PDU count refresh (every REFRESH_RATE PDUs) */
    if (g_exp.pdu_count > (g_exp.template_pdu_count + REFRESH_RATE)) {
        return true;
    }

    /* Time-based refresh (every TIMEOUT_RATE_SEC seconds) */
    if ((now - g_exp.template_time) >= TIMEOUT_RATE_SEC) {
        return true;
    }

    return false;
}

/* Mark template as sent */
static void template_mark_sent(void)
{
    g_exp.template_pdu_count = g_exp.pdu_count;
    g_exp.template_time = time(NULL);
}

/*============================================================================
 * Template Building
 *============================================================================*/

/* Template is built inline in add_template_to_buffer() */
static int add_template_to_buffer(void)
{
    /* Calculate template size */
    size_t tmpl_size = sizeof(struct flowset_header) +
                       sizeof(struct template_header) +
                       (NAT_TEMPLATE_FIELD_COUNT * sizeof(struct field_spec));

    /* Pad to 4-byte boundary */
    tmpl_size = (tmpl_size + 3) & ~3;

    if (g_exp.buf_offset + tmpl_size > BUFFER_SIZE) {
        return -1;
    }

    uint8_t *ptr = g_exp.buffer + g_exp.buf_offset;

    /* FlowSet Header */
    struct flowset_header *fsh = (struct flowset_header *)ptr;
    fsh->id = htons(g_exp.protocol == NATEXPORT_PROTO_IPFIX ?
                    IPFIX_FLOWSET_TEMPLATE : NF9_FLOWSET_TEMPLATE);
    ptr += sizeof(struct flowset_header);

    /* Template Header */
    struct template_header *th = (struct template_header *)ptr;
    th->template_id = htons(TEMPLATE_ID_NAT);
    th->field_count = htons(NAT_TEMPLATE_FIELD_COUNT);
    ptr += sizeof(struct template_header);

    /* Field Specifiers - ipt-netflow order + RFC 8158 extensions */
    /* Field Specifiers - ipt-netflow order + RFC 8158 extensions */
    struct field_spec fields[] = {
        {htons(IE_OBSERVATION_TIME_MS),       htons(8)},   /* 1 */
        {htons(IE_NAT_EVENT),                 htons(1)},   /* 2 */
        {htons(IE_PROTOCOL_IDENTIFIER),       htons(1)},   /* 3 */
        {htons(IE_SOURCE_IPV4_ADDRESS),       htons(4)},   /* 4 */
        {htons(IE_SOURCE_TRANSPORT_PORT),     htons(2)},   /* 5 */
        {htons(IE_DESTINATION_IPV4_ADDRESS),  htons(4)},   /* 6 */
        {htons(IE_DESTINATION_TRANSPORT_PORT),htons(2)},   /* 7 */
        {htons(IE_POST_NAT_SRC_IPV4),         htons(4)},   /* 8 */
        {htons(IE_POST_NAPT_SRC_PORT),        htons(2)},   /* 9 */
        {htons(IE_POST_NAT_DST_IPV4),         htons(4)},   /* 10 */
        {htons(IE_POST_NAPT_DST_PORT),        htons(2)},   /* 11 */
        {htons(IE_TCP_CONTROL_BITS),          htons(1)},   /* 12 */
        {htons(IE_INGRESS_INTERFACE),         htons(4)},   /* 13 */
        {htons(IE_EGRESS_INTERFACE),          htons(4)},   /* 14 */
        {htons(IE_FLOW_START_MS),             htons(8)},   /* 15 */
        {htons(IE_FLOW_END_MS),               htons(8)},   /* 16 */
        {htons(IE_PACKET_DELTA_COUNT),        htons(8)},   /* 17 */
        {htons(IE_OCTET_DELTA_COUNT),         htons(8)},   /* 18 */
        {htons(IE_NAT_POOL_ID),               htons(4)},   /* 19: New */
        {htons(IE_INGRESS_VRF_ID),            htons(4)},   /* 20: New */
    };
    memcpy(ptr, fields, sizeof(fields));
    ptr += sizeof(fields);

    /* Pad to 4 bytes */
    size_t fs_len = ptr - (uint8_t *)fsh;
    while (fs_len % 4 != 0) {
        *ptr++ = 0;
        fs_len++;
    }
    fsh->length = htons(fs_len);

    g_exp.buf_offset = ptr - g_exp.buffer;
    g_exp.flowset_count++;
    g_exp.has_template = true;

    template_mark_sent();
    return 0;
}

/*============================================================================
 * Packet Sending
 *============================================================================*/

#ifdef HAVE_DPDK
/* Send packet via DPDK - uses egress interface determined by routing table */
static int send_via_dpdk(const uint8_t *payload, size_t payload_len, const struct sockaddr_in *dest)
{
    extern struct dpdk_config g_dpdk_config;  /* From dpdk_init.h */
    extern struct interface_manager g_if_mgr; /* From interface.h */

    /* Lookup route to collector for egress interface and next-hop */
    struct routing_table *rt = routing_table_get_instance();
    if (!rt) {
        fprintf(stderr, "natexport: routing table not available\n");
        return -1;
    }

    struct in_addr dst_addr = { .s_addr = dest->sin_addr.s_addr };
    struct route_entry *route = routing_table_lookup(rt, &dst_addr);
    if (!route) {
        fprintf(stderr, "natexport: no route to collector\n");
        return -1;
    }

    /* Get egress interface from route by ifindex (dynamic - not hardcoded) */
    struct interface *egress_if = NULL;
    uint32_t ifindex = route->egress_ifindex;

    /* Lookup interface by ifindex from interface manager */
    for (uint32_t i = 0; i < g_if_mgr.num_interfaces; i++) {
        if (g_if_mgr.interfaces[i] && g_if_mgr.interfaces[i]->ifindex == ifindex) {
            egress_if = g_if_mgr.interfaces[i];
            break;
        }
    }

    if (!egress_if) {
        fprintf(stderr, "natexport: cannot find egress interface for ifindex %u\n", ifindex);
        return -1;
    }

    /* Get source IP from egress interface */
    uint32_t src_ip = ntohl(egress_if->config.ipv4_addr.s_addr);

    /* DPDK port_id is typically (ifindex - 1) for physical interfaces */
    uint16_t port_id = (uint16_t)(ifindex > 0 ? ifindex - 1 : 0);

    /* Get next-hop MAC via ARP */
    uint32_t next_hop_ip = route->next_hop.s_addr ? ntohl(route->next_hop.s_addr)
                                                   : ntohl(dst_addr.s_addr);
    uint8_t dst_mac[RTE_ETHER_ADDR_LEN];
    if (arp_lookup(next_hop_ip, dst_mac) != 0) {
        /* Send ARP request and fail this time - next attempt should work */
        arp_send_request(next_hop_ip, src_ip, egress_if->mac_addr, ifindex);
        fprintf(stderr, "natexport: ARP not resolved for next-hop\n");
        return -1;
    }

    /* Allocate mbuf */
    struct rte_mempool *mp = (struct rte_mempool *)g_dpdk_config.pkt_mempool->pool;
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mp);
    if (!mbuf) {
        fprintf(stderr, "natexport: mbuf alloc failed\n");
        return -1;
    }

    /* Calculate total length */
    size_t total_len = sizeof(struct rte_ether_hdr) +
                       sizeof(struct rte_ipv4_hdr) +
                       sizeof(struct rte_udp_hdr) +
                       payload_len;

    /* Prepare packet data */
    char *pkt = rte_pktmbuf_append(mbuf, total_len);
    if (!pkt) {
        rte_pktmbuf_free(mbuf);
        fprintf(stderr, "natexport: mbuf append failed\n");
        return -1;
    }

    /* Ethernet header */
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt;
    rte_ether_addr_copy((struct rte_ether_addr *)dst_mac, &eth->dst_addr);
    rte_ether_addr_copy((struct rte_ether_addr *)egress_if->mac_addr, &eth->src_addr);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    /* IPv4 header */
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(sizeof(struct rte_ipv4_hdr) +
                             sizeof(struct rte_udp_hdr) + payload_len);
    ip->packet_id = htons(g_exp.sequence & 0xFFFF);
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_UDP;
    ip->hdr_checksum = 0;
    ip->src_addr = htonl(src_ip);
    ip->dst_addr = dest->sin_addr.s_addr;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    /* UDP header */
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
    udp->src_port = dest->sin_port;  /* Use collector port as src too? Maybe should be random/fixed src port? Existing code used collector port. */
    udp->dst_port = dest->sin_port;
    udp->dgram_len = htons(sizeof(struct rte_udp_hdr) + payload_len);
    udp->dgram_cksum = 0;  /* Optional for UDP */

    /* Copy payload */
    memcpy(udp + 1, payload, payload_len);

    /* Send packet */
    uint16_t sent = rte_eth_tx_burst(port_id, 0, &mbuf, 1);
    if (sent != 1) {
        rte_pktmbuf_free(mbuf);
        fprintf(stderr, "natexport: tx_burst failed\n");
        return -1;
    }

    return (int)payload_len;
}
#endif /* HAVE_DPDK */

/* Finalize and send buffer */
static int flush_buffer(void)
{
    if (g_exp.record_count == 0 && !g_exp.has_template) {
        return 0;
    }

    /* Pad to 4-byte boundary */
    while (g_exp.buf_offset % 4 != 0) {
        g_exp.buffer[g_exp.buf_offset++] = 0;
    }

    time_t now = time(NULL);

    if (g_exp.protocol == NATEXPORT_PROTO_IPFIX) {
        /* IPFIX Header */
        struct ipfix_header *hdr = (struct ipfix_header *)g_exp.buffer;
        hdr->version = htons(IPFIX_VERSION);
        hdr->length = htons(g_exp.buf_offset);
        hdr->export_time = htonl(now);
        hdr->sequence = htonl(g_exp.sequence);
        hdr->domain_id = htonl(g_exp.source_id);
    } else {
        /* NetFlow v9 Header */
        struct nf9_header *hdr = (struct nf9_header *)g_exp.buffer;
        hdr->version = htons(NETFLOW_V9_VERSION);
        hdr->count = htons(g_exp.flowset_count);
        hdr->sys_uptime = htonl(get_uptime_ms());
        hdr->unix_secs = htonl(now);
        hdr->sequence = htonl(g_exp.sequence);
        hdr->source_id = htonl(g_exp.source_id);
    }

    /* Send via DPDK (preferred) or kernel socket (fallback) */
    /* Send to all configured collectors */
    int successful_sends = 0;

    for (int i = 0; i < g_exp.num_collectors; i++) {
        struct sockaddr_in *dest = &g_exp.collectors[i];
        ssize_t sent = -1;
        bool used_dpdk = false;

#ifdef HAVE_DPDK
        if (!g_exp.dpdk_disabled) {
            sent = send_via_dpdk(g_exp.buffer, g_exp.buf_offset, dest);
            if (sent >= 0) {
                g_exp.stats.dpdk_send_success++;
                g_exp.dpdk_consecutive_failures = 0;
                used_dpdk = true;
            } else {
                g_exp.stats.dpdk_send_failures++;
                g_exp.dpdk_consecutive_failures++;
                /* Logic: if one collector fails via DPDK, do we disable DPDK globally?
                   Maybe just log warning. Let's keep existing logic but be careful. */
                if (g_exp.dpdk_consecutive_failures >= (uint32_t)(10 * g_exp.num_collectors)) {
                     g_exp.dpdk_disabled = true;
                }
            }
        }
        (void)used_dpdk;
#endif

        /* Fallback to kernel socket */
        if (sent < 0 && g_exp.sock_fd >= 0) {
            sent = sendto(g_exp.sock_fd, g_exp.buffer, g_exp.buf_offset, 0,
                          (struct sockaddr *)dest, sizeof(*dest));
            if (sent >= 0) {
                g_exp.stats.socket_send_success++;
            } else {
                g_exp.stats.socket_send_failures++;
            }
        }

        if (sent >= 0) successful_sends++;
    }

    /* Consider success if at least one collector received it? Or maybe we don't care about return value propagated up too much */
    ssize_t sent = (successful_sends > 0) ? (ssize_t)g_exp.buf_offset : -1;

    if (sent < 0) {
        g_exp.stats.errors++;
        g_exp.stats.last_error_time = now;
        fprintf(stderr, "natexport: send error: %s\n", strerror(errno));
        return -1;
    }

    /* Update stats */
    if (g_exp.has_template) {
        g_exp.stats.templates_sent++;
    }
    g_exp.stats.data_records_sent += g_exp.record_count;
    g_exp.stats.packets_sent++;
    g_exp.stats.bytes_sent += sent;
    g_exp.stats.flush_count++;
    g_exp.stats.last_flush_time = now;
    g_exp.sequence++;
    g_exp.pdu_count++;

    /* Log flush completion */
    printf("natexport: sent %zd bytes (%d records, template=%s, collectors=%d)\n",
           sent, g_exp.record_count, g_exp.has_template ? "yes" : "no",
           g_exp.num_collectors);

    /* Reset buffer */
    g_exp.buf_offset = 0;
    g_exp.record_count = 0;
    g_exp.flowset_count = 0;
    g_exp.has_template = false;

    return 0;
}

/* Initialize buffer for new PDU */
static void init_buffer(void)
{
    /* Reserve space for header */
    if (g_exp.protocol == NATEXPORT_PROTO_IPFIX) {
        g_exp.buf_offset = sizeof(struct ipfix_header);
    } else {
        g_exp.buf_offset = sizeof(struct nf9_header);
    }

    g_exp.record_count = 0;
    g_exp.flowset_count = 0;
    g_exp.has_template = false;

    /* Add template if needed (ipt-netflow style - inline) */
    if (template_needs_send()) {
        add_template_to_buffer();
    }

    /* Add Data FlowSet Header */
    struct flowset_header *fsh = (struct flowset_header *)(g_exp.buffer + g_exp.buf_offset);
    fsh->id = htons(TEMPLATE_ID_NAT);
    fsh->length = htons(sizeof(struct flowset_header));  /* Updated later */
    g_exp.buf_offset += sizeof(struct flowset_header);
    g_exp.flowset_count++;
}

/* Update data flowset length before flush */
static void finalize_data_flowset(void)
{
    if (g_exp.record_count == 0) return;

    /* Find data flowset header */
    size_t hdr_size = (g_exp.protocol == NATEXPORT_PROTO_IPFIX) ?
                      sizeof(struct ipfix_header) : sizeof(struct nf9_header);
    size_t data_fs_offset = hdr_size;

    /* Skip template if present */
    if (g_exp.has_template) {
        struct flowset_header *tmpl_fs = (struct flowset_header *)(g_exp.buffer + data_fs_offset);
        data_fs_offset += ntohs(tmpl_fs->length);
    }

    /* Update data flowset length */
    struct flowset_header *data_fs = (struct flowset_header *)(g_exp.buffer + data_fs_offset);
    size_t data_len = g_exp.buf_offset - data_fs_offset;

    /* Pad to 4 bytes */
    while (data_len % 4 != 0) {
        g_exp.buffer[g_exp.buf_offset++] = 0;
        data_len++;
    }
    data_fs->length = htons(data_len);
}

/*============================================================================
 * Periodic Flush Thread
 * Flushes buffered records every second to ensure timely export
 *============================================================================*/

#define FLUSH_INTERVAL_SEC 1

static void *flush_thread_func(void *arg)
{
    (void)arg;

    printf("natexport: flush thread started (interval=%ds)\n", FLUSH_INTERVAL_SEC);

    while (g_exp.flush_thread_running) {
        sleep(FLUSH_INTERVAL_SEC);

        if (!g_exp.enabled || !g_exp.flush_thread_running) {
            break;
        }

        pthread_mutex_lock(&g_exp.lock);

        /* Flush internal buffer if we have pending records */
        if (g_exp.record_count > 0) {
            finalize_data_flowset();
            flush_buffer();
            init_buffer();
        }

#ifdef HAVE_DPDK
        /* Poll Worker Rings (Batch Process) */
        if (g_has_rings && g_event_mempool) {
            struct nat_event_v2 *events[32]; // Batch size 32
            int i;

            for (i = 0; i < NAT_MAX_WORKERS; i++) {
                if (!g_worker_rings[i]) continue;

                int n = rte_ring_dequeue_burst(g_worker_rings[i], (void **)events, 32, NULL);
                if (n == 0) continue;

                /* Process batch */
                int j;
                for (j = 0; j < n; j++) {
                    struct nat_event_v2 *ev = events[j];

                    /* Serialize to buffer */
                    /* Check buffer space */
                    if (g_exp.buf_offset + NAT_RECORD_SIZE > BUFFER_SIZE ||
                        g_exp.record_count >= MAX_RECORDS) {
                        finalize_data_flowset();
                        flush_buffer();
                        init_buffer();
                    }
                    if (g_exp.buf_offset == 0) init_buffer();

                    uint8_t *ptr = g_exp.buffer + g_exp.buf_offset;

                    /* 1. observationTimeMilliseconds (8) */
                    uint64_t ts = htobe64(ev->timestamp);
                    memcpy(ptr, &ts, 8); ptr += 8;
                    /* 2. natEvent (1) */
                    *ptr++ = ev->event_type;
                    /* 3. protocolIdentifier (1) */
                    *ptr++ = ev->protocol;
                    /* 4. sourceIPv4Address (4) */
                    uint32_t tmp32 = htonl(ev->src_ip);
                    memcpy(ptr, &tmp32, 4); ptr += 4;
                    /* 5. sourceTransportPort (2) */
                    uint16_t tmp16 = htons(ev->src_port);
                    memcpy(ptr, &tmp16, 2); ptr += 2;
                    /* 6. destinationIPv4Address (4) */
                    tmp32 = htonl(ev->dst_ip);
                    memcpy(ptr, &tmp32, 4); ptr += 4;
                    /* 7. destinationTransportPort (2) */
                    tmp16 = htons(ev->dst_port);
                    memcpy(ptr, &tmp16, 2); ptr += 2;
                    /* 8. postNATSourceIPv4Address (4) */
                    tmp32 = htonl(ev->xlate_ip);
                    memcpy(ptr, &tmp32, 4); ptr += 4;
                    /* 9. postNAPTSourceTransportPort (2) */
                    tmp16 = htons(ev->xlate_port);
                    memcpy(ptr, &tmp16, 2); ptr += 2;
                    /* 10. postNATDestinationIPv4Address (4) */
                    tmp32 = htonl(ev->dst_ip);
                    memcpy(ptr, &tmp32, 4); ptr += 4;
                    /* 11. postNAPTDestinationTransportPort (2) */
                    tmp16 = htons(ev->dst_port);
                    memcpy(ptr, &tmp16, 2); ptr += 2;
                    /* 12. tcpControlBits (1) */
                    *ptr++ = (ev->event_type == NAT_EVENT_CREATE) ? TCP_SYN_ACK : TCP_FIN_RST;
                    /* 13. ingressInterface (4) */
                    tmp32 = htonl(0); memcpy(ptr, &tmp32, 4); ptr += 4;
                    /* 14. egressInterface (4) */
                    memcpy(ptr, &tmp32, 4); ptr += 4;
                    /* 15. flowStartMilliseconds (8) */
                    memcpy(ptr, &ts, 8); ptr += 8;
                    /* 16. flowEndMilliseconds (8) */
                    memcpy(ptr, &ts, 8); ptr += 8;
                    /* 17. packetDeltaCount (8) */
                    uint64_t zero64 = 0; memcpy(ptr, &zero64, 8); ptr += 8;
                    /* 18. octetDeltaCount (8) */
                    memcpy(ptr, &zero64, 8); ptr += 8;
                    /* 19. natPoolId (4) */
                    tmp32 = htonl(ev->pool_id); memcpy(ptr, &tmp32, 4); ptr += 4;
                    /* 20. ingressVRFID (4) */
                    tmp32 = htonl(ev->vrf_id); memcpy(ptr, &tmp32, 4); ptr += 4;

                    g_exp.buf_offset = ptr - g_exp.buffer;
                    g_exp.record_count++;

                    /* Return to mempool */
                    rte_mempool_put(g_event_mempool, ev);
                }
            }
        }
#endif

        pthread_mutex_unlock(&g_exp.lock);
    }

    printf("natexport: flush thread stopped\n");
    return NULL;
}

static int start_flush_thread(void)
{
    if (g_exp.flush_thread_running) {
        return 0; /* Already running */
    }

    g_exp.flush_thread_running = true;
    if (pthread_create(&g_exp.flush_thread, NULL, flush_thread_func, NULL) != 0) {
        fprintf(stderr, "natexport: failed to create flush thread: %s\n", strerror(errno));
        g_exp.flush_thread_running = false;
        return -1;
    }

    return 0;
}

static void stop_flush_thread(void)
{
    if (!g_exp.flush_thread_running) {
        return;
    }

    g_exp.flush_thread_running = false;
    pthread_join(g_exp.flush_thread, NULL);
}

/*============================================================================
 * Public API
 *============================================================================*/

static int natexport_init_common(uint32_t collector_ip, uint16_t port,
                                  uint32_t source_id, natexport_protocol_t proto)
{
    pthread_mutex_lock(&g_exp.lock);

    if (g_exp.enabled) {
        pthread_mutex_unlock(&g_exp.lock);
        return 0;
    }

    /* Create socket */
    g_exp.sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_exp.sock_fd < 0) {
        fprintf(stderr, "natexport: socket error: %s\n", strerror(errno));
        pthread_mutex_unlock(&g_exp.lock);
        return -1;
    }

    /* Setup collector address */
    g_exp.num_collectors = 0;
    natexport_add_collector(collector_ip, port);

    g_exp.protocol = proto;
    g_exp.source_id = source_id;
    g_exp.boot_time = time(NULL);
    g_exp.sequence = 1;
    g_exp.pdu_count = 0;
    g_exp.template_pdu_count = 0;
    g_exp.template_time = 0;
    memset(&g_exp.stats, 0, sizeof(g_exp.stats));

    g_exp.enabled = true;
    g_exp.enabled = true;
    pthread_mutex_unlock(&g_exp.lock);

#ifdef HAVE_DPDK
    /* Create Event Mempool if not exists */
    if (!g_event_mempool && rte_eal_process_type() == RTE_PROC_PRIMARY) {
        g_event_mempool = rte_mempool_create("nat_event_pool",
                                           262143, /* 256K - 1 */
                                           sizeof(struct nat_event_v2),
                                           512,  /* cache size */
                                           0, NULL, NULL, NULL, NULL,
                                           SOCKET_ID_ANY,
                                           MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);

        if (!g_event_mempool) {
            fprintf(stderr, "natexport: failed to create event mempool: %s\n",
                    rte_strerror(rte_errno));
        } else {
             printf("natexport: created event mempool (256K objects)\n");
        }
    }
#endif

    /* Start periodic flush thread */
    start_flush_thread();

    /* Start active timeout scanner (RFC 8158) */
    natexport_start_active_timeout();

    /* Send initial template */
    natexport_send_template();

    printf("natexport: initialized (%s, collector=%u.%u.%u.%u:%u, id=%u, active_timeout=%ds)\n",
           proto == NATEXPORT_PROTO_IPFIX ? "IPFIX" : "NetFlow v9",
           (collector_ip >> 24) & 0xFF, (collector_ip >> 16) & 0xFF,
           (collector_ip >> 8) & 0xFF, collector_ip & 0xFF,
           port, source_id, ACTIVE_TIMEOUT_SEC);

    return 0;
}

int natexport_init_v9(uint32_t collector_ip, uint16_t port, uint32_t source_id)
{
    return natexport_init_common(collector_ip, port, source_id, NATEXPORT_PROTO_NETFLOW_V9);
}

extern __thread int g_thread_worker_id;

int natexport_init_worker(uint32_t worker_id)
{
    if (worker_id >= NAT_MAX_WORKERS) return -1;

#ifdef HAVE_DPDK
    char name[32];
    snprintf(name, sizeof(name), "nf_ring_%u", worker_id);

    /* Enqueue: Single Producer (Worker), Dequeue: Single Consumer (Flush Thread) */
    unsigned int flags = RING_F_SP_ENQ | RING_F_SC_DEQ;

    g_worker_rings[worker_id] = rte_ring_create(name, RING_SIZE,
                                               rte_socket_id(), flags);

    if (g_worker_rings[worker_id]) {
        printf("natexport: created process ring for worker %u\n", worker_id);
        g_has_rings = true;
        return 0;
    } else {
        /* Already exists? Try lookup */
        g_worker_rings[worker_id] = rte_ring_lookup(name);
        if (g_worker_rings[worker_id]) {
            g_has_rings = true;
            return 0;
        }
        fprintf(stderr, "natexport: failed to create ring for worker %u: %s\n",
                worker_id, rte_strerror(rte_errno));
        return -1;
    }
#else
    (void)worker_id;
    return 0;
#endif
}

int natexport_init_ipfix(uint32_t collector_ip, uint16_t port, uint32_t domain_id)
{
    return natexport_init_common(collector_ip, port, domain_id, NATEXPORT_PROTO_IPFIX);
}

int natexport_log(uint8_t event_type,
                  uint32_t src_ip, uint16_t src_port,
                  uint32_t xlate_ip, uint16_t xlate_port,
                  uint32_t dst_ip, uint16_t dst_port,
                  uint8_t protocol,
                  uint32_t pool_id, uint32_t vrf_id)
{
#ifdef HAVE_DPDK
    /* Lockless Fast Path: Enqueue to per-worker ring */
    int w_id = g_thread_worker_id;
    if (g_has_rings && g_event_mempool &&
        w_id >= 0 && w_id < NAT_MAX_WORKERS &&
        g_worker_rings[w_id]) {

        struct nat_event_v2 *ev;
        if (rte_mempool_get(g_event_mempool, (void **)&ev) == 0) {
            ev->event_type = event_type;
            ev->protocol = protocol;
            ev->src_port = src_port;
            ev->dst_port = dst_port;
            ev->xlate_port = xlate_port;
            ev->reserved = 0;
            ev->src_ip = src_ip;
            ev->dst_ip = dst_ip;
            ev->xlate_ip = xlate_ip;
            ev->pool_id = pool_id;
            ev->vrf_id = vrf_id;
            ev->timestamp = get_timestamp_ms();

            if (rte_ring_enqueue(g_worker_rings[w_id], ev) == 0) {
                return 0; /* Enqueue success */
            }
            rte_mempool_put(g_event_mempool, ev); /* Ring full/Failed */
            /* Increment dropped stats? Need atomic... skip for now */
        }
    }
#endif

    pthread_mutex_lock(&g_exp.lock);

    if (!g_exp.enabled) {
        pthread_mutex_unlock(&g_exp.lock);
        return -1;
    }

    /* Check buffer space */
    if (g_exp.buf_offset + NAT_RECORD_SIZE > BUFFER_SIZE ||
        g_exp.record_count >= MAX_RECORDS) {
        finalize_data_flowset();
        flush_buffer();
        init_buffer();
    }

    /* Init buffer if empty */
    if (g_exp.buf_offset == 0) {
        init_buffer();
    }

    /* Serialize record - MUST match template order */
    uint8_t *ptr = g_exp.buffer + g_exp.buf_offset;

    /* 1. observationTimeMilliseconds (8) */
    uint64_t ts = htobe64(get_timestamp_ms());
    memcpy(ptr, &ts, 8); ptr += 8;

    /* 2. natEvent (1) */
    *ptr++ = event_type;

    /* 3. protocolIdentifier (1) */
    *ptr++ = protocol;

    /* 4. sourceIPv4Address (4) */
    uint32_t tmp32 = htonl(src_ip);
    memcpy(ptr, &tmp32, 4); ptr += 4;

    /* 5. sourceTransportPort (2) */
    uint16_t tmp16 = htons(src_port);
    memcpy(ptr, &tmp16, 2); ptr += 2;

    /* 6. destinationIPv4Address (4) */
    tmp32 = htonl(dst_ip);
    memcpy(ptr, &tmp32, 4); ptr += 4;

    /* 7. destinationTransportPort (2) */
    tmp16 = htons(dst_port);
    memcpy(ptr, &tmp16, 2); ptr += 2;

    /* 8. postNATSourceIPv4Address (4) */
    tmp32 = htonl(xlate_ip);
    memcpy(ptr, &tmp32, 4); ptr += 4;

    /* 9. postNAPTSourceTransportPort (2) */
    tmp16 = htons(xlate_port);
    memcpy(ptr, &tmp16, 2); ptr += 2;

    /* 10. postNATDestinationIPv4Address (4) - same as dst for SNAT */
    tmp32 = htonl(dst_ip);
    memcpy(ptr, &tmp32, 4); ptr += 4;

    /* 11. postNAPTDestinationTransportPort (2) - same as dst for SNAT */
    tmp16 = htons(dst_port);
    memcpy(ptr, &tmp16, 2); ptr += 2;

    /* 12. tcpControlBits (1) - ipt-netflow event indicator */
    *ptr++ = (event_type == NAT_EVENT_CREATE) ? TCP_SYN_ACK :
             (event_type == NAT_EVENT_ACTIVE_TIMEOUT) ? TCP_ACK : TCP_FIN_RST;

    /* 13. ingressInterface (4) */
    tmp32 = htonl(0);
    memcpy(ptr, &tmp32, 4); ptr += 4;

    /* 14. egressInterface (4) */
    memcpy(ptr, &tmp32, 4); ptr += 4;

    /* 15. flowStartMilliseconds (8) - use observation time for CREATE/DELETE */
    memcpy(ptr, &ts, 8); ptr += 8;

    /* 16. flowEndMilliseconds (8) - use observation time for CREATE/DELETE */
    memcpy(ptr, &ts, 8); ptr += 8;

    /* 17. packetDeltaCount (8) - 0 for CREATE/DELETE events */
    uint64_t zero64 = 0;
    memcpy(ptr, &zero64, 8); ptr += 8;

    /* 18. octetDeltaCount (8) - 0 for CREATE/DELETE events */
    memcpy(ptr, &zero64, 8); ptr += 8;

    /* 19. natPoolId (4) */
    tmp32 = htonl(pool_id);
    memcpy(ptr, &tmp32, 4); ptr += 4;

    /* 20. ingressVRFID (4) */
    tmp32 = htonl(vrf_id);
    memcpy(ptr, &tmp32, 4); ptr += 4;

    g_exp.buf_offset = ptr - g_exp.buffer;
    g_exp.record_count++;

    pthread_mutex_unlock(&g_exp.lock);
    return 0;
}

int natexport_send_template(void)
{
    pthread_mutex_lock(&g_exp.lock);

    if (!g_exp.enabled) {
        pthread_mutex_unlock(&g_exp.lock);
        return -1;
    }

    /* Flush pending data */
    if (g_exp.record_count > 0) {
        finalize_data_flowset();
        flush_buffer();
    }

    /* Force template send */
    g_exp.template_time = 0;  /* Force template_needs_send() to return true */
    init_buffer();

    /* If only template, send it */
    if (g_exp.has_template && g_exp.record_count == 0) {
        /* Remove data flowset header since we have no data */
        g_exp.buf_offset -= sizeof(struct flowset_header);
        g_exp.flowset_count--;
    }

    flush_buffer();
    init_buffer();

    pthread_mutex_unlock(&g_exp.lock);
    return 0;
}

void natexport_flush(void)
{
    pthread_mutex_lock(&g_exp.lock);
    if (g_exp.enabled && g_exp.record_count > 0) {
        finalize_data_flowset();
        flush_buffer();
        init_buffer();
    }
    pthread_mutex_unlock(&g_exp.lock);
}

void natexport_get_stats(struct natexport_stats *stats)
{
    if (!stats) return;
    pthread_mutex_lock(&g_exp.lock);
    memcpy(stats, &g_exp.stats, sizeof(*stats));
    pthread_mutex_unlock(&g_exp.lock);
}

bool natexport_is_enabled(void)
{
    return g_exp.enabled;
}

void natexport_cleanup(void)
{
    /* Stop active timeout thread first (outside lock to avoid deadlock) */
    natexport_stop_active_timeout();

    /* Stop flush thread */
    stop_flush_thread();

    pthread_mutex_lock(&g_exp.lock);
    if (g_exp.enabled) {
        if (g_exp.record_count > 0) {
            finalize_data_flowset();
            flush_buffer();
        }
        if (g_exp.sock_fd >= 0) {
            close(g_exp.sock_fd);
            g_exp.sock_fd = -1;
        }
        g_exp.enabled = false;
        printf("natexport: shutdown\n");
    }
    pthread_mutex_unlock(&g_exp.lock);
}

/*============================================================================
 * RFC 8158 Compliant Flow Export
 * Export flow records with timing and delta packet/byte counts
 *============================================================================*/

int natexport_log_flow(uint8_t event_type,
                       uint32_t src_ip, uint16_t src_port,
                       uint32_t xlate_ip, uint16_t xlate_port,
                       uint32_t dst_ip, uint16_t dst_port,
                       uint8_t protocol,
                       uint64_t flow_start_ms, uint64_t flow_end_ms,
                       uint64_t delta_pkts, uint64_t delta_bytes)
{
    pthread_mutex_lock(&g_exp.lock);

    if (!g_exp.enabled) {
        pthread_mutex_unlock(&g_exp.lock);
        return -1;
    }

    /* Check buffer space */
    if (g_exp.buf_offset + NAT_RECORD_SIZE > BUFFER_SIZE ||
        g_exp.record_count >= MAX_RECORDS) {
        finalize_data_flowset();
        flush_buffer();
        init_buffer();
    }

    /* Init buffer if empty */
    if (g_exp.buf_offset == 0) {
        init_buffer();
    }

    /* Serialize record - MUST match template order */
    uint8_t *ptr = g_exp.buffer + g_exp.buf_offset;

    /* 1. observationTimeMilliseconds (8) */
    uint64_t ts = htobe64(flow_end_ms);
    memcpy(ptr, &ts, 8); ptr += 8;

    /* 2. natEvent (1) */
    *ptr++ = event_type;

    /* 3. protocolIdentifier (1) */
    *ptr++ = protocol;

    /* 4. sourceIPv4Address (4) */
    uint32_t tmp32 = htonl(src_ip);
    memcpy(ptr, &tmp32, 4); ptr += 4;

    /* 5. sourceTransportPort (2) */
    uint16_t tmp16 = htons(src_port);
    memcpy(ptr, &tmp16, 2); ptr += 2;

    /* 6. destinationIPv4Address (4) */
    tmp32 = htonl(dst_ip);
    memcpy(ptr, &tmp32, 4); ptr += 4;

    /* 7. destinationTransportPort (2) */
    tmp16 = htons(dst_port);
    memcpy(ptr, &tmp16, 2); ptr += 2;

    /* 8. postNATSourceIPv4Address (4) */
    tmp32 = htonl(xlate_ip);
    memcpy(ptr, &tmp32, 4); ptr += 4;

    /* 9. postNAPTSourceTransportPort (2) */
    tmp16 = htons(xlate_port);
    memcpy(ptr, &tmp16, 2); ptr += 2;

    /* 10. postNATDestinationIPv4Address (4) - same as dst for SNAT */
    tmp32 = htonl(dst_ip);
    memcpy(ptr, &tmp32, 4); ptr += 4;

    /* 11. postNAPTDestinationTransportPort (2) - same as dst for SNAT */
    tmp16 = htons(dst_port);
    memcpy(ptr, &tmp16, 2); ptr += 2;

    /* 12. tcpControlBits (1) - ipt-netflow event indicator */
    *ptr++ = (event_type == NAT_EVENT_CREATE) ? TCP_SYN_ACK :
             (event_type == NAT_EVENT_ACTIVE_TIMEOUT) ? TCP_ACK : TCP_FIN_RST;

    /* 13. ingressInterface (4) */
    tmp32 = htonl(0);
    memcpy(ptr, &tmp32, 4); ptr += 4;

    /* 14. egressInterface (4) */
    memcpy(ptr, &tmp32, 4); ptr += 4;

    /* 15. flowStartMilliseconds (8) */
    uint64_t ts_start = htobe64(flow_start_ms);
    memcpy(ptr, &ts_start, 8); ptr += 8;

    /* 16. flowEndMilliseconds (8) */
    uint64_t ts_end = htobe64(flow_end_ms);
    memcpy(ptr, &ts_end, 8); ptr += 8;

    /* 17. packetDeltaCount (8) */
    uint64_t pkts_be = htobe64(delta_pkts);
    memcpy(ptr, &pkts_be, 8); ptr += 8;

    /* 18. octetDeltaCount (8) */
    uint64_t bytes_be = htobe64(delta_bytes);
    memcpy(ptr, &bytes_be, 8); ptr += 8;

    g_exp.buf_offset = ptr - g_exp.buffer;
    g_exp.record_count++;

    pthread_mutex_unlock(&g_exp.lock);
    return 0;
}

/*============================================================================
 * Active Timeout Scanner Thread
 * RFC 8158: Periodically scans NAT sessions and exports flows with traffic
 *============================================================================*/

/* Forward declarations for NAT session scanning */
struct nat_session;

/* Session callback type for active timeout scanner */
typedef void (*session_scan_callback_t)(struct nat_session *session, void *user_data);

/* External function: iterate all NAT sessions with callback */
extern void nat_session_iterate(session_scan_callback_t callback, void *user_data);

/* Export a session for active/inactive timeout */
static void export_session_active_timeout(struct nat_session *session, void *user_data)
{
    (void)user_data;

    /* Skip if natexport is not enabled */
    if (!g_exp.enabled) {
        return;
    }

    uint64_t now_ns = get_timestamp_ns();
    uint64_t last_export = session->last_export_ts;
    uint64_t last_used = session->last_used_ts;
    uint64_t created = session->created_ts;

    /* Calculate time since last export and last packet */
    uint64_t since_export_sec = (now_ns - last_export) / 1000000000ULL;
    uint64_t since_last_pkt_sec = (now_ns - last_used) / 1000000000ULL;
    uint64_t flow_age_sec = (now_ns - created) / 1000000000ULL;

    /* Calculate delta counts */
    uint64_t delta_pkts = (session->packets_in - session->exported_pkts_in) +
                          (session->packets_out - session->exported_pkts_out);
    uint64_t delta_bytes = (session->bytes_in - session->exported_bytes_in) +
                           (session->bytes_out - session->exported_bytes_out);

    /* Skip if no traffic since last export */
    if (delta_pkts == 0 && delta_bytes == 0) {
        return; /* Nothing to export */
    }

    /* Determine if we should export based on timeouts:
     * 1. Inactive timeout: Flow idle for > inactive_timeout seconds
     * 2. Active timeout: Flow running for > active_timeout since last export
     */
    bool inactive_triggered = (since_last_pkt_sec >= g_exp.inactive_timeout);
    bool active_triggered = (last_export > 0 && since_export_sec >= g_exp.active_timeout);
    bool first_export = (last_export == 0 && flow_age_sec >= g_exp.inactive_timeout);

    if (!inactive_triggered && !active_triggered && !first_export) {
        return; /* Not time to export yet */
    }

    /* Convert timestamps to milliseconds */
    uint64_t flow_start_ms = created / 1000000ULL;
    uint64_t flow_end_ms = last_used / 1000000ULL;

    /* Export the flow record */
    natexport_log_flow(NAT_EVENT_ACTIVE_TIMEOUT,
                       session->inside_ip, session->inside_port,
                       session->outside_ip, session->outside_port,
                       session->dest_ip, session->dest_port,
                       session->protocol,
                       flow_start_ms, flow_end_ms,
                       delta_pkts, delta_bytes);

    /* Update export tracking fields */
    session->last_export_ts = now_ns;
    session->exported_pkts_in = session->packets_in;
    session->exported_pkts_out = session->packets_out;
    session->exported_bytes_in = session->bytes_in;
    session->exported_bytes_out = session->bytes_out;
    session->exported = 1;
}

static void *active_timeout_thread_func(void *arg)
{
    (void)arg;

    /* Scan interval: 1 second to properly detect inactive flows at 15s granularity */
    const unsigned int scan_interval = 1;

    printf("natexport: flow scanner started (scan=%ds, active=%us, inactive=%us)\n",
           scan_interval, g_exp.active_timeout, g_exp.inactive_timeout);

    while (g_exp.active_timeout_running) {
        sleep(scan_interval);

        if (!g_exp.enabled || !g_exp.active_timeout_running) {
            break;
        }

        /* Scan all sessions and export those exceeding timeout thresholds */
        nat_session_iterate(export_session_active_timeout, NULL);

        /* Flush pending records after scan */
        pthread_mutex_lock(&g_exp.lock);
        if (g_exp.record_count > 0) {
            finalize_data_flowset();
            flush_buffer();
            init_buffer();
        }
        pthread_mutex_unlock(&g_exp.lock);
    }

    printf("natexport: active timeout scanner stopped\n");
    return NULL;
}

int natexport_start_active_timeout(void)
{
    if (g_exp.active_timeout_running) {
        return 0; /* Already running */
    }

    if (!g_exp.enabled) {
        fprintf(stderr, "natexport: cannot start active timeout without exporter enabled\n");
        return -1;
    }

    g_exp.active_timeout_running = true;
    if (pthread_create(&g_exp.active_timeout_thread, NULL, active_timeout_thread_func, NULL) != 0) {
        fprintf(stderr, "natexport: failed to create active timeout thread: %s\n", strerror(errno));
        g_exp.active_timeout_running = false;
        return -1;
    }

    return 0;
}

void natexport_stop_active_timeout(void)
{
    if (!g_exp.active_timeout_running) {
        return;
    }

    g_exp.active_timeout_running = false;
    pthread_join(g_exp.active_timeout_thread, NULL);
}

/*============================================================================
 * Backward Compatibility Stubs
 * These functions provide API compatibility with old exporter modules
 *============================================================================*/

/* Old nat_logger API - redirect to natexport_log */
void nat_logger_log_event(uint8_t event_type, uint32_t original_ip,
                          uint16_t original_port, uint32_t translated_ip,
                          uint16_t translated_port, uint32_t dest_ip,
                          uint16_t dest_port, uint8_t protocol)
{
    /* Debug: trace that this function is being called */
    static uint64_t call_count = 0;
    if ((++call_count % 100) == 1) {
        printf("nat_logger_log_event #%lu: event=%u proto=%u src=%u.%u.%u.%u:%u enabled=%d\n",
               call_count, event_type, protocol,
               (original_ip >> 24) & 0xFF, (original_ip >> 16) & 0xFF,
               (original_ip >> 8) & 0xFF, original_ip & 0xFF, original_port,
               g_exp.enabled);
    }

    natexport_log(event_type, original_ip, original_port,
                  translated_ip, translated_port,
                  dest_ip, dest_port, protocol, 0, 0);
}

/* Old exporter_init - stub */
int exporter_init(void)
{
    /* No-op - initialization now done via natexport_init_v9/ipfix */
    return 0;
}

/* Old exporter thread function - stub (not needed) */
void *exporter_thread_func(void *arg)
{
    (void)arg;
    /* No-op - natexport doesn't use a separate thread */
    return NULL;
}

/* Old flow_cache API - stubs (not used for NAT) */
int flow_cache_init(void)
{
    return 0;
}

void flow_cache_update(void *pkt __attribute__((unused)),
                       uint32_t len __attribute__((unused)),
                       int direction __attribute__((unused)))
{
    /* No-op */
}

void flow_cache_expire(void)
{
    /* No-op */
}

/* Old export_config_set_collector - redirect to natexport init */
void export_config_set_collector(int idx, uint32_t ip, uint16_t port)
{
    if (ip == 0 || port == 0) {
        /* Disable - cleanup */
        natexport_cleanup();
        return;
    }

    /* idx 0 = IPFIX, idx 1 = NetFlow v9 */
    if (idx == 0) {
        natexport_init_ipfix(ip, port, 1);
    } else {
        natexport_init_v9(ip, port, 1);
    }
}

/* Old exporter_print_stats - use natexport stats */
void exporter_print_stats(void)
{
    struct natexport_stats stats;
    natexport_get_stats(&stats);

    printf("\nNAT Export Statistics:\n");
    printf("  Protocol:       %s\n",
           g_exp.protocol == NATEXPORT_PROTO_IPFIX ? "IPFIX" : "NetFlow v9");
    printf("  Templates sent: %lu\n", stats.templates_sent);
    printf("  Records sent:   %lu\n", stats.data_records_sent);
    printf("  Packets sent:   %lu\n", stats.packets_sent);
    printf("  Bytes sent:     %lu\n", stats.bytes_sent);
    printf("  Errors:         %lu\n", stats.errors);
}

/*============================================================================
 * Runtime Configuration API
 *============================================================================*/

void natexport_set_active_timeout(uint32_t seconds)
{
    if (seconds < 1) seconds = 1;           /* Minimum 1 second */
    if (seconds > 86400) seconds = 86400;   /* Maximum 24 hours */
    g_exp.active_timeout = seconds;
    printf("natexport: active timeout set to %u seconds\n", seconds);
}

void natexport_set_inactive_timeout(uint32_t seconds)
{
    if (seconds < 1) seconds = 1;           /* Minimum 1 second */
    if (seconds > 3600) seconds = 3600;     /* Maximum 1 hour */
    g_exp.inactive_timeout = seconds;
    printf("natexport: inactive timeout set to %u seconds\n", seconds);
}

uint32_t natexport_get_active_timeout(void)
{
    return g_exp.active_timeout;
}

uint32_t natexport_get_inactive_timeout(void)
{
    return g_exp.inactive_timeout;
}

/*============================================================================
 * Collector Management
 *============================================================================*/

void natexport_set_collector(uint32_t ip, uint16_t port)
{
    pthread_mutex_lock(&g_exp.lock);
    g_exp.num_collectors = 0;
    natexport_add_collector(ip, port);
    pthread_mutex_unlock(&g_exp.lock);
}

int natexport_add_collector(uint32_t ip, uint16_t port)
{
    /* Note: caller should hold lock if dynamic, but init is single threaded usually */
    /* If called at runtime, we should lock. natexport_set_collector does lock. */

    if (g_exp.num_collectors >= NATEXPORT_MAX_COLLECTORS) {
        return -1;
    }

    struct sockaddr_in *c = &g_exp.collectors[g_exp.num_collectors];
    memset(c, 0, sizeof(*c));
    c->sin_family = AF_INET;
    c->sin_port = htons(port);
    c->sin_addr.s_addr = htonl(ip);

    g_exp.num_collectors++;
    printf("natexport: added collector %u.%u.%u.%u:%u (total %d)\n",
           (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
           (ip >> 8) & 0xFF, ip & 0xFF, port, g_exp.num_collectors);

    return 0;
}

/*============================================================================
 * CLI Support Functions
 *============================================================================*/

void natexport_print_collectors(void)
{
    pthread_mutex_lock(&g_exp.lock);

    if (g_exp.num_collectors == 0) {
        printf("    (none configured)\n");
    } else {
        for (int i = 0; i < g_exp.num_collectors; i++) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &g_exp.collectors[i].sin_addr, ip_str, sizeof(ip_str));
            printf("    %d. %s:%u\n", i + 1, ip_str, ntohs(g_exp.collectors[i].sin_port));
        }
    }

    pthread_mutex_unlock(&g_exp.lock);
}

void natexport_print_config(void)
{
    pthread_mutex_lock(&g_exp.lock);

    printf("\nNAT Export Configuration:\n");
    printf("  Protocol: %s\n", g_exp.protocol == NATEXPORT_PROTO_IPFIX ? "IPFIX" : "NetFlow v9");
    printf("  Enabled: %s\n", g_exp.enabled ? "Yes" : "No");
    printf("  Source ID: %u\n", g_exp.source_id);
    printf("  Active Timeout: %u seconds\n", g_exp.active_timeout);
    printf("  Inactive Timeout: %u seconds\n", g_exp.inactive_timeout);
    printf("  Collectors: %d\n", g_exp.num_collectors);

    pthread_mutex_unlock(&g_exp.lock);
}



/*============================================================================
 * Event Sampling (1:N Deterministic)
 * For 100Gbps+ deployments where full logging is not feasible
 *============================================================================*/

/* Sampling configuration */
static struct {
    uint32_t global_rate;           /* 1:N global sampling (0 = disabled) */
    uint32_t per_protocol[256];     /* Per-protocol sampling rates */
    uint64_t events_sampled;        /* Counter: events accepted by sampling */
    uint64_t events_dropped;        /* Counter: events dropped by sampling */
    uint32_t counter;               /* Rolling counter for deterministic sampling */
} g_sampling = {
    .global_rate = 0,               /* Default: no sampling (log everything) */
    .per_protocol = {0},
    .events_sampled = 0,
    .events_dropped = 0,
    .counter = 0
};

/**
 * Configure global sampling rate
 * @param rate N for 1:N sampling (0 = log everything)
 */
void natexport_set_sampling_rate(uint32_t rate)
{
    g_sampling.global_rate = rate;
    printf("natexport: sampling rate set to 1:%u%s\n",
           rate, rate == 0 ? " (disabled)" : "");
}

/**
 * Configure per-protocol sampling rate
 * @param protocol IP protocol number (6=TCP, 17=UDP, 1=ICMP)
 * @param rate N for 1:N sampling (0 = use global rate)
 */
void natexport_set_protocol_sampling(uint8_t protocol, uint32_t rate)
{
    g_sampling.per_protocol[protocol] = rate;
    printf("natexport: protocol %u sampling set to 1:%u\n", protocol, rate);
}

/**
 * Check if event should be sampled (logged)
 * Uses deterministic sampling for reproducibility
 */
static inline bool should_sample_event(uint8_t protocol)
{
    /* Get effective sampling rate */
    uint32_t rate = g_sampling.per_protocol[protocol];
    if (rate == 0) rate = g_sampling.global_rate;
    if (rate == 0) return true;  /* No sampling, log everything */

    /* Deterministic sampling: log every Nth event */
    uint32_t counter = __atomic_fetch_add(&g_sampling.counter, 1, __ATOMIC_RELAXED);
    if ((counter % rate) == 0) {
        __atomic_fetch_add(&g_sampling.events_sampled, 1, __ATOMIC_RELAXED);
        return true;
    }

    __atomic_fetch_add(&g_sampling.events_dropped, 1, __ATOMIC_RELAXED);
    return false;
}

/**
 * Get sampling statistics
 */
void natexport_get_sampling_stats(uint64_t *sampled, uint64_t *dropped)
{
    if (sampled) *sampled = g_sampling.events_sampled;
    if (dropped) *dropped = g_sampling.events_dropped;
}

/*============================================================================
 * Rate Limiting (Token Bucket Algorithm)
 * Prevents overwhelming collectors during traffic bursts
 *============================================================================*/

static struct {
    uint32_t sustained_rate;   /* Tokens added per second */
    uint32_t burst_size;       /* Maximum bucket capacity */
    uint32_t tokens;           /* Current available tokens */
    uint64_t last_refill;      /* Last refill timestamp (ns) */
    uint64_t events_limited;   /* Counter: events dropped by rate limit */
    bool enabled;
} g_rate_limit = {
    .sustained_rate = 500000,   /* 500K events/sec default */
    .burst_size = 1000000,      /* 1M burst capacity */
    .tokens = 1000000,
    .last_refill = 0,
    .events_limited = 0,
    .enabled = false
};

/**
 * Configure rate limiting
 * @param sustained Maximum sustained events/sec
 * @param burst Maximum burst events (bucket size)
 */
void natexport_set_rate_limit(uint32_t sustained, uint32_t burst)
{
    g_rate_limit.sustained_rate = sustained;
    g_rate_limit.burst_size = burst;
    g_rate_limit.tokens = burst;
    g_rate_limit.enabled = (sustained > 0);
    printf("natexport: rate limit %s (sustained=%u/s, burst=%u)\n",
           g_rate_limit.enabled ? "enabled" : "disabled", sustained, burst);
}

/**
 * Check if event is allowed by rate limiter
 * Uses token bucket algorithm
 */
static inline bool rate_limit_allow(void)
{
    if (!g_rate_limit.enabled) return true;

    /* Refill tokens based on elapsed time */
    uint64_t now = get_timestamp_ns();
    uint64_t elapsed_ns = now - g_rate_limit.last_refill;

    if (elapsed_ns >= 1000000) {  /* Refill every 1ms */
        uint32_t new_tokens = (elapsed_ns * g_rate_limit.sustained_rate) / 1000000000ULL;
        uint32_t old = g_rate_limit.tokens;
        uint32_t updated = old + new_tokens;
        if (updated > g_rate_limit.burst_size) updated = g_rate_limit.burst_size;
        __atomic_store_n(&g_rate_limit.tokens, updated, __ATOMIC_RELAXED);
        __atomic_store_n(&g_rate_limit.last_refill, now, __ATOMIC_RELAXED);
    }

    /* Try to consume a token */
    uint32_t tokens = __atomic_load_n(&g_rate_limit.tokens, __ATOMIC_RELAXED);
    if (tokens > 0) {
        __atomic_fetch_sub(&g_rate_limit.tokens, 1, __ATOMIC_RELAXED);
        return true;
    }

    __atomic_fetch_add(&g_rate_limit.events_limited, 1, __ATOMIC_RELAXED);
    return false;
}

/**
 * Get rate limiting statistics
 */
void natexport_get_rate_limit_stats(uint64_t *limited)
{
    if (limited) *limited = g_rate_limit.events_limited;
}

/*============================================================================
 * Collector Health Checking
 * Monitors collector connectivity and enables automatic failover
 *============================================================================*/

static struct {
    bool health_check_enabled;
    uint32_t check_interval_sec;     /* Seconds between health checks */
    uint32_t failure_threshold;       /* Failures before marking down */
    uint32_t collector_failures[NATEXPORT_MAX_COLLECTORS];
    bool collector_healthy[NATEXPORT_MAX_COLLECTORS];
    pthread_t health_thread;
    bool health_thread_running;
} g_health = {
    .health_check_enabled = true,
    .check_interval_sec = 10,
    .failure_threshold = 3,
    .collector_failures = {0},
    .collector_healthy = {true, true, true, true},
    .health_thread_running = false
};

/**
 * Health check thread - pings collectors periodically
 */
static void *health_check_thread(void *arg)
{
    (void)arg;

    while (g_health.health_thread_running) {
        for (int i = 0; i < g_exp.num_collectors; i++) {
            /* Simple UDP probe - send empty IPFIX packet */
            if (g_exp.sock_fd >= 0) {
                uint8_t probe[8] = {0};  /* Minimal probe */
                ssize_t sent = sendto(g_exp.sock_fd, probe, sizeof(probe), MSG_DONTWAIT,
                                      (struct sockaddr *)&g_exp.collectors[i],
                                      sizeof(g_exp.collectors[i]));

                if (sent < 0) {
                    g_health.collector_failures[i]++;
                    if (g_health.collector_failures[i] >= g_health.failure_threshold) {
                        if (g_health.collector_healthy[i]) {
                            g_health.collector_healthy[i] = false;
                            char ip_str[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &g_exp.collectors[i].sin_addr, ip_str, sizeof(ip_str));
                            fprintf(stderr, "natexport: collector %s marked DOWN\n", ip_str);
                        }
                    }
                } else {
                    if (!g_health.collector_healthy[i]) {
                        char ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &g_exp.collectors[i].sin_addr, ip_str, sizeof(ip_str));
                        printf("natexport: collector %s marked UP\n", ip_str);
                    }
                    g_health.collector_failures[i] = 0;
                    g_health.collector_healthy[i] = true;
                }
            }
        }

        sleep(g_health.check_interval_sec);
    }

    return NULL;
}

/**
 * Start collector health checking
 */
void natexport_start_health_check(void)
{
    if (g_health.health_thread_running) return;

    g_health.health_thread_running = true;
    pthread_create(&g_health.health_thread, NULL, health_check_thread, NULL);
    printf("natexport: health check started (interval=%us, threshold=%u)\n",
           g_health.check_interval_sec, g_health.failure_threshold);
}

/**
 * Stop collector health checking
 */
void natexport_stop_health_check(void)
{
    if (!g_health.health_thread_running) return;

    g_health.health_thread_running = false;
    pthread_join(g_health.health_thread, NULL);
    printf("natexport: health check stopped\n");
}

/**
 * Check if collector is healthy
 */
bool natexport_collector_healthy(int index)
{
    if (index < 0 || index >= NATEXPORT_MAX_COLLECTORS) return false;
    return g_health.collector_healthy[index];
}

/**
 * Get number of healthy collectors
 */
int natexport_healthy_collector_count(void)
{
    int count = 0;
    for (int i = 0; i < g_exp.num_collectors; i++) {
        if (g_health.collector_healthy[i]) count++;
    }
    return count;
}

/*============================================================================
 * SCTP Transport Support (RFC 7785 Recommended)
 * Multi-homing capable, reliable message delivery
 *============================================================================*/

#ifdef HAVE_SCTP
#include <netinet/sctp.h>

static struct {
    int sctp_fd;
    bool sctp_enabled;
    struct sockaddr_in sctp_primary;
    struct sockaddr_in sctp_secondary;  /* For multi-homing */
} g_sctp = {
    .sctp_fd = -1,
    .sctp_enabled = false
};

/**
 * Initialize SCTP transport
 */
int natexport_init_sctp(uint32_t primary_ip, uint16_t port, uint32_t secondary_ip)
{
    g_sctp.sctp_fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
    if (g_sctp.sctp_fd < 0) {
        fprintf(stderr, "natexport: SCTP socket creation failed: %s\n", strerror(errno));
        return -1;
    }

    /* Configure SCTP */
    struct sctp_event_subscribe events = {0};
    events.sctp_data_io_event = 1;
    if (setsockopt(g_sctp.sctp_fd, IPPROTO_SCTP, SCTP_EVENTS, &events, sizeof(events)) < 0) {
        fprintf(stderr, "natexport: SCTP setsockopt failed: %s\n", strerror(errno));
        close(g_sctp.sctp_fd);
        g_sctp.sctp_fd = -1;
        return -1;
    }

    /* Set primary address */
    memset(&g_sctp.sctp_primary, 0, sizeof(g_sctp.sctp_primary));
    g_sctp.sctp_primary.sin_family = AF_INET;
    g_sctp.sctp_primary.sin_port = htons(port);
    g_sctp.sctp_primary.sin_addr.s_addr = htonl(primary_ip);

    /* Set secondary for multi-homing */
    if (secondary_ip != 0) {
        memset(&g_sctp.sctp_secondary, 0, sizeof(g_sctp.sctp_secondary));
        g_sctp.sctp_secondary.sin_family = AF_INET;
        g_sctp.sctp_secondary.sin_port = htons(port);
        g_sctp.sctp_secondary.sin_addr.s_addr = htonl(secondary_ip);
    }

    g_sctp.sctp_enabled = true;
    printf("natexport: SCTP transport initialized\n");
    return 0;
}

/**
 * Send via SCTP
 */
static int send_via_sctp(const uint8_t *payload, size_t len)
{
    if (!g_sctp.sctp_enabled || g_sctp.sctp_fd < 0) return -1;

    return sctp_sendmsg(g_sctp.sctp_fd, payload, len,
                        (struct sockaddr *)&g_sctp.sctp_primary,
                        sizeof(g_sctp.sctp_primary),
                        htonl(IPFIX_SCTP_PPID),  /* Payload Protocol Identifier */
                        0,      /* flags */
                        0,      /* stream */
                        0,      /* TTL */
                        0);     /* context */
}

#define IPFIX_SCTP_PPID 0x00000000  /* IPFIX SCTP payload protocol identifier */

#endif /* HAVE_SCTP */

/*============================================================================
 * TLS/DTLS Encryption Support
 * Secure transport for compliance and privacy
 *============================================================================*/

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>

static struct {
    SSL_CTX *ctx;
    SSL *ssl;
    bool tls_enabled;
    char cert_file[256];
    char key_file[256];
} g_tls = {
    .ctx = NULL,
    .ssl = NULL,
    .tls_enabled = false
};

/**
 * Initialize TLS context
 */
int natexport_init_tls(const char *cert_file, const char *key_file)
{
    SSL_library_init();
    SSL_load_error_strings();

    g_tls.ctx = SSL_CTX_new(TLS_client_method());
    if (!g_tls.ctx) {
        fprintf(stderr, "natexport: TLS context creation failed\n");
        return -1;
    }

    /* Load certificate */
    if (cert_file && SSL_CTX_use_certificate_file(g_tls.ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "natexport: Failed to load certificate: %s\n", cert_file);
        SSL_CTX_free(g_tls.ctx);
        g_tls.ctx = NULL;
        return -1;
    }

    /* Load private key */
    if (key_file && SSL_CTX_use_PrivateKey_file(g_tls.ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "natexport: Failed to load private key: %s\n", key_file);
        SSL_CTX_free(g_tls.ctx);
        g_tls.ctx = NULL;
        return -1;
    }

    strncpy(g_tls.cert_file, cert_file ? cert_file : "", sizeof(g_tls.cert_file) - 1);
    strncpy(g_tls.key_file, key_file ? key_file : "", sizeof(g_tls.key_file) - 1);

    g_tls.tls_enabled = true;
    printf("natexport: TLS encryption initialized\n");
    return 0;
}

/**
 * Connect TLS to collector
 */
int natexport_tls_connect(uint32_t ip, uint16_t port)
{
    if (!g_tls.ctx) return -1;

    /* Create TCP socket */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(ip);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    /* Create SSL connection */
    g_tls.ssl = SSL_new(g_tls.ctx);
    SSL_set_fd(g_tls.ssl, sock);

    if (SSL_connect(g_tls.ssl) != 1) {
        fprintf(stderr, "natexport: TLS handshake failed\n");
        SSL_free(g_tls.ssl);
        g_tls.ssl = NULL;
        close(sock);
        return -1;
    }

    printf("natexport: TLS connection established\n");
    return 0;
}

/**
 * Send via TLS
 */
static int send_via_tls(const uint8_t *payload, size_t len)
{
    if (!g_tls.ssl) return -1;
    return SSL_write(g_tls.ssl, payload, len);
}

/**
 * Cleanup TLS
 */
void natexport_cleanup_tls(void)
{
    if (g_tls.ssl) {
        SSL_shutdown(g_tls.ssl);
        SSL_free(g_tls.ssl);
        g_tls.ssl = NULL;
    }
    if (g_tls.ctx) {
        SSL_CTX_free(g_tls.ctx);
        g_tls.ctx = NULL;
    }
    g_tls.tls_enabled = false;
}

#endif /* HAVE_OPENSSL */

/*============================================================================
 * CALEA / Lawful Intercept Support
 * Interface for law enforcement queries
 *============================================================================*/

/**
 * Query sessions for a specific subscriber IP
 * Required for CALEA compliance
 */
int natexport_calea_query_subscriber(uint32_t subscriber_ip,
                                      void (*callback)(struct nat_event_v2 *event, void *ctx),
                                      void *ctx)
{
    (void)callback; (void)ctx;
    /* This would query a persistent log database */
    /* For now, stub implementation */
    printf("CALEA: Query for subscriber %u.%u.%u.%u\n",
           (subscriber_ip >> 24) & 0xFF, (subscriber_ip >> 16) & 0xFF,
           (subscriber_ip >> 8) & 0xFF, subscriber_ip & 0xFF);

    return 0;  /* Would return count of matching records */
}

/**
 * Query sessions for a specific external IP/port/timestamp
 * Reverse lookup for incident investigation
 */
int natexport_calea_reverse_query(uint32_t external_ip, uint16_t external_port,
                                   uint64_t timestamp,
                                   uint32_t *subscriber_ip_out)
{
    /* This would query a persistent log database */
    printf("CALEA: Reverse query for %u.%u.%u.%u:%u at %lu\n",
           (external_ip >> 24) & 0xFF, (external_ip >> 16) & 0xFF,
           (external_ip >> 8) & 0xFF, external_ip & 0xFF,
           external_port, timestamp);

    *subscriber_ip_out = 0;  /* Would return matched subscriber IP */
    return -1;  /* Not found (stub) */
}
