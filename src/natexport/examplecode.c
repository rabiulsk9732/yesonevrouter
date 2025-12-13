/*
 * DPDK-based NetFlow v9/IPFIX Exporter
 *
 * Compilation:
 * gcc -O3 dpdk_ipfix.c -o dpdk_ipfix $(pkg-config --cflags --libs libdpdk) -lpthread
 *
 * Usage:
 * ./dpdk_ipfix -l 0-3 -n 4 -- -p 0x1 -c 192.168.1.100:2055
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_FLOW_ENTRIES 1000000
#define FLOW_TIMEOUT_SEC 30
#define ACTIVE_TIMEOUT_SEC 120
#define EXPORT_INTERVAL_MS 5000

/* IPFIX/NetFlow structures */
#define IPFIX_VERSION 10
#define NETFLOW_V9_VERSION 9
#define IPFIX_SET_ID_TEMPLATE 2
#define IPFIX_SET_ID_DATA 256

/* Information Element IDs (IPFIX/NetFlow v9) */
#define IE_SOURCE_IPV4 8
#define IE_DEST_IPV4 12
#define IE_NEXT_HOP_IPV4 15
#define IE_INPUT_SNMP 10
#define IE_OUTPUT_SNMP 14
#define IE_PACKET_COUNT 2
#define IE_BYTE_COUNT 1
#define IE_FLOW_START_MS 152
#define IE_FLOW_END_MS 153
#define IE_SOURCE_PORT 7
#define IE_DEST_PORT 11
#define IE_TCP_FLAGS 6
#define IE_PROTOCOL 4
#define IE_TOS 5
#define IE_SOURCE_AS 16
#define IE_DEST_AS 17
#define IE_SOURCE_MASK 9
#define IE_DEST_MASK 13

/* IPFIX message header */
struct ipfix_header {
    uint16_t version;
    uint16_t length;
    uint32_t export_time;
    uint32_t sequence_number;
    uint32_t observation_domain_id;
} __rte_packed;

/* IPFIX set header */
struct ipfix_set_header {
    uint16_t set_id;
    uint16_t length;
} __rte_packed;

/* IPFIX template record header */
struct ipfix_template_header {
    uint16_t template_id;
    uint16_t field_count;
} __rte_packed;

/* IPFIX template field */
struct ipfix_field {
    uint16_t field_id;
    uint16_t field_length;
} __rte_packed;

/* Flow key for hash table */
struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t pad[3];
} __rte_packed;

/* Flow record */
struct flow_record {
    struct flow_key key;
    uint64_t packet_count;
    uint64_t byte_count;
    uint64_t first_seen;
    uint64_t last_seen;
    uint8_t tcp_flags;
    uint8_t tos;
    uint16_t input_snmp;
    uint16_t output_snmp;
} __rte_packed;

/* IPFIX data record format */
struct ipfix_data_record {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint32_t next_hop;
    uint16_t input_snmp;
    uint16_t output_snmp;
    uint64_t packet_count;
    uint64_t byte_count;
    uint64_t flow_start;
    uint64_t flow_end;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t tcp_flags;
    uint8_t protocol;
    uint8_t tos;
    uint8_t pad;
} __rte_packed;

/* Global configuration */
struct config {
    uint32_t enabled_port_mask;
    uint32_t collector_ip;
    uint16_t collector_port;
    uint32_t observation_domain_id;
    bool use_ipfix;
} __rte_cache_aligned;

static struct config app_config = {
    .enabled_port_mask = 0,
    .collector_ip = 0,
    .collector_port = 2055,
    .observation_domain_id = 1,
    .use_ipfix = true,
};

/* Per-lcore statistics */
struct lcore_stats {
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t flows_created;
    uint64_t flows_exported;
    uint64_t flows_expired;
} __rte_cache_aligned;

static struct lcore_stats lcore_stats[RTE_MAX_LCORE];

/* Flow table */
static struct rte_hash *flow_table = NULL;
static struct flow_record *flow_records = NULL;
static uint32_t sequence_number = 0;
static uint16_t template_id = 256;

static volatile bool force_quit = false;

/* Ethernet addresses of ports */
static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_RSS,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
        },
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
    },
};

/* Initialize a port */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf_local = port_conf;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error getting device info: %s\n", strerror(-retval));
        return retval;
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf_local.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf_local);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf_local.txmode.offloads;
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }

    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    retval = rte_eth_macaddr_get(port, &ports_eth_addr[port]);
    if (retval != 0)
        return retval;

    printf("Port %u MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
           ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
            port,
            RTE_ETHER_ADDR_BYTES(&ports_eth_addr[port]));

    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;

    return 0;
}

/* Create IPFIX template packet */
static struct rte_mbuf *
create_ipfix_template(struct rte_mempool *mbuf_pool)
{
    struct rte_mbuf *m;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ip_hdr;
    struct rte_udp_hdr *udp_hdr;
    struct ipfix_header *ipfix_hdr;
    struct ipfix_set_header *set_hdr;
    struct ipfix_template_header *template_hdr;
    struct ipfix_field *fields;
    uint8_t *ptr;
    uint16_t total_len;
    uint16_t field_count = 15;

    m = rte_pktmbuf_alloc(mbuf_pool);
    if (m == NULL)
        return NULL;

    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
    ipfix_hdr = (struct ipfix_header *)(udp_hdr + 1);
    set_hdr = (struct ipfix_set_header *)(ipfix_hdr + 1);
    template_hdr = (struct ipfix_template_header *)(set_hdr + 1);
    fields = (struct ipfix_field *)(template_hdr + 1);

    /* Build IPFIX template */
    ipfix_hdr->version = rte_cpu_to_be_16(IPFIX_VERSION);
    ipfix_hdr->export_time = rte_cpu_to_be_32(time(NULL));
    ipfix_hdr->sequence_number = 0;
    ipfix_hdr->observation_domain_id = rte_cpu_to_be_32(app_config.observation_domain_id);

    set_hdr->set_id = rte_cpu_to_be_16(IPFIX_SET_ID_TEMPLATE);

    template_hdr->template_id = rte_cpu_to_be_16(template_id);
    template_hdr->field_count = rte_cpu_to_be_16(field_count);

    /* Define template fields */
    ptr = (uint8_t *)fields;
    int i = 0;

    fields[i].field_id = rte_cpu_to_be_16(IE_SOURCE_IPV4);
    fields[i++].field_length = rte_cpu_to_be_16(4);

    fields[i].field_id = rte_cpu_to_be_16(IE_DEST_IPV4);
    fields[i++].field_length = rte_cpu_to_be_16(4);

    fields[i].field_id = rte_cpu_to_be_16(IE_NEXT_HOP_IPV4);
    fields[i++].field_length = rte_cpu_to_be_16(4);

    fields[i].field_id = rte_cpu_to_be_16(IE_INPUT_SNMP);
    fields[i++].field_length = rte_cpu_to_be_16(2);

    fields[i].field_id = rte_cpu_to_be_16(IE_OUTPUT_SNMP);
    fields[i++].field_length = rte_cpu_to_be_16(2);

    fields[i].field_id = rte_cpu_to_be_16(IE_PACKET_COUNT);
    fields[i++].field_length = rte_cpu_to_be_16(8);

    fields[i].field_id = rte_cpu_to_be_16(IE_BYTE_COUNT);
    fields[i++].field_length = rte_cpu_to_be_16(8);

    fields[i].field_id = rte_cpu_to_be_16(IE_FLOW_START_MS);
    fields[i++].field_length = rte_cpu_to_be_16(8);

    fields[i].field_id = rte_cpu_to_be_16(IE_FLOW_END_MS);
    fields[i++].field_length = rte_cpu_to_be_16(8);

    fields[i].field_id = rte_cpu_to_be_16(IE_SOURCE_PORT);
    fields[i++].field_length = rte_cpu_to_be_16(2);

    fields[i].field_id = rte_cpu_to_be_16(IE_DEST_PORT);
    fields[i++].field_length = rte_cpu_to_be_16(2);

    fields[i].field_id = rte_cpu_to_be_16(IE_TCP_FLAGS);
    fields[i++].field_length = rte_cpu_to_be_16(1);

    fields[i].field_id = rte_cpu_to_be_16(IE_PROTOCOL);
    fields[i++].field_length = rte_cpu_to_be_16(1);

    fields[i].field_id = rte_cpu_to_be_16(IE_TOS);
    fields[i++].field_length = rte_cpu_to_be_16(1);

    uint16_t set_len = sizeof(*set_hdr) + sizeof(*template_hdr) +
                       field_count * sizeof(struct ipfix_field);
    set_hdr->length = rte_cpu_to_be_16(set_len);

    uint16_t ipfix_len = sizeof(*ipfix_hdr) + set_len;
    ipfix_hdr->length = rte_cpu_to_be_16(ipfix_len);

    total_len = sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*udp_hdr) + ipfix_len;
    m->data_len = total_len;
    m->pkt_len = total_len;

    return m;
}

/* Export flows to collector */
static void
export_flows(struct rte_mempool *mbuf_pool, uint16_t port)
{
    struct rte_mbuf *m;
    uint32_t *keys;
    uint32_t next = 0;
    int32_t ret;
    int exported = 0;

    /* Send template first */
    m = create_ipfix_template(mbuf_pool);
    if (m != NULL) {
        /* Note: In production, add proper UDP/IP/Ethernet headers */
        rte_pktmbuf_free(m);
    }

    keys = rte_malloc(NULL, sizeof(uint32_t) * MAX_FLOW_ENTRIES, 0);
    if (keys == NULL)
        return;

    /* Iterate through flow table */
    while ((ret = rte_hash_iterate(flow_table, (const void **)&keys,
                                    (void **)&next, &next)) >= 0) {
        struct flow_record *flow = &flow_records[ret];
        uint64_t now = rte_get_timer_cycles() / rte_get_timer_hz();

        /* Check if flow should be exported */
        if ((now - flow->last_seen > FLOW_TIMEOUT_SEC) ||
            (now - flow->first_seen > ACTIVE_TIMEOUT_SEC)) {

            /* Create IPFIX data packet */
            /* In production: build proper IPFIX data message */

            exported++;

            /* Remove expired flow */
            rte_hash_del_key(flow_table, &flow->key);
        }
    }

    rte_free(keys);
    lcore_stats[rte_lcore_id()].flows_exported += exported;
}

/* Process a single packet */
static inline void
process_packet(struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ip_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    struct rte_udp_hdr *udp_hdr;
    struct flow_key key;
    struct flow_record *flow;
    int ret;
    uint64_t now;

    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    /* Only process IPv4 */
    if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
        return;

    ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

    memset(&key, 0, sizeof(key));
    key.src_ip = rte_be_to_cpu_32(ip_hdr->src_addr);
    key.dst_ip = rte_be_to_cpu_32(ip_hdr->dst_addr);
    key.protocol = ip_hdr->next_proto_id;

    /* Extract port numbers */
    if (ip_hdr->next_proto_id == IPPROTO_TCP) {
        tcp_hdr = (struct rte_tcp_hdr *)((uint8_t *)ip_hdr +
                                         (ip_hdr->version_ihl & 0x0F) * 4);
        key.src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
        key.dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
    } else if (ip_hdr->next_proto_id == IPPROTO_UDP) {
        udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ip_hdr +
                                         (ip_hdr->version_ihl & 0x0F) * 4);
        key.src_port = rte_be_to_cpu_16(udp_hdr->src_port);
        key.dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
    }

    now = rte_get_timer_cycles() / rte_get_timer_hz();

    /* Lookup or create flow */
    ret = rte_hash_lookup(flow_table, &key);
    if (ret < 0) {
        /* New flow */
        ret = rte_hash_add_key(flow_table, &key);
        if (ret < 0)
            return; /* Hash table full */

        flow = &flow_records[ret];
        memset(flow, 0, sizeof(*flow));
        memcpy(&flow->key, &key, sizeof(key));
        flow->first_seen = now;
        flow->tos = ip_hdr->type_of_service;

        lcore_stats[rte_lcore_id()].flows_created++;
    } else {
        flow = &flow_records[ret];
    }

    /* Update flow statistics */
    flow->packet_count++;
    flow->byte_count += rte_pktmbuf_pkt_len(m);
    flow->last_seen = now;

    if (ip_hdr->next_proto_id == IPPROTO_TCP) {
        tcp_hdr = (struct rte_tcp_hdr *)((uint8_t *)ip_hdr +
                                         (ip_hdr->version_ihl & 0x0F) * 4);
        flow->tcp_flags |= tcp_hdr->tcp_flags;
    }
}

/* Main packet processing loop */
static int
lcore_main(void *arg)
{
    struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
    uint16_t port;
    uint64_t last_export = 0;
    unsigned lcore_id = rte_lcore_id();

    printf("Core %u starting packet processing\n", lcore_id);

    RTE_ETH_FOREACH_DEV(port) {
        if ((app_config.enabled_port_mask & (1 << port)) == 0)
            continue;

        while (!force_quit) {
            struct rte_mbuf *bufs[BURST_SIZE];
            const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

            if (unlikely(nb_rx == 0))
                continue;

            lcore_stats[lcore_id].rx_packets += nb_rx;

            /* Process packets */
            for (uint16_t i = 0; i < nb_rx; i++) {
                process_packet(bufs[i]);
                rte_pktmbuf_free(bufs[i]);
            }

            /* Export flows periodically */
            uint64_t now = rte_get_timer_cycles();
            if ((now - last_export) > (EXPORT_INTERVAL_MS * rte_get_timer_hz() / 1000)) {
                export_flows(mbuf_pool, port);
                last_export = now;
            }
        }
    }

    return 0;
}

/* Signal handler */
static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

/* Parse collector address */
static int
parse_collector(const char *str)
{
    char *colon;
    char ip_str[32];

    strncpy(ip_str, str, sizeof(ip_str) - 1);
    colon = strchr(ip_str, ':');

    if (colon) {
        *colon = '\0';
        app_config.collector_port = atoi(colon + 1);
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1)
        return -1;

    app_config.collector_ip = ntohl(addr.s_addr);
    return 0;
}

/* Parse command line arguments */
static int
parse_args(int argc, char **argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "p:c:")) != -1) {
        switch (opt) {
        case 'p':
            app_config.enabled_port_mask = strtoul(optarg, NULL, 16);
            break;
        case 'c':
            if (parse_collector(optarg) < 0) {
                printf("Invalid collector address\n");
                return -1;
            }
            break;
        default:
            printf("Usage: %s -p PORT_MASK -c COLLECTOR_IP:PORT\n", argv[0]);
            return -1;
        }
    }

    return 0;
}

/* Main function */
int
main(int argc, char **argv)
{
    struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    uint16_t portid;
    int ret;

    /* Initialize EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    /* Parse application arguments */
    if (parse_args(argc, argv) < 0)
        rte_exit(EXIT_FAILURE, "Invalid arguments\n");

    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Check ports */
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");

    /* Create mbuf pool */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Create flow hash table */
    struct rte_hash_parameters hash_params = {
        .name = "flow_table",
        .entries = MAX_FLOW_ENTRIES,
        .key_len = sizeof(struct flow_key),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };

    flow_table = rte_hash_create(&hash_params);
    if (flow_table == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create flow hash table\n");

    flow_records = rte_zmalloc(NULL, sizeof(struct flow_record) * MAX_FLOW_ENTRIES, 0);
    if (flow_records == NULL)
        rte_exit(EXIT_FAILURE, "Cannot allocate flow records\n");

    /* Initialize ports */
    RTE_ETH_FOREACH_DEV(portid) {
        if ((app_config.enabled_port_mask & (1 << portid)) == 0)
            continue;

        if (port_init(portid, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);
    }

    if (rte_lcore_count() > 1)
        printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

    /* Launch main loop */
    lcore_main(mbuf_pool);

    /* Cleanup */
    printf("\nCleaning up...\n");

    RTE_ETH_FOREACH_DEV(portid) {
        if ((app_config.enabled_port_mask & (1 << portid)) == 0)
            continue;
        printf("Closing port %d...", portid);
        ret = rte_eth_dev_stop(portid);
        if (ret != 0)
            printf("rte_eth_dev_stop: err=%d, port=%d\n", ret, portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }

    /* Print statistics */
    printf("\n=== Statistics ===\n");
    for (unsigned i = 0; i < RTE_MAX_LCORE; i++) {
        if (lcore_stats[i].rx_packets > 0) {
            printf("Core %u: RX=%" PRIu64 " Flows Created=%" PRIu64
                   " Exported=%" PRIu64 "\n",
                   i, lcore_stats[i].rx_packets,
                   lcore_stats[i].flows_created,
                   lcore_stats[i].flows_exported);
        }
    }

    rte_hash_free(flow_table);
    rte_free(flow_records);
    rte_eal_cleanup();

    return 0;
}
