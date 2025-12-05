/**
 * @file nat_load_test.c
 * @brief NAT Load Testing Tool - Measures MPPS per core with real NAT sessions
 *
 * Usage: nat_load_test <num_sessions> <packets_per_session> <duration_sec>
 * Example: nat_load_test 10000 1000 60
 */

#include "config.h"
#include "dpdk_init.h"
#include "interface.h"
#include "log.h"
#include "nat.h"
#include "packet.h"
#include "routing_table.h"
#include "vpp_parser.h"
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_DPDK
#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>
#endif

/* Test configuration */
static volatile bool g_running = true;
static _Atomic uint64_t g_packets_processed = 0;
static _Atomic uint64_t g_packets_dropped = 0;
static _Atomic uint64_t g_sessions_created = 0;

/* Test parameters */
static uint32_t g_num_sessions = 10000;
static uint32_t g_packets_per_session = 1000;
static uint32_t g_duration_sec = 60;
static uint32_t g_num_threads = 8;

/* Statistics per thread */
struct thread_stats {
    uint64_t packets_processed;
    uint64_t packets_dropped;
    uint64_t sessions_created;
    uint64_t lookup_hits;
    uint64_t lookup_misses;
    uint32_t thread_id;
};

static struct thread_stats g_thread_stats[16];

/* Signal handler */
static void signal_handler(int signum)
{
    (void)signum;
    g_running = false;
    printf("\nLoad test interrupted, stopping...\n");
}

/* Generate test packet */
static struct pkt_buf *generate_test_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port,
                                            uint16_t dst_port, uint8_t protocol, uint16_t seq)
{
    struct pkt_buf *pkt = pkt_alloc();
    if (!pkt) {
        return NULL;
    }

#ifdef HAVE_DPDK
    /* Build Ethernet header */
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt->data;
    memset(eth->dst_addr.addr_bytes, 0xFF, 6); /* Broadcast */
    memset(eth->src_addr.addr_bytes, 0x00, 6);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    /* Build IP header */
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pkt->data + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + 8);
    ip->packet_id = rte_cpu_to_be_16(seq);
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = protocol;
    ip->src_addr = rte_cpu_to_be_32(src_ip);
    ip->dst_addr = rte_cpu_to_be_32(dst_ip);
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    if (protocol == IPPROTO_ICMP) {
        /* Build ICMP header */
        struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(ip + 1);
        icmp->icmp_type = 8; /* Echo Request */
        icmp->icmp_code = 0;
        icmp->icmp_ident = rte_cpu_to_be_16(src_port);
        icmp->icmp_seq_nb = rte_cpu_to_be_16(seq);
        icmp->icmp_cksum = 0;
        /* Calculate ICMP checksum manually (avoiding packed struct alignment issues) */
        uint32_t sum = 0;
        uint8_t *bytes = (uint8_t *)icmp;
        /* Process as bytes to avoid alignment issues - ICMP header is 8 bytes */
        for (int i = 0; i < 8; i += 2) {
            /* Read as big-endian (network byte order) */
            uint16_t word = ((uint16_t)bytes[i] << 8) | bytes[i + 1];
            sum += word;
        }
        /* Fold carry bits */
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        icmp->icmp_cksum = rte_cpu_to_be_16((uint16_t)~sum);
    } else if (protocol == IPPROTO_UDP) {
        /* Build UDP header */
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
        udp->src_port = rte_cpu_to_be_16(src_port);
        udp->dst_port = rte_cpu_to_be_16(dst_port);
        udp->dgram_len = rte_cpu_to_be_16(8);
        udp->dgram_cksum = 0;
    }

    pkt->len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + 8;
    pkt->meta.ingress_ifindex = 2; /* LAN interface */
    pkt->meta.protocol = protocol;
    pkt->meta.src_ip = src_ip;
    pkt->meta.dst_ip = dst_ip;
#endif

    return pkt;
}

/* Worker thread - generates and processes packets */
static void *worker_thread(void *arg)
{
    struct thread_stats *stats = (struct thread_stats *)arg;
    uint32_t thread_id = stats->thread_id;

    /* Each thread handles a subset of sessions */
    uint32_t sessions_per_thread = g_num_sessions / g_num_threads;
    uint32_t start_session = thread_id * sessions_per_thread;
    uint32_t end_session = start_session + sessions_per_thread;

    /* Create mock interface for testing - use interface 1 (WAN) */
    struct interface *mock_iface = interface_find_by_index(1);
    if (!mock_iface) {
        /* If no interface exists, we'll need to create one or skip interface check */
        printf("Thread %u: Warning - No interface found, continuing anyway\n", thread_id);
    }

    printf("Thread %u: Processing sessions %u-%u\n", thread_id, start_session, end_session - 1);

    uint32_t packet_count = 0;
    time_t start_time = time(NULL);

    while (g_running) {
        /* Check duration */
        if (time(NULL) - start_time >= g_duration_sec) {
            break;
        }

        /* Process packets for each session in this thread's range */
        for (uint32_t s = start_session; s < end_session && g_running; s++) {
            /* Generate source IP/port for this session */
            uint32_t src_ip = 0x0A000000 | (s & 0x0000FFFF); /* 10.0.0.x */
            uint16_t src_port = 1024 + (s % 60000);
            uint32_t dst_ip = 0x08080808; /* 8.8.8.8 */
            uint16_t dst_port = 53;       /* DNS */
            uint8_t protocol = (s % 3 == 0)   ? IPPROTO_TCP
                               : (s % 3 == 1) ? IPPROTO_UDP
                                              : IPPROTO_ICMP;

            /* Generate packets for this session */
            for (uint32_t p = 0; p < g_packets_per_session && g_running; p++) {
                struct pkt_buf *pkt =
                    generate_test_packet(src_ip, dst_ip, src_port, dst_port, protocol, p);
                if (!pkt) {
                    stats->packets_dropped++;
                    atomic_fetch_add(&g_packets_dropped, 1);
                    continue;
                }

                /* Apply NAT SNAT */
                if (mock_iface) {
                    int nat_result = nat_translate_snat(pkt, mock_iface);
                    if (nat_result == 0) {
                        stats->packets_processed++;
                        stats->lookup_hits++;
                        __atomic_fetch_add(&g_packets_processed, 1, __ATOMIC_RELAXED);
                    } else if (nat_result == -1) {
                        /* Session created */
                        stats->sessions_created++;
                        stats->packets_processed++;
                        stats->lookup_misses++;
                        __atomic_fetch_add(&g_sessions_created, 1, __ATOMIC_RELAXED);
                        __atomic_fetch_add(&g_packets_processed, 1, __ATOMIC_RELAXED);
                    } else {
                        stats->packets_dropped++;
                        __atomic_fetch_add(&g_packets_dropped, 1, __ATOMIC_RELAXED);
                    }
                } else {
                    /* No interface - just count as processed for testing */
                    stats->packets_processed++;
                    __atomic_fetch_add(&g_packets_processed, 1, __ATOMIC_RELAXED);
                }

                pkt_free(pkt);
                packet_count++;
            }
        }
    }

    stats->packets_processed = packet_count;
    printf("Thread %u: Processed %lu packets, created %lu sessions\n", thread_id,
           stats->packets_processed, stats->sessions_created);

    return NULL;
}

/* Print statistics */
static void print_stats(void)
{
    extern struct nat_config g_nat_config;
    struct nat_stats *stats = &g_nat_config.stats;

    printf("\n=== NAT Statistics ===\n");
    printf("Active sessions: %lu\n", stats->active_sessions);
    printf("Sessions created: %lu\n", stats->sessions_created);
    printf("Sessions deleted: %lu\n", stats->sessions_deleted);
    printf("In2Out hits: %lu\n", stats->in2out_hits);
    printf("In2Out misses: %lu\n", stats->in2out_misses);
    printf("Out2In hits: %lu\n", stats->out2in_hits);
    printf("Out2In misses: %lu\n", stats->out2in_misses);
}

/* Main function */
int main(int argc, char **argv)
{
    printf("========================================\n");
    printf("NAT Load Test - MPPS Per Core\n");
    printf("========================================\n\n");

    /* Parse arguments */
    if (argc >= 2) {
        g_num_sessions = atoi(argv[1]);
    }
    if (argc >= 3) {
        g_packets_per_session = atoi(argv[2]);
    }
    if (argc >= 4) {
        g_duration_sec = atoi(argv[3]);
    }
    if (argc >= 5) {
        g_num_threads = atoi(argv[4]);
    }

    printf("Test Configuration:\n");
    printf("  Sessions: %u\n", g_num_sessions);
    printf("  Packets per session: %u\n", g_packets_per_session);
    printf("  Duration: %u seconds\n", g_duration_sec);
    printf("  Threads: %u\n", g_num_threads);
    printf("  Total packets: %lu\n", (unsigned long)g_num_sessions * g_packets_per_session);
    printf("\n");

    /* Initialize VPP config defaults (needed for other subsystems) */
    vpp_config_init_defaults();

    /* Initialize DPDK (required for NAT mempool) */
    /* Use minimal DPDK args for load testing */
    int dpdk_argc = 3;
    char *dpdk_argv[] = {"nat_load_test", "--no-huge", "--no-pci", NULL};
    if (dpdk_init(dpdk_argc, dpdk_argv) != 0) {
        fprintf(stderr, "Failed to initialize DPDK\n");
        return 1;
    }
    printf("DPDK initialized\n");

    /* Initialize configuration (needed for other subsystems) */
    if (config_init() != 0) {
        fprintf(stderr, "Failed to initialize configuration\n");
        return 1;
    }

    /* Initialize interfaces (needed for NAT) */
    if (interface_init() != 0) {
        fprintf(stderr, "Failed to initialize interface subsystem\n");
        return 1;
    }

    /* Initialize routing table (needed for NAT) */
    if (routing_table_init() == NULL) {
        fprintf(stderr, "Failed to initialize routing table\n");
        return 1;
    }

    if (nat_init() != 0) {
        fprintf(stderr, "Failed to initialize NAT subsystem\n");
        return 1;
    }

    /* Create dummy WAN interface for testing if not found */
    if (!interface_find_by_index(1)) {
        struct interface *iface = interface_create("wan0", IF_TYPE_DUMMY);
        if (iface) {
            iface->ifindex = 1;
            iface->state = IF_STATE_UP;
            iface->config.ipv4_addr.s_addr = 0x08080808; /* 8.8.8.8 */
            iface->config.ipv4_mask.s_addr = 0xFFFFFF00;
            printf("Created dummy WAN interface 'wan0' (index 1)\n");
        }
    }

    /* Enable NAT */
    extern struct nat_config g_nat_config;
    g_nat_config.enabled = true;

    /* Create NAT pool */
    if (nat_pool_create("TEST_POOL", 0x01020300, 0x010203FF, 0xFFFFFF00) != 0) {
        fprintf(stderr, "Failed to create NAT pool\n");
        return 1;
    }

    printf("NAT pool created: 1.2.3.0/24\n");

    /* Setup signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize thread stats */
    for (uint32_t i = 0; i < g_num_threads; i++) {
        memset(&g_thread_stats[i], 0, sizeof(g_thread_stats[i]));
        g_thread_stats[i].thread_id = i;
    }

    printf("Starting load test...\n");
    time_t test_start = time(NULL);

    /* Create worker threads */
    pthread_t threads[16];
    for (uint32_t i = 0; i < g_num_threads; i++) {
        if (pthread_create(&threads[i], NULL, worker_thread, &g_thread_stats[i]) != 0) {
            fprintf(stderr, "Failed to create thread %u\n", i);
            return 1;
        }
    }

    /* Wait for threads */
    for (uint32_t i = 0; i < g_num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    time_t test_end = time(NULL);
    uint32_t test_duration = (uint32_t)(test_end - test_start);

    /* Calculate statistics */
    uint64_t total_packets = __atomic_load_n(&g_packets_processed, __ATOMIC_RELAXED);
    uint64_t total_dropped = __atomic_load_n(&g_packets_dropped, __ATOMIC_RELAXED);
    uint64_t total_sessions = __atomic_load_n(&g_sessions_created, __ATOMIC_RELAXED);

    double mpps = (double)total_packets / (test_duration * 1000000.0);
    double mpps_per_core = mpps / g_num_threads;
    double pps = (double)total_packets / test_duration;

    printf("\n========================================\n");
    printf("Load Test Results\n");
    printf("========================================\n");
    printf("Test duration: %u seconds\n", test_duration);
    printf("Total packets processed: %lu\n", total_packets);
    printf("Total packets dropped: %lu\n", total_dropped);
    printf("Total sessions created: %lu\n", total_sessions);
    printf("\n");
    printf("Throughput: %.2f MPPS (%.2f M packets/sec)\n", mpps, mpps);
    printf("Per-core throughput: %.2f MPPS/core\n", mpps_per_core);
    printf("Packets per second: %.0f\n", pps);
    printf("Packet loss: %.2f%%\n",
           (double)total_dropped * 100.0 / (total_packets + total_dropped));
    printf("\n");

    /* Per-thread statistics */
    printf("Per-Thread Statistics:\n");
    for (uint32_t i = 0; i < g_num_threads; i++) {
        double thread_mpps =
            (double)g_thread_stats[i].packets_processed / (test_duration * 1000000.0);
        printf("  Thread %u: %.2f MPPS, %lu packets, %lu sessions, %lu hits, %lu misses\n", i,
               thread_mpps, g_thread_stats[i].packets_processed, g_thread_stats[i].sessions_created,
               g_thread_stats[i].lookup_hits, g_thread_stats[i].lookup_misses);
    }
    printf("\n");

    /* NAT statistics */
    print_stats();

    /* Cleanup */
    nat_cleanup();

    printf("========================================\n");
    printf("Load test complete!\n");
    printf("========================================\n");

    return 0;
}
