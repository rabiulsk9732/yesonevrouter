/**
 * @file packet_rx.c
 * @brief Packet Reception and Processing
 *
 * References:
 * - DPDK Programmer's Guide: https://doc.dpdk.org/guides/prog_guide/
 * - VPP Developer Guide: https://my-vpp-docs.readthedocs.io/en/latest/gettingstarted/developers/
 */

#include "interface.h"
#include "packet.h"
#include "arp.h"
#include "routing_table.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <arpa/inet.h>

#ifdef HAVE_DPDK
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#include <rte_arp.h>
#else
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#endif

static volatile bool g_rx_running = false;
static pthread_t g_rx_thread;

/* Process ARP packet */
static void process_arp(struct pkt_buf *pkt)
{
    /* Validate ARP header - l3_offset points to ARP header after Ethernet */
    if (pkt->len < pkt->meta.l3_offset + sizeof(struct arp_hdr)) {
        YLOG_WARNING("Truncated ARP packet");
        return;
    }

    YLOG_INFO("Processing ARP packet on interface %u", pkt->meta.ingress_ifindex);

    /* Pass ARP data (starting at l3_offset, after Ethernet header) to ARP subsystem */
    uint8_t *arp_data = pkt->data + pkt->meta.l3_offset;
    uint16_t arp_len = pkt->len - pkt->meta.l3_offset;
    arp_process_packet(arp_data, arp_len, pkt->meta.ingress_ifindex);
}

/* Calculate checksum - used for IP/ICMP */
static uint16_t calc_checksum(void *data, int len)
{
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)data;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(uint8_t *)ptr;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t)~sum;
}

/* Process ICMP echo request - send reply using DPDK structures */
static void process_icmp_echo(struct pkt_buf *pkt, struct interface *iface)
{
#ifdef HAVE_DPDK
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt->data;
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pkt->data + sizeof(struct rte_ether_hdr));
    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(pkt->data + sizeof(struct rte_ether_hdr) + ihl);

    /* Only handle echo request (type 8) */
    if (icmp->icmp_type != RTE_IP_ICMP_ECHO_REQUEST) {
        return;
    }

    YLOG_INFO("ICMP echo request from %u.%u.%u.%u",
              (rte_be_to_cpu_32(ip->src_addr) >> 24) & 0xFF,
              (rte_be_to_cpu_32(ip->src_addr) >> 16) & 0xFF,
              (rte_be_to_cpu_32(ip->src_addr) >> 8) & 0xFF,
              rte_be_to_cpu_32(ip->src_addr) & 0xFF);

    /* Allocate reply packet */
    struct pkt_buf *reply = pkt_alloc();
    if (!reply) {
        YLOG_ERROR("Failed to allocate ICMP reply packet");
        return;
    }

    /* Copy original packet */
    memcpy(reply->data, pkt->data, pkt->len);
    reply->len = pkt->len;

    /* Swap Ethernet addresses */
    struct rte_ether_hdr *reply_eth = (struct rte_ether_hdr *)reply->data;
    rte_ether_addr_copy(&eth->src_addr, &reply_eth->dst_addr);
    memcpy(&reply_eth->src_addr, iface->mac_addr, RTE_ETHER_ADDR_LEN);

    /* Swap IP addresses */
    struct rte_ipv4_hdr *reply_ip = (struct rte_ipv4_hdr *)(reply->data + sizeof(struct rte_ether_hdr));
    uint32_t tmp_ip = reply_ip->src_addr;
    reply_ip->src_addr = reply_ip->dst_addr;
    reply_ip->dst_addr = tmp_ip;

    /* Recalculate IP checksum */
    reply_ip->hdr_checksum = 0;
    reply_ip->hdr_checksum = rte_ipv4_cksum(reply_ip);

    /* Change ICMP type to echo reply (type 0) */
    struct rte_icmp_hdr *reply_icmp = (struct rte_icmp_hdr *)(reply->data + sizeof(struct rte_ether_hdr) + ihl);
    reply_icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;

    /* Recalculate ICMP checksum */
    int icmp_len = rte_be_to_cpu_16(reply_ip->total_length) - ihl;
    reply_icmp->icmp_cksum = 0;
    reply_icmp->icmp_cksum = calc_checksum(reply_icmp, icmp_len);

    /* Send reply */
    if (interface_send(iface, reply) == 0) {
        YLOG_INFO("ICMP echo reply sent");
    } else {
        YLOG_ERROR("Failed to send ICMP echo reply");
    }

    pkt_free(reply);
#else
    (void)pkt;
    (void)iface;
#endif
}

/* Process IPv4 packet */
static void process_ipv4(struct pkt_buf *pkt)
{
    struct interface *iface = interface_find_by_index(pkt->meta.ingress_ifindex);
    if (!iface) {
        return;
    }

    /* Check if destined for us */
    if (iface->config.ipv4_addr.s_addr != 0 &&
        pkt->meta.dst_ip == ntohl(iface->config.ipv4_addr.s_addr)) {

        /* Packet is for us */
        if (pkt->meta.protocol == IPPROTO_ICMP) {
            process_icmp_echo(pkt, iface);
        }
    }
}

/* Main packet processing function */
static void process_packet(struct pkt_buf *pkt)
{
    /* Extract metadata (parse headers) */
    if (pkt_extract_metadata(pkt) != 0) {
        YLOG_WARNING("Failed to extract packet metadata");
        return;
    }

    /* Dispatch based on L3 type */
    switch (pkt->meta.l3_type) {
        case PKT_L3_ARP:
            process_arp(pkt);
            break;
        case PKT_L3_IPV4:
            process_ipv4(pkt);
            break;
        default:
            YLOG_DEBUG("Unknown L3 packet type: %d", pkt->meta.l3_type);
            break;
    }
}

/* RX thread function */
static void *rx_thread_func(void *arg)
{
    (void)arg;
    struct interface *iface;
    struct pkt_buf *pkt;
    uint32_t i;
    int ret;

    YLOG_INFO("RX thread started");

    while (g_rx_running) {
        bool work_done = false;

        /* Poll all interfaces */
        /* Note: In a real high-performance system, we'd use epoll or DPDK polling */
        for (i = 1; i <= interface_count(); i++) {
            iface = interface_find_by_index(i);
            if (!iface || iface->state != IF_STATE_UP) {
                continue;
            }

            /* Try to receive a packet */
            ret = interface_recv(iface, &pkt);
            if (ret > 0 && pkt) {
                pkt->meta.ingress_ifindex = iface->ifindex;
                process_packet(pkt);
                pkt_free(pkt); /* Free packet after processing */
                work_done = true;
            }
        }

        /* Sleep briefly if no work was done to avoid 100% CPU usage */
        if (!work_done) {
            usleep(100); /* 100 microseconds */
        }
    }

    YLOG_INFO("RX thread stopped");
    return NULL;
}

int packet_rx_start(void)
{
    if (g_rx_running) {
        return 0;
    }

    g_rx_running = true;
    if (pthread_create(&g_rx_thread, NULL, rx_thread_func, NULL) != 0) {
        YLOG_ERROR("Failed to create RX thread");
        g_rx_running = false;
        return -1;
    }

    return 0;
}

void packet_rx_stop(void)
{
    if (!g_rx_running) {
        return;
    }

    g_rx_running = false;
    pthread_join(g_rx_thread, NULL);
}
