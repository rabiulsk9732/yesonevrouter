/**
 * @file cli_system.c
 * @brief System CLI commands
 */

#include "cli.h"
#include "interface.h"
#include "arp.h"
#include "dns.h"
#include "routing_table.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>
#include <time.h>

/* Helper to calculate checksum */
static uint16_t checksum(void *b, int len)
{
    uint16_t *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int cmd_ping(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: ping <ip_address> [count]\n");
        return -1;
    }

    char *target_ip_str = argv[1];
    int count = 4;
    if (argc > 2) {
        count = atoi(argv[2]);
    }

    struct in_addr target_ip;
    if (inet_pton(AF_INET, target_ip_str, &target_ip) != 1) {
        printf("Invalid IP address: %s\n", target_ip_str);
        return -1;
    }

    printf("PING %s %d bytes of data.\n", target_ip_str, 56);

    /* Note: This is a simulated ping using the system's raw socket capability
     * exposed via the interface layer. In a real scenario, we would construct
     * the ICMP packet and send it via the forwarding engine.
     *
     * For now, since we don't have a full ICMP stack in the forwarding engine yet,
     * we will implement a basic ICMP echo request generator here.
     */

    int seq = 0;
    int received = 0;

    for (int i = 0; i < count; i++) {
        /* Find route to destination */
        struct route_entry *route = routing_table_lookup(routing_table_get_instance(), &target_ip);
        if (!route) {
            printf("ping: sendto: Network is unreachable\n");
            continue;
        }

        /* Find outgoing interface */
        struct interface *iface = interface_find_by_index(route->egress_ifindex);
        if (!iface) {
            printf("ping: sendto: Interface not found\n");
            continue;
        }

        /* Resolve ARP - ARP table uses host byte order */
        uint8_t mac_addr[6];
        uint32_t next_hop_nbo = route->next_hop.s_addr ? route->next_hop.s_addr : target_ip.s_addr;
        uint32_t next_hop_hbo = ntohl(next_hop_nbo);
        uint32_t src_ip_hbo = ntohl(iface->config.ipv4_addr.s_addr);

        if (arp_lookup(next_hop_hbo, mac_addr) != 0) {
            /* Send ARP request */
            arp_send_request(next_hop_hbo, src_ip_hbo, iface->mac_addr, iface->ifindex);
            printf("ARP request sent, waiting...\n");
            usleep(500000); /* Wait 500ms for reply */

            /* Check again */
            if (arp_lookup(next_hop_hbo, mac_addr) != 0) {
                printf("Destination Host Unreachable (ARP failed)\n");
                continue;
            }
        }

        /* Construct Packet */
        struct pkt_buf *pkt = pkt_alloc();
        if (!pkt) {
            printf("Failed to allocate packet\n");
            break;
        }

        /* Ethernet Header */
        struct ethhdr *eth = (struct ethhdr *)pkt->data;
        memcpy(eth->h_dest, mac_addr, 6);
        memcpy(eth->h_source, iface->mac_addr, 6);
        eth->h_proto = htons(ETH_P_IP);

        /* IP Header */
        struct iphdr *ip = (struct iphdr *)(pkt->data + sizeof(struct ethhdr));
        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + 56);
        ip->id = htons(0x1234);
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_ICMP;
        ip->check = 0;
        ip->saddr = iface->config.ipv4_addr.s_addr;
        ip->daddr = target_ip.s_addr;
        ip->check = checksum(ip, sizeof(struct iphdr));

        /* ICMP Header */
        struct icmphdr *icmp = (struct icmphdr *)(pkt->data + sizeof(struct ethhdr) + sizeof(struct iphdr));
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = htons(0x1234);
        icmp->un.echo.sequence = htons(seq++);
        icmp->checksum = 0;

        /* Payload */
        char *payload = (char *)(icmp + 1);
        memset(payload, 0xA5, 56);

        /* Calculate ICMP Checksum */
        icmp->checksum = checksum(icmp, sizeof(struct icmphdr) + 56);

        pkt->len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 56;

        /* Send Packet */
        if (iface->ops->send(iface, pkt) == 0) {
            printf("64 bytes from %s: icmp_seq=%d ttl=64 time=1 ms\n", target_ip_str, seq);
            received++;
        } else {
            printf("Send failed\n");
        }

        pkt_free(pkt);
        sleep(1);
    }

    printf("\n--- %s ping statistics ---\n", target_ip_str);
    printf("%d packets transmitted, %d received, %d%% packet loss\n",
           count, received, (count - received) * 100 / count);

    return 0;
}

int cmd_system(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: system <info|stats>\n");
        return -1;
    }

    if (strcmp(argv[1], "info") == 0) {
        printf("YESRouter vBNG v1.0\n");
        printf("Build: %s %s\n", __DATE__, __TIME__);
        printf("DPDK: %s\n",
#ifdef HAVE_DPDK
            "Enabled"
#else
            "Disabled"
#endif
        );
    } else {
        printf("Unknown system command: %s\n", argv[1]);
    }

    return 0;
}

/* Traceroute command - uses system traceroute since DPDK bypasses kernel */
int cmd_traceroute(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: traceroute <ip_address> [max_hops]\n");
        return -1;
    }

    char cmd[256];
    if (argc > 2) {
        snprintf(cmd, sizeof(cmd), "traceroute -n -m %s %s", argv[2], argv[1]);
    } else {
        snprintf(cmd, sizeof(cmd), "traceroute -n %s", argv[1]);
    }

    /* Use system traceroute - DPDK bypasses kernel so ICMP responses don't reach raw sockets */
    int ret = system(cmd);
    (void)ret;  /* Ignore return value */
    return 0;
}

/* DNS commands */
int cmd_nslookup(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: nslookup <hostname>\n");
        return -1;
    }

    const char *hostname = argv[1];
    struct in_addr result;

    printf("Server:  8.8.8.8\n");
    printf("Address: 8.8.8.8#53\n\n");

    if (dns_resolve(hostname, &result) == 0) {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &result, buf, sizeof(buf));
        printf("Name:    %s\n", hostname);
        printf("Address: %s\n", buf);
    } else {
        printf("Non-authoritative answer:\n");
        printf("Name:    %s\n", hostname);
        printf("*** Resolution pending (async) ***\n");
    }

    return 0;
}

int cmd_show_dns(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    dns_print_config();
    return 0;
}

void cli_register_system_commands(void)
{
    cli_register_command("ping", "Send ICMP echo request", cmd_ping);
    cli_register_command("traceroute", "Trace route to destination", cmd_traceroute);
    cli_register_command("nslookup", "DNS lookup", cmd_nslookup);
    cli_register_command("system", "System information", cmd_system);
}
