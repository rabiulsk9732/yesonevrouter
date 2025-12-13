/**
 * @file dns.c
 * @brief DNS Resolver/Proxy Implementation
 */

#define _DEFAULT_SOURCE  /* For usleep */
#include "dns.h"
#include "interface.h"
#include "routing_table.h"
#include "arp.h"
#include "packet.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#ifdef HAVE_DPDK
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#endif

/* DNS Header */
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qcount;    /* Question count */
    uint16_t ancount;   /* Answer count */
    uint16_t nscount;   /* Authority count */
    uint16_t arcount;   /* Additional count */
} __attribute__((packed));

/* DNS Flags */
#define DNS_FLAG_QR     0x8000  /* Query/Response */
#define DNS_FLAG_OPCODE 0x7800  /* Opcode */
#define DNS_FLAG_AA     0x0400  /* Authoritative Answer */
#define DNS_FLAG_TC     0x0200  /* Truncated */
#define DNS_FLAG_RD     0x0100  /* Recursion Desired */
#define DNS_FLAG_RA     0x0080  /* Recursion Available */
#define DNS_FLAG_RCODE  0x000F  /* Response Code */

/* DNS Types */
#define DNS_TYPE_A      1
#define DNS_TYPE_NS     2
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_SOA    6
#define DNS_TYPE_PTR    12
#define DNS_TYPE_MX     15
#define DNS_TYPE_TXT    16
#define DNS_TYPE_AAAA   28

/* DNS Class */
#define DNS_CLASS_IN    1

/* DNS Cache Entry */
struct dns_cache_entry {
    char hostname[256];
    uint32_t ip_address;
    time_t expire_time;
    uint32_t ttl;
    struct dns_cache_entry *next;
};

/* DNS Configuration */
struct dns_config {
    struct in_addr servers[DNS_MAX_SERVERS];
    int num_servers;
    uint32_t timeout_ms;
    uint32_t cache_ttl;
    bool cache_enabled;
    struct dns_cache_entry *cache;
    pthread_mutex_t cache_lock;
    struct dns_stats stats;
};

static struct dns_config *g_dns = NULL;

/* Calculate checksum */
static uint16_t dns_checksum(void *b, int len)
{
    uint16_t *buf = b;
    unsigned int sum = 0;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

/* Encode hostname to DNS format */
static int dns_encode_hostname(const char *hostname, uint8_t *buf, int maxlen)
{
    int pos = 0;
    const char *p = hostname;

    while (*p && pos < maxlen - 1) {
        const char *dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);

        if (pos + len + 1 >= maxlen) break;

        buf[pos++] = len;
        memcpy(&buf[pos], p, len);
        pos += len;

        if (dot) p = dot + 1;
        else break;
    }

    buf[pos++] = 0;  /* Null terminator */
    return pos;
}

/* Decode hostname from DNS format (used for response parsing) */
__attribute__((unused))
static int dns_decode_hostname(const uint8_t *pkt, int offset, char *hostname, int maxlen)
{
    int pos = 0;
    int jumped = 0;
    int orig_offset = offset;

    while (pkt[offset] != 0 && pos < maxlen - 1) {
        if ((pkt[offset] & 0xC0) == 0xC0) {
            /* Pointer */
            offset = ((pkt[offset] & 0x3F) << 8) | pkt[offset + 1];
            if (!jumped) orig_offset += 2;
            jumped = 1;
        } else {
            int len = pkt[offset++];
            if (pos + len >= maxlen - 1) break;

            if (pos > 0) hostname[pos++] = '.';
            memcpy(&hostname[pos], &pkt[offset], len);
            pos += len;
            offset += len;

            if (!jumped) orig_offset = offset;
        }
    }

    hostname[pos] = '\0';
    return jumped ? orig_offset : offset + 1;
}

/**
 * Initialize DNS subsystem
 */
int dns_init(void)
{
    if (g_dns) return 0;

    g_dns = calloc(1, sizeof(*g_dns));
    if (!g_dns) return -1;

    /* Default settings */
    g_dns->timeout_ms = 5000;
    g_dns->cache_ttl = 300;
    g_dns->cache_enabled = true;
    pthread_mutex_init(&g_dns->cache_lock, NULL);

    /* Default DNS servers (Google) */
    inet_pton(AF_INET, "8.8.8.8", &g_dns->servers[0]);
    inet_pton(AF_INET, "8.8.4.4", &g_dns->servers[1]);
    g_dns->num_servers = 2;

    /* YLOG_INFO("DNS subsystem initialized"); */
    return 0;
}

/**
 * Cleanup DNS subsystem
 */
void dns_cleanup(void)
{
    if (!g_dns) return;

    /* Free cache */
    pthread_mutex_lock(&g_dns->cache_lock);
    struct dns_cache_entry *entry = g_dns->cache;
    while (entry) {
        struct dns_cache_entry *next = entry->next;
        free(entry);
        entry = next;
    }
    pthread_mutex_unlock(&g_dns->cache_lock);

    pthread_mutex_destroy(&g_dns->cache_lock);
    free(g_dns);
    g_dns = NULL;
}

/**
 * Add DNS server
 */
int dns_add_server(const struct in_addr *server)
{
    if (!g_dns || !server) return -1;
    if (g_dns->num_servers >= DNS_MAX_SERVERS) return -1;

    g_dns->servers[g_dns->num_servers++] = *server;
    return 0;
}

/**
 * Clear DNS servers
 */
void dns_clear_servers(void)
{
    if (!g_dns) return;
    g_dns->num_servers = 0;
}

/**
 * Cache lookup
 */
static int dns_cache_lookup(const char *hostname, uint32_t *ip_address)
{
    if (!g_dns || !g_dns->cache_enabled) return -1;

    pthread_mutex_lock(&g_dns->cache_lock);

    time_t now = time(NULL);
    struct dns_cache_entry *entry = g_dns->cache;

    while (entry) {
        if (strcmp(entry->hostname, hostname) == 0) {
            if (entry->expire_time > now) {
                *ip_address = entry->ip_address;
                g_dns->stats.cache_hits++;
                pthread_mutex_unlock(&g_dns->cache_lock);
                return 0;
            }
            break;  /* Expired */
        }
        entry = entry->next;
    }

    g_dns->stats.cache_misses++;
    pthread_mutex_unlock(&g_dns->cache_lock);
    return -1;
}

/**
 * Add to cache (used when processing DNS responses)
 */
__attribute__((unused))
static void dns_cache_add(const char *hostname, uint32_t ip_address, uint32_t ttl)
{
    if (!g_dns || !g_dns->cache_enabled) return;

    pthread_mutex_lock(&g_dns->cache_lock);

    /* Check if exists */
    struct dns_cache_entry *entry = g_dns->cache;
    while (entry) {
        if (strcmp(entry->hostname, hostname) == 0) {
            entry->ip_address = ip_address;
            entry->ttl = ttl;
            entry->expire_time = time(NULL) + ttl;
            pthread_mutex_unlock(&g_dns->cache_lock);
            return;
        }
        entry = entry->next;
    }

    /* Create new entry */
    entry = calloc(1, sizeof(*entry));
    if (entry) {
        strncpy(entry->hostname, hostname, sizeof(entry->hostname) - 1);
        entry->ip_address = ip_address;
        entry->ttl = ttl;
        entry->expire_time = time(NULL) + ttl;
        entry->next = g_dns->cache;
        g_dns->cache = entry;
    }

    pthread_mutex_unlock(&g_dns->cache_lock);
}

/**
 * Resolve hostname to IP address
 */
int dns_resolve(const char *hostname, struct in_addr *result)
{
    if (!g_dns || !hostname || !result) return -1;
    if (g_dns->num_servers == 0) return -1;

    g_dns->stats.queries++;

    /* Check cache first */
    uint32_t cached_ip;
    if (dns_cache_lookup(hostname, &cached_ip) == 0) {
        result->s_addr = cached_ip;
        return 0;
    }

    /* Build DNS query */
    uint8_t query[512];
    memset(query, 0, sizeof(query));

    struct dns_header *hdr = (struct dns_header *)query;
    hdr->id = htons(rand() & 0xFFFF);
    hdr->flags = htons(DNS_FLAG_RD);  /* Recursion desired */
    hdr->qcount = htons(1);

    /* Encode hostname */
    int qlen = dns_encode_hostname(hostname, query + sizeof(*hdr),
                                   sizeof(query) - sizeof(*hdr) - 4);

    /* Query type and class */
    uint8_t *qtype = query + sizeof(*hdr) + qlen;
    qtype[0] = 0; qtype[1] = DNS_TYPE_A;   /* Type A */
    qtype[2] = 0; qtype[3] = DNS_CLASS_IN; /* Class IN */

    int query_len = sizeof(*hdr) + qlen + 4;

    /* Find route to DNS server */
    struct route_entry *route = routing_table_lookup(routing_table_get_instance(),
                                                     &g_dns->servers[0]);
    if (!route) {
        YLOG_ERROR("No route to DNS server");
        return -1;
    }

    struct interface *iface = interface_find_by_index(route->egress_ifindex);
    if (!iface) {
        YLOG_ERROR("Interface not found for DNS");
        return -1;
    }

    /* Resolve gateway ARP */
    uint8_t gw_mac[6];
    uint32_t next_hop_nbo = route->next_hop.s_addr ? route->next_hop.s_addr : g_dns->servers[0].s_addr;
    uint32_t next_hop_hbo = ntohl(next_hop_nbo);
    uint32_t src_ip_hbo = ntohl(iface->config.ipv4_addr.s_addr);

    if (arp_lookup(next_hop_hbo, gw_mac) != 0) {
        arp_send_request(next_hop_hbo, src_ip_hbo, iface->mac_addr, iface->ifindex);
        usleep(500000);
        if (arp_lookup(next_hop_hbo, gw_mac) != 0) {
            YLOG_ERROR("ARP failed for DNS gateway");
            return -1;
        }
    }

    /* Build packet */
    struct pkt_buf *pkt = pkt_alloc();
    if (!pkt) return -1;

    /* Ethernet */
    struct ethhdr *eth = (struct ethhdr *)pkt->data;
    memcpy(eth->h_dest, gw_mac, 6);
    memcpy(eth->h_source, iface->mac_addr, 6);
    eth->h_proto = htons(ETH_P_IP);

    /* IP */
    struct iphdr *ip = (struct iphdr *)(pkt->data + sizeof(struct ethhdr));
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + query_len);
    ip->id = htons(rand() & 0xFFFF);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = iface->config.ipv4_addr.s_addr;
    ip->daddr = g_dns->servers[0].s_addr;
    ip->check = dns_checksum(ip, sizeof(struct iphdr));

    /* UDP */
    struct udphdr *udp = (struct udphdr *)(pkt->data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    udp->source = htons(12345 + (rand() % 50000));
    udp->dest = htons(53);
    udp->len = htons(sizeof(struct udphdr) + query_len);
    udp->check = 0;  /* Optional for IPv4 */

    /* DNS Query */
    memcpy(pkt->data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr),
           query, query_len);

    pkt->len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + query_len;

    /* Send */
    if (iface->ops->send(iface, pkt) != 0) {
        pkt_free(pkt);
        return -1;
    }

    pkt_free(pkt);
    g_dns->stats.queries_sent++;

    /* Note: In a real implementation, we'd wait for the DNS response packet.
     * For now, we'll simulate with a timeout and indicate pending resolution.
     */
    YLOG_INFO("DNS query sent for %s", hostname);

    return -1;  /* Resolution pending */
}

/**
 * Get DNS statistics
 */
int dns_get_stats(struct dns_stats *stats)
{
    if (!g_dns || !stats) return -1;
    memcpy(stats, &g_dns->stats, sizeof(*stats));
    return 0;
}

/**
 * Print DNS configuration
 */
void dns_print_config(void)
{
    if (!g_dns) {
        printf("DNS not initialized\n");
        return;
    }

    printf("\nDNS Configuration:\n");
    printf("  Servers:\n");
    for (int i = 0; i < g_dns->num_servers; i++) {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &g_dns->servers[i], buf, sizeof(buf));
        printf("    %d. %s\n", i + 1, buf);
    }
    printf("  Timeout: %u ms\n", g_dns->timeout_ms);
    printf("  Cache: %s (TTL: %u sec)\n",
           g_dns->cache_enabled ? "Enabled" : "Disabled", g_dns->cache_ttl);
    printf("\n  Statistics:\n");
    printf("    Queries: %lu\n", g_dns->stats.queries);
    printf("    Responses: %lu\n", g_dns->stats.responses);
    printf("    Cache hits: %lu\n", g_dns->stats.cache_hits);
    printf("    Cache misses: %lu\n", g_dns->stats.cache_misses);
    printf("    Timeouts: %lu\n", g_dns->stats.timeouts);
    printf("\n");
}
