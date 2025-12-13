/**
 * @file nat64.c
 * @brief NAT64 Translation Engine (RFC 6146/6145)
 *
 * Stateful NAT64 for IPv6-only networks accessing IPv4 content.
 * Implements header translation and ICMPv6/v4 translation.
 */

#include "nat.h"
#include "log.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

/**
 * Portable IPv6 header struct (matches DPDK naming)
 * DPDK's rte_ipv6_hdr is not available in all versions
 */
struct nat64_ipv6_hdr {
    uint32_t vtc_flow;      /* Version, Traffic Class, Flow Label */
    uint16_t payload_len;   /* Payload length */
    uint8_t  proto;         /* Next header (protocol) */
    uint8_t  hop_limits;    /* Hop limit (TTL) */
    uint8_t  src_addr[16];  /* Source address */
    uint8_t  dst_addr[16];  /* Destination address */
} __attribute__((packed));

/* Alias for compatibility */
#define rte_ipv6_hdr nat64_ipv6_hdr

/* NAT64 Well-Known Prefix: 64:ff9b::/96 (RFC 6052) */
static const uint8_t NAT64_WKP[12] = {
    0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

/* NAT64 Configuration */
static struct {
    bool enabled;
    uint8_t prefix[16];      /* NAT64 prefix */
    uint8_t prefix_len;      /* Prefix length (96 for WKP) */
    uint32_t pool_start;     /* IPv4 pool start */
    uint32_t pool_end;       /* IPv4 pool end */
} g_nat64_config = {
    .enabled = false,
    .prefix_len = 96
};

/**
 * Initialize NAT64 subsystem
 */
int nat64_init(void)
{
    /* Set default well-known prefix */
    memcpy(g_nat64_config.prefix, NAT64_WKP, 12);
    memset(&g_nat64_config.prefix[12], 0, 4);
    g_nat64_config.prefix_len = 96;

    YLOG_INFO("NAT64 initialized with WKP 64:ff9b::/96");
    return 0;
}

/**
 * Enable/disable NAT64
 */
void nat64_enable(bool enable)
{
    g_nat64_config.enabled = enable;
    YLOG_INFO("NAT64 %s", enable ? "enabled" : "disabled");
}

/**
 * Check if NAT64 is enabled
 */
bool nat64_is_enabled(void)
{
    return g_nat64_config.enabled;
}

/**
 * Configure NAT64 prefix
 */
int nat64_set_prefix(const uint8_t *prefix, uint8_t prefix_len)
{
    if (!prefix || prefix_len != 96) {
        YLOG_ERROR("NAT64: Only /96 prefix supported currently");
        return -1;
    }

    memcpy(g_nat64_config.prefix, prefix, 12);
    g_nat64_config.prefix_len = prefix_len;

    char prefix_str[64];
    inet_ntop(AF_INET6, g_nat64_config.prefix, prefix_str, sizeof(prefix_str));
    YLOG_INFO("NAT64 prefix set to %s/%u", prefix_str, prefix_len);

    return 0;
}

/**
 * Check if IPv6 destination matches NAT64 prefix
 */
bool nat64_is_nat64_address(const uint8_t *ipv6_addr)
{
    if (!g_nat64_config.enabled) return false;

    /* Compare first 12 bytes (96 bits) */
    return memcmp(ipv6_addr, g_nat64_config.prefix, 12) == 0;
}

/**
 * Extract IPv4 address from NAT64 IPv6 address
 * For /96 prefix, IPv4 is in bytes 12-15
 */
uint32_t nat64_extract_ipv4(const uint8_t *ipv6_addr)
{
    uint32_t ipv4;
    memcpy(&ipv4, &ipv6_addr[12], 4);
    return ntohl(ipv4);
}

/**
 * Construct NAT64 IPv6 address from IPv4
 * For /96 prefix, embed IPv4 in bytes 12-15
 */
void nat64_construct_ipv6(uint8_t *ipv6_out, uint32_t ipv4_addr)
{
    memcpy(ipv6_out, g_nat64_config.prefix, 12);
    uint32_t net_ipv4 = htonl(ipv4_addr);
    memcpy(&ipv6_out[12], &net_ipv4, 4);
}

/**
 * Map IPv6 Traffic Class to IPv4 TOS (RFC 6145)
 */
static uint8_t map_tc_to_tos(uint32_t vtc_flow)
{
    /* Traffic class is bits 4-11 of vtc_flow (network order) */
    return (uint8_t)((ntohl(vtc_flow) >> 20) & 0xFF);
}

/**
 * Map IPv6 Hop Limit to IPv4 TTL
 */
static uint8_t map_hop_limit_to_ttl(uint8_t hop_limit)
{
    return hop_limit;
}

/**
 * Calculate IPv4 packet ID
 * Note: For fragmentation, proper ID generation needed
 */
static uint16_t generate_ipv4_id(void)
{
    static uint16_t id_counter = 0;
    return __atomic_fetch_add(&id_counter, 1, __ATOMIC_RELAXED);
}

/**
 * Translate IPv6 header to IPv4 header (RFC 6145)
 * Returns length of translated IPv4 header
 */
int nat64_translate_header_6to4(const struct rte_ipv6_hdr *ip6_hdr,
                                 struct rte_ipv4_hdr *ip4_hdr,
                                 uint32_t src_ipv4, uint32_t dst_ipv4)
{
    /* Version: 4, IHL: 5 (no options) */
    ip4_hdr->version_ihl = 0x45;

    /* TOS from Traffic Class */
    ip4_hdr->type_of_service = map_tc_to_tos(ip6_hdr->vtc_flow);

    /* Total Length = Payload Length + 20 (IPv4 header) */
    ip4_hdr->total_length = rte_cpu_to_be_16(
        rte_be_to_cpu_16(ip6_hdr->payload_len) + sizeof(struct rte_ipv4_hdr));

    /* Packet ID */
    ip4_hdr->packet_id = rte_cpu_to_be_16(generate_ipv4_id());

    /* Flags and Fragment Offset: DF set, no fragmentation */
    ip4_hdr->fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG);

    /* TTL from Hop Limit - 1 */
    ip4_hdr->time_to_live = map_hop_limit_to_ttl(ip6_hdr->hop_limits);
    if (ip4_hdr->time_to_live > 0) ip4_hdr->time_to_live--;

    /* Protocol: Direct mapping for TCP/UDP/ICMP */
    if (ip6_hdr->proto == IPPROTO_ICMPV6) {
        ip4_hdr->next_proto_id = IPPROTO_ICMP;
    } else {
        ip4_hdr->next_proto_id = ip6_hdr->proto;
    }

    /* Source and Destination addresses */
    ip4_hdr->src_addr = rte_cpu_to_be_32(src_ipv4);
    ip4_hdr->dst_addr = rte_cpu_to_be_32(dst_ipv4);

    /* Checksum */
    ip4_hdr->hdr_checksum = 0;
    ip4_hdr->hdr_checksum = rte_ipv4_cksum(ip4_hdr);

    return sizeof(struct rte_ipv4_hdr);
}

/**
 * Translate IPv4 header to IPv6 header (RFC 6145)
 * Returns length of translated IPv6 header
 */
int nat64_translate_header_4to6(const struct rte_ipv4_hdr *ip4_hdr,
                                 struct rte_ipv6_hdr *ip6_hdr,
                                 const uint8_t *src_ipv6, const uint8_t *dst_ipv6)
{
    /* Version: 6, Traffic Class from TOS, Flow Label: 0 */
    ip6_hdr->vtc_flow = rte_cpu_to_be_32(
        (6 << 28) | ((uint32_t)ip4_hdr->type_of_service << 20));

    /* Payload Length = Total Length - IPv4 header length */
    uint16_t ip4_hdr_len = (ip4_hdr->version_ihl & 0x0F) * 4;
    ip6_hdr->payload_len = rte_cpu_to_be_16(
        rte_be_to_cpu_16(ip4_hdr->total_length) - ip4_hdr_len);

    /* Next Header: Direct mapping for TCP/UDP/ICMP */
    if (ip4_hdr->next_proto_id == IPPROTO_ICMP) {
        ip6_hdr->proto = IPPROTO_ICMPV6;
    } else {
        ip6_hdr->proto = ip4_hdr->next_proto_id;
    }

    /* Hop Limit from TTL - 1 */
    ip6_hdr->hop_limits = ip4_hdr->time_to_live;
    if (ip6_hdr->hop_limits > 0) ip6_hdr->hop_limits--;

    /* Source and Destination addresses */
    memcpy(ip6_hdr->src_addr, src_ipv6, 16);
    memcpy(ip6_hdr->dst_addr, dst_ipv6, 16);

    return sizeof(struct rte_ipv6_hdr);
}

/**
 * Translate ICMPv6 to ICMPv4 (RFC 6145 Section 4)
 */
int nat64_translate_icmp6_to_icmp4(const uint8_t *icmp6_data, int icmp6_len,
                                    uint8_t *icmp4_data, int *icmp4_len)
{
    if (icmp6_len < 8) return -1;

    uint8_t icmp6_type = icmp6_data[0];
    uint8_t icmp6_code = icmp6_data[1];

    /* Map ICMPv6 types to ICMPv4 */
    uint8_t icmp4_type = 0, icmp4_code = 0;

    switch (icmp6_type) {
        case 128: /* Echo Request */
            icmp4_type = 8;  /* ICMPv4 Echo Request */
            icmp4_code = 0;
            break;
        case 129: /* Echo Reply */
            icmp4_type = 0;  /* ICMPv4 Echo Reply */
            icmp4_code = 0;
            break;
        case 1: /* Destination Unreachable */
            icmp4_type = 3;
            switch (icmp6_code) {
                case 0: icmp4_code = 1; break; /* No route -> Host unreachable */
                case 1: icmp4_code = 10; break; /* Admin prohibited */
                case 3: icmp4_code = 1; break; /* Address unreachable */
                case 4: icmp4_code = 3; break; /* Port unreachable */
                default: icmp4_code = 1; break;
            }
            break;
        case 2: /* Packet Too Big */
            icmp4_type = 3;
            icmp4_code = 4; /* Fragmentation needed */
            break;
        case 3: /* Time Exceeded */
            icmp4_type = 11;
            icmp4_code = icmp6_code;
            break;
        default:
            return -1; /* Unsupported type */
    }

    /* Build ICMPv4 header */
    icmp4_data[0] = icmp4_type;
    icmp4_data[1] = icmp4_code;
    icmp4_data[2] = 0; /* Checksum placeholder */
    icmp4_data[3] = 0;

    /* Copy rest of message (identifier, sequence, data) */
    int copy_len = icmp6_len - 4;
    if (copy_len > 0) {
        memcpy(&icmp4_data[4], &icmp6_data[4], copy_len);
    }

    *icmp4_len = 4 + copy_len;

    /* Checksum will be calculated by caller */
    return 0;
}

/**
 * Translate ICMPv4 to ICMPv6 (RFC 6145 Section 5)
 */
int nat64_translate_icmp4_to_icmp6(const uint8_t *icmp4_data, int icmp4_len,
                                    uint8_t *icmp6_data, int *icmp6_len)
{
    if (icmp4_len < 8) return -1;

    uint8_t icmp4_type = icmp4_data[0];
    uint8_t icmp4_code = icmp4_data[1];

    /* Map ICMPv4 types to ICMPv6 */
    uint8_t icmp6_type = 0, icmp6_code = 0;

    switch (icmp4_type) {
        case 8: /* Echo Request */
            icmp6_type = 128; /* ICMPv6 Echo Request */
            icmp6_code = 0;
            break;
        case 0: /* Echo Reply */
            icmp6_type = 129; /* ICMPv6 Echo Reply */
            icmp6_code = 0;
            break;
        case 3: /* Destination Unreachable */
            icmp6_type = 1;
            switch (icmp4_code) {
                case 0: case 1: icmp6_code = 0; break; /* No route */
                case 2: icmp6_code = 4; break; /* Protocol unreachable -> Port */
                case 3: icmp6_code = 4; break; /* Port unreachable */
                case 4: icmp6_code = 0; break; /* Frag needed */
                case 9: case 10: icmp6_code = 1; break; /* Admin prohibited */
                default: icmp6_code = 0; break;
            }
            break;
        case 11: /* Time Exceeded */
            icmp6_type = 3;
            icmp6_code = icmp4_code;
            break;
        default:
            return -1; /* Unsupported type */
    }

    /* Build ICMPv6 header */
    icmp6_data[0] = icmp6_type;
    icmp6_data[1] = icmp6_code;
    icmp6_data[2] = 0; /* Checksum placeholder */
    icmp6_data[3] = 0;

    /* Copy rest of message (identifier, sequence, data) */
    int copy_len = icmp4_len - 4;
    if (copy_len > 0) {
        memcpy(&icmp6_data[4], &icmp4_data[4], copy_len);
    }

    *icmp6_len = 4 + copy_len;

    /* Checksum will be calculated by caller */
    return 0;
}

/**
 * NAT64 statistics
 */
static struct {
    uint64_t packets_6to4;
    uint64_t packets_4to6;
    uint64_t errors;
} g_nat64_stats = {0};

/**
 * Get NAT64 statistics
 */
void nat64_get_stats(uint64_t *pkts_6to4, uint64_t *pkts_4to6, uint64_t *errors)
{
    if (pkts_6to4) *pkts_6to4 = g_nat64_stats.packets_6to4;
    if (pkts_4to6) *pkts_4to6 = g_nat64_stats.packets_4to6;
    if (errors) *errors = g_nat64_stats.errors;
}

/**
 * Print NAT64 configuration
 */
void nat64_print_config(void)
{
    printf("\nNAT64 Configuration:\n");
    printf("  Status: %s\n", g_nat64_config.enabled ? "Enabled" : "Disabled");

    char prefix_str[64];
    inet_ntop(AF_INET6, g_nat64_config.prefix, prefix_str, sizeof(prefix_str));
    printf("  Prefix: %s/%u\n", prefix_str, g_nat64_config.prefix_len);

    printf("  Packets 6→4: %lu\n", g_nat64_stats.packets_6to4);
    printf("  Packets 4→6: %lu\n", g_nat64_stats.packets_4to6);
    printf("  Errors: %lu\n", g_nat64_stats.errors);
}
