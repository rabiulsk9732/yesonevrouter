/**
 * @file nat_deterministic.c
 * @brief Deterministic NAT (RFC 7422)
 *
 * Predictable NAT mapping for lawful intercept and logging compliance
 * Maps inside IP to outside IP:port deterministically using hash function
 */

#include "nat.h"
#include "log.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

/* Deterministic NAT configuration */
struct det_nat_config {
    bool enabled;
    uint32_t inside_prefix;      /* Private subnet (e.g., 100.64.0.0) */
    uint8_t inside_prefix_len;   /* Prefix length (e.g., 10) */
    uint32_t outside_prefix;     /* Public subnet */
    uint8_t outside_prefix_len;
    uint16_t ports_per_user;     /* Ports allocated per subscriber */
    uint32_t users_per_ip;       /* Subscribers sharing one public IP */
};

static struct det_nat_config g_det_nat_config;

/**
 * Configure deterministic NAT
 */
int nat_deterministic_configure(uint32_t inside_prefix, uint8_t inside_prefix_len,
                                uint32_t outside_prefix, uint8_t outside_prefix_len,
                                uint16_t ports_per_user)
{
    g_det_nat_config.inside_prefix = inside_prefix;
    g_det_nat_config.inside_prefix_len = inside_prefix_len;
    g_det_nat_config.outside_prefix = outside_prefix;
    g_det_nat_config.outside_prefix_len = outside_prefix_len;
    g_det_nat_config.ports_per_user = ports_per_user;

    /* Calculate users per IP: (65536 - 1024) / ports_per_user */
    g_det_nat_config.users_per_ip = (65536 - 1024) / ports_per_user;
    g_det_nat_config.enabled = true;

    YLOG_INFO("Deterministic NAT configured: %u users/IP, %u ports/user",
              g_det_nat_config.users_per_ip, ports_per_user);

    return 0;
}

/**
 * Deterministic mapping: inside IP → (outside IP, port range)
 * Algorithm: Hash inside IP to get consistent outside mapping
 */
int nat_deterministic_map(uint32_t inside_ip, uint32_t *outside_ip,
                          uint16_t *port_start, uint16_t *port_end)
{
    if (!g_det_nat_config.enabled || !outside_ip || !port_start || !port_end) {
        return -1;
    }

    /* Check if inside IP is within configured prefix */
    uint32_t mask = (0xFFFFFFFF << (32 - g_det_nat_config.inside_prefix_len));
    if ((inside_ip & mask) != (g_det_nat_config.inside_prefix & mask)) {
        return -1;  /* Not in inside prefix */
    }

    /* Calculate offset within inside prefix */
    uint32_t inside_offset = inside_ip & ~mask;

    /* Determine outside IP (round-robin across outside pool) */
    uint32_t ip_index = inside_offset / g_det_nat_config.users_per_ip;
    uint32_t user_index = inside_offset % g_det_nat_config.users_per_ip;

    *outside_ip = g_det_nat_config.outside_prefix + ip_index;

    /* Calculate port range for this user */
    *port_start = 1024 + (user_index * g_det_nat_config.ports_per_user);
    *port_end = *port_start + g_det_nat_config.ports_per_user - 1;

    return 0;
}

/**
 * Reverse lookup: outside IP:port → inside IP
 * Critical for lawful intercept
 */
int nat_deterministic_reverse_lookup(uint32_t outside_ip, uint16_t outside_port, uint32_t *inside_ip)
{
    if (!g_det_nat_config.enabled || !inside_ip) {
        return -1;
    }

    /* Calculate IP offset */
    uint32_t ip_offset = outside_ip - g_det_nat_config.outside_prefix;

    /* Calculate user index from port */
    if (outside_port < 1024) {
        return -1;  /* Invalid port */
    }

    uint32_t port_offset = outside_port - 1024;
    uint32_t user_index = port_offset / g_det_nat_config.ports_per_user;

    /* Calculate inside offset */
    uint32_t inside_offset = (ip_offset * g_det_nat_config.users_per_ip) + user_index;

    /* Calculate inside IP */
    *inside_ip = g_det_nat_config.inside_prefix + inside_offset;

    return 0;
}

/**
 * Print deterministic NAT configuration
 */
void nat_deterministic_print_config(void)
{
    if (!g_det_nat_config.enabled) {
        printf("Deterministic NAT: Disabled\n");
        return;
    }

    char inside_str[32], outside_str[32];
    struct in_addr addr;

    addr.s_addr = htonl(g_det_nat_config.inside_prefix);
    inet_ntop(AF_INET, &addr, inside_str, sizeof(inside_str));

    addr.s_addr = htonl(g_det_nat_config.outside_prefix);
    inet_ntop(AF_INET, &addr, outside_str, sizeof(outside_str));

    printf("\nDeterministic NAT Configuration:\n");
    printf("  Inside prefix: %s/%u\n", inside_str, g_det_nat_config.inside_prefix_len);
    printf("  Outside prefix: %s/%u\n", outside_str, g_det_nat_config.outside_prefix_len);
    printf("  Ports per user: %u\n", g_det_nat_config.ports_per_user);
    printf("  Users per IP: %u\n", g_det_nat_config.users_per_ip);
    printf("\n");
}
