/**
 * @file ipv6_route.c
 * @brief IPv6 Routing Table Implementation
 */

#include "ipv6/ipv6.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>

/* Global Routing Table List */
static struct ipv6_route *g_route_list = NULL;
static pthread_mutex_t g_route_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Helper: Address match */
static bool ipv6_prefix_match(const struct ipv6_addr *a, const struct ipv6_addr *b, uint8_t len)
{
    /* Match 'len' bits between a and b */
    /* Implementation: byte by byte, then mask */
    int bytes = len / 8;
    int bits = len % 8;

    if (bytes > 0) {
        if (memcmp(a->addr, b->addr, bytes) != 0) {
            return false;
        }
    }

    if (bits > 0) {
        uint8_t mask = 0xFF << (8 - bits);
        if ((a->addr[bytes] & mask) != (b->addr[bytes] & mask)) {
            return false;
        }
    }

    return true;
}

int ipv6_route_init(void)
{
    g_route_list = NULL;
    YLOG_INFO("IPv6 Routing Table initialized");
    return 0;
}

int ipv6_route_add(const struct ipv6_addr *dest, uint8_t len,
                   const struct ipv6_addr *next_hop, const char *iface, uint32_t metric)
{
    struct ipv6_route *route;

    if (!dest || len > 128 || !iface) {
        return -1;
    }

    /* TODO: Check if route already exists and update it */
    ipv6_route_del(dest, len);

    pthread_mutex_lock(&g_route_mutex);

    route = calloc(1, sizeof(struct ipv6_route));
    if (!route) {
        pthread_mutex_unlock(&g_route_mutex);
        return -1;
    }

    route->dest_prefix = *dest;
    route->prefix_len = len;
    if (next_hop) {
        route->next_hop = *next_hop;
    }
    strncpy(route->interface, iface, sizeof(route->interface) - 1);
    route->metric = metric;

    /* Add to head */
    route->next = g_route_list;
    g_route_list = route;

    char dest_str[64];
    inet_ntop(AF_INET6, dest->addr, dest_str, sizeof(dest_str));
    YLOG_INFO("IPv6 Route added: %s/%u via %s dev %s",
              dest_str, len, next_hop ? "GW" : "Direct", iface);

    pthread_mutex_unlock(&g_route_mutex);
    return 0;
}

int ipv6_route_del(const struct ipv6_addr *dest, uint8_t len)
{
    struct ipv6_route *curr, *prev = NULL;

    pthread_mutex_lock(&g_route_mutex);

    curr = g_route_list;
    while (curr) {
        if (curr->prefix_len == len &&
            ipv6_prefix_match(&curr->dest_prefix, dest, 128)) { /* Exact match on address */

            if (prev) {
                prev->next = curr->next;
            } else {
                g_route_list = curr->next;
            }
            free(curr);
            pthread_mutex_unlock(&g_route_mutex);
            YLOG_INFO("IPv6 Route deleted");
            return 0;
        }
        prev = curr;
        curr = curr->next;
    }

    pthread_mutex_unlock(&g_route_mutex);
    return -1; /* Not found */
}

struct ipv6_route *ipv6_route_lookup(const struct ipv6_addr *dest)
{
    struct ipv6_route *curr;
    struct ipv6_route *best_match = NULL;

    /* Iterate list finding Longest Prefix Match */
    if (!dest) return NULL;

    pthread_mutex_lock(&g_route_mutex);
    curr = g_route_list;

    while (curr) {
        if (ipv6_prefix_match(&curr->dest_prefix, dest, curr->prefix_len)) {
            if (!best_match || curr->prefix_len > best_match->prefix_len) {
                best_match = curr;
            }
        }
        curr = curr->next;
    }

    pthread_mutex_unlock(&g_route_mutex);
    return best_match;
}

void ipv6_route_dump(void)
{
    struct ipv6_route *curr;
    char dest_str[64];
    char gw_str[64];

    pthread_mutex_lock(&g_route_mutex);
    curr = g_route_list;

    printf("IPv6 Routing Table:\n");
    while (curr) {
        inet_ntop(AF_INET6, curr->dest_prefix.addr, dest_str, sizeof(dest_str));
        inet_ntop(AF_INET6, curr->next_hop.addr, gw_str, sizeof(gw_str));

        printf("%s/%u via %s dev %s metric %u\n",
               dest_str, curr->prefix_len, gw_str, curr->interface, curr->metric);
        curr = curr->next;
    }
    pthread_mutex_unlock(&g_route_mutex);
}
