/**
 * @file ipv6_fetcher.c
 * @brief IPv6 Address Fetcher (DHCPv6-PD Client)
 */

#include "ipv6/ipv6.h"
#include "log.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

/* Global Configuration */
static struct ipv6_fetcher_config g_config;
static pthread_t g_fetcher_thread;
static bool g_running = false;

/* Initializer */
int ipv6_fetcher_init(void)
{
    memset(&g_config, 0, sizeof(g_config));
    g_config.enabled = false;
    g_config.requested_prefix_len = 64; /* Default */

    YLOG_INFO("IPv6 Fetcher initialized");
    return 0;
}

/* Thread loop for the Fetcher (Placeholder for actual DHCPv6 state machine) */
static void *ipv6_fetcher_loop(void *arg)
{
    (void)arg;
    YLOG_INFO("IPv6 Fetcher thread started on interface %s", g_config.interface);

    while (g_running) {
        /* TODO: Implement DHCPv6 SOLICIT/REQUEST loop here */
        /* For now, just sleep to simulate background activity */
        sleep(5);
    }

    YLOG_INFO("IPv6 Fetcher thread stopped");
    return NULL;
}

int ipv6_fetcher_start(const char *interface)
{
    if (g_running) {
        return 0; /* Already running */
    }

    if (!interface) {
        return -1;
    }

    strncpy(g_config.interface, interface, sizeof(g_config.interface) - 1);
    g_running = true;

    if (pthread_create(&g_fetcher_thread, NULL, ipv6_fetcher_loop, NULL) != 0) {
        YLOG_ERROR("Failed to start IPv6 Fetcher thread");
        g_running = false;
        return -1;
    }

    return 0;
}

int ipv6_fetcher_stop(void)
{
    if (!g_running) {
        return 0;
    }

    g_running = false;
    pthread_join(g_fetcher_thread, NULL);
    return 0;
}

/* Mock implementation for now - returns a static ULA prefix */
int ipv6_fetcher_get_prefix(struct ipv6_addr *prefix, uint8_t *len)
{
    if (!prefix || !len) return -1;

    /* Mock: fd00:abcd::/64 */
    memset(prefix->addr, 0, 16);
    prefix->addr[0] = 0xfd;
    prefix->addr[1] = 0x00;
    prefix->addr[2] = 0xab;
    prefix->addr[3] = 0xcd;

    *len = 64;
    return 0;
}
