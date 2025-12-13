/**
 * @file ipv6_core.c
 * @brief IPv6 Subsystem Core Implementation
 */

#include "ipv6/ipv6.h"
#include "log.h"
#include <stdio.h>
#include <string.h>

static bool g_ipv6_enabled = false;

int ipv6_init(void)
{
    g_ipv6_enabled = false;

    printf("IPv6: Core initializing...\n");
    YLOG_ERROR("IPv6 subsystem initialized (disabled by default)");

    /* Initialize Fetcher submodule */
    if (ipv6_fetcher_init() != 0) {
        YLOG_ERROR("Failed to initialize IPv6 Fetcher");
        return -1;
    }

    return 0;
}

void ipv6_cleanup(void)
{
    g_ipv6_enabled = false;
    YLOG_INFO("IPv6 subsystem cleanup complete");
}

bool ipv6_is_enabled(void)
{
    return g_ipv6_enabled;
}

void ipv6_enable(bool enable)
{
    g_ipv6_enabled = enable;
    YLOG_INFO("IPv6 %s globally", enable ? "enabled" : "disabled");
}
