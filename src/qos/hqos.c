/**
 * @file hqos.c
 * @brief Hierarchical QoS (HQoS) Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hqos.h"
#include "qos.h"
#include "log.h"

#define MAX_QOS_CLASSES 8
#define MAX_QUEUES_PER_CLASS 8

/* Traffic class definition */
struct hqos_class {
    char name[32];
    uint8_t priority;       /* 0-7, higher = more priority */
    uint64_t weight;        /* WFQ weight */
    uint64_t rate_limit;    /* Max rate in bps */
    uint64_t min_rate;      /* Guaranteed rate in bps */
    bool strict_priority;   /* True = SP, False = WFQ */
};

/* Per-port HQoS configuration */
struct hqos_port {
    uint16_t port_id;
    struct hqos_class classes[MAX_QOS_CLASSES];
    int num_classes;
    uint64_t port_rate;     /* Port rate limit */
    bool enabled;
};

static struct {
    struct hqos_port ports[8];
    int num_ports;
} g_hqos;

int hqos_init(void)
{
    memset(&g_hqos, 0, sizeof(g_hqos));

    YLOG_INFO("HQoS: Hierarchical QoS initialized");
    return 0;
}

int hqos_port_init(uint16_t port_id, uint64_t port_rate)
{
    if (g_hqos.num_ports >= 8) return -1;

    struct hqos_port *port = &g_hqos.ports[g_hqos.num_ports];
    port->port_id = port_id;
    port->port_rate = port_rate;
    port->num_classes = 0;
    port->enabled = true;

    /* Default classes */
    hqos_add_class(port_id, "realtime", 7, 0, port_rate / 10, port_rate / 5, true);
    hqos_add_class(port_id, "priority", 6, 0, port_rate / 10, port_rate / 4, true);
    hqos_add_class(port_id, "business", 4, 50, 0, port_rate / 2, false);
    hqos_add_class(port_id, "default", 2, 30, 0, port_rate, false);
    hqos_add_class(port_id, "bulk", 0, 20, 0, port_rate, false);

    g_hqos.num_ports++;
    YLOG_INFO("HQoS: Port %u configured with %lu bps rate, %d classes",
              port_id, port_rate, port->num_classes);
    return 0;
}

int hqos_add_class(uint16_t port_id, const char *name, uint8_t priority,
                   uint64_t weight, uint64_t min_rate, uint64_t max_rate, bool strict)
{
    struct hqos_port *port = NULL;
    for (int i = 0; i < g_hqos.num_ports; i++) {
        if (g_hqos.ports[i].port_id == port_id) {
            port = &g_hqos.ports[i];
            break;
        }
    }

    if (!port || port->num_classes >= MAX_QOS_CLASSES) return -1;

    struct hqos_class *cls = &port->classes[port->num_classes];
    snprintf(cls->name, sizeof(cls->name), "%s", name);
    cls->priority = priority;
    cls->weight = weight;
    cls->min_rate = min_rate;
    cls->rate_limit = max_rate;
    cls->strict_priority = strict;

    port->num_classes++;
    YLOG_DEBUG("HQoS: Added class '%s' (prio=%u, weight=%lu, min=%lu, max=%lu, %s)",
               name, priority, weight, min_rate, max_rate, strict ? "SP" : "WFQ");
    return port->num_classes - 1;
}

uint8_t hqos_classify_packet(uint8_t dscp)
{
    /* Map DSCP to traffic class */
    switch (dscp >> 3) {  /* Top 3 bits = class selector */
    case 7: return 0; /* realtime */
    case 6: return 1; /* priority */
    case 5:
    case 4: return 2; /* business */
    case 3:
    case 2: return 3; /* default */
    default: return 4; /* bulk */
    }
}

int hqos_enqueue(uint16_t port_id, uint8_t class_id, void *packet)
{
    /* TODO: Implement actual queue management */
    (void)port_id;
    (void)class_id;
    (void)packet;
    return 0;
}

void *hqos_dequeue(uint16_t port_id)
{
    /* TODO: Implement SP/WFQ scheduling */
    (void)port_id;
    return NULL;
}

void hqos_show_config(uint16_t port_id)
{
    struct hqos_port *port = NULL;
    for (int i = 0; i < g_hqos.num_ports; i++) {
        if (g_hqos.ports[i].port_id == port_id) {
            port = &g_hqos.ports[i];
            break;
        }
    }

    if (!port) {
        printf("Port %u not configured for HQoS\n", port_id);
        return;
    }

    printf("HQoS Port %u (Rate: %lu Mbps):\n", port_id, port->port_rate / 1000000);
    printf("%-12s %-6s %-8s %-12s %-12s %-6s\n",
           "Class", "Prio", "Weight", "Min Rate", "Max Rate", "Type");
    printf("%-12s %-6s %-8s %-12s %-12s %-6s\n",
           "------------", "------", "--------", "------------", "------------", "------");

    for (int i = 0; i < port->num_classes; i++) {
        struct hqos_class *cls = &port->classes[i];
        printf("%-12s %-6u %-8lu %-12lu %-12lu %-6s\n",
               cls->name, cls->priority, cls->weight,
               cls->min_rate / 1000000, cls->rate_limit / 1000000,
               cls->strict_priority ? "SP" : "WFQ");
    }
}

void hqos_cleanup(void)
{
    memset(&g_hqos, 0, sizeof(g_hqos));
    YLOG_INFO("HQoS: Cleanup complete");
}
