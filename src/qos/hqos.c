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
#ifdef HAVE_DPDK
#include <rte_ring.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#endif

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
#ifdef HAVE_DPDK
    struct rte_ring *queue; /* DPDK Ring for Packet Queue */
#endif
    uint64_t bytes;
    uint64_t packets;
    uint64_t drops;
};

/* Per-port HQoS configuration */
struct hqos_port {
    uint16_t port_id;
    struct hqos_class classes[MAX_QOS_CLASSES];
    int num_classes;
    uint64_t port_rate;     /* Port rate limit */
    struct token_bucket tb; /* Port Shaper */
    bool enabled;
};

static struct {
    struct hqos_port ports[8];
    int num_ports;
} g_hqos;

bool hqos_is_active(uint16_t port_id) {
    for (int i = 0; i < g_hqos.num_ports; i++) {
        if (g_hqos.ports[i].port_id == port_id && g_hqos.ports[i].enabled) {
            return true;
        }
    }
    return false;
}



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
    g_hqos.num_ports++; /* MUST increment BEFORE hqos_add_class */
    qos_tb_init(&port->tb, port_rate, port_rate / 8); /* Burst = 1/8 sec */

    /* Default classes */
    hqos_add_class(port_id, "realtime", 7, 0, port_rate / 10, port_rate / 5, true);
    hqos_add_class(port_id, "priority", 6, 0, port_rate / 10, port_rate / 4, true);
    hqos_add_class(port_id, "business", 4, 50, 0, port_rate / 2, false);
    hqos_add_class(port_id, "default", 2, 30, 0, port_rate, false);
    hqos_add_class(port_id, "bulk", 0, 20, 0, port_rate, false);

    /* num_ports already incremented above */

              YLOG_INFO("HQoS: Port %u configured with %lu bps rate, %d classes", port_id, port_rate, port->num_classes);
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

#ifdef HAVE_DPDK
    char ring_name[32];
    snprintf(ring_name, sizeof(ring_name), "hqos_p%u_c%u", port_id, port->num_classes);
    cls->queue = rte_ring_create(ring_name, 1024, rte_socket_id(), RING_F_SC_DEQ);
    if (!cls->queue) {
        YLOG_ERROR("HQoS: Failed to create ring %s", ring_name);
        return -1;
    }
#endif

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
#ifdef HAVE_DPDK
    struct hqos_port *port = NULL;
    for (int i = 0; i < g_hqos.num_ports; i++) {
        if (g_hqos.ports[i].port_id == port_id) {
            port = &g_hqos.ports[i];
            break;
        }
    }
    if (!port || class_id >= port->num_classes) return -1;
    struct hqos_class *cls = &port->classes[class_id];

    if (rte_ring_enqueue(cls->queue, packet) != 0) {
        cls->drops++;
        return -1;
    }
    struct rte_mbuf *m = (struct rte_mbuf *)packet;
    cls->bytes += m->pkt_len;
    cls->packets++;
    return 0;
#else
    return -1;
#endif
}

void hqos_run(void) {
#ifdef HAVE_DPDK
    for (int p = 0; p < g_hqos.num_ports; p++) {
        struct hqos_port *port = &g_hqos.ports[p];
        if (!port->enabled) continue;

        /* Dequeue Logic: SP then R-R */
        /* Currently simplest implementation: Strict Priority only for PoC */
        /* Iterating high priority to low */
        /* Check Port Shaper */

        /* Burst Dequeue 32 packets total */
        struct rte_mbuf *pkts[32];
        int count = 0;

        /* Check if we can send 1 packet (MTU size check?) */
        /* Peek tokens (MTU) */
        if (!qos_tb_check(&port->tb, 1500)) {
            continue; /* Port Rate Limited */
        }

        for (int c = 0; c < port->num_classes; c++) {
            /* SP Logic */
             struct hqos_class *cls = &port->classes[c];

             void *obj;
             /* Dequeue up to 32 packets */
             if (rte_ring_dequeue(cls->queue, &obj) == 0) {
                 pkts[count++] = (struct rte_mbuf *)obj;
                 if (count >= 32) break;
                 if (cls->strict_priority) {
                    while (count < 32 && rte_ring_dequeue(cls->queue, &obj) == 0) {
                        pkts[count++] = (struct rte_mbuf *)obj;
                    }
                 }
             }
             if (count >= 32) break;
        }

        if (count > 0) {
             uint16_t sent = rte_eth_tx_burst(port->port_id, 0, pkts, count);
             uint32_t sent_bytes = 0;
             for (int i = 0; i < sent; i++) {
                 sent_bytes += pkts[i]->pkt_len;
                 /* Driver takes ownership, do not free */
             }

             if (sent < count) {
                 /* Free failed */
                 for (int i = sent; i < count; i++) rte_pktmbuf_free(pkts[i]);
             }

             /* Charge tokens for SENT packets */
             if (sent > 0) {
                 qos_tb_consume(&port->tb, sent_bytes);
                 if (sent_bytes > 0) {
                     /* Rate limit logs */
                     static uint64_t last_log = 0;
                     uint64_t now = rte_get_timer_cycles();
                     if (now - last_log > rte_get_timer_hz()) {
                        YLOG_INFO("HQoS: Port %u sent %u packets (%u bytes)",
                                  port->port_id, sent, sent_bytes);
                        last_log = now;
                     }
                 }
             }
        }
    }
#endif
}

void *hqos_dequeue(uint16_t port_id)
{
    /* Deprecated in favor of hqos_run */
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
