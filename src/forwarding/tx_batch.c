/**
 * @file tx_batch.c
 * @brief TX Batching for High-Throughput Packet Transmission
 * Buffers packets per-port and sends in bursts for efficiency
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_DPDK
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#endif

#include "tx_batch.h"
#include "log.h"

#ifdef HAVE_DPDK

#define TX_BATCH_SIZE       32      /* Max packets in batch */
#define TX_BATCH_TIMEOUT_US 100     /* Flush after 100us */
#define MAX_TX_PORTS        8

/* Per-port TX buffer */
struct tx_buffer {
    struct rte_mbuf *pkts[TX_BATCH_SIZE];
    uint16_t count;
    uint64_t last_flush_cycles;
    uint16_t port_id;
    uint16_t queue_id;
};

static struct tx_buffer g_tx_buffers[MAX_TX_PORTS];
static int g_num_ports = 0;
static uint64_t g_flush_cycles;

int tx_batch_init(int num_ports)
{
    if (num_ports > MAX_TX_PORTS) num_ports = MAX_TX_PORTS;
    g_num_ports = num_ports;

    /* Calculate cycles for timeout */
    g_flush_cycles = (rte_get_tsc_hz() * TX_BATCH_TIMEOUT_US) / 1000000;

    memset(g_tx_buffers, 0, sizeof(g_tx_buffers));
    for (int i = 0; i < num_ports; i++) {
        g_tx_buffers[i].port_id = i;
        g_tx_buffers[i].queue_id = 0;
        g_tx_buffers[i].last_flush_cycles = rte_get_tsc_cycles();
    }

    YLOG_INFO("TX Batch: Initialized %d ports, batch=%d, timeout=%uus",
              num_ports, TX_BATCH_SIZE, TX_BATCH_TIMEOUT_US);
    return 0;
}

static void tx_buffer_flush(struct tx_buffer *buf)
{
    if (buf->count == 0) return;

    uint16_t sent = rte_eth_tx_burst(buf->port_id, buf->queue_id, buf->pkts, buf->count);

    /* Free unsent packets */
    if (sent < buf->count) {
        for (uint16_t i = sent; i < buf->count; i++) {
            rte_pktmbuf_free(buf->pkts[i]);
        }
        YLOG_WARNING("TX Batch: Dropped %u packets on port %u",
                     buf->count - sent, buf->port_id);
    }

    buf->count = 0;
    buf->last_flush_cycles = rte_get_tsc_cycles();
}

int tx_batch_enqueue(uint16_t port_id, struct rte_mbuf *mbuf)
{
    if (port_id >= g_num_ports) {
        rte_pktmbuf_free(mbuf);
        return -1;
    }

    struct tx_buffer *buf = &g_tx_buffers[port_id];
    buf->pkts[buf->count++] = mbuf;

    /* Flush if batch is full */
    if (buf->count >= TX_BATCH_SIZE) {
        tx_buffer_flush(buf);
    }

    return 0;
}

void tx_batch_flush_port(uint16_t port_id)
{
    if (port_id < g_num_ports) {
        tx_buffer_flush(&g_tx_buffers[port_id]);
    }
}

void tx_batch_flush_all(void)
{
    for (int i = 0; i < g_num_ports; i++) {
        tx_buffer_flush(&g_tx_buffers[i]);
    }
}

void tx_batch_check_timeouts(void)
{
    uint64_t now = rte_get_tsc_cycles();

    for (int i = 0; i < g_num_ports; i++) {
        struct tx_buffer *buf = &g_tx_buffers[i];

        if (buf->count > 0 && (now - buf->last_flush_cycles) > g_flush_cycles) {
            tx_buffer_flush(buf);
        }
    }
}

void tx_batch_cleanup(void)
{
    tx_batch_flush_all();
    g_num_ports = 0;
    YLOG_INFO("TX Batch: Cleanup complete");
}

#else /* !HAVE_DPDK */

int tx_batch_init(int num_ports) { (void)num_ports; return 0; }
void tx_batch_cleanup(void) {}
int tx_batch_enqueue(uint16_t port_id, void *mbuf) { (void)port_id; (void)mbuf; return -1; }
void tx_batch_flush_port(uint16_t port_id) { (void)port_id; }
void tx_batch_flush_all(void) {}
void tx_batch_check_timeouts(void) {}

#endif /* HAVE_DPDK */
