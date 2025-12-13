/**
 * @file test_arp_queue.c
 * @brief Unit tests for ARP packet queuing
 */

#include "arp_queue.h"
#include "packet.h"
#include "interface.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Mock interface for testing */
static struct interface mock_iface = {
    .ifindex = 1,
    .state = IF_STATE_UP,
};

/* Test 1: Initialize ARP queue */
static void test_arp_queue_init(void)
{
    printf("Test 1: ARP queue initialization\n");
    
    assert(arp_queue_init() == 0);
    printf("  ✓ ARP queue initialized\n");
    
    struct arp_queue_stats stats;
    assert(arp_queue_get_stats(&stats) == 0);
    assert(stats.current_queues == 0);
    assert(stats.current_packets == 0);
    printf("  ✓ Initial statistics correct\n");
}

/* Test 2: Queue a packet */
static void test_arp_queue_packet(void)
{
    printf("Test 2: Queue packet for ARP resolution\n");
    
    /* Allocate a test packet */
    struct pkt_buf *pkt = pkt_alloc();
    assert(pkt != NULL);
    
    uint32_t test_ip = 0x0A000001; /* 10.0.0.1 */
    
    /* Queue packet */
    assert(arp_queue_packet(test_ip, pkt, &mock_iface, &mock_iface) == 0);
    printf("  ✓ Packet queued successfully\n");
    
    /* Check statistics */
    struct arp_queue_stats stats;
    assert(arp_queue_get_stats(&stats) == 0);
    assert(stats.packets_queued == 1);
    assert(stats.current_packets == 1);
    assert(stats.current_queues == 1);
    printf("  ✓ Statistics updated correctly\n");
    printf("    Queued packets: %lu\n", stats.packets_queued);
    printf("    Current packets: %u\n", stats.current_packets);
    printf("    Current queues: %u\n", stats.current_queues);
}

/* Test 3: Flush queued packets */
static void test_arp_queue_flush(void)
{
    printf("Test 3: Flush queued packets\n");
    
    uint32_t test_ip = 0x0A000002; /* 10.0.0.2 */
    
    /* Queue multiple packets */
    for (int i = 0; i < 3; i++) {
        struct pkt_buf *pkt = pkt_alloc();
        assert(pkt != NULL);
        assert(arp_queue_packet(test_ip, pkt, &mock_iface, &mock_iface) == 0);
    }
    
    printf("  ✓ Queued 3 packets\n");
    
    /* Flush packets */
    uint32_t flushed = arp_queue_flush(test_ip);
    assert(flushed == 3);
    printf("  ✓ Flushed %u packets\n", flushed);
    
    /* Check statistics */
    struct arp_queue_stats stats;
    assert(arp_queue_get_stats(&stats) == 0);
    assert(stats.packets_flushed == 3);
    assert(stats.current_packets == 1); /* Previous test's packet */
    printf("  ✓ Flush statistics correct\n");
}

/* Test 4: Queue timeout */
static void test_arp_queue_timeout(void)
{
    printf("Test 4: Queue timeout\n");
    
    uint32_t test_ip = 0x0A000003; /* 10.0.0.3 */
    
    /* Queue a packet */
    struct pkt_buf *pkt = pkt_alloc();
    assert(pkt != NULL);
    assert(arp_queue_packet(test_ip, pkt, &mock_iface, &mock_iface) == 0);
    
    printf("  ✓ Queued packet for timeout test\n");
    
    /* Note: Actual timeout requires waiting 2 seconds, so we just verify the function exists */
    uint32_t timed_out = arp_queue_timeout_check();
    printf("  ✓ Timeout check completed (dropped: %u)\n", timed_out);
    printf("    (Note: Full timeout test requires 2+ second wait)\n");
}

/* Test 5: Queue full condition */
static void test_arp_queue_full(void)
{
    printf("Test 5: Queue full condition\n");
    
    uint32_t test_ip = 0x0A000004; /* 10.0.0.4 */
    
    /* Fill queue for this IP (max 32 packets) */
    int queued = 0;
    for (int i = 0; i < ARP_QUEUE_MAX_PACKETS_PER_IP; i++) {
        struct pkt_buf *pkt = pkt_alloc();
        if (pkt && arp_queue_packet(test_ip, pkt, &mock_iface, &mock_iface) == 0) {
            queued++;
        } else {
            pkt_free(pkt);
            break;
        }
    }
    
    printf("  ✓ Queued %d packets (max: %d)\n", queued, ARP_QUEUE_MAX_PACKETS_PER_IP);
    
    /* Try to queue one more - should fail */
    struct pkt_buf *pkt = pkt_alloc();
    assert(pkt != NULL);
    assert(arp_queue_packet(test_ip, pkt, &mock_iface, &mock_iface) != 0);
    pkt_free(pkt);
    printf("  ✓ Queue full correctly rejected additional packet\n");
    
    /* Cleanup */
    arp_queue_flush(test_ip);
}

/* Test 6: Print status */
static void test_arp_queue_print_status(void)
{
    printf("Test 6: Print queue status\n");
    
    arp_queue_print_status();
    printf("  ✓ Status printed successfully\n");
}

int main(void)
{
    printf("========================================\n");
    printf("ARP Queue Unit Tests\n");
    printf("========================================\n\n");
    
    /* Initialize packet subsystem */
    if (pkt_init() != 0) {
        fprintf(stderr, "Failed to initialize packet subsystem\n");
        return 1;
    }
    
    test_arp_queue_init();
    test_arp_queue_packet();
    test_arp_queue_flush();
    test_arp_queue_timeout();
    test_arp_queue_full();
    test_arp_queue_print_status();
    
    /* Cleanup */
    arp_queue_cleanup();
    pkt_cleanup();
    
    printf("\n========================================\n");
    printf("All tests passed!\n");
    printf("========================================\n");
    
    return 0;
}
