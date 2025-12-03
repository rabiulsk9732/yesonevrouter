/**
 * @file main.c
 * @brief YESRouter vBNG Main Entry Point
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include "dpdk_init.h"
#include "cpu_scheduler.h"
#include "packet.h"
#include "interface.h"

static volatile bool g_running = true;

static void signal_handler(int signum)
{
    (void)signum;
    printf("\nShutdown signal received\n");
    g_running = false;
}

int main(int argc, char *argv[])
{
    int ret;

    printf("========================================\n");
    printf("YESRouter vBNG - Starting\n");
    printf("========================================\n\n");

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize CPU scheduler */
    ret = cpu_scheduler_init();
    if (ret < 0) {
        fprintf(stderr, "Failed to initialize CPU scheduler\n");
        return EXIT_FAILURE;
    }

    cpu_scheduler_print_topology();

    /* Initialize DPDK (if available) */
    ret = dpdk_init(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "Failed to initialize DPDK\n");
        cpu_scheduler_cleanup();
        return EXIT_FAILURE;
    }

    if (dpdk_is_enabled()) {
        printf("\nDPDK Status: Enabled\n");
        printf("  Logical cores: %u\n", dpdk_get_lcore_count());
        printf("  Socket ID: %u\n", dpdk_get_socket_id());
    } else {
        printf("\nDPDK Status: Disabled (running in software mode)\n");
    }

    /* Initialize packet buffer subsystem */
    ret = pkt_buf_init();
    if (ret < 0) {
        fprintf(stderr, "Failed to initialize packet buffer subsystem\n");
        dpdk_cleanup();
        cpu_scheduler_cleanup();
        return EXIT_FAILURE;
    }

    /* Test packet buffer allocation */
    printf("\nTesting packet buffer allocation...\n");
    struct pkt_buf *test_pkt = pkt_alloc();
    if (test_pkt) {
        printf("  Successfully allocated packet buffer\n");
        printf("  Buffer address: %p\n", (void *)test_pkt);
        printf("  Data address: %p\n", (void *)pkt_data(test_pkt));
        printf("  Headroom: %u bytes\n", test_pkt->headroom);
        pkt_free(test_pkt);
        printf("  Packet freed successfully\n");
    } else {
        fprintf(stderr, "  Failed to allocate packet buffer\n");
    }

    /* Initialize interface subsystem */
    ret = interface_init();
    if (ret < 0) {
        fprintf(stderr, "Failed to initialize interface subsystem\n");
        pkt_buf_cleanup();
        dpdk_cleanup();
        cpu_scheduler_cleanup();
        return EXIT_FAILURE;
    }

    /* Create loopback interface for testing */
    struct interface *lo = interface_create("lo", IF_TYPE_LOOPBACK);
    if (lo) {
        printf("\nCreated loopback interface\n");
        interface_up(lo);
        interface_print(lo);
    }

    printf("\n========================================\n");
    printf("YESRouter vBNG - Initialization Complete\n");
    printf("========================================\n");
    printf("Press Ctrl+C to exit\n\n");

    /* Main loop */
    while (g_running) {
        sleep(1);
    }

    /* Cleanup */
    printf("\n========================================\n");
    printf("YESRouter vBNG - Shutting Down\n");
    printf("========================================\n\n");

    interface_cleanup();
    pkt_buf_cleanup();
    dpdk_cleanup();
    cpu_scheduler_cleanup();

    printf("Shutdown complete\n");
    return EXIT_SUCCESS;
}
