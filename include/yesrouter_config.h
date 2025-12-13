#ifndef YESROUTER_CONFIG_H
#define YESROUTER_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

/**
 * YESRouter Configuration Structure
 * Hardware & resource configuration (loaded from yesrouter.conf)
 * Runtime config (NAT pools, interfaces) comes from startup.gate
 */
struct yesrouter_hw_config {
    /* Unix settings */
    struct {
        bool interactive;
        char exec_script[256];
        char cli_listen[256];
        char log_file[256];
    } unix_config;

    /* DPDK settings */
    struct {
        bool enabled;
        struct {
            char pci_addr[32];
            char name[32];
            int num_rx_queues;
            int num_tx_queues;
            int num_rx_desc;
            int num_tx_desc;
        } devices[32];
        int num_devices;
        /* Virtual devices (TAP, etc.) */
        struct {
            char vdev_arg[128];  /* e.g., "net_tap0,iface=vbng_in" */
        } vdevs[8];
        int num_vdevs;
        bool no_pci;
        int socket_mem; /* MB */
        int num_mbufs;
    } dpdk_config;

    /* CPU settings */
    struct {
        int main_core;
        char corelist_workers[256];
        int num_workers; /* Parsed from corelist */
        bool skip_cores;
    } cpu_config;

    /* NAT Performance Tuning */
    struct {
        int workers;            /* Number of NAT workers */
        int max_sessions;       /* Max concurrent sessions */
        int session_cache_size; /* Per-worker L1 cache size */
    } nat_config;
};

/* Global configuration instance */
extern struct yesrouter_hw_config g_yesrouter_hw_config;

/* Initialize configuration with defaults */
void yesrouter_config_init_defaults(void);

/* Parse configuration file */
int yesrouter_config_parse(const char *filename);

/* Print current configuration */
void yesrouter_config_print(void);

/* Apply NAT configuration to nat module */
void yesrouter_config_apply_nat(void);

/* Get worker count from corelist string (e.g., "1-15" -> 15) */
int yesrouter_config_parse_corelist(const char *corelist);

#endif /* YESROUTER_CONFIG_H */
