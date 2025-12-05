#ifndef VPP_PARSER_H
#define VPP_PARSER_H

#include <stdbool.h>
#include <stdint.h>

/* VPP-style configuration structure */
struct vpp_config {
    struct {
        bool interactive;
        char exec_script[256];
        char cli_listen[256];
        char log_file[256];
    } unix_config;

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
        bool no_pci;
        int socket_mem;
        int num_mbufs;
    } dpdk_config;

    struct {
        int main_core;
        char corelist_workers[256];
        bool skip_cores;
    } cpu_config;
};

/* Global configuration instance */
extern struct vpp_config g_vpp_config;

/* Initialize configuration with defaults */
void vpp_config_init_defaults(void);

/* Parse VPP-style configuration file */
int vpp_config_parse(const char *filename);

/* Print current configuration */
void vpp_config_print(void);

#endif /* VPP_PARSER_H */
