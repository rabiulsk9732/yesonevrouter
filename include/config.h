/**
 * @file config.h
 * @brief Configuration Management Framework
 *
 * Provides configuration parsing, validation, and management.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "interface_types.h"

#define CONFIG_MAX_PATH         256
#define CONFIG_MAX_NAME         64
#define CONFIG_MAX_INTERFACES   32
#define CONFIG_MAX_POOLS        16
#define CONFIG_MAX_BGP_PEERS    16

/* System configuration */
struct system_config {
    char hostname[CONFIG_MAX_NAME];
    uint32_t log_level;
    bool daemonize;
    char pid_file[CONFIG_MAX_PATH];
};

/* Interface configuration */
struct interface_config {
    char name[CONFIG_MAX_NAME];
    uint32_t ifindex;
    bool enabled;
    uint32_t mtu;
    uint32_t speed;             /* Mbps */
    struct in_addr ipv4_addr;
    struct in_addr ipv4_mask;
    uint16_t vlan_id;
    enum interface_type type; // Using interface_type from interface.h
};

/* IP address pool configuration */
struct ip_pool_config {
    char name[CONFIG_MAX_NAME];
    struct in_addr start_ip;
    struct in_addr end_ip;
    struct in_addr netmask;
    struct in_addr gateway;
    struct in_addr dns_primary;
    struct in_addr dns_secondary;
    uint32_t lease_time;        /* seconds */
};

/* BGP peer configuration */
struct bgp_peer_config {
    struct in_addr peer_ip;
    uint32_t remote_as;
    uint32_t local_as;
    uint16_t hold_time;
    uint16_t keepalive_interval;
    bool enabled;
    char description[CONFIG_MAX_NAME];
};

/* Routing configuration */
struct routing_config {
    uint32_t local_as;
    struct in_addr router_id;
    uint32_t num_bgp_peers;
    struct bgp_peer_config bgp_peers[CONFIG_MAX_BGP_PEERS];
};

/* BNG/Access configuration */
struct bng_config {
    bool pppoe_enabled;
    bool ipoe_enabled;
    char ac_name[CONFIG_MAX_NAME];      /* Access Concentrator name */
    uint16_t pppoe_mtu;
    uint32_t session_timeout;           /* seconds */
    uint32_t max_sessions;
    uint32_t num_ip_pools;
    struct ip_pool_config ip_pools[CONFIG_MAX_POOLS];
};

/* CGNAT configuration */
struct cgnat_config {
    bool enabled;
    struct in_addr public_ip_start;
    struct in_addr public_ip_end;
    uint16_t port_range_start;
    uint16_t port_range_end;
    uint32_t session_timeout;
    bool logging_enabled;
    char log_server[CONFIG_MAX_NAME];
};

/* QoS configuration */
struct qos_config {
    bool enabled;
    uint32_t default_rate_limit_down;   /* kbps */
    uint32_t default_rate_limit_up;     /* kbps */
    uint32_t burst_size;                /* bytes */
};

/* Firewall configuration */
struct firewall_config {
    bool enabled;
    bool stateful_enabled;
    uint32_t connection_timeout;        /* seconds */
    uint32_t max_connections;
};

/* Management configuration */
struct management_config {
    bool rest_api_enabled;
    uint16_t rest_api_port;
    char rest_api_bind[CONFIG_MAX_NAME];
    bool cli_enabled;
    uint16_t cli_port;
};

/* Main configuration structure */
struct yesrouter_config {
    char config_file[CONFIG_MAX_PATH];
    uint32_t version;

    struct system_config system;

    uint32_t num_interfaces;
    struct interface_config interfaces[CONFIG_MAX_INTERFACES];

    struct routing_config routing;
    struct bng_config bng;
    struct cgnat_config cgnat;
    struct qos_config qos;
    struct firewall_config firewall;
    struct management_config management;

    /* Runtime flags */
    bool is_loaded;
    bool is_valid;
    uint64_t load_time;
};

/* Global configuration instance */
extern struct yesrouter_config g_config;

/**
 * Initialize configuration subsystem
 * @return 0 on success, -1 on failure
 */
int config_init(void);

/**
 * Load configuration from file
 * @param filename Configuration file path
 * @return 0 on success, -1 on failure
 */
int config_load(const char *filename);

/**
 * Reload configuration (hot-reload)
 * @return 0 on success, -1 on failure
 */
int config_reload(void);

/**
 * Validate configuration
 * @param cfg Configuration to validate
 * @return 0 if valid, -1 if invalid
 */
int config_validate(struct yesrouter_config *cfg);

/**
 * Save configuration to file
 * @param filename Output file path
 * @return 0 on success, -1 on failure
 */
int config_save(const char *filename);

/**
 * Create backup of current configuration
 * @return 0 on success, -1 on failure
 */
int config_backup(void);

/**
 * Rollback to previous configuration
 * @return 0 on success, -1 on failure
 */
int config_rollback(void);

/**
 * Get current configuration
 * @return Pointer to configuration structure
 */
struct yesrouter_config *config_get(void);

/**
 * Set default configuration values
 * @param cfg Configuration structure to initialize
 */
void config_set_defaults(struct yesrouter_config *cfg);

/**
 * Print configuration summary
 */
void config_print(void);

/**
 * Cleanup configuration subsystem
 */
void config_cleanup(void);

/* Helper functions */
int config_parse_ip(const char *str, struct in_addr *addr);
const char *config_ip_to_str(struct in_addr addr);

#endif /* CONFIG_H */
