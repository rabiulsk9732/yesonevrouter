/**
 * @file service_profile.h
 * @brief PPPoE Service Profile API (Enhanced)
 *
 * Supports: interface binding, multiple service-names, pool name
 */

#ifndef SERVICE_PROFILE_H
#define SERVICE_PROFILE_H

#include <stdint.h>
#include <stdbool.h>

#define MAX_SERVICE_NAMES 8

/* Service profile info (for lookups) */
struct service_profile_info {
    char name[32];

    /* Interface binding */
    char iface_name[32];         /* "eth0", empty = any */
    uint16_t vlan_id;            /* 0 = root interface */

    /* AC-Name (empty = use global) */
    char ac_name[64];

    /* Pool name (string, not ID) */
    char pool_name[32];

    /* Multiple service-names */
    char service_names[MAX_SERVICE_NAMES][32];
    int num_service_names;

    /* QoS */
    uint64_t cir_up;
    uint64_t cir_down;
    uint64_t mir_up;
    uint64_t mir_down;

    /* Timeouts */
    uint32_t session_timeout;
    uint32_t idle_timeout;

    /* Status */
    bool enabled;
};

/**
 * Initialize service profile subsystem
 */
int service_profile_init(void);

/**
 * Cleanup service profiles
 */
void service_profile_cleanup(void);

/**
 * Create a new service profile
 */
int service_profile_create(const char *name);

/**
 * Delete a service profile
 */
int service_profile_delete(const char *name);

/**
 * Set profile interface binding
 */
int service_profile_set_interface(const char *profile, const char *iface, uint16_t vlan_id);

/**
 * Set profile pool
 */
int service_profile_set_pool(const char *profile, const char *pool_name);

/**
 * Set profile AC-Name override
 */
int service_profile_set_ac_name(const char *profile, const char *ac_name);

/**
 * Add service-name to profile
 */
int service_profile_add_service_name(const char *profile, const char *service_name);

/**
 * Remove service-name from profile
 */
int service_profile_remove_service_name(const char *profile, const char *service_name);

/**
 * Find service profile by name
 * @return Profile index or -1 if not found
 */
int service_profile_find(const char *name, struct service_profile_info *info);

/**
 * Find profile matching interface/vlan/service-name
 */
int service_profile_match(const char *iface, uint16_t vlan_id, const char *service_name,
                          struct service_profile_info *info);

/**
 * Set default profile
 */
int service_profile_set_default(const char *name);

/**
 * Get default profile
 */
int service_profile_get_default(struct service_profile_info *info);

/**
 * List all service profiles
 */
void service_profile_list(void);

#endif /* SERVICE_PROFILE_H */
