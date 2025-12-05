/**
 * @file service_profile.h
 * @brief PPPoE Service Profile API
 */

#ifndef SERVICE_PROFILE_H
#define SERVICE_PROFILE_H

#include <stdint.h>
#include <stdbool.h>

/* Service profile info (for lookups) */
struct service_profile_info {
    char name[32];
    char ac_name[64];
    uint32_t ip_pool_id;
    uint64_t cir_up;
    uint64_t cir_down;
    uint64_t mir_up;
    uint64_t mir_down;
    uint32_t session_timeout;
    uint32_t idle_timeout;
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
int service_profile_create(const char *name, const char *ac_name, uint32_t pool_id,
                           uint64_t cir_up, uint64_t cir_down,
                           uint64_t mir_up, uint64_t mir_down,
                           uint32_t session_timeout, uint32_t idle_timeout);

/**
 * Delete a service profile
 */
int service_profile_delete(const char *name);

/**
 * Find service profile by name
 * @return Profile index or -1 if not found
 */
int service_profile_find(const char *name, struct service_profile_info *info);

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
