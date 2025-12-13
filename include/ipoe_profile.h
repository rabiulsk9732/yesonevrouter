/**
 * @file ipoe_profile.h
 * @brief IPoE Service Profile - BISON-style VLAN→Profile binding
 *
 * Service profiles define subscriber policies:
 * - IP pool binding
 * - Rate limiting
 * - ACL binding
 * - DHCP options
 */

#ifndef IPOE_PROFILE_H
#define IPOE_PROFILE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Forward declaration */
struct ipoe_session;

/*============================================================================
 * Constants
 *============================================================================*/

#define IPOE_MAX_PROFILES           256
#define IPOE_PROFILE_NAME_LEN       32
#define IPOE_POOL_NAME_LEN          32
#define IPOE_ACL_NAME_LEN           32
#define IPOE_OPT82_TEMPLATE_LEN     128

/*============================================================================
 * Option 82 Template Configuration (BISON-style)
 *============================================================================*/

/**
 * Per-interface Option 82 templates
 * Supports variables: %port%, %svlan%, %cvlan%, %mac%, %ifname%, %slot%
 */
struct ipoe_opt82_config {
    bool     enabled;
    char     circuit_id_template[IPOE_OPT82_TEMPLATE_LEN];
    char     remote_id_template[IPOE_OPT82_TEMPLATE_LEN];
    bool     trust_incoming;     /* Trust client's Option 82 */
    bool     strip_on_reply;     /* Remove Option 82 on reply */
};

/*============================================================================
 * DHCP Pool Profile (BISON-style named pools)
 *============================================================================*/

struct ipoe_pool_profile {
    char     name[IPOE_POOL_NAME_LEN];
    bool     enabled;

    /* IP Range */
    uint32_t start_ip;
    uint32_t end_ip;
    uint32_t netmask;
    uint32_t gateway;

    /* DNS */
    uint32_t dns_primary;
    uint32_t dns_secondary;

    /* Lease times */
    uint32_t default_lease;      /* seconds */
    uint32_t min_lease;
    uint32_t max_lease;

    /* Pool state */
    uint32_t total_ips;
    uint32_t used_ips;
    uint32_t reserved_ips;
};

/*============================================================================
 * Service Profile (BISON-style VLAN→Profile binding)
 *============================================================================*/

struct ipoe_service_profile {
    char     name[IPOE_PROFILE_NAME_LEN];
    bool     enabled;

    /* Matching criteria */
    uint16_t svlan;              /* 0 = any */
    uint16_t svlan_mask;         /* For range matching */
    uint16_t cvlan;              /* 0 = any */
    uint16_t cvlan_mask;
    uint32_t ifindex;            /* 0 = any interface */

    /* Pool binding */
    char     pool_name[IPOE_POOL_NAME_LEN];

    /* Rate limiting */
    uint32_t rate_limit_up;      /* kbps, 0 = unlimited */
    uint32_t rate_limit_down;

    /* ACL */
    char     acl_in[IPOE_ACL_NAME_LEN];
    char     acl_out[IPOE_ACL_NAME_LEN];

    /* Timeouts */
    uint32_t session_timeout;    /* 0 = use global */
    uint32_t idle_timeout;

    /* RADIUS overrides */
    bool     use_radius_pool;    /* Use Framed-Pool from RADIUS */
    bool     use_radius_rate;    /* Use rate from RADIUS */

    /* Option 82 config for this profile */
    struct ipoe_opt82_config opt82;

    /* Priority (lower = higher priority) */
    uint8_t  priority;
};

/*============================================================================
 * Profile Manager Context
 *============================================================================*/

struct ipoe_profile_mgr {
    struct ipoe_service_profile profiles[IPOE_MAX_PROFILES];
    uint32_t num_profiles;

    struct ipoe_pool_profile pools[IPOE_MAX_PROFILES];
    uint32_t num_pools;

    char default_profile[IPOE_PROFILE_NAME_LEN];
};

/*============================================================================
 * Profile API
 *============================================================================*/

/* Initialization */
int ipoe_profile_init(void);
void ipoe_profile_cleanup(void);

/* Service Profile CRUD */
int ipoe_profile_create(const char *name);
int ipoe_profile_delete(const char *name);
struct ipoe_service_profile *ipoe_profile_find(const char *name);

/* Profile matching */
struct ipoe_service_profile *ipoe_profile_match(uint16_t svlan, uint16_t cvlan,
                                                  uint32_t ifindex);
int ipoe_profile_set_default(const char *name);

/* Profile configuration */
int ipoe_profile_set_pool(const char *profile, const char *pool_name);
int ipoe_profile_set_vlan(const char *profile, uint16_t svlan, uint16_t cvlan);
int ipoe_profile_set_rate_limit(const char *profile, uint32_t up, uint32_t down);
int ipoe_profile_set_acl(const char *profile, const char *acl_in, const char *acl_out);
int ipoe_profile_set_timeout(const char *profile, uint32_t session, uint32_t idle);

/* Pool Profile CRUD */
int ipoe_pool_create(const char *name);
int ipoe_pool_delete(const char *name);
struct ipoe_pool_profile *ipoe_pool_find(const char *name);
int ipoe_pool_set_range(const char *pool, uint32_t start, uint32_t end, uint32_t mask);
int ipoe_pool_set_dns(const char *pool, uint32_t primary, uint32_t secondary);
int ipoe_pool_set_gateway(const char *pool, uint32_t gateway);
int ipoe_pool_set_lease(const char *pool, uint32_t default_lease, uint32_t min, uint32_t max);

/* IP allocation from pool */
uint32_t ipoe_pool_allocate_ip(const char *pool_name);
int ipoe_pool_release_ip(const char *pool_name, uint32_t ip);

/* Option 82 template */
int ipoe_profile_set_opt82(const char *profile, const char *circuit_id_tmpl,
                            const char *remote_id_tmpl);
int ipoe_opt82_expand_template(const char *tmpl, struct ipoe_session *sess,
                                char *output, size_t len);

/* Statistics */
void ipoe_profile_print_all(void);
void ipoe_pool_print_all(void);

#endif /* IPOE_PROFILE_H */

/*============================================================================
 * Pool Allocator API (production-grade)
 *============================================================================*/

/* Initialize pool allocator with bitmap */
int ipoe_pool_alloc_init(const char *name, uint32_t start_ip, uint32_t end_ip);

/* Allocate specific IP (for static assignment) */
int ipoe_pool_allocate_specific(const char *pool_name, uint32_t ip);

/* Get pool statistics */
void ipoe_pool_get_stats(const char *pool_name, uint32_t *total,
                          uint32_t *used, uint32_t *free);

/* Print all pool allocator stats */
void ipoe_pool_alloc_print_stats(void);
