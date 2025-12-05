/**
 * @file acl.h
 * @brief Access Control List API
 */

#ifndef ACL_H
#define ACL_H

#include <stdint.h>

typedef enum {
    ACL_PERMIT,
    ACL_DENY
} acl_action_t;

/**
 * Initialize ACL subsystem
 */
int acl_init(void);

/**
 * Cleanup ACL subsystem
 */
void acl_cleanup(void);

/**
 * Create a new ACL
 * @return ACL ID or -1 on error
 */
int acl_create(const char *name);

/**
 * Delete an ACL
 */
int acl_delete(const char *name);

/**
 * Find ACL by name
 */
int acl_find(const char *name);

/**
 * Add entry to ACL
 * @param protocol 0 for any, 6 for TCP, 17 for UDP, etc.
 */
int acl_add_entry(const char *acl_name, acl_action_t action, uint8_t protocol,
                  uint32_t src_ip, uint32_t src_mask,
                  uint32_t dst_ip, uint32_t dst_mask,
                  uint16_t src_port_min, uint16_t src_port_max,
                  uint16_t dst_port_min, uint16_t dst_port_max);

/**
 * Check packet against ACL
 * @return ACL_PERMIT or ACL_DENY
 */
acl_action_t acl_check(const char *acl_name, uint8_t protocol,
                       uint32_t src_ip, uint32_t dst_ip,
                       uint16_t src_port, uint16_t dst_port);

/**
 * Show ACL(s)
 * @param acl_name NULL for all ACLs
 */
void acl_show(const char *acl_name);

#endif /* ACL_H */
