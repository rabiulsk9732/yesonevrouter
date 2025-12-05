/**
 * @file vlan_db.h
 * @brief VLAN Database Management
 *
 * Global VLAN database for managing VLANs independently of interfaces.
 * Supports Cisco/Huawei-style VLAN configuration.
 */

#ifndef VLAN_DB_H
#define VLAN_DB_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define VLAN_NAME_MAX       32
#define VLAN_DESC_MAX       128
#define VLAN_DB_MAX_VLANS   4096

/**
 * @brief VLAN database entry
 */
struct vlan_entry {
    uint16_t vlan_id;                   /* VLAN ID (1-4094) */
    char name[VLAN_NAME_MAX];           /* VLAN name */
    char description[VLAN_DESC_MAX];    /* Description */
    bool active;                        /* Is VLAN active */
    time_t created;                     /* Creation timestamp */

    /* Statistics */
    uint32_t num_interfaces;            /* Number of interfaces in this VLAN */
    uint64_t rx_packets;
    uint64_t tx_packets;
};

/**
 * @brief VLAN database
 */
struct vlan_database {
    struct vlan_entry *vlans[VLAN_DB_MAX_VLANS];  /* Indexed by VLAN ID */
    uint32_t num_vlans;                            /* Number of active VLANs */
    bool initialized;
};

/**
 * @brief Initialize VLAN database
 * @return 0 on success, -1 on error
 */
int vlan_db_init(void);

/**
 * @brief Get VLAN database instance
 * @return Pointer to global VLAN database
 */
struct vlan_database *vlan_db_get_instance(void);

/**
 * @brief Create a VLAN
 * @param vlan_id VLAN ID (1-4094)
 * @param name Optional VLAN name (can be NULL)
 * @return 0 on success, -1 on error
 */
int vlan_db_create(uint16_t vlan_id, const char *name);

/**
 * @brief Delete a VLAN
 * @param vlan_id VLAN ID
 * @return 0 on success, -1 on error
 */
int vlan_db_delete(uint16_t vlan_id);

/**
 * @brief Create multiple VLANs (batch)
 * @param vlan_ids Array of VLAN IDs
 * @param count Number of VLANs to create
 * @return Number of VLANs created
 */
int vlan_db_create_batch(const uint16_t *vlan_ids, uint32_t count);

/**
 * @brief Create range of VLANs
 * @param start_vlan Start VLAN ID
 * @param end_vlan End VLAN ID (inclusive)
 * @return Number of VLANs created
 */
int vlan_db_create_range(uint16_t start_vlan, uint16_t end_vlan);

/**
 * @brief Check if VLAN exists
 * @param vlan_id VLAN ID
 * @return true if exists, false otherwise
 */
bool vlan_db_exists(uint16_t vlan_id);

/**
 * @brief Get VLAN entry
 * @param vlan_id VLAN ID
 * @return Pointer to VLAN entry or NULL if not found
 */
struct vlan_entry *vlan_db_get(uint16_t vlan_id);

/**
 * @brief Set VLAN name
 * @param vlan_id VLAN ID
 * @param name VLAN name
 * @return 0 on success, -1 on error
 */
int vlan_db_set_name(uint16_t vlan_id, const char *name);

/**
 * @brief Set VLAN description
 * @param vlan_id VLAN ID
 * @param description Description
 * @return 0 on success, -1 on error
 */
int vlan_db_set_description(uint16_t vlan_id, const char *description);

/**
 * @brief Print VLAN database (for debugging)
 */
void vlan_db_print(void);

/**
 * @brief Print brief VLAN list
 */
void vlan_db_print_brief(void);

/**
 * @brief Cleanup VLAN database
 */
void vlan_db_cleanup(void);

#endif /* VLAN_DB_H */
