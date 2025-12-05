/**
 * @file vlan_db.c
 * @brief VLAN Database Implementation
 */

#include "vlan_db.h"
#include "vlan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Global VLAN database */
static struct vlan_database g_vlan_db = {0};

/**
 * @brief Initialize VLAN database
 */
int vlan_db_init(void)
{
    memset(&g_vlan_db, 0, sizeof(g_vlan_db));
    g_vlan_db.initialized = true;
    printf("VLAN database initialized\n");
    return 0;
}

/**
 * @brief Get VLAN database instance
 */
struct vlan_database *vlan_db_get_instance(void)
{
    if (!g_vlan_db.initialized) {
        vlan_db_init();
    }
    return &g_vlan_db;
}

/**
 * @brief Create a VLAN
 */
int vlan_db_create(uint16_t vlan_id, const char *name)
{
    if (!vlan_id_is_valid(vlan_id)) {
        fprintf(stderr, "Invalid VLAN ID: %u\n", vlan_id);
        return -1;
    }

    if (g_vlan_db.vlans[vlan_id] != NULL) {
        /* VLAN already exists */
        return 0;
    }

    struct vlan_entry *entry = calloc(1, sizeof(struct vlan_entry));
    if (!entry) {
        fprintf(stderr, "Failed to allocate VLAN entry\n");
        return -1;
    }

    entry->vlan_id = vlan_id;
    entry->active = true;
    entry->created = time(NULL);

    if (name) {
        strncpy(entry->name, name, VLAN_NAME_MAX - 1);
    } else {
        snprintf(entry->name, VLAN_NAME_MAX, "VLAN%04u", vlan_id);
    }

    g_vlan_db.vlans[vlan_id] = entry;
    g_vlan_db.num_vlans++;

    return 0;
}

/**
 * @brief Delete a VLAN
 */
int vlan_db_delete(uint16_t vlan_id)
{
    if (!vlan_id_is_valid(vlan_id)) {
        return -1;
    }

    if (g_vlan_db.vlans[vlan_id] == NULL) {
        return -1;  /* VLAN doesn't exist */
    }

    free(g_vlan_db.vlans[vlan_id]);
    g_vlan_db.vlans[vlan_id] = NULL;
    g_vlan_db.num_vlans--;

    return 0;
}

/**
 * @brief Create multiple VLANs (batch)
 */
int vlan_db_create_batch(const uint16_t *vlan_ids, uint32_t count)
{
    int created = 0;

    for (uint32_t i = 0; i < count; i++) {
        if (vlan_db_create(vlan_ids[i], NULL) == 0) {
            created++;
        }
    }

    return created;
}

/**
 * @brief Create range of VLANs
 */
int vlan_db_create_range(uint16_t start_vlan, uint16_t end_vlan)
{
    if (start_vlan > end_vlan) {
        fprintf(stderr, "Invalid VLAN range: %u to %u\n", start_vlan, end_vlan);
        return 0;
    }

    int created = 0;

    for (uint16_t vlan_id = start_vlan; vlan_id <= end_vlan; vlan_id++) {
        if (vlan_db_create(vlan_id, NULL) == 0) {
            created++;
        }
    }

    return created;
}

/**
 * @brief Check if VLAN exists
 */
bool vlan_db_exists(uint16_t vlan_id)
{
    if (!vlan_id_is_valid(vlan_id)) {
        return false;
    }

    return (g_vlan_db.vlans[vlan_id] != NULL);
}

/**
 * @brief Get VLAN entry
 */
struct vlan_entry *vlan_db_get(uint16_t vlan_id)
{
    if (!vlan_id_is_valid(vlan_id)) {
        return NULL;
    }

    return g_vlan_db.vlans[vlan_id];
}

/**
 * @brief Set VLAN name
 */
int vlan_db_set_name(uint16_t vlan_id, const char *name)
{
    struct vlan_entry *entry = vlan_db_get(vlan_id);
    if (!entry || !name) {
        return -1;
    }

    strncpy(entry->name, name, VLAN_NAME_MAX - 1);
    entry->name[VLAN_NAME_MAX - 1] = '\0';

    return 0;
}

/**
 * @brief Set VLAN description
 */
int vlan_db_set_description(uint16_t vlan_id, const char *description)
{
    struct vlan_entry *entry = vlan_db_get(vlan_id);
    if (!entry || !description) {
        return -1;
    }

    strncpy(entry->description, description, VLAN_DESC_MAX - 1);
    entry->description[VLAN_DESC_MAX - 1] = '\0';

    return 0;
}

/**
 * @brief Print VLAN database
 */
void vlan_db_print(void)
{
    printf("\n");
    printf("================================================================================\n");
    printf("VLAN Database\n");
    printf("================================================================================\n");
    printf("%-6s %-20s %-10s %s\n", "VLAN", "Name", "Status", "Description");
    printf("--------------------------------------------------------------------------------\n");

    for (uint16_t vlan_id = VLAN_ID_MIN; vlan_id <= VLAN_ID_MAX; vlan_id++) {
        struct vlan_entry *entry = g_vlan_db.vlans[vlan_id];
        if (entry) {
            printf("%-6u %-20s %-10s %s\n",
                   entry->vlan_id,
                   entry->name,
                   entry->active ? "active" : "inactive",
                   entry->description[0] ? entry->description : "-");
        }
    }

    printf("--------------------------------------------------------------------------------\n");
    printf("Total VLANs: %u\n", g_vlan_db.num_vlans);
    printf("================================================================================\n\n");
}

/**
 * @brief Print brief VLAN list
 */
void vlan_db_print_brief(void)
{
    printf("\n");
    printf("VLAN ID  Name                 Status\n");
    printf("-------  -------------------  ------\n");

    for (uint16_t vlan_id = VLAN_ID_MIN; vlan_id <= VLAN_ID_MAX; vlan_id++) {
        struct vlan_entry *entry = g_vlan_db.vlans[vlan_id];
        if (entry) {
            printf("%-7u  %-19s  %s\n",
                   entry->vlan_id,
                   entry->name,
                   entry->active ? "active" : "inactive");
        }
    }

    printf("\nTotal: %u VLANs\n\n", g_vlan_db.num_vlans);
}

/**
 * @brief Cleanup VLAN database
 */
void vlan_db_cleanup(void)
{
    for (uint16_t vlan_id = VLAN_ID_MIN; vlan_id <= VLAN_ID_MAX; vlan_id++) {
        if (g_vlan_db.vlans[vlan_id]) {
            free(g_vlan_db.vlans[vlan_id]);
            g_vlan_db.vlans[vlan_id] = NULL;
        }
    }

    g_vlan_db.num_vlans = 0;
    g_vlan_db.initialized = false;

    printf("VLAN database cleaned up\n");
}
