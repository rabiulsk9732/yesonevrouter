/**
 * @file cli_vlan.c
 * @brief VLAN CLI Commands
 *
 * Cisco/Huawei-style VLAN management commands
 */

#include "cli.h"
#include "vlan_db.h"
#include "vlan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Current VLAN being configured */
static uint16_t g_current_vlan = 0;

/**
 * Command: vlan <id>
 * Enter VLAN configuration mode
 */
static int cmd_vlan(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: vlan <vlan-id>\n");
        return -1;
    }

    int vlan_id = atoi(argv[1]);
    if (!vlan_id_is_valid(vlan_id)) {
        printf("Invalid VLAN ID: %d (valid range: 1-4094)\n", vlan_id);
        return -1;
    }

    /* Create VLAN if it doesn't exist */
    vlan_db_create(vlan_id, NULL);

    g_current_vlan = vlan_id;

    printf("VLAN %d created/configured\n", vlan_id);

    /* TODO: Enter VLAN config mode context */

    return 0;
}

/**
 * Command: vlan batch <list> | <start> to <end>
 * Create multiple VLANs
 */
static int cmd_vlan_batch(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: vlan batch <vlan-list> | <start> to <end>\n");
        printf("Examples:\n");
        printf("  vlan batch 100 200 300\n");
        printf("  vlan batch 100 to 200\n");
        printf("  vlan batch 10 20 30 to 50\n");
        return -1;
    }

    int created = 0;

    /* Check if "to" keyword exists for range */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "to") == 0 && i + 1 < argc) {
            /* Range: <start> to <end> */
            int start = atoi(argv[i - 1]);
            int end = atoi(argv[i + 1]);
            created += vlan_db_create_range(start, end);
            i++;  /* Skip end value */
        } else if (strcmp(argv[i], "to") != 0) {
            /* Individual VLAN */
            int vlan_id = atoi(argv[i]);
            if (vlan_id_is_valid(vlan_id)) {
                if (vlan_db_create(vlan_id, NULL) == 0) {
                    created++;
                }
            }
        }
    }

    printf("Created %d VLAN(s)\n", created);
    return 0;
}

/**
 * Command: no vlan <id>
 * Delete VLAN
 */
static int cmd_no_vlan(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: no vlan <vlan-id>\n");
        return -1;
    }

    int vlan_id = atoi(argv[2]);
    if (!vlan_id_is_valid(vlan_id)) {
        printf("Invalid VLAN ID: %d\n", vlan_id);
        return -1;
    }

    if (vlan_db_delete(vlan_id) == 0) {
        printf("VLAN %d deleted\n", vlan_id);
    } else {
        printf("VLAN %d does not exist\n", vlan_id);
    }

    return 0;
}

/**
 * Command: name <name>
 * Set VLAN name (in VLAN config mode)
 */
static int cmd_vlan_name(int argc, char **argv)
{
    if (g_current_vlan == 0) {
        printf("Not in VLAN configuration mode\n");
        return -1;
    }

    if (argc < 2) {
        printf("Usage: name <vlan-name>\n");
        return -1;
    }

    if (vlan_db_set_name(g_current_vlan, argv[1]) == 0) {
        printf("VLAN %d name set to: %s\n", g_current_vlan, argv[1]);
    } else {
        printf("Failed to set VLAN name\n");
    }

    return 0;
}

/**
 * Command: description <text>
 * Set VLAN description (in VLAN config mode)
 */
static int cmd_vlan_description(int argc, char **argv)
{
    if (g_current_vlan == 0) {
        printf("Not in VLAN configuration mode\n");
        return -1;
    }

    if (argc < 2) {
        printf("Usage: description <text>\n");
        return -1;
    }

    /* Concatenate all arguments as description */
    char desc[128] = {0};
    for (int i = 1; i < argc; i++) {
        if (i > 1) strcat(desc, " ");
        strcat(desc, argv[i]);
    }

    if (vlan_db_set_description(g_current_vlan, desc) == 0) {
        printf("VLAN %d description set\n", g_current_vlan);
    } else {
        printf("Failed to set VLAN description\n");
    }

    return 0;
}

/**
 * Command: show vlan
 * Display VLAN database
 */
static int cmd_show_vlan(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    vlan_db_print();
    return 0;
}

/**
 * Command: show vlan brief
 * Display brief VLAN list
 */
static int cmd_show_vlan_brief(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    vlan_db_print_brief();
    return 0;
}

/**
 * Command: show vlan id <vlan-id>
 * Display specific VLAN
 */
static int cmd_show_vlan_id(int argc, char **argv)
{
    if (argc < 4) {
        printf("Usage: show vlan id <vlan-id>\n");
        return -1;
    }

    int vlan_id = atoi(argv[3]);
    if (!vlan_id_is_valid(vlan_id)) {
        printf("Invalid VLAN ID: %d\n", vlan_id);
        return -1;
    }

    struct vlan_entry *entry = vlan_db_get(vlan_id);
    if (!entry) {
        printf("VLAN %d does not exist\n", vlan_id);
        return -1;
    }

    printf("\nVLAN %d\n", entry->vlan_id);
    printf("  Name: %s\n", entry->name);
    printf("  Description: %s\n", entry->description[0] ? entry->description : "-");
    printf("  Status: %s\n", entry->active ? "active" : "inactive");
    printf("  Interfaces: %u\n", entry->num_interfaces);
    printf("  RX Packets: %lu\n", entry->rx_packets);
    printf("  TX Packets: %lu\n\n", entry->tx_packets);

    return 0;
}

/**
 * Register VLAN CLI commands
 */
void cli_vlan_register_commands(void)
{
    /* VLAN creation commands */
    cli_register_command("vlan", "Enter VLAN configuration mode", cmd_vlan);
    cli_register_command("vlan batch", "Create multiple VLANs", cmd_vlan_batch);
    cli_register_command("no vlan", "Delete VLAN", cmd_no_vlan);

    /* VLAN configuration commands (in VLAN mode) */
    cli_register_command("name", "Set VLAN name", cmd_vlan_name);
    cli_register_command("description", "Set VLAN description", cmd_vlan_description);

    /* Show commands */
    cli_register_command("show vlan", "Display VLAN database", cmd_show_vlan);
    cli_register_command("show vlan brief", "Display brief VLAN list", cmd_show_vlan_brief);
    cli_register_command("show vlan id", "Display specific VLAN", cmd_show_vlan_id);

    printf("VLAN CLI commands registered\n");
}
