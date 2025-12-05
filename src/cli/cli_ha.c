#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "cli.h"
#include "ha.h"
#include "log.h"

static int cmd_ha_mode(int count, char **args)
{
    if (count < 2) {
        printf("Usage: ha mode <master|backup>\n");
        return 0;
    }

    if (strcmp(args[1], "master") == 0) {
        g_ha_config.mode = HA_STATE_MASTER;
        printf("HA mode set to MASTER\n");
    } else if (strcmp(args[1], "backup") == 0) {
        g_ha_config.mode = HA_STATE_BACKUP;
        printf("HA mode set to BACKUP\n");
    } else {
        printf("Invalid mode. Use 'master' or 'backup'\n");
    }
    return 0;
}

static int cmd_ha_peer(int count, char **args)
{
    if (count < 2) {
        printf("Usage: ha peer <ip>\n");
        return 0;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, args[1], &addr) != 1) {
        printf("Invalid IP address\n");
        return 0;
    }

    g_ha_config.peer_ip = ntohl(addr.s_addr);
    ha_init(g_ha_config.local_ip, g_ha_config.peer_ip);
    printf("HA peer set to %s\n", args[1]);
    return 0;
}

static int cmd_ha_vip(int count, char **args)
{
    /* args[0]="ha", args[1]="vip", args[2]=ip, args[3]=mask, args[4]="interface", args[5]=iface */
    if (count < 6) {
        printf("Usage: ha vip <ip> <mask> interface <iface>\n");
        return 0;
    }

    struct in_addr ip, mask;
    if (inet_pton(AF_INET, args[2], &ip) != 1 || inet_pton(AF_INET, args[3], &mask) != 1) {
        printf("Invalid IP or Mask\n");
        return 0;
    }

    g_ha_config.vip_ip = ntohl(ip.s_addr);
    g_ha_config.vip_mask = ntohl(mask.s_addr);
    strncpy(g_ha_config.vip_iface, args[5], sizeof(g_ha_config.vip_iface) - 1);

    printf("HA VIP configured: %s/%s on %s\n", args[2], args[3], args[5]);
    return 0;
}

static int cmd_show_ha(int count, char **args)
{
    (void)args;
    (void)count;

    printf("HA Status:\n");
    printf("  Mode: %s\n", g_ha_config.mode == HA_STATE_MASTER ? "MASTER" : "BACKUP");
    printf("  Peer IP: %u.%u.%u.%u\n",
           (g_ha_config.peer_ip >> 24) & 0xFF, (g_ha_config.peer_ip >> 16) & 0xFF,
           (g_ha_config.peer_ip >> 8) & 0xFF, g_ha_config.peer_ip & 0xFF);
    printf("  VIP: %u.%u.%u.%u Mask: %u.%u.%u.%u Interface: %s\n",
           (g_ha_config.vip_ip >> 24) & 0xFF, (g_ha_config.vip_ip >> 16) & 0xFF,
           (g_ha_config.vip_ip >> 8) & 0xFF, g_ha_config.vip_ip & 0xFF,
           (g_ha_config.vip_mask >> 24) & 0xFF, (g_ha_config.vip_mask >> 16) & 0xFF,
           (g_ha_config.vip_mask >> 8) & 0xFF, g_ha_config.vip_mask & 0xFF,
           g_ha_config.vip_iface);

    return 0;
}

void cli_register_ha_commands(void)
{
    cli_register_command("ha mode", "Set HA mode (master/backup)", cmd_ha_mode);
    cli_register_command("ha peer", "Set HA peer IP", cmd_ha_peer);
    cli_register_command("ha vip", "Set HA Virtual IP", cmd_ha_vip);
    cli_register_command("show ha", "Show HA status", cmd_show_ha);
}
