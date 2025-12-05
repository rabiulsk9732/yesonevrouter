/**
 * @file cli_nat.c
 * @brief NAT CLI Commands
 */

#include "acl.h"
#include "cli.h"
#include "interface.h"
#include "nat.h"
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern struct nat_config g_nat_config;

/* Command: ip nat pool */
int cmd_ip_nat_pool(int argc, char **argv)
{
    /* Format: ip nat pool <name> <start-ip> <end-ip> netmask <mask> */
    if (argc < 7) {
        printf("Usage: ip nat pool <name> <start-ip> <end-ip> netmask <mask>\n");
        return -1;
    }

    const char *name = argv[3];
    struct in_addr start_addr, end_addr, netmask_addr;

    if (inet_pton(AF_INET, argv[4], &start_addr) != 1) {
        printf("Invalid start IP address\n");
        return -1;
    }

    if (inet_pton(AF_INET, argv[5], &end_addr) != 1) {
        printf("Invalid end IP address\n");
        return -1;
    }

    if (strcmp(argv[6], "netmask") == 0 && argc >= 8) {
        if (inet_pton(AF_INET, argv[7], &netmask_addr) != 1) {
            printf("Invalid netmask\n");
            return -1;
        }
    } else {
        printf("Missing netmask\n");
        return -1;
    }

    uint32_t start_ip = ntohl(start_addr.s_addr);
    uint32_t end_ip = ntohl(end_addr.s_addr);
    uint32_t netmask = ntohl(netmask_addr.s_addr);

    if (nat_pool_create(name, start_ip, end_ip, netmask) == 0) {
        printf("NAT pool '%s' created successfully\n", name);
    } else {
        printf("Failed to create NAT pool\n");
        return -1;
    }

    return 0;
}

/* Command: ip nat inside source */
int cmd_ip_nat_inside_source(int argc, char **argv)
{
    /*
     * Supported formats:
     * 1. ip nat inside source list <acl> pool <pool> [overload]
     * 2. ip nat inside source list <acl> interface <intf> [overload] (Masquerade)
     * 3. ip nat inside source static <local-ip> <global-ip>
     */

    if (argc < 6) {
        printf("Usage:\n");
        printf("  ip nat inside source list <acl> pool <pool> [overload]\n");
        return -1;
    }

    if (strcmp(argv[4], "list") == 0) {
        /* Dynamic NAT / PAT */
        /* argv[5] is ACL name - ignored for now as we match all subscribers */

        if (argc >= 8 && strcmp(argv[6], "pool") == 0) {
            /* Pool based NAT */
            const char *pool_name = argv[7];
            bool overload = (argc >= 9 && strcmp(argv[8], "overload") == 0);

            /* Check/Create ACL */
            const char *acl_name = argv[5];
            if (acl_find(acl_name) < 0) {
                /* Auto-create ACL if it doesn't exist (simulating "access-list standard") */
                /* For simplicity, we assume "LAN" means permit everything private, but here we just
                 * create it */
                acl_create(acl_name);
                /* Add default permit entry - effectively "permit any" for now to match behavior */
                /* Traffic filtering should be done by explicit ACL commands if needed */
                acl_add_entry(acl_name, ACL_PERMIT, 0, 0, 0, 0, 0, 0, 0, 0, 0);
                printf("%% ACL '%s' did not exist, auto-created (permit any)\n", acl_name);
            }

            /* Create NAT Rule */
            if (g_nat_config.num_rules < NAT_MAX_RULES) {
                struct nat_rule *rule = &g_nat_config.rules[g_nat_config.num_rules];
                strncpy(rule->acl_name, acl_name, 31);
                strncpy(rule->pool_name, pool_name, 31);
                rule->active = true;
                rule->priority = g_nat_config.num_rules; /* Order of configuration */
                g_nat_config.num_rules++;

                printf("NAT Rule Added: List '%s' -> Pool '%s' (Overload: %s)\n", acl_name,
                       pool_name, overload ? "Yes" : "No");
            } else {
                printf("Error: Max NAT rules reached\n");
                return -1;
            }

            /* Enable NAT globally when a rule is configured */
            nat_enable(true);

        } else if (argc >= 8 && strcmp(argv[6], "interface") == 0) {
            /* Interface based NAT (Masquerade) */
            /* ip nat inside source list <acl> interface <intf> [overload] */
            const char *ifname = argv[7];
            struct interface *iface = interface_find_by_name(ifname);

            if (!iface) {
                printf("Error: Interface %s not found\n", ifname);
                return -1;
            }

            if (iface->config.ipv4_addr.s_addr == 0) {
                printf("Error: Interface %s has no IP address\n", ifname);
                return -1;
            }

            /* Create a hidden pool with the interface IP */
            char pool_name[64];
            snprintf(pool_name, sizeof(pool_name), "_masq_%s", iface->name);

            /* Check if pool already exists (delete if it does to update IP) */
            nat_pool_delete(pool_name);

            uint32_t ip = ntohl(iface->config.ipv4_addr.s_addr);

            /* Create single-IP pool */
            if (nat_pool_create(pool_name, ip, ip, 0xFFFFFFFF) == 0) {
                bool overload = (argc >= 9 && strcmp(argv[8], "overload") == 0);
                const char *acl_name = argv[5]; /* ACL name from command */

                /* Create NAT Rule for this masquerade */
                if (g_nat_config.num_rules < NAT_MAX_RULES) {
                    struct nat_rule *rule = &g_nat_config.rules[g_nat_config.num_rules];
                    strncpy(rule->acl_name, acl_name, 31);
                    strncpy(rule->pool_name, pool_name, 63);
                    rule->active = true;
                    rule->priority = g_nat_config.num_rules;
                    g_nat_config.num_rules++;
                }

                printf("NAT configured: Masquerade on %s (%u.%u.%u.%u)\n", iface->name,
                       (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
                printf("  Created internal pool: %s\n", pool_name);
                printf("  Overload: %s\n", overload ? "Yes" : "No");

                /* Enable NAT globally */
                nat_enable(true);
            } else {
                printf("Error: Failed to create masquerade pool\n");
                return -1;
            }
        }
    } else if (strcmp(argv[4], "static") == 0) {
        /* Static NAT / Port Forwarding */
        /* Format: ip nat inside source static <proto> <inside-ip> <inside-port> interface <intf>
         * <global-port> */

        if (argc < 10) {
            printf("Usage: ip nat inside source static <proto> <inside-ip> <inside-port> interface "
                   "<intf> <global-port>\n");
            return -1;
        }

        const char *proto_str = argv[5];
        const char *inside_ip_str = argv[6];
        uint16_t inside_port = atoi(argv[7]);
        const char *ifname = argv[9];
        uint16_t outside_port = atoi(argv[10]);

        uint8_t protocol;
        if (strcasecmp(proto_str, "tcp") == 0)
            protocol = IPPROTO_TCP;
        else if (strcasecmp(proto_str, "udp") == 0)
            protocol = IPPROTO_UDP;
        else if (strcasecmp(proto_str, "icmp") == 0)
            protocol = IPPROTO_ICMP;
        else {
            printf("Error: Unsupported protocol %s\n", proto_str);
            return -1;
        }

        struct interface *iface = interface_find_by_name(ifname);
        if (!iface || iface->config.ipv4_addr.s_addr == 0) {
            printf("Error: Interface %s not found or has no IP\n", ifname);
            return -1;
        }

        uint32_t inside_ip;
        if (inet_pton(AF_INET, inside_ip_str, &inside_ip) != 1) {
            printf("Error: Invalid inside IP\n");
            return -1;
        }
        inside_ip = ntohl(inside_ip);
        uint32_t outside_ip = ntohl(iface->config.ipv4_addr.s_addr);

        /* Create permanent session */
        struct nat_session *session =
            nat_session_create(inside_ip, inside_port, outside_ip, outside_port, protocol);
        if (session) {
            session->is_static = 1;
            /* Set a very long timeout just in case, though is_static check handles expiration */
            session->timeout = 0xFFFFFFFF;

            printf("Static NAT rule created:\n");
            printf("  %s %s:%u <-> %s(%s):%u\n", proto_str, inside_ip_str, inside_port, ifname,
                   inet_ntoa(iface->config.ipv4_addr), outside_port);

            nat_enable(true);
        } else {
            printf("Error: Failed to create static NAT rule (Port likely in use)\n");
            return -1;
        }
    }

    return 0;
}

/* Command: show ip nat */
int cmd_show_ip_nat(int argc, char **argv)
{
    /* show ip nat statistics */
    /* show ip nat translations */
    if (argc < 4) {
        return -1;
    }

    if (strcmp(argv[3], "statistics") == 0) {
        nat_print_config();
    } else if (strcmp(argv[3], "translations") == 0) {
        nat_print_sessions();
    }

    return 0;
}

/* Command: clear ip nat translation */
int cmd_clear_ip_nat_translation(int argc, char **argv)
{
    /* Usage: clear ip nat translation * */
    if (argc < 5) {
        printf("Usage: clear ip nat translation *\n");
        return -1;
    }

    if (strcmp(argv[4], "*") == 0) {
        nat_clear_sessions();
        printf("NAT translations cleared\n");
    } else {
        printf("Selective clear not implemented, use *\n");
        return -1;
    }

    return 0;
}

/* Dispatcher: ip nat ... */
int cmd_ip_nat(int argc, char **argv)
{
    /* Expected: ip nat <subcommand> ... */
    /* argv[0]="ip", argv[1]="nat", argv[2]="subcommand" */

    if (argc < 3) {
        printf("Usage: ip nat <pool|inside>\n");
        return -1;
    }

    if (strcmp(argv[2], "pool") == 0) {
        return cmd_ip_nat_pool(argc, argv);
    } else if (strcmp(argv[2], "inside") == 0) {
        return cmd_ip_nat_inside_source(argc, argv);
    } else {
        printf("%% Unknown command: ip nat %s\n", argv[2]);
        return -1;
    }
}

/* Register NAT commands */
void cli_register_nat_commands(void)
{
    /* We don't register "ip nat" here because "ip" is a top-level command handled in cli.c */
    /* But we register show commands */
    cli_register_command("show ip nat statistics", "Display NAT statistics", cmd_show_ip_nat);
    cli_register_command("show ip nat translations", "Display NAT translations", cmd_show_ip_nat);

    /* Cisco style clear */
    cli_register_command("clear ip nat translation", "Clear NAT translations",
                         cmd_clear_ip_nat_translation);

    printf("Cisco-style NAT commands registered\n");
}
