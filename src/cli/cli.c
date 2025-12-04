/**
 * @file cli.c
 * @brief YESRouter CLI Core Engine (Cisco-style)
 */

#include "cli.h"
#include "log.h"
#include "interface.h"
#include "routing_table.h"
#include "auth.h"
#include "authz.h"
#include "user_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <unistd.h>

static void system_no_ret(const char *command) {
    if (system(command) != 0) {
        /* The return value is intentionally ignored. */
    }
}

#define MAX_COMMANDS 64
#define MAX_ARGS 32
#define MAX_LINE 1024

/* CLI modes (Cisco-style) */
typedef enum {
    CLI_MODE_EXEC,           /* User EXEC mode */
    CLI_MODE_PRIV_EXEC,      /* Privileged EXEC mode */
    CLI_MODE_CONFIG,         /* Global configuration mode */
    CLI_MODE_CONFIG_IF,      /* Interface configuration mode */
} cli_mode_t;

static struct cli_command commands[MAX_COMMANDS];
static int num_commands = 0;
static cli_mode_t current_mode = CLI_MODE_EXEC;  /* Start in user EXEC mode */
static char hostname[64] = "yesrouter";
static bool privileged_mode = false;  /* Track if user used 'enable' */

/* Forward declarations */
static int parse_args(char *line, char **argv, int max_args);

/**
 * Register a command
 */
int cli_register_command(const char *name, const char *help,
                         cli_cmd_handler_t handler)
{
    if (num_commands >= MAX_COMMANDS) {
        return -1;
    }

    commands[num_commands].name = name;
    commands[num_commands].help = help;
    commands[num_commands].handler = handler;
    num_commands++;

    return 0;
}

/* Command: enable secret (config mode) */
static int cmd_config_enable_secret(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: enable secret <password>\n");
        return -1;
    }

    const char *password = argv[2];
    if (user_db_set_global_enable_password(password) == 0) {
        printf("%% Enable secret set\n");
        return 0;
    } else {
        printf("%% Failed to set enable secret\n");
        return -1;
    }
}

/* Command: show (Main dispatcher) */
int cmd_show(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: show <interfaces|ip route|arp|running-config|version|users|sessions>\n");
        return -1;
    }

    if (strcmp(argv[1], "interfaces") == 0) {
        if (argc >= 3 && strcmp(argv[2], "brief") == 0) {
            return cmd_show_interfaces_brief(argc, argv);
        }
        return cmd_show_interfaces(argc, argv);
    } else if (strcmp(argv[1], "ip") == 0 && argc >= 3 && strcmp(argv[2], "route") == 0) {
        return cmd_show_routes(argc, argv);
    } else if (strcmp(argv[1], "routes") == 0) {
        return cmd_show_routes(argc, argv);
    } else if (strcmp(argv[1], "arp") == 0) {
        return cmd_show_arp(argc, argv);
    } else if (strcmp(argv[1], "running-config") == 0) {
        /* Show running config */
        printf("!\n! yesrouter Running Configuration\n!\n");
        printf("hostname %s\n!\n", hostname);

        for (uint32_t i = 1; i <= interface_count(); i++) {
            struct interface *iface = interface_find_by_index(i);
            if (!iface) continue;

            printf("interface %s\n", iface->name);
            if (iface->config.ipv4_addr.s_addr) {
                char ip_buf[INET_ADDRSTRLEN], mask_buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &iface->config.ipv4_addr, ip_buf, sizeof(ip_buf));
                inet_ntop(AF_INET, &iface->config.ipv4_mask, mask_buf, sizeof(mask_buf));
                printf(" ip address %s %s\n", ip_buf, mask_buf);
            }
            printf(" %s\n!\n", iface->state == IF_STATE_UP ? "no shutdown" : "shutdown");
        }

        printf("!\nend\n");
        return 0;
    } else if (strcmp(argv[1], "version") == 0) {
        printf("yesrouter vBNG Software\nVersion 1.0.0\n");
        printf("Compiled: %s %s\n\n", __DATE__, __TIME__);
        printf("DPDK: %s\n",
#ifdef HAVE_DPDK
            "Enabled"
#else
            "Disabled"
#endif
        );
        return 0;
    } else if (strcmp(argv[1], "users") == 0) {
        return cmd_show_users(argc, argv);
    } else if (strcmp(argv[1], "user") == 0) {
        return cmd_show_user(argc, argv);
    } else if (strcmp(argv[1], "sessions") == 0) {
        return cmd_show_sessions(argc, argv);
    } else {
        printf("%% Unknown show command: %s\n", argv[1]);
        return -1;
    }
}

/* Command: configure terminal */
static int cmd_configure(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "terminal") == 0) {
        if (!privileged_mode) {
            printf("%% Privileged mode required. Use 'enable' command.\n");
            return -1;
        }
        current_mode = CLI_MODE_CONFIG;
        printf("Enter configuration commands, one per line.  End with CNTL/Z.\n");
        return 0;
    }
    printf("Usage: configure terminal\n");
    return -1;
}

/* Command: enable (Cisco-style) */
static int cmd_enable(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    struct user *user = auth_get_current_user();
    if (!user) {
        printf("%% Not authenticated\n");
        return -1;
    }

    /* Check if enable password is required */
    char enable_password[USER_MAX_PASS_LEN] = {0};

    /* Check if any enable password exists */
    if (user_db_verify_enable_password(user->username, "") == -1) {
        /* Enable password required */
        printf("Password: ");
        fflush(stdout);
        system_no_ret("stty -echo");
        if (!fgets(enable_password, sizeof(enable_password), stdin)) {
            system_no_ret("stty echo");
            printf("\n");
            return -1;
        }
        system_no_ret("stty echo");
        printf("\n");
        enable_password[strcspn(enable_password, "\n")] = '\0';

        if (user_db_verify_enable_password(user->username, enable_password) != 0) {
            printf("%% Bad secrets\n");
            return -1;
        }
    }

    /* Enter privileged mode */
    privileged_mode = true;
    current_mode = CLI_MODE_PRIV_EXEC;
    return 0;
}

/* Command: disable (Cisco-style) */
static int cmd_disable(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    privileged_mode = false;
    current_mode = CLI_MODE_EXEC;
    return 0;
}

/* Command: exit */
static int cmd_exit(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    switch (current_mode) {
    case CLI_MODE_CONFIG_IF:
        current_mode = CLI_MODE_CONFIG;
        cli_exit_interface_config();
        break;
    case CLI_MODE_CONFIG:
        current_mode = CLI_MODE_PRIV_EXEC;
        break;
    default:
        return 1;  /* Exit CLI */
    }
    return 0;
}

/* Command: end */
static int cmd_end(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    current_mode = CLI_MODE_PRIV_EXEC;
    cli_exit_interface_config();
    return 0;
}

/* Command: help */
int cmd_help(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("\nAvailable commands:\n");
    printf("  show interfaces [brief] - Display interface status\n");
    printf("  show ip route           - Display routing table\n");
    printf("  show arp                - Display ARP table\n");
    printf("  show running-config     - Display running configuration\n");
    printf("  show version            - Display version information\n");
    printf("  show users              - Display user list\n");
    printf("  show sessions           - Display active sessions\n\n");
    printf("  enable                  - Enter privileged EXEC mode\n");
    printf("  disable                 - Exit privileged EXEC mode\n");
    printf("  hostname <name>         - Set system hostname\n");
    printf("  configure terminal      - Enter configuration mode\n");
    printf("  interface <name>        - Configure interface (in config mode)\n");
    printf("  ip route <net> <mask> <gw> - Add static route (in config mode)\n");
    printf("  username <name> ...     - Manage users (in config mode)\n");
    printf("  enable secret <pass>    - Set enable password (in config mode)\n\n");
    printf("  ping <ip> [count]       - Send ICMP echo request\n");
    printf("  traceroute <ip>         - Trace route to destination\n");
    printf("  nslookup <hostname>     - DNS lookup\n");
    printf("  exit                    - Exit current mode\n");
    printf("  end                     - Return to privileged exec mode\n\n");
    return 0;
}

/* Parse command line */
static int parse_args(char *line, char **argv, int max_args)
{
    int argc = 0;
    char *p = line;
    bool in_quotes = false;

    while (*p && argc < max_args) {
        while (*p && isspace(*p)) p++;
        if (!*p) break;

        if (*p == '"') {
            in_quotes = true;
            p++;
        }

        argv[argc++] = p;

        if (in_quotes) {
            while (*p && *p != '"') p++;
            if (*p) *p++ = '\0';
            in_quotes = false;
        } else {
            while (*p && !isspace(*p)) p++;
            if (*p) *p++ = '\0';
        }
    }

    return argc;
}

/* Execute a command */
int cli_execute(const char *cmdline)
{
    char line[MAX_LINE];
    char *argv[MAX_ARGS];
    int argc;

    strncpy(line, cmdline, sizeof(line) - 1);
    line[sizeof(line) - 1] = '\0';

    argc = parse_args(line, argv, MAX_ARGS);
    if (argc == 0) return 0;

    /* Check if user is authenticated (except for enable/disable) */
    if (strcmp(argv[0], "enable") != 0 && strcmp(argv[0], "disable") != 0) {
        struct user *user = auth_get_current_user();
        if (!user) {
            printf("%% Not authenticated\n");
            return -1;
        }

        /* Check if command requires privileged mode */
        if (current_mode == CLI_MODE_PRIV_EXEC || current_mode == CLI_MODE_CONFIG ||
            current_mode == CLI_MODE_CONFIG_IF) {
            if (!privileged_mode) {
                printf("%% Privileged mode required. Use 'enable' command.\n");
                return -1;
            }
        }

        if (!authz_check_command(user, argv[0], argc, argv)) {
            printf("%% Permission denied: Insufficient privileges\n");
            return -1;
        }
    }

    /* Find and execute registered command */
    for (int i = 0; i < num_commands; i++) {
        if (strcmp(argv[0], commands[i].name) == 0) {
            return commands[i].handler(argc, argv);
        }
    }

    printf("%% Unknown command: %s\n", argv[0]);
    return -1;
}

/* Cisco-style prompt (no username) */
static void print_prompt(void)
{
    struct interface *cfg_if = cli_get_config_interface();

    switch (current_mode) {
    case CLI_MODE_EXEC:
        printf("%s>", hostname);
        break;
    case CLI_MODE_PRIV_EXEC:
        printf("%s#", hostname);
        break;
    case CLI_MODE_CONFIG:
        printf("%s(config)#", hostname);
        break;
    case CLI_MODE_CONFIG_IF:
        if (cfg_if) {
            printf("%s(config-if-%s)#", hostname, cfg_if->name);
        } else {
            printf("%s(config-if)#", hostname);
        }
        break;
    }
}

/* Command: hostname (set hostname) */
static int cmd_hostname(int argc, char **argv)
{
    if (argc < 2) {
        printf("Current hostname: %s\n", hostname);
        printf("Usage: hostname <name>\n");
        return -1;
    }

    if (strlen(argv[1]) >= sizeof(hostname)) {
        printf("%% Hostname too long (max %zu characters)\n", sizeof(hostname) - 1);
        return -1;
    }

    strncpy(hostname, argv[1], sizeof(hostname) - 1);
    hostname[sizeof(hostname) - 1] = '\0';
    printf("%% Hostname set to %s\n", hostname);
    return 0;
}

/* Interactive mode */
int cli_interactive(void)
{
    char line[MAX_LINE];

    printf("\nyesrouter vBNG\nCopyright (c) 2025\n\n");

    /* DEVELOPMENT MODE: Auto-login as admin */
    if (!auth_get_current_user()) {
        printf("Auto-logging in as admin (Development Mode)...\n");
        if (!auth_login("admin", "admin").success) {
            printf("Failed to auto-login as admin\n");
            return -1;
        }
    }

    while (1) {
        print_prompt();
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) break;

        line[strcspn(line, "\n")] = '\0';

        if (line[0] == '\0' || line[0] == '!') continue;

        if (strcmp(line, "?") == 0) {
            cmd_help(0, NULL);
            continue;
        }

        /* Parse for mode-specific handling */
        char line_copy[MAX_LINE];
        char *argv[MAX_ARGS];
        snprintf(line_copy, sizeof(line_copy), "%s", line);
        int argc = parse_args(line_copy, argv, MAX_ARGS);
        if (argc == 0) continue;

        /* Handle exit/end in any config mode */
        if (current_mode == CLI_MODE_CONFIG || current_mode == CLI_MODE_CONFIG_IF) {
            if (strcmp(argv[0], "exit") == 0) {
                if (cmd_exit(argc, argv) == 1) break;
                continue;
            }
            if (strcmp(argv[0], "end") == 0) {
                cmd_end(argc, argv);
                continue;
            }
        }

        /* Interface config mode commands */
        if (current_mode == CLI_MODE_CONFIG_IF) {
            if (strcmp(argv[0], "ip") == 0 && argc >= 3 && strcmp(argv[1], "address") == 0) {
                cli_cmd_if_ip_address(argc, argv);
                continue;
            }
            if (strcmp(argv[0], "no") == 0 && argc >= 2 && strcmp(argv[1], "shutdown") == 0) {
                cli_cmd_if_no_shutdown();
                continue;
            }
            if (strcmp(argv[0], "shutdown") == 0) {
                cli_cmd_if_shutdown();
                continue;
            }
        }

        /* Global config mode commands */
        if (current_mode == CLI_MODE_CONFIG) {
            if (strcmp(argv[0], "interface") == 0 && argc >= 2) {
                if (cli_cmd_config_interface(argc, argv) == 0) {
                    current_mode = CLI_MODE_CONFIG_IF;
                }
                continue;
            }
            if (strcmp(argv[0], "ip") == 0 && argc >= 5 && strcmp(argv[1], "route") == 0) {
                /* ip route <network> <mask> <gateway> */
                struct in_addr network, mask, gateway;
                if (inet_pton(AF_INET, argv[2], &network) == 1 &&
                    inet_pton(AF_INET, argv[3], &mask) == 1 &&
                    inet_pton(AF_INET, argv[4], &gateway) == 1) {
                    uint32_t m = ntohl(mask.s_addr);
                    int prefix_len = 0;
                    while (m & 0x80000000) { prefix_len++; m <<= 1; }
                    if (routing_table_add(routing_table_get_instance(), &network, prefix_len,
                                         &gateway, 1, 1, ROUTE_SOURCE_STATIC, "static") == 0) {
                        printf("%% Route added\n");
                    } else {
                        printf("%% Failed to add route\n");
                    }
                }
                continue;
            }
            if (strcmp(argv[0], "hostname") == 0 && argc >= 2) {
                cmd_hostname(argc, argv);
                continue;
            }
            if (strcmp(argv[0], "enable") == 0 && argc >= 3 && strcmp(argv[1], "secret") == 0) {
                cmd_config_enable_secret(argc, argv);
                continue;
            }
            if (strcmp(argv[0], "username") == 0) {
                cmd_username(argc, argv);
                continue;
            }
        }

        /* Execute registered commands */
        int ret = cli_execute(line);
        if (ret == 1) break;
    }

    return 0;
}

/* Initialize CLI */
int cli_init(void)
{
    cli_register_command("show", "Display information", cmd_show);
    cli_register_command("configure", "Enter configuration mode", cmd_configure);
    cli_register_command("enable", "Turn on privileged commands", cmd_enable);
    cli_register_command("disable", "Turn off privileged commands", cmd_disable);
    cli_register_command("hostname", "Set system hostname", cmd_hostname);
    cli_register_command("exit", "Exit current mode", cmd_exit);
    cli_register_command("end", "Return to exec mode", cmd_end);
    cli_register_command("help", "Show help", cmd_help);

    cli_register_interface_commands();
    cli_register_route_commands();
    cli_register_arp_commands();
    cli_register_system_commands();
    cli_register_auth_commands();

    YLOG_INFO("CLI initialized with %d commands", num_commands);
    return 0;
}

/* Cleanup CLI */
void cli_cleanup(void)
{
    num_commands = 0;
    YLOG_INFO("CLI cleanup complete");
}
