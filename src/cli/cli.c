/**
 * @file cli.c
 * @brief YESRouter CLI Core Engine (Cisco-style)
 */

#include "cli.h"
#include "interface.h"
#include "log.h"
#include "routing_table.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_READLINE
#include <readline/history.h>
#include <readline/readline.h>
#endif

#define MAX_COMMANDS 64
#define MAX_ARGS 32
#define MAX_LINE 1024

/* CLI modes (Cisco-style) */
typedef enum {
    CLI_MODE_EXEC,      /* User EXEC mode */
    CLI_MODE_PRIV_EXEC, /* Privileged EXEC mode (Always active now) */
    CLI_MODE_CONFIG,    /* Global configuration mode */
    CLI_MODE_CONFIG_IF, /* Interface configuration mode */
} cli_mode_t;

static struct cli_command commands[MAX_COMMANDS];
static int num_commands = 0;

/* Exported for tab completion from socket handler */
const char *cli_commands[MAX_COMMANDS];
int cli_command_count = 0;

/* Forward declarations */
void show_context_help(const char *partial);
void cli_register_pppoe_commands(void);
void cli_register_ha_commands(void);

/* Command handlers */
static int cmd_hostname(int argc, char **argv);
static int cmd_exit(int argc, char **argv);
static int cmd_end(int argc, char **argv);

#ifdef HAVE_READLINE
/* Immediate help display when ? is typed */
static int show_help_on_question_mark(int count, int key)
{
    (void)count;
    (void)key;

    /* Get current line buffer */
    char *line = rl_line_buffer;
    int len = rl_point;

    /* Create prefix from typed text */
    char prefix[256];
    if (len > 255)
        len = 255;
    strncpy(prefix, line, len);
    prefix[len] = '\0';

    /* Trim trailing spaces */
    while (len > 0 && prefix[len - 1] == ' ') {
        prefix[--len] = '\0';
    }

    /* Show matching commands */
    printf("\n");
    show_context_help(prefix[0] != '\0' ? prefix : NULL);

    /* Redisplay the prompt and line */
    rl_on_new_line();
    rl_redisplay();

    return 0;
}

/* Command generator for readline - matches against full line */
static char *command_generator(const char *text, int state)
{
    static int list_index;
    static size_t text_len;

    /* Initialization on first call */
    if (!state) {
        list_index = 0;
        text_len = strlen(text);
    }

    /* Return next matching command */
    while (list_index < num_commands) {
        const char *name = commands[list_index].name;
        list_index++;

        if (strncmp(name, text, text_len) == 0) {
            return strdup(name);
        }
    }

    return NULL;
}

/* Custom completion function */
static char **command_completion(const char *text, int start, int end)
{
    (void)text;
    (void)start; /* Unused */
    (void)end;

    char **matches = NULL;

    /* Disable default filename completion */
    rl_attempted_completion_over = 1;

    /* For commands, we want to match against the entire line, not just current word */
    /* Use rl_line_buffer which contains everything user has typed */
    matches = rl_completion_matches(rl_line_buffer, command_generator);

    return matches;
}
#endif

/* Thread-local state for multi-user support */
static __thread cli_mode_t current_mode = CLI_MODE_PRIV_EXEC; /* Default to privileged */
static char hostname[64] = "yesrouter";

/* Forward declarations */
static int parse_args(char *line, char **argv, int max_args);

/**
 * Register a command
 */
int cli_register_command(const char *name, const char *help, cli_cmd_handler_t handler)
{
    if (num_commands >= MAX_COMMANDS) {
        return -1;
    }

    commands[num_commands].name = name;
    commands[num_commands].help = help;
    commands[num_commands].handler = handler;

    /* Also add to exported array for tab completion */
    cli_commands[num_commands] = name;
    cli_command_count = num_commands + 1;

    num_commands++;

    return 0;
}

/* Command: show (Main dispatcher) */
int cmd_show(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: show <interfaces|ip route|arp|running-config|version>\n");
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
            if (!iface)
                continue;

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
    } else if (strcmp(argv[1], "nat") == 0) {
        /* Dispatch to NAT show commands */
        extern int cmd_show_nat(int argc, char **argv);
        return cmd_show_nat(argc, argv);
    } else {
        printf("%% Unknown show command: %s\n", argv[1]);
        return -1;
    }
}

/* Command: configure terminal */
static int cmd_configure(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "terminal") == 0) {
        current_mode = CLI_MODE_CONFIG;
        printf("Enter configuration commands, one per line.  End with CNTL/Z.\n");
        return 0;
    }
    printf("Usage: configure terminal\n");
    return -1;
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
        return 1; /* Exit CLI */
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

/* Context-sensitive help - show matching commands */
void show_context_help(const char *partial)
{
    int matches = 0;
    int partial_len = partial ? strlen(partial) : 0;

    printf("\n");

    for (int i = 0; i < num_commands; i++) {
        if (!partial || partial_len == 0 || strncmp(commands[i].name, partial, partial_len) == 0) {
            printf("  %-25s - %s\n", commands[i].name, commands[i].help);
            matches++;
        }
    }

    if (matches == 0) {
        printf("  %% No matching commands found\n");
    }
    printf("\n");
}

/* Command: help */
int cmd_help(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("\nAvailable commands in current mode:\n");
    printf("================================================================================\n");

    /* List all registered commands */
    for (int i = 0; i < num_commands; i++) {
        printf("  %-25s - %s\n", commands[i].name, commands[i].help);
    }

    printf("================================================================================\n");
    printf("\nTip: Type '?' after a command for context-sensitive help\n");
    printf("     Type 'help' or '?' for full command list\n\n");
    return 0;
}

/* Parse command line */
static int parse_args(char *line, char **argv, int max_args)
{
    int argc = 0;
    char *p = line;
    bool in_quotes = false;

    while (*p && argc < max_args) {
        while (*p && isspace(*p))
            p++;
        if (!*p)
            break;

        if (*p == '"') {
            in_quotes = true;
            p++;
        }

        argv[argc++] = p;

        if (in_quotes) {
            while (*p && *p != '"')
                p++;
            if (*p)
                *p++ = '\0';
            in_quotes = false;
        } else {
            while (*p && !isspace(*p))
                p++;
            if (*p)
                *p++ = '\0';
        }
    }

    return argc;
}

/* Execute a registered command */
static int cli_execute_registered(int argc, char *argv[])
{
    /* Check if user is authenticated (except for enable/disable) */
    if (strcmp(argv[0], "enable") != 0 && strcmp(argv[0], "disable") != 0) {
        /* Authentication check removed */
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

int cli_execute(const char *cmdline)
{
    char line_copy[MAX_LINE];
    char *argv[MAX_ARGS];
    int argc;

    if (!cmdline || cmdline[0] == '\0')
        return 0;

    snprintf(line_copy, sizeof(line_copy), "%s", cmdline);
    argc = parse_args(line_copy, argv, MAX_ARGS);
    if (argc == 0)
        return 0;

    printf("DEBUG: cli_execute cmd='%s' mode=%d\n", argv[0], current_mode);

    /* Handle exit/end in any config mode */
    if (current_mode == CLI_MODE_CONFIG || current_mode == CLI_MODE_CONFIG_IF) {
        if (strcmp(argv[0], "exit") == 0) {
            return cmd_exit(argc, argv);
        }
        if (strcmp(argv[0], "end") == 0) {
            return cmd_end(argc, argv);
        }
    }

    /* Interface config mode commands */
    if (current_mode == CLI_MODE_CONFIG_IF) {
        if (strcmp(argv[0], "ip") == 0 && argc >= 3 && strcmp(argv[1], "address") == 0) {
            return cli_cmd_if_ip_address(argc, argv);
        }
        if (strcmp(argv[0], "no") == 0 && argc >= 2 && strcmp(argv[1], "shutdown") == 0) {
            return cli_cmd_if_no_shutdown();
        }
        if (strcmp(argv[0], "shutdown") == 0) {
            return cli_cmd_if_shutdown();
        }
    }

    /* Global config mode commands */
    if (current_mode == CLI_MODE_CONFIG) {
        if (strcmp(argv[0], "interface") == 0 && argc >= 2) {
            if (cli_cmd_config_interface(argc, argv) == 0) {
                current_mode = CLI_MODE_CONFIG_IF;
                return 0;
            }
            return -1;
        }
        if (strcmp(argv[0], "ip") == 0 && argc >= 5 && strcmp(argv[1], "route") == 0) {
            /* ip route <network> <mask> <gateway> */
            struct in_addr network, mask, gateway;
            if (inet_pton(AF_INET, argv[2], &network) == 1 &&
                inet_pton(AF_INET, argv[3], &mask) == 1 &&
                inet_pton(AF_INET, argv[4], &gateway) == 1) {
                uint32_t m = ntohl(mask.s_addr);
                int prefix_len = 0;
                while (m & 0x80000000) {
                    prefix_len++;
                    m <<= 1;
                }
                if (routing_table_add(routing_table_get_instance(), &network, prefix_len, &gateway,
                                      1, 1, ROUTE_SOURCE_STATIC, "static") == 0) {
                    printf("%% Route added\n");
                    return 0;
                } else {
                    printf("%% Failed to add route\n");
                    return -1;
                }
            }
            return -1;
        }
        if (strcmp(argv[0], "hostname") == 0 && argc >= 2) {
            return cmd_hostname(argc, argv);
        }
        /* NAT commands in config mode */
        if (strcmp(argv[0], "nat") == 0) {
            extern int cmd_nat_pool(int argc, char **argv);
            extern int cmd_nat_enable(int argc, char **argv);
            extern int cmd_nat_disable(int argc, char **argv);

            if (argc >= 2 && strcmp(argv[1], "pool") == 0) {
                return cmd_nat_pool(argc, argv);
            } else if (argc >= 2 && strcmp(argv[1], "enable") == 0) {
                return cmd_nat_enable(argc, argv);
            } else if (argc >= 2 && strcmp(argv[1], "disable") == 0) {
                return cmd_nat_disable(argc, argv);
            } else {
                printf("Usage: nat {pool|enable|disable}\n");
                return -1;
            }
        }
    }

    /* NAT commands also available in EXEC mode */
    if (strcmp(argv[0], "nat") == 0) {
        extern int cmd_nat_pool(int argc, char **argv);
        extern int cmd_nat_enable(int argc, char **argv);
        extern int cmd_nat_disable(int argc, char **argv);

        if (argc >= 2 && strcmp(argv[1], "pool") == 0) {
            return cmd_nat_pool(argc, argv);
        } else if (argc >= 2 && strcmp(argv[1], "enable") == 0) {
            return cmd_nat_enable(argc, argv);
        } else if (argc >= 2 && strcmp(argv[1], "disable") == 0) {
            return cmd_nat_disable(argc, argv);
        } else {
            printf("Usage: nat {pool|enable|disable}\n");
            return -1;
        }
    }

    return cli_execute_registered(argc, argv);
}

/**
 * Execute CLI commands from a file
 */
int cli_execute_file(const char *filename)
{
    FILE *fp;
    char line[MAX_LINE];
    int line_num = 0;
    int errors = 0;

    if (!filename) {
        YLOG_ERROR("CLI exec file: NULL filename");
        return -1;
    }

    fp = fopen(filename, "r");
    if (!fp) {
        YLOG_ERROR("CLI exec file: Failed to open '%s'", filename);
        return -1;
    }

    YLOG_INFO("Executing CLI commands from: %s", filename);
    printf("Executing startup commands from %s...\n", filename);

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        /* Remove newline */
        line[strcspn(line, "\r\n")] = '\0';

        /* Trim leading whitespace */
        char *p = line;
        while (*p && isspace(*p))
            p++;

        /* Skip empty lines and comments */
        if (*p == '\0' || *p == '#' || *p == '!') {
            continue;
        }

        /* Execute command */
        printf("  [%d] %s\n", line_num, p);
        int ret = cli_execute(p);
        if (ret < 0) {
            YLOG_WARNING("CLI exec file: Error on line %d: %s", line_num, p);
            errors++;
        }
    }

    fclose(fp);

    if (errors > 0) {
        YLOG_WARNING("CLI exec file: Completed with %d errors", errors);
    } else {
        YLOG_INFO("CLI exec file: Completed successfully");
        printf("Startup commands executed successfully.\n");
    }

    return errors > 0 ? -1 : 0;
}

/* Cisco-style prompt (no username) */
#ifndef HAVE_READLINE
static void print_prompt(void)
{
    struct interface *cfg_if = cli_get_config_interface();

    switch (current_mode) {
    case CLI_MODE_EXEC:
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
#endif

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
#ifdef HAVE_READLINE
    char *line = NULL;
#else
    char line[MAX_LINE];
#endif

    printf("\nyesrouter vBNG\nCopyright (c) 2025\n\n");

#ifdef HAVE_READLINE
    /* Enable tab completion and history */
    using_history();
    rl_attempted_completion_function = command_completion;

    /* CRITICAL: For multi-word commands like "show interfaces", we need to
     * treat the ENTIRE LINE as one word, not break on spaces.
     * Set word break characters to empty string (don't break on anything) */
    rl_completer_word_break_characters = "";

    /* Bind ? to show immediate help (Cisco-style) */
    rl_bind_key('?', show_help_on_question_mark);
#endif

    while (1) {
#ifdef HAVE_READLINE
        /* Build prompt string */
        char prompt[128];
        struct interface *cfg_if = cli_get_config_interface();

        switch (current_mode) {
        case CLI_MODE_EXEC:
        case CLI_MODE_PRIV_EXEC:
            snprintf(prompt, sizeof(prompt), "%s# ", hostname);
            break;
        case CLI_MODE_CONFIG:
            snprintf(prompt, sizeof(prompt), "%s(config)# ", hostname);
            break;
        case CLI_MODE_CONFIG_IF:
            if (cfg_if) {
                snprintf(prompt, sizeof(prompt), "%s(config-if-%s)# ", hostname, cfg_if->name);
            } else {
                snprintf(prompt, sizeof(prompt), "%s(config-if)# ", hostname);
            }
            break;
        }

        /* Read line with readline (provides tab completion & history) */
        line = readline(prompt);

        if (!line)
            break; /* EOF */

        /* Skip empty lines */
        if (line[0] == '\0' || line[0] == '!') {
            free(line);
            continue;
        }

        /* Add to history if non-empty */
        if (line[0] != '\0') {
            add_history(line);
        }

        /* Handle context-sensitive help */
        char *question = strchr(line, '?');
        if (question) {
            *question = '\0'; /* Terminate string at ? */

            /* Trim trailing whitespace before ? */
            char *p = question - 1;
            while (p >= line && (*p == ' ' || *p == '\t')) {
                *p = '\0';
                p--;
            }

            /* Show matching commands */
            show_context_help(line[0] != '\0' ? line : NULL);
            free(line);
            continue;
        }

        /* Handle plain ? for full help */
        if (strcmp(line, "?") == 0) {
            cmd_help(0, NULL);
            free(line);
            continue;
        }
#else
        print_prompt();
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin))
            break;

        line[strcspn(line, "\n")] = '\0';

        if (line[0] == '\0' || line[0] == '!')
            continue;

        /* Handle context-sensitive help */
        char *question = strchr(line, '?');
        if (question) {
            *question = '\0'; /* Terminate string at ? */

            /* Trim trailing whitespace before ? */
            char *p = question - 1;
            while (p >= line && (*p == ' ' || *p == '\t')) {
                *p = '\0';
                p--;
            }

            /* Show matching commands */
            show_context_help(line[0] != '\0' ? line : NULL);
            continue;
        }

        if (strcmp(line, "?") == 0) {
            cmd_help(0, NULL);
            continue;
        }
#endif

        /* Execute command */
#ifdef HAVE_READLINE
        int ret = cli_execute(line);
        free(line); /* Free readline-allocated memory */
        if (ret == 1)
            break;
#else
        int ret = cli_execute(line);
        if (ret == 1)
            break;
#endif
    }

    return 0;
}

/* Initialize CLI */
int cli_init(void)
{
    /* Register built-in commands */
    cli_register_command("show", "Display information", cmd_show);
    cli_register_command("configure", "Enter configuration mode", cmd_configure);
    /* cli_register_command("enable", "Turn on privileged commands", cmd_enable); */
    /* cli_register_command("disable", "Turn off privileged commands", cmd_disable); */
    cli_register_command("hostname", "Set system hostname", cmd_hostname);
    cli_register_command("exit", "Exit current mode", cmd_exit);
    cli_register_command("end", "Return to exec mode", cmd_end);
    cli_register_command("help", "Show help", cmd_help);

    /* Register show system commands for tab completion */
    cli_register_command("show running-config", "Display running configuration", cmd_show);
    cli_register_command("show version", "Display version information", cmd_show);

    /* Register module commands */
    cli_register_interface_commands();
    cli_register_route_commands();
    cli_register_arp_commands();
    cli_register_system_commands();
    /* cli_register_auth_commands(); */
    cli_vlan_register_commands();
    cli_register_config_commands();
    cli_register_debug_commands();
    cli_register_nat_commands();
    cli_register_pppoe_commands();
    cli_register_ha_commands();

    YLOG_INFO("CLI initialized with %d commands", num_commands);
    return 0;
}

/* Cleanup CLI */
void cli_cleanup(void)
{
    num_commands = 0;
    YLOG_INFO("CLI cleanup complete");
}
