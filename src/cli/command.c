/**
 * @file command.c
 * @brief Command Registration and Dispatch (Cisco IOS / FRR Style)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "command.h"
#include "vty.h"

/* Command nodes */
static struct cmd_node *cmd_nodes[NODE_TYPE_MAX] = {0};

/* Default node structures */
static struct cmd_node view_node = {
    .node = VIEW_NODE,
    .prompt = "%s> "
};

static struct cmd_node enable_node = {
    .node = ENABLE_NODE,
    .prompt = "%s# "
};

static struct cmd_node config_node = {
    .node = CONFIG_NODE,
    .prompt = "%s(config)# "
};

static struct cmd_node interface_node = {
    .node = INTERFACE_NODE,
    .prompt = "%s(config-if)# "
};

static struct cmd_node pppoe_node = {
    .node = PPPOE_NODE,
    .prompt = "%s(config-pppoe)# "
};

/**
 * Parse command line into argv
 */
int cmd_parse_line(const char *line, char *argv[], int max_argc)
{
    static char buf[VTY_BUFSIZ];
    int argc = 0;
    char *p;
    int in_quote = 0;

    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    p = buf;
    while (*p && argc < max_argc) {
        /* Skip whitespace */
        while (*p && isspace(*p))
            p++;

        if (!*p)
            break;

        /* Handle quotes */
        if (*p == '"') {
            in_quote = 1;
            p++;
            argv[argc++] = p;
            while (*p && *p != '"')
                p++;
            if (*p)
                *p++ = '\0';
        } else {
            argv[argc++] = p;
            while (*p && !isspace(*p))
                p++;
            if (*p)
                *p++ = '\0';
        }
    }

    return argc;
}

/**
 * Match command string against input
 * Returns: 0 = no match, 1 = partial match, 2 = exact match
 */
static int cmd_match_word(const char *cmd_word, const char *input)
{
    size_t input_len = strlen(input);
    size_t cmd_len = strlen(cmd_word);

    if (input_len == 0)
        return 0;

    /* Check for variable tokens */
    if (cmd_word[0] == '<' || cmd_word[0] == '[') {
        /* Variable - accept any input */
        return 2;
    }

    /* Check for WORD/LINE tokens */
    if (strcmp(cmd_word, "WORD") == 0 || strcmp(cmd_word, "LINE") == 0) {
        return 2;
    }

    /* Check for A.B.C.D (IPv4) */
    if (strcmp(cmd_word, "A.B.C.D") == 0) {
        /* Simple IPv4 validation */
        int a, b, c, d;
        if (sscanf(input, "%d.%d.%d.%d", &a, &b, &c, &d) == 4)
            return 2;
        return 0;
    }

    /* Exact or prefix match for keywords */
    if (strncasecmp(cmd_word, input, input_len) == 0) {
        return (input_len == cmd_len) ? 2 : 1;
    }

    return 0;
}

/**
 * Find matching command
 */
static struct cmd_element *cmd_find_match(struct cmd_node *node, int argc,
                                          const char *argv[], int *match_argc)
{
    struct cmd_element *best_match = NULL;
    int best_match_count = 0;

    if (!node || !node->cmds)
        return NULL;

    for (int i = 0; i < node->cmd_count; i++) {
        struct cmd_element *cmd = node->cmds[i];
        char *cmd_argv[CMD_MAX_ARGC];
        int cmd_argc;

        /* Parse command string */
        cmd_argc = cmd_parse_line(cmd->string, cmd_argv, CMD_MAX_ARGC);

        /* Try to match */
        int matched = 0;
        int j;
        for (j = 0; j < argc && j < cmd_argc; j++) {
            int m = cmd_match_word(cmd_argv[j], argv[j]);
            if (m == 0)
                break;
            matched++;
        }

        /* Check if this is a better match */
        if (matched > best_match_count) {
            /* Must match all input tokens */
            if (matched == argc) {
                best_match = cmd;
                best_match_count = matched;
                *match_argc = matched;
            }
        }
    }

    return best_match;
}

/**
 * Execute command
 */
int cmd_execute(struct vty *vty, const char *line)
{
    char *argv[CMD_MAX_ARGC];
    int argc;
    struct cmd_element *cmd;
    int match_argc = 0;

    /* Skip empty lines and comments */
    if (!line || !*line)
        return CMD_SUCCESS;

    while (*line && isspace(*line))
        line++;

    if (*line == '!' || *line == '#')
        return CMD_SUCCESS;

    /* Parse line */
    argc = cmd_parse_line(line, argv, CMD_MAX_ARGC);
    if (argc == 0)
        return CMD_SUCCESS;

    /* Get current node */
    struct cmd_node *node = cmd_nodes[vty->node];
    if (!node)
        return CMD_ERR_NO_MATCH;

    /* Find matching command */
    cmd = cmd_find_match(node, argc, (const char **)argv, &match_argc);

    if (!cmd) {
        /* Try enable node if in view mode */
        if (vty->node == VIEW_NODE) {
            node = cmd_nodes[ENABLE_NODE];
            if (node)
                cmd = cmd_find_match(node, argc, (const char **)argv, &match_argc);
        }
    }

    if (!cmd)
        return CMD_ERR_NO_MATCH;

    /* Check privilege */
    if (cmd->privilege > vty->privilege)
        return CMD_ERR_PRIVILEGE;

    /* Execute */
    return cmd->func(vty, argc, (const char **)argv);
}

/**
 * Describe available commands (for ? help)
 */
void cmd_describe(struct vty *vty, const char *line)
{
    char *argv[CMD_MAX_ARGC];
    int argc;
    struct cmd_node *node;

    argc = cmd_parse_line(line, argv, CMD_MAX_ARGC);
    node = cmd_nodes[vty->node];

    if (!node || !node->cmds) {
        vty_out(vty, "%% No commands available\r\n");
        return;
    }

    vty_out(vty, "\r\n");

    for (int i = 0; i < node->cmd_count; i++) {
        struct cmd_element *cmd = node->cmds[i];
        char *cmd_argv[CMD_MAX_ARGC];
        int cmd_argc;

        if (cmd->hidden)
            continue;

        cmd_argc = cmd_parse_line(cmd->string, cmd_argv, CMD_MAX_ARGC);

        /* Check if command matches current input */
        int matched = 1;
        for (int j = 0; j < argc && j < cmd_argc; j++) {
            if (cmd_match_word(cmd_argv[j], argv[j]) == 0) {
                matched = 0;
                break;
            }
        }

        if (matched) {
            /* Show next possible token */
            if (argc < cmd_argc) {
                vty_out(vty, "  %-20s %s\r\n", cmd_argv[argc],
                        cmd->doc ? cmd->doc : "");
            } else if (argc == cmd_argc) {
                vty_out(vty, "  <cr>\r\n");
            }
        }
    }
}

/**
 * Install a command node
 */
void install_node(struct cmd_node *node)
{
    if (node->node < NODE_TYPE_MAX) {
        cmd_nodes[node->node] = node;
    }
}

/**
 * Install a command element to a node
 */
void install_element(enum node_type ntype, struct cmd_element *cmd)
{
    struct cmd_node *node = cmd_nodes[ntype];

    if (!node)
        return;

    /* Grow array if needed */
    if (node->cmd_count >= node->cmd_alloc) {
        int new_alloc = node->cmd_alloc ? node->cmd_alloc * 2 : 32;
        struct cmd_element **new_cmds = realloc(node->cmds,
                                                 new_alloc * sizeof(struct cmd_element *));
        if (!new_cmds)
            return;
        node->cmds = new_cmds;
        node->cmd_alloc = new_alloc;
    }

    node->cmds[node->cmd_count++] = cmd;
}

/* ============================================================================
 * Built-in Commands
 * ============================================================================ */

/* enable - enter privileged mode */
DEFUN(cmd_enable,
      cmd_enable_cmd,
      "enable",
      "Turn on privileged mode\n")
{
    vty->node = ENABLE_NODE;
    vty->privilege = 15;
    return CMD_SUCCESS;
}

/* disable - return to view mode */
DEFUN(cmd_disable,
      cmd_disable_cmd,
      "disable",
      "Turn off privileged mode\n")
{
    vty->node = VIEW_NODE;
    vty->privilege = 1;
    return CMD_SUCCESS;
}

/* configure terminal - enter config mode */
DEFUN(cmd_config_terminal,
      cmd_config_terminal_cmd,
      "configure terminal",
      "Enter configuration mode\n"
      "Configure from the terminal\n")
{
    vty->node = CONFIG_NODE;
    return CMD_SUCCESS;
}

/* end - exit to enable mode */
DEFUN(cmd_end,
      cmd_end_cmd,
      "end",
      "End current mode and change to enable mode\n")
{
    if (vty->node != VIEW_NODE && vty->node != ENABLE_NODE) {
        vty->node = ENABLE_NODE;
    }
    return CMD_SUCCESS;
}

/* exit - exit current mode */
DEFUN(cmd_exit,
      cmd_exit_cmd,
      "exit",
      "Exit current mode and down to previous mode\n")
{
    switch (vty->node) {
    case VIEW_NODE:
    case ENABLE_NODE:
        vty->status = VTY_CLOSE;
        vty_out(vty, "Goodbye!\r\n");
        break;
    case CONFIG_NODE:
        vty->node = ENABLE_NODE;
        break;
    case INTERFACE_NODE:
    case PPPOE_NODE:
    case RADIUS_NODE:
    case IP_POOL_NODE:
        vty->node = CONFIG_NODE;
        vty->context[0] = '\0';
        break;
    default:
        vty->node = CONFIG_NODE;
        break;
    }
    return CMD_SUCCESS;
}

/* help */
DEFUN(cmd_help,
      cmd_help_cmd,
      "help",
      "Description of the interactive help system\n")
{
    vty_out(vty,
        "YESRouter CLI Help\r\n"
        "==================\r\n"
        "\r\n"
        "Use '?' to get context-sensitive help.\r\n"
        "Use <Tab> for command completion.\r\n"
        "\r\n"
        "Command Modes:\r\n"
        "  Router>          User EXEC mode (limited commands)\r\n"
        "  Router#          Privileged EXEC mode (all commands)\r\n"
        "  Router(config)#  Global configuration mode\r\n"
        "\r\n"
        "Navigation:\r\n"
        "  enable           Enter privileged mode\r\n"
        "  configure terminal  Enter configuration mode\r\n"
        "  exit             Exit current mode\r\n"
        "  end              Return to privileged mode\r\n"
        "\r\n");
    return CMD_SUCCESS;
}

/* show version */
DEFUN(cmd_show_version,
      cmd_show_version_cmd,
      "show version",
      SHOW_STR
      "System version information\n")
{
    vty_out(vty,
        "YESRouter vBNG Version 1.0.0\r\n"
        "Copyright (c) 2025 YESRouter Project\r\n"
        "\r\n"
        "Build: DPDK-based High Performance vBNG\r\n"
        "Features: PPPoE, IPoE, RADIUS, NAT, QoS\r\n"
        "\r\n");
    return CMD_SUCCESS;
}

/* show history */
DEFUN(cmd_show_history,
      cmd_show_history_cmd,
      "show history",
      SHOW_STR
      "Display command history\n")
{
    for (int i = 0; i < vty->hindex; i++) {
        if (vty->hist[i])
            vty_out(vty, "  %d  %s\r\n", i + 1, vty->hist[i]);
    }
    return CMD_SUCCESS;
}

/* hostname */
DEFUN(cmd_hostname,
      cmd_hostname_cmd,
      "hostname WORD",
      "Set system hostname\n"
      "Hostname string\n")
{
    if (argc > 1) {
        strncpy(g_hostname, argv[1], sizeof(g_hostname) - 1);
        g_hostname[sizeof(g_hostname) - 1] = '\0';
    }
    return CMD_SUCCESS;
}

/**
 * Install default commands for a node
 */
void install_default(enum node_type ntype)
{
    install_element(ntype, &cmd_exit_cmd);
    install_element(ntype, &cmd_help_cmd);

    if (ntype != VIEW_NODE) {
        install_element(ntype, &cmd_end_cmd);
    }
}

/**
 * Initialize command system
 */
void cmd_init(void)
{
    /* Install nodes */
    install_node(&view_node);
    install_node(&enable_node);
    install_node(&config_node);
    install_node(&interface_node);
    install_node(&pppoe_node);

    /* Install default commands */
    install_default(VIEW_NODE);
    install_default(ENABLE_NODE);
    install_default(CONFIG_NODE);
    install_default(INTERFACE_NODE);
    install_default(PPPOE_NODE);

    /* View mode commands */
    install_element(VIEW_NODE, &cmd_enable_cmd);
    install_element(VIEW_NODE, &cmd_show_version_cmd);
    install_element(VIEW_NODE, &cmd_show_history_cmd);

    /* Enable mode commands */
    install_element(ENABLE_NODE, &cmd_disable_cmd);
    install_element(ENABLE_NODE, &cmd_config_terminal_cmd);
    install_element(ENABLE_NODE, &cmd_show_version_cmd);
    install_element(ENABLE_NODE, &cmd_show_history_cmd);

    /* Config mode commands */
    install_element(CONFIG_NODE, &cmd_hostname_cmd);
}

/**
 * Terminate command system
 */
void cmd_terminate(void)
{
    for (int i = 0; i < NODE_TYPE_MAX; i++) {
        if (cmd_nodes[i]) {
            free(cmd_nodes[i]->cmds);
            cmd_nodes[i]->cmds = NULL;
            cmd_nodes[i]->cmd_count = 0;
            cmd_nodes[i]->cmd_alloc = 0;
        }
    }
}
