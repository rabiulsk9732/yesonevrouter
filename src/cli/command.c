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
 * Check if a command token is a keyword (not a variable like WORD, A.B.C.D, etc)
 */
static int is_keyword_token(const char *token)
{
    if (!token || !*token)
        return 0;
    /* Variable tokens: WORD, LINE, A.B.C.D, <range>, [optional] */
    if (strcmp(token, "WORD") == 0 || strcmp(token, "LINE") == 0)
        return 0;
    if (strcmp(token, "A.B.C.D") == 0 || strcmp(token, "A.B.C.D/M") == 0)
        return 0;
    if (token[0] == '<' || token[0] == '[')
        return 0;
    /* All uppercase words are usually variables */
    int all_upper = 1;
    for (const char *p = token; *p; p++) {
        if (*p >= 'a' && *p <= 'z') {
            all_upper = 0;
            break;
        }
    }
    if (all_upper && strlen(token) > 1)
        return 0;
    return 1;
}

/**
 * Find matching command
 * Priority: 1) Exact token count match, 2) More keyword matches, 3) More total matches
 */
static struct cmd_element *cmd_find_match(struct cmd_node *node, int argc,
                                          const char *argv[], int *match_argc)
{
    struct cmd_element *best_match = NULL;
    int best_match_count = 0;
    int best_keyword_count = 0;
    int best_exact = 0;

    if (!node || !node->cmds)
        return NULL;

    /* CRITICAL: Copy argv values to local storage because cmd_parse_line uses static buffer */
    char argv_copy[CMD_MAX_ARGC][128];
    for (int i = 0; i < argc && i < CMD_MAX_ARGC; i++) {
        strncpy(argv_copy[i], argv[i], 127);
        argv_copy[i][127] = '\0';
    }

    for (int i = 0; i < node->cmd_count; i++) {
        struct cmd_element *cmd = node->cmds[i];
        char *cmd_argv[CMD_MAX_ARGC];
        int cmd_argc;

        /* Parse command string */
        cmd_argc = cmd_parse_line(cmd->string, cmd_argv, CMD_MAX_ARGC);

        /* Try to match all input tokens against command tokens */
        int matched = 0;
        int keyword_matches = 0;
        for (int j = 0; j < argc && j < cmd_argc; j++) {
            int m = cmd_match_word(cmd_argv[j], argv_copy[j]);
            if (m == 0)
                break;
            matched++;
            /* Count keyword matches (non-variable matches) */
            if (is_keyword_token(cmd_argv[j])) {
                keyword_matches++;
            }
        }

        /* Must match all input tokens */
        if (matched != argc)
            continue;

        /* Check if command length matches (exact) or has more tokens (partial) */
        int is_exact = (argc == cmd_argc);

        /* Scoring: prefer exact > more keywords > more matches */
        int is_better = 0;
        if (best_match == NULL) {
            is_better = 1;
        } else if (is_exact && !best_exact) {
            is_better = 1;
        } else if (is_exact == best_exact) {
            /* Same exactness - prefer more keyword matches */
            if (keyword_matches > best_keyword_count) {
                is_better = 1;
            } else if (keyword_matches == best_keyword_count && matched > best_match_count) {
                is_better = 1;
            }
        }

        if (is_better) {
            best_match = cmd;
            best_match_count = matched;
            best_keyword_count = keyword_matches;
            best_exact = is_exact;
            *match_argc = matched;
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
 * Get the Nth help string from a multi-line doc string
 * Returns pointer to static buffer
 */
static const char *get_token_help(const char *doc, int token_idx)
{
    static char help_buf[256];
    const char *p = doc;
    int idx = 0;

    if (!doc)
        return "";

    /* Skip to the Nth line (each token's help is on a separate line) */
    while (p && *p && idx < token_idx) {
        p = strchr(p, '\n');
        if (p) p++;
        idx++;
    }

    if (!p || !*p)
        return "";

    /* Copy until newline or end */
    int i = 0;
    while (*p && *p != '\n' && i < (int)sizeof(help_buf) - 1) {
        help_buf[i++] = *p++;
    }
    help_buf[i] = '\0';

    return help_buf;
}

/**
 * Describe available commands (for ? help) - Cisco IOS style
 * 
 * Key behavior:
 * - "sho?" shows tokens that START WITH "sho" (i.e., "show")
 * - "show ?" shows tokens that come AFTER "show"
 */
void cmd_describe(struct vty *vty, const char *line)
{
    char *argv[CMD_MAX_ARGC];
    int argc;
    struct cmd_node *node;
    
    /* Track unique tokens */
    struct {
        char token[64];
        char help[128];
    } tokens[128];
    int token_count = 0;
    int has_cr = 0;

    argc = cmd_parse_line(line, argv, CMD_MAX_ARGC);
    node = cmd_nodes[vty->node];

    if (!node || !node->cmds) {
        vty_out(vty, "%% No commands available\r\n");
        return;
    }

    /* Determine if we're completing a partial word or starting a new one */
    int line_len = line ? strlen(line) : 0;
    int completing_new_word = (line_len == 0) || 
                              (line[line_len - 1] == ' ') || 
                              (line[line_len - 1] == '\t');
    
    char partial[128] = "";  /* Local buffer - cmd_parse_line uses static buffer! */
    int partial_len = 0;
    int match_argc = argc;  /* Number of COMPLETE tokens to match exactly */
    
    if (!completing_new_word && argc > 0) {
        /* Last word is partial - we want to show what matches it */
        /* CRITICAL: Copy to local buffer because cmd_parse_line uses static buffer */
        strncpy(partial, argv[argc - 1], sizeof(partial) - 1);
        partial[sizeof(partial) - 1] = '\0';
        partial_len = strlen(partial);
        match_argc = argc - 1;
    }
    

    /* Collect matching completions */
    for (int i = 0; i < node->cmd_count; i++) {
        struct cmd_element *cmd = node->cmds[i];
        char *cmd_argv[CMD_MAX_ARGC];
        int cmd_argc;

        if (cmd->hidden)
            continue;

        cmd_argc = cmd_parse_line(cmd->string, cmd_argv, CMD_MAX_ARGC);

        /* Check if all COMPLETE tokens match exactly */
        int matched = 1;
        for (int j = 0; j < match_argc && j < cmd_argc; j++) {
            int m = cmd_match_word(cmd_argv[j], argv[j]);
            if (m == 0) {
                matched = 0;
                break;
            }
        }

        if (!matched)
            continue;
        
        /* Need at least as many tokens */
        if (match_argc > cmd_argc)
            continue;

        /* Get the token at position match_argc */
        if (match_argc < cmd_argc) {
            const char *next_token = cmd_argv[match_argc];
            
            /* Check if it matches partial (prefix match) */
            if (partial_len == 0 || strncasecmp(next_token, partial, partial_len) == 0) {
                const char *help = get_token_help(cmd->doc, match_argc);

                /* Check if already seen */
                int found = 0;
                for (int k = 0; k < token_count; k++) {
                    if (strcasecmp(tokens[k].token, next_token) == 0) {
                        found = 1;
                        break;
                    }
                }

                if (!found && token_count < 128) {
                    strncpy(tokens[token_count].token, next_token, 63);
                    tokens[token_count].token[63] = '\0';
                    strncpy(tokens[token_count].help, help, 127);
                    tokens[token_count].help[127] = '\0';
                    token_count++;
                }
            }
        } else if (match_argc == cmd_argc && partial_len == 0) {
            /* Command is complete and no partial - can execute */
            has_cr = 1;
        }
    }

    /* Sort tokens alphabetically */
    for (int i = 0; i < token_count - 1; i++) {
        for (int j = i + 1; j < token_count; j++) {
            if (strcasecmp(tokens[i].token, tokens[j].token) > 0) {
                char tmp_tok[64], tmp_help[128];
                strcpy(tmp_tok, tokens[i].token);
                strcpy(tmp_help, tokens[i].help);
                strcpy(tokens[i].token, tokens[j].token);
                strcpy(tokens[i].help, tokens[j].help);
                strcpy(tokens[j].token, tmp_tok);
                strcpy(tokens[j].help, tmp_help);
            }
        }
    }

    /* Output */
    vty_out(vty, "\r\n");

    if (has_cr) {
        vty_out(vty, "  <cr>\r\n");
    }

    for (int i = 0; i < token_count; i++) {
        vty_out(vty, "  %-18s  %s\r\n", tokens[i].token, tokens[i].help);
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

/**
 * Complete command (for tab completion) - Cisco IOS style
 * Returns array of possible completions
 */
char **cmd_complete(struct vty *vty, const char *line, int *count)
{
    char *argv[CMD_MAX_ARGC];
    int argc;
    struct cmd_node *node;
    char **completions = NULL;
    int num_completions = 0;
    int alloc_size = 32;
    
    /* Parse the input line */
    char line_copy[1024];
    strncpy(line_copy, line ? line : "", sizeof(line_copy) - 1);
    line_copy[sizeof(line_copy) - 1] = '\0';
    
    argc = cmd_parse_line(line_copy, argv, CMD_MAX_ARGC);
    node = cmd_nodes[vty->node];

    if (!node || !node->cmds) {
        *count = 0;
        return NULL;
    }

    completions = malloc(alloc_size * sizeof(char *));
    if (!completions) {
        *count = 0;
        return NULL;
    }

    /* Determine if we're completing a partial word or starting a new one */
    char partial[128] = "";  /* Local buffer - cmd_parse_line uses static buffer! */
    int partial_len = 0;
    int match_argc = argc;  /* Number of complete tokens to match */
    
    /* Check if line ends with space (completing new word) */
    int line_len = line ? strlen(line) : 0;
    int completing_new_word = (line_len == 0) || 
                              (line[line_len - 1] == ' ') || 
                              (line[line_len - 1] == '\t');
    
    if (!completing_new_word && argc > 0) {
        /* User is typing a partial word - match it */
        strncpy(partial, argv[argc - 1], sizeof(partial) - 1);
        partial[sizeof(partial) - 1] = '\0';
        partial_len = strlen(partial);
        match_argc = argc - 1;  /* Don't match the partial as complete */
    }

    /* Collect matching completions */
    for (int i = 0; i < node->cmd_count; i++) {
        struct cmd_element *cmd = node->cmds[i];
        char *cmd_argv[CMD_MAX_ARGC];
        int cmd_argc;

        if (cmd->hidden)
            continue;

        cmd_argc = cmd_parse_line(cmd->string, cmd_argv, CMD_MAX_ARGC);

        /* Check if command matches all complete tokens */
        int matched = 1;
        for (int j = 0; j < match_argc && j < cmd_argc; j++) {
            if (cmd_match_word(cmd_argv[j], argv[j]) == 0) {
                matched = 0;
                break;
            }
        }

        if (!matched)
            continue;

        /* Also need enough tokens in command */
        if (match_argc > cmd_argc)
            continue;

        /* Get the next token to complete */
        if (match_argc < cmd_argc) {
            const char *next_token = cmd_argv[match_argc];
            
            /* Check if it matches partial (case-insensitive prefix match) */
            if (partial_len == 0 || strncasecmp(next_token, partial, partial_len) == 0) {
                /* Check if we already have this completion */
                int found = 0;
                for (int k = 0; k < num_completions; k++) {
                    if (strcasecmp(completions[k], next_token) == 0) {
                        found = 1;
                        break;
                    }
                }

                if (!found) {
                    if (num_completions >= alloc_size) {
                        alloc_size *= 2;
                        char **new_completions = realloc(completions, alloc_size * sizeof(char *));
                        if (!new_completions) {
                            for (int k = 0; k < num_completions; k++)
                                free(completions[k]);
                            free(completions);
                            *count = 0;
                            return NULL;
                        }
                        completions = new_completions;
                    }
                    completions[num_completions++] = strdup(next_token);
                }
            }
        }
    }

    *count = num_completions;
    return completions;
}
