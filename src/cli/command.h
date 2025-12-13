/**
 * @file command.h
 * @brief Command Registration and Dispatch (Cisco IOS / FRR Style)
 */

#ifndef _COMMAND_H
#define _COMMAND_H

#include "vty.h"

#define CMD_MAX_TOKENS      32
#define CMD_MAX_ARGC        32
#define CMD_TOKEN_LEN       256

/* Help strings */
#define SHOW_STR            "Show running system information\n"
#define CLEAR_STR           "Reset functions\n"
#define DEBUG_STR           "Debugging functions\n"
#define NO_STR              "Negate a command or set its defaults\n"
#define CONFIG_STR          "Configuration commands\n"
#define INTERFACE_STR       "Interface configuration\n"
#define PPPOE_STR           "PPPoE configuration\n"
#define RADIUS_STR          "RADIUS configuration\n"

/* Command element */
struct cmd_element {
    const char *string;         /* Command definition string */
    const char *doc;            /* Documentation/help string */
    int (*func)(struct vty *vty, int argc, const char *argv[]);
    uint8_t privilege;          /* Required privilege (0-15) */
    uint8_t hidden;             /* Hidden command */
};

/* Command node */
struct cmd_node {
    enum node_type node;        /* Node type */
    const char *prompt;         /* Prompt string */
    int (*func)(struct vty *);  /* Node entry function */
    struct cmd_element **cmds;  /* Command vector */
    int cmd_count;              /* Number of commands */
    int cmd_alloc;              /* Allocated size */
};

/* Token types for parsing */
enum cmd_token_type {
    TOKEN_KEYWORD,              /* Fixed keyword */
    TOKEN_VARIABLE,             /* <variable> */
    TOKEN_OPTION,               /* [optional] */
    TOKEN_RANGE,                /* <0-100> */
    TOKEN_IPV4,                 /* A.B.C.D */
    TOKEN_IPV4_PREFIX,          /* A.B.C.D/M */
    TOKEN_WORD,                 /* WORD */
    TOKEN_LINE                  /* LINE (rest of input) */
};

/* Parsed token */
struct cmd_token {
    enum cmd_token_type type;
    char text[CMD_TOKEN_LEN];
    char desc[CMD_TOKEN_LEN];
    int min, max;               /* For range tokens */
};

/* Match result */
struct cmd_match {
    struct cmd_element *cmd;
    int argc;
    const char *argv[CMD_MAX_ARGC];
    int match_type;             /* Exact, partial, etc */
};

/* Command registration macros (FRR style) */
#define DEFUN(funcname, cmdname, cmdstr, helpstr) \
    static int funcname(struct vty *vty, int argc, const char *argv[]); \
    static struct cmd_element cmdname = { \
        .string = cmdstr, \
        .doc = helpstr, \
        .func = funcname, \
        .privilege = 1, \
        .hidden = 0 \
    }; \
    static int funcname(struct vty *vty, int argc, const char *argv[])

#define DEFUN_HIDDEN(funcname, cmdname, cmdstr, helpstr) \
    static int funcname(struct vty *vty, int argc, const char *argv[]); \
    static struct cmd_element cmdname = { \
        .string = cmdstr, \
        .doc = helpstr, \
        .func = funcname, \
        .privilege = 1, \
        .hidden = 1 \
    }; \
    static int funcname(struct vty *vty, int argc, const char *argv[])

#define ALIAS(funcname, cmdname, cmdstr, helpstr) \
    static struct cmd_element cmdname = { \
        .string = cmdstr, \
        .doc = helpstr, \
        .func = funcname, \
        .privilege = 1, \
        .hidden = 0 \
    }

/* Command functions */
void cmd_init(void);
void cmd_terminate(void);

/* Node management */
void install_node(struct cmd_node *node);
void install_element(enum node_type node, struct cmd_element *cmd);
void install_default(enum node_type node);

/* Command execution */
int cmd_execute(struct vty *vty, const char *line);
int cmd_execute_command(struct vty *vty, int argc, const char *argv[]);

/* Help and completion */
char **cmd_complete(struct vty *vty, const char *line, int *count);
void cmd_describe(struct vty *vty, const char *line);

/* Built-in commands */
void cmd_install_defaults(void);

/* Utility */
int cmd_parse_line(const char *line, char *argv[], int max_argc);

#endif /* _COMMAND_H */
