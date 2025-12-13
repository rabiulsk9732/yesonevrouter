/**
 * @file vty.h
 * @brief Virtual Terminal Interface (Cisco IOS / FRR Style)
 *
 * RFC-compliant CLI virtual terminal implementation.
 */

#ifndef _VTY_H
#define _VTY_H

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/types.h>

#define VTY_MAXHIST     20
#define VTY_BUFSIZ      4096
#define VTY_MAX_PROMPT  64
#define HOSTNAME_LEN    64

/* VTY status */
enum vty_status {
    VTY_NORMAL,
    VTY_CLOSE,
    VTY_MORE,
    VTY_TIMEOUT
};

/* Command return codes */
#define CMD_SUCCESS           0
#define CMD_WARNING           1
#define CMD_ERR_NO_MATCH      2
#define CMD_ERR_AMBIGUOUS     3
#define CMD_ERR_INCOMPLETE    4
#define CMD_ERR_PRIVILEGE     5
#define CMD_COMPLETE_MATCH    6
#define CMD_COMPLETE_LIST     7

/* Node types (command modes) */
enum node_type {
    AUTH_NODE,              /* Authentication mode */
    VIEW_NODE,              /* User EXEC mode (Router>) */
    ENABLE_NODE,            /* Privileged EXEC mode (Router#) */
    CONFIG_NODE,            /* Global config (Router(config)#) */
    INTERFACE_NODE,         /* Interface config */
    PPPOE_NODE,             /* PPPoE config */
    RADIUS_NODE,            /* RADIUS config */
    IP_POOL_NODE,           /* IP Pool config */
    VTY_NODE,               /* VTY line config */
    NODE_TYPE_MAX
};

/* VTY structure */
struct vty {
    /* File descriptor */
    int fd;

    /* Socket type */
    enum {
        VTY_TERM,           /* Terminal */
        VTY_FILE,           /* File */
        VTY_SHELL           /* Shell */
    } type;

    /* Current node (command mode) */
    enum node_type node;

    /* Privilege level (0-15) */
    uint8_t privilege;

    /* Fail count for authentication */
    int fail;

    /* Input buffer */
    char *buf;
    size_t max;             /* Max buffer size */
    size_t length;          /* Current input length */
    size_t cp;              /* Cursor position */

    /* Command history */
    char *hist[VTY_MAXHIST];
    int hp;                 /* History pointer */
    int hindex;             /* History index */

    /* Output buffer */
    char *obuf;
    size_t obuf_size;
    size_t obuf_len;

    /* Status */
    enum vty_status status;

    /* Lines for paging */
    int lines;
    int width;

    /* Context data (interface name, etc) */
    char context[64];
    int context_index;

    /* Escape sequence state */
    int escape;

    /* IAC handling for telnet */
    int iac;
    int iac_sb;

    /* Timeout */
    time_t timeout;
};

/* Global hostname */
extern char g_hostname[HOSTNAME_LEN];

/* VTY functions */
struct vty *vty_new(int fd);
void vty_free(struct vty *vty);

/* Output functions */
int vty_out(struct vty *vty, const char *format, ...);
void vty_prompt(struct vty *vty);
void vty_hello(struct vty *vty);

/* Input processing */
int vty_read(struct vty *vty);
int vty_execute(struct vty *vty);

/* Node functions */
const char *vty_node_name(enum node_type node);
void vty_set_node(struct vty *vty, enum node_type node);

/* Socket server */
int vty_serv_sock(const char *path);
void vty_serv_close(void);
void vty_accept(int server_fd);

/* Initialization */
void vty_init(void);
void vty_terminate(void);

#endif /* _VTY_H */
