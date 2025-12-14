/**
 * @file vty.c
 * @brief Virtual Terminal Implementation (Cisco IOS / FRR Style)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>

#include "vty.h"
#include "command.h"

/* Control plane integration (optional) */
#ifdef USE_CONTROL_PLANE
#include "control_plane.h"
#endif

/* Global hostname */
char g_hostname[HOSTNAME_LEN] = "Router";

/* Server socket */
static int vty_server_fd = -1;
static char vty_sock_path[256] = "/run/yesrouter/cli.sock";
static pthread_t vty_accept_thread;
static volatile int vty_running = 0;

/* Node prompts */
static const char *node_prompts[] = {
    [AUTH_NODE]       = "Password: ",
    [VIEW_NODE]       = ">",
    [ENABLE_NODE]     = "#",
    [CONFIG_NODE]     = "(config)#",
    [INTERFACE_NODE]  = "(config-if)#",
    [PPPOE_NODE]      = "(config-pppoe)#",
    [RADIUS_NODE]     = "(config-radius)#",
    [IP_POOL_NODE]    = "(config-pool)#",
    [VTY_NODE]        = "(config-vty)#"
};

/* Banner */
static const char *vty_banner =
    "\r\n"
    "╔══════════════════════════════════════════════════════════════╗\r\n"
    "║           YESRouter vBNG - High Performance Router           ║\r\n"
    "║                    Version 1.0.0 (DPDK)                      ║\r\n"
    "╚══════════════════════════════════════════════════════════════╝\r\n"
    "\r\n";

/**
 * Create new VTY
 */
struct vty *vty_new(int fd)
{
    struct vty *vty;

    vty = calloc(1, sizeof(struct vty));
    if (!vty)
        return NULL;

    vty->fd = fd;
    vty->type = VTY_TERM;
    vty->node = ENABLE_NODE;
    vty->privilege = 15;
    vty->status = VTY_NORMAL;

    /* Allocate buffers */
    vty->max = VTY_BUFSIZ;
    vty->buf = calloc(1, vty->max);
    vty->obuf_size = VTY_BUFSIZ * 4;
    vty->obuf = calloc(1, vty->obuf_size);

    if (!vty->buf || !vty->obuf) {
        free(vty->buf);
        free(vty->obuf);
        free(vty);
        return NULL;
    }

    vty->lines = 24;
    vty->width = 80;

    return vty;
}

/**
 * Free VTY
 */
void vty_free(struct vty *vty)
{
    if (!vty)
        return;

    /* Free history */
    for (int i = 0; i < VTY_MAXHIST; i++) {
        free(vty->hist[i]);
    }

    free(vty->buf);
    free(vty->obuf);

    if (vty->fd >= 0)
        close(vty->fd);

    free(vty);
}

/**
 * Output to VTY
 */
int vty_out(struct vty *vty, const char *format, ...)
{
    va_list args;
    char buf[4096];
    int len;

    va_start(args, format);
    len = vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    if (len <= 0)
        return 0;

    /* Write to fd */
    if (vty->fd >= 0) {
        write(vty->fd, buf, len);
    }

    return len;
}

/**
 * Get node name
 */
const char *vty_node_name(enum node_type node)
{
    static const char *names[] = {
        [AUTH_NODE]       = "auth",
        [VIEW_NODE]       = "view",
        [ENABLE_NODE]     = "enable",
        [CONFIG_NODE]     = "config",
        [INTERFACE_NODE]  = "interface",
        [PPPOE_NODE]      = "pppoe",
        [RADIUS_NODE]     = "radius",
        [IP_POOL_NODE]    = "ip-pool",
        [VTY_NODE]        = "vty"
    };

    if (node < NODE_TYPE_MAX)
        return names[node];
    return "unknown";
}

/**
 * Display prompt
 */
void vty_prompt(struct vty *vty)
{
    const char *suffix = node_prompts[vty->node];

    if (vty->node == INTERFACE_NODE && vty->context[0]) {
        vty_out(vty, "%s(config-if-%s)# ", g_hostname, vty->context);
    } else {
        vty_out(vty, "%s%s ", g_hostname, suffix);
    }
}

/**
 * Display hello banner
 */
void vty_hello(struct vty *vty)
{
    vty_out(vty, "%s", vty_banner);
    vty_out(vty, "  Type 'help' or '?' for available commands\r\n");
    vty_out(vty, "  Type 'enable' to enter privileged mode\r\n");
    vty_out(vty, "\r\n");
}

/**
 * Set VTY node
 */
void vty_set_node(struct vty *vty, enum node_type node)
{
    vty->node = node;
}

/**
 * Add to history
 */
static void vty_hist_add(struct vty *vty, const char *line)
{
    if (!line || !line[0])
        return;

    /* Don't add duplicates */
    if (vty->hindex > 0 && vty->hist[vty->hindex - 1] &&
        strcmp(vty->hist[vty->hindex - 1], line) == 0)
        return;

    /* Free oldest if full */
    if (vty->hindex >= VTY_MAXHIST) {
        free(vty->hist[0]);
        memmove(vty->hist, vty->hist + 1, sizeof(vty->hist[0]) * (VTY_MAXHIST - 1));
        vty->hindex = VTY_MAXHIST - 1;
    }

    vty->hist[vty->hindex++] = strdup(line);
    vty->hp = vty->hindex;
}

/**
 * Execute command line
 */
int vty_execute(struct vty *vty)
{
    char *line = vty->buf;
    int ret;

    /* Trim whitespace */
    while (*line && isspace(*line))
        line++;

    char *end = line + strlen(line) - 1;
    while (end > line && isspace(*end))
        *end-- = '\0';

    /* Empty line */
    if (!*line) {
        vty_out(vty, "\r\n");
        return CMD_SUCCESS;
    }

    /* Add to history */
    vty_hist_add(vty, line);

    vty_out(vty, "\r\n");

    /* Execute command */
    ret = cmd_execute(vty, line);

    /* Handle return code */
    switch (ret) {
    case CMD_ERR_NO_MATCH:
        vty_out(vty, "%% Unknown command: %s\r\n", line);
        break;
    case CMD_ERR_AMBIGUOUS:
        vty_out(vty, "%% Ambiguous command: %s\r\n", line);
        break;
    case CMD_ERR_INCOMPLETE:
        vty_out(vty, "%% Incomplete command\r\n");
        break;
    case CMD_ERR_PRIVILEGE:
        vty_out(vty, "%% Permission denied\r\n");
        break;
    }

    return ret;
}

/**
 * Read from VTY (handle telnet/raw input)
 */
int vty_read(struct vty *vty)
{
    char buf[256];
    ssize_t nbytes;

    nbytes = read(vty->fd, buf, sizeof(buf) - 1);
    if (nbytes <= 0) {
        vty->status = VTY_CLOSE;
        return -1;
    }

    buf[nbytes] = '\0';

    for (int i = 0; i < nbytes; i++) {
        char c = buf[i];

        /* Handle telnet IAC */
        if (c == 255) {  /* IAC */
            vty->iac = 1;
            continue;
        }

        if (vty->iac) {
            if (vty->iac == 1) {
                /* Command byte */
                if (c >= 251 && c <= 254) {
                    vty->iac = 2;  /* Expect option */
                } else {
                    vty->iac = 0;
                }
                continue;
            } else {
                /* Option byte - ignore */
                vty->iac = 0;
                continue;
            }
        }

        /* Handle escape sequences */
        if (c == 27) {  /* ESC */
            vty->escape = 1;
            continue;
        }

        if (vty->escape) {
            if (vty->escape == 1 && c == '[') {
                vty->escape = 2;
                continue;
            }
            if (vty->escape == 2) {
                /* Arrow keys */
                switch (c) {
                case 'A':  /* Up */
                    if (vty->hp > 0 && vty->hist[vty->hp - 1]) {
                        vty->hp--;
                        /* Clear line */
                        vty_out(vty, "\r%s%s \r%s%s ",
                                g_hostname, node_prompts[vty->node],
                                g_hostname, node_prompts[vty->node]);
                        strcpy(vty->buf, vty->hist[vty->hp]);
                        vty->length = strlen(vty->buf);
                        vty->cp = vty->length;
                        vty_out(vty, "%s", vty->buf);
                    }
                    break;
                case 'B':  /* Down */
                    if (vty->hp < vty->hindex - 1) {
                        vty->hp++;
                        vty_out(vty, "\r%s%s \r%s%s ",
                                g_hostname, node_prompts[vty->node],
                                g_hostname, node_prompts[vty->node]);
                        strcpy(vty->buf, vty->hist[vty->hp]);
                        vty->length = strlen(vty->buf);
                        vty->cp = vty->length;
                        vty_out(vty, "%s", vty->buf);
                    } else if (vty->hp == vty->hindex - 1) {
                        vty->hp++;
                        vty_out(vty, "\r%s%s \r%s%s ",
                                g_hostname, node_prompts[vty->node],
                                g_hostname, node_prompts[vty->node]);
                        vty->buf[0] = '\0';
                        vty->length = 0;
                        vty->cp = 0;
                    }
                    break;
                }
                vty->escape = 0;
                continue;
            }
            vty->escape = 0;
        }

        /* Handle special characters */
        switch (c) {
        case '\r':
        case '\n':
            /* Execute command */
            vty->buf[vty->length] = '\0';
            vty_execute(vty);

            /* Reset buffer */
            vty->length = 0;
            vty->cp = 0;
            vty->buf[0] = '\0';

            /* Show prompt */
            if (vty->status == VTY_NORMAL)
                vty_prompt(vty);
            break;

        case 0x7f:  /* DEL */
        case '\b':  /* Backspace */
            if (vty->length > 0) {
                vty->length--;
                vty->cp--;
                vty->buf[vty->length] = '\0';
                vty_out(vty, "\b \b");
            }
            break;

        case '\t':  /* Tab - completion (Cisco-style) */
            {
                int count = 0;
                char **completions;

                vty->buf[vty->length] = '\0';
                completions = cmd_complete(vty, vty->buf, &count);

                if (count == 0) {
                    /* No completions - beep */
                    vty_out(vty, "\a");
                } else if (count == 1) {
                    /* Single completion - complete it with trailing space */
                    const char *comp = completions[0];
                    int comp_len = strlen(comp);

                    /* Find partial word start */
                    int partial_start = vty->length;
                    while (partial_start > 0 && vty->buf[partial_start-1] != ' ')
                        partial_start--;
                    int partial_len = vty->length - partial_start;

                    /* Erase partial and print full completion + space */
                    for (int k = 0; k < partial_len; k++)
                        vty_out(vty, "\b \b");

                    strcpy(vty->buf + partial_start, comp);
                    vty->buf[partial_start + comp_len] = ' ';
                    vty->buf[partial_start + comp_len + 1] = '\0';
                    vty->length = partial_start + comp_len + 1;
                    vty->cp = vty->length;
                    vty_out(vty, "%s ", comp);
                } else {
                    /* Multiple completions - find longest common prefix */
                    int prefix_len = strlen(completions[0]);
                    for (int k = 1; k < count && prefix_len > 0; k++) {
                        int j = 0;
                        while (j < prefix_len &&
                               tolower(completions[0][j]) == tolower(completions[k][j])) {
                            j++;
                        }
                        prefix_len = j;
                    }

                    /* Find what user has typed */
                    int partial_start = vty->length;
                    while (partial_start > 0 && vty->buf[partial_start-1] != ' ')
                        partial_start--;
                    int partial_len = vty->length - partial_start;

                    if (prefix_len > partial_len) {
                        /* Complete to common prefix (no trailing space) */
                        for (int k = 0; k < partial_len; k++)
                            vty_out(vty, "\b \b");

                        /* Copy common prefix */
                        char prefix[256];
                        strncpy(prefix, completions[0], prefix_len);
                        prefix[prefix_len] = '\0';

                        strcpy(vty->buf + partial_start, prefix);
                        vty->length = partial_start + prefix_len;
                        vty->cp = vty->length;
                        vty->buf[vty->length] = '\0';
                        vty_out(vty, "%s", prefix);
                    } else {
                        /* Already at common prefix - show options */
                        vty_out(vty, "\r\n");
                        for (int k = 0; k < count; k++) {
                            vty_out(vty, "  %s\r\n", completions[k]);
                        }
                        vty_prompt(vty);
                        vty_out(vty, "%s", vty->buf);
                    }
                }

                /* Free completions */
                for (int k = 0; k < count; k++)
                    free(completions[k]);
                free(completions);
            }
            break;


        case '?':
            /* Context help */
            vty->buf[vty->length] = '\0';
            vty_out(vty, "?\r\n");
            cmd_describe(vty, vty->buf);
            vty_prompt(vty);
            vty_out(vty, "%s", vty->buf);
            break;

        case 0x03:  /* Ctrl-C */
            vty_out(vty, "^C\r\n");
            vty->length = 0;
            vty->cp = 0;
            vty->buf[0] = '\0';
            vty_prompt(vty);
            break;

        case 0x04:  /* Ctrl-D */
            if (vty->length == 0) {
                vty_out(vty, "\r\nGoodbye!\r\n");
                vty->status = VTY_CLOSE;
            }
            break;

        case 0x15:  /* Ctrl-U - clear line */
            while (vty->length > 0) {
                vty->length--;
                vty_out(vty, "\b \b");
            }
            vty->cp = 0;
            vty->buf[0] = '\0';
            break;

        case 0x17:  /* Ctrl-W - delete word */
            while (vty->length > 0 && vty->buf[vty->length - 1] == ' ') {
                vty->length--;
                vty_out(vty, "\b \b");
            }
            while (vty->length > 0 && vty->buf[vty->length - 1] != ' ') {
                vty->length--;
                vty_out(vty, "\b \b");
            }
            vty->cp = vty->length;
            vty->buf[vty->length] = '\0';
            break;

        default:
            /* Regular character */
            if (c >= 32 && c < 127 && vty->length < vty->max - 1) {
                vty->buf[vty->length++] = c;
                vty->buf[vty->length] = '\0';
                vty->cp++;
                vty_out(vty, "%c", c);
            }
            break;
        }
    }

    return 0;
}

/**
 * Session handler thread
 */
static void *vty_session_handler(void *arg)
{
    struct vty *vty = (struct vty *)arg;

    /* Send banner */
    vty_hello(vty);
    vty_prompt(vty);

    /* Main loop */
    while (vty->status == VTY_NORMAL && vty_running) {
        if (vty_read(vty) < 0)
            break;
    }

    vty_free(vty);
    return NULL;
}

/**
 * Accept thread
 */
static void *vty_accept_handler(void *arg)
{
    (void)arg;

    while (vty_running) {
        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(vty_server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        /* Create VTY for client */
        struct vty *vty = vty_new(client_fd);
        if (!vty) {
            close(client_fd);
            continue;
        }

        /* Start session thread */
        pthread_t thread;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        if (pthread_create(&thread, &attr, vty_session_handler, vty) != 0) {
            vty_free(vty);
        }

        pthread_attr_destroy(&attr);
    }

    return NULL;
}

/**
 * Start VTY server
 */
int vty_serv_sock(const char *path)
{
    struct sockaddr_un addr;

    if (path)
        strncpy(vty_sock_path, path, sizeof(vty_sock_path) - 1);

    /* Create directory */
    char *dir = strdup(vty_sock_path);
    char *last_slash = strrchr(dir, '/');
    if (last_slash) {
        *last_slash = '\0';
        mkdir(dir, 0755);
    }
    free(dir);

    /* Remove old socket */
    unlink(vty_sock_path);

    /* Create socket */
    vty_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (vty_server_fd < 0)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, vty_sock_path, sizeof(addr.sun_path) - 1);

    if (bind(vty_server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(vty_server_fd);
        vty_server_fd = -1;
        return -1;
    }

    chmod(vty_sock_path, 0666);

    if (listen(vty_server_fd, 5) < 0) {
        close(vty_server_fd);
        vty_server_fd = -1;
        return -1;
    }

    /* Start accept thread */
    vty_running = 1;
    if (pthread_create(&vty_accept_thread, NULL, vty_accept_handler, NULL) != 0) {
        close(vty_server_fd);
        vty_server_fd = -1;
        return -1;
    }

    return 0;
}

/**
 * Close VTY server
 */
void vty_serv_close(void)
{
    vty_running = 0;

    if (vty_server_fd >= 0) {
        close(vty_server_fd);
        vty_server_fd = -1;
    }

    unlink(vty_sock_path);

    pthread_join(vty_accept_thread, NULL);
}

/**
 * Initialize VTY subsystem
 */
void vty_init(void)
{
    cmd_init();
}

/**
 * Terminate VTY subsystem
 */
void vty_terminate(void)
{
    vty_serv_close();
    cmd_terminate();
}

/* ============================================================================
 * Compatibility Functions (for main.c)
 * ============================================================================ */

/* Forward declarations for module init */
extern void cli_pppoe_init(void);
extern void cli_interface_init(void);
extern void cli_system_init(void);
extern void cli_radius_init(void);
extern void cli_ippool_init(void);
extern void cli_route_init(void);
extern void cli_nat_init(void);
extern void cli_vlan_init(void);

/**
 * Initialize CLI (called from main.c)
 */
int cli_init(void)
{
    vty_init();
    cli_pppoe_init();
    cli_interface_init();
    cli_system_init();
    cli_radius_init();
    cli_ippool_init();
    cli_route_init();
    cli_nat_init();
    cli_vlan_init();
    return 0;
}

/**
 * Execute a single command line
 */
int cli_execute(const char *cmdline)
{
    static struct vty console_vty = {
        .fd = STDOUT_FILENO,
        .node = ENABLE_NODE,
        .privilege = 15
    };

    return cmd_execute(&console_vty, cmdline);
}

/**
 * Execute commands from a file
 */
int cli_execute_file(const char *filename)
{
    FILE *f;
    char line[4096];
    int errors = 0;

    if (!filename)
        return -1;

    f = fopen(filename, "r");
    if (!f)
        return -1;

    while (fgets(line, sizeof(line), f)) {
        /* Remove newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        nl = strchr(line, '\r');
        if (nl) *nl = '\0';

        /* Skip empty lines and comments */
        char *p = line;
        while (*p && isspace(*p)) p++;
        if (!*p || *p == '!' || *p == '#')
            continue;

        if (cli_execute(p) != CMD_SUCCESS)
            errors++;
    }

    fclose(f);
    return errors ? -1 : 0;
}

/**
 * Interactive CLI mode
 */
void cli_interactive(void)
{
    struct vty *vty;
    char line[VTY_BUFSIZ];

    vty = vty_new(STDIN_FILENO);
    if (!vty)
        return;

    vty->node = ENABLE_NODE;
    vty->privilege = 15;

    vty_hello(vty);

    while (vty->status == VTY_NORMAL) {
        vty_prompt(vty);
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin))
            break;

        /* Remove newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        strncpy(vty->buf, line, vty->max - 1);
        vty->length = strlen(vty->buf);

        vty_execute(vty);
    }

    vty_free(vty);
}

/**
 * Initialize socket server
 */
int cli_socket_server_init(const char *path)
{
    return vty_serv_sock(path);
}

/**
 * Start socket server (already started in init)
 */
int cli_socket_server_start(void)
{
    return 0;  /* Already started */
}

/**
 * Stop socket server
 */
void cli_socket_server_stop(void)
{
    vty_serv_close();
}
