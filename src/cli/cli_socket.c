/**
 * @file cli_socket.c
 * @brief Unix Socket CLI Server Implementation
 *
 * VPP-style CLI over Unix domain socket.
 * Multiple concurrent sessions, exit only disconnects client.
 */

#include "cli_socket.h"
#include "cli.h"
#include "log.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/* Telnet protocol constants for client negotiation */
#define IAC 255 /* Interpret As Command */
#define WILL 251
#define DO 252
#define SB 250 /* Subnegotiation Begin */
#define SE 240 /* Subnegotiation End */

#define TELOPT_TTYPE 24 /* Terminal Type */
#define TELOPT_NAWS 31  /* Window Size */
#define TELOPT_ECHO 1   /* Echo */

#define CLI_SOCKET_DEFAULT_PATH "/run/yesrouter/cli.sock"
#define CLI_SOCKET_MAX_SESSIONS 16

/* Global state */
static int g_server_fd = -1;
static char g_socket_path[256] = CLI_SOCKET_DEFAULT_PATH;
static pthread_t g_acceptor_thread;
static bool g_server_running = false;
static struct cli_socket_session g_sessions[CLI_SOCKET_MAX_SESSIONS];
static pthread_mutex_t g_session_lock = PTHREAD_MUTEX_INITIALIZER;

/* Forward declarations */
static void *cli_session_handler(void *arg);
static void *cli_socket_acceptor(void *arg);

/**
 * Initialize CLI socket server
 */
int cli_socket_server_init(const char *socket_path)
{
    struct sockaddr_un addr;

    if (socket_path) {
        size_t len = strlen(socket_path);
        if (len >= sizeof(g_socket_path)) {
            YLOG_ERROR("Socket path too long: %s", socket_path);
            return -1;
        }
        strcpy(g_socket_path, socket_path);
    }

    /* Create parent directory if needed */
    char dir_path[256];
    strncpy(dir_path, g_socket_path, sizeof(dir_path) - 1);
    dir_path[sizeof(dir_path) - 1] = '\0'; /* Ensure null termination */
    char *last_slash = strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        mkdir(dir_path, 0755);
    }

    /* Remove old socket file if exists */
    unlink(g_socket_path);

    /* Create Unix socket */
    g_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_server_fd < 0) {
        YLOG_ERROR("Failed to create CLI socket: %s", strerror(errno));
        return -1;
    }

    /* Bind to path */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t path_len = strlen(g_socket_path);
    if (path_len >= sizeof(addr.sun_path)) {
        YLOG_ERROR("Socket path too long for sockaddr_un");
        close(g_server_fd);
        g_server_fd = -1;
        return -1;
    }
    memcpy(addr.sun_path, g_socket_path, path_len + 1); /* Include null terminator */

    if (bind(g_server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        YLOG_ERROR("Failed to bind CLI socket to %s: %s", g_socket_path, strerror(errno));
        close(g_server_fd);
        g_server_fd = -1;
        return -1;
    }

    /* Listen for connections */
    if (listen(g_server_fd, 5) < 0) {
        YLOG_ERROR("Failed to listen on CLI socket: %s", strerror(errno));
        close(g_server_fd);
        g_server_fd = -1;
        return -1;
    }

    /* Set socket permissions (rw for owner only) */
    chmod(g_socket_path, 0600);

    /* Initialize session table */
    memset(g_sessions, 0, sizeof(g_sessions));

    YLOG_INFO("CLI socket server initialized on %s", g_socket_path);
    return 0;
}

/**
 * Send telnet option negotiation to client
 */
static void send_telnet_options(int fd)
{
    unsigned char opts[] = {
        IAC, WILL, TELOPT_ECHO,  /* Server will echo */
        IAC, DO,   TELOPT_TTYPE, /* Request terminal type */
        IAC, DO,   TELOPT_NAWS   /* Request window size */
    };
    ssize_t n = write(fd, opts, sizeof(opts));
    (void)n; /* Ignore write errors */
}

/**
 * Handle CLI session - manual processing (readline doesn't work on sockets)
 */
static void *cli_session_handler(void *arg)
{
    struct cli_socket_session *session = (struct cli_socket_session *)arg;
    FILE *client_fp;

    YLOG_INFO("CLI session %d connected", session->session_id);

    /* Send telnet negotiation for full readline support */
    send_telnet_options(session->socket_fd);

    /* Create FILE* from socket for easier I/O */
    client_fp = fdopen(dup(session->socket_fd), "w+");
    if (!client_fp) {
        YLOG_ERROR("Failed to fdopen socket for session %d", session->session_id);
        goto cleanup;
    }

    /* Disable buffering for immediate output */
    setvbuf(client_fp, NULL, _IONBF, 0);

    /* Send welcome banner */
    fprintf(client_fp, "\nyesrouter vBNG\n");
    fprintf(client_fp, "Type 'help' for available commands\n");
    fprintf(client_fp, "Type 'exit' to disconnect\n\n");

    /* Send initial prompt */
    fprintf(client_fp, "yesrouter# ");
    fflush(client_fp);

    /* Command loop - handle raw mode character-by-character input */
    char line_buffer[1024];
    int line_pos = 0;
    unsigned char last_char = 0; /* Track last char to handle \r\n */

/* Command history */
#define MAX_HISTORY 20
    static char history[MAX_HISTORY][1024];
    static int history_count = 0;
    int history_idx = -1;       /* -1 = current line, 0+ = history index */
    char saved_line[1024] = ""; /* Save current line when browsing history */
    int saved_pos = 0;

    /* Escape sequence tracking */
    int esc_state = 0; /* 0=normal, 1=got ESC, 2=got ESC[ */

    while (session->active) {
        /* Read one character at a time (client is in raw mode) */
        unsigned char c;
        ssize_t n = read(session->socket_fd, &c, 1);
        if (n <= 0) {
            break; /* Connection closed */
        }

        /* Handle escape sequences (arrow keys) */
        if (esc_state == 1) {
            if (c == '[') {
                esc_state = 2;
                continue;
            } else {
                esc_state = 0; /* Not a valid sequence */
            }
        } else if (esc_state == 2) {
            esc_state = 0;
            if (c == 'A') {
                /* Up arrow - previous history */
                if (history_count > 0) {
                    if (history_idx == -1) {
                        /* Save current line */
                        strcpy(saved_line, line_buffer);
                        saved_pos = line_pos;
                        history_idx = 0;
                    } else if (history_idx < history_count - 1) {
                        history_idx++;
                    } else {
                        continue; /* Already at oldest */
                    }

                    /* Clear current line on screen */
                    while (line_pos > 0) {
                        fprintf(client_fp, "\b \b");
                        line_pos--;
                    }

                    /* Show history entry */
                    int hi = history_count - 1 - history_idx;
                    strcpy(line_buffer, history[hi]);
                    line_pos = strlen(line_buffer);
                    fprintf(client_fp, "%s", line_buffer);
                    fflush(client_fp);
                }
                continue;
            } else if (c == 'B') {
                /* Down arrow - next history */
                if (history_idx >= 0) {
                    /* Clear current line on screen */
                    while (line_pos > 0) {
                        fprintf(client_fp, "\b \b");
                        line_pos--;
                    }

                    if (history_idx > 0) {
                        history_idx--;
                        int hi = history_count - 1 - history_idx;
                        strcpy(line_buffer, history[hi]);
                        line_pos = strlen(line_buffer);
                    } else {
                        /* Restore saved line */
                        history_idx = -1;
                        strcpy(line_buffer, saved_line);
                        line_pos = saved_pos;
                    }
                    fprintf(client_fp, "%s", line_buffer);
                    fflush(client_fp);
                }
                continue;
            }
            /* Ignore other escape sequences (left/right arrows, etc.) */
            continue;
        }

        if (c == 27) { /* ESC */
            esc_state = 1;
            continue;
        }

        /* Handle special characters */
        if (c == '\r' || c == '\n') {
            /* Skip \n after \r (Windows-style line endings) */
            if (c == '\n' && last_char == '\r') {
                last_char = c;
                continue;
            }
            last_char = c;

            /* End of line - process command */
            if (line_pos > 0) {
                line_buffer[line_pos] = '\0';

                /* Echo newline */
                fprintf(client_fp, "\r\n");

                /* Save to history (before any modification) */
                if (line_pos > 0 && history_count < MAX_HISTORY) {
                    strcpy(history[history_count], line_buffer);
                    history_count++;
                } else if (line_pos > 0) {
                    /* Shift history and add new */
                    memmove(history[0], history[1], (MAX_HISTORY - 1) * sizeof(history[0]));
                    strcpy(history[MAX_HISTORY - 1], line_buffer);
                }
                history_idx = -1; /* Reset history index */

                /* Update activity */
                session->last_activity = time(NULL);

                /* Check for exit */
                if (strcmp(line_buffer, "exit") == 0 || strcmp(line_buffer, "quit") == 0) {
                    fprintf(client_fp, "Disconnecting from yesrouter...\r\n");
                    break;
                }

                /* Redirect stdout/stderr */
                int saved_stdout = dup(STDOUT_FILENO);
                int saved_stderr = dup(STDERR_FILENO);
                dup2(fileno(client_fp), STDOUT_FILENO);
                dup2(fileno(client_fp), STDERR_FILENO);

                /* Handle ? for help */
                char *question = strchr(line_buffer, '?');
                if (question) {
                    *question = '\0';
                    char *p = question - 1;
                    while (p >= line_buffer && (*p == ' ' || *p == '\t')) {
                        *p = '\0';
                        p--;
                    }
                    extern void show_context_help(const char *prefix);
                    show_context_help(line_buffer[0] != '\0' ? line_buffer : NULL);
                } else if (strcmp(line_buffer, "?") == 0) {
                    extern int cmd_help(int argc, char **argv);
                    cmd_help(0, NULL);
                } else {
                    /* Execute command */
                    extern int cli_execute(const char *line);
                    cli_execute(line_buffer);
                }

                /* Restore stdout/stderr */
                fflush(stdout);
                fflush(stderr);
                dup2(saved_stdout, STDOUT_FILENO);
                dup2(saved_stderr, STDERR_FILENO);
                close(saved_stdout);
                close(saved_stderr);

                /* Prompt for next command */
                fprintf(client_fp, "yesrouter# ");
                fflush(client_fp);
            } else {
                /* Empty line - just show prompt */
                fprintf(client_fp, "\r\nyesrouter# ");
                fflush(client_fp);
            }

            line_pos = 0; /* Reset buffer */

        } else if (c == 127 || c == 8) {
            /* Backspace */
            if (line_pos > 0) {
                line_pos--;
                fprintf(client_fp, "\b \b"); /* Erase character on screen */
                fflush(client_fp);
            }
        } else if (c == 9) {
            /* Tab - auto-completion */
            line_buffer[line_pos] = '\0';

            /* Use show_context_help to get matching commands */
            /* For now, implement simple completion using command list */
            extern const char *cli_commands[];
            extern int cli_command_count;

            const char *match = NULL;
            int match_count = 0;
            int match_len = 0;

            /* Find matching commands */
            for (int i = 0; i < cli_command_count; i++) {
                if (strncmp(cli_commands[i], line_buffer, line_pos) == 0) {
                    if (match_count == 0) {
                        match = cli_commands[i];
                        match_len = strlen(cli_commands[i]);
                    } else {
                        /* Find common prefix length */
                        int j = 0;
                        while (j < match_len && match[j] == cli_commands[i][j])
                            j++;
                        match_len = j;
                    }
                    match_count++;
                }
            }

            if (match_count == 1) {
                /* Single match - complete it */
                int add_len = strlen(match) - line_pos;
                if (add_len > 0) {
                    fprintf(client_fp, "%s ", match + line_pos);
                    strcpy(line_buffer + line_pos, match + line_pos);
                    line_pos = strlen(match);
                    line_buffer[line_pos++] = ' ';
                    line_buffer[line_pos] = '\0';
                    fflush(client_fp);
                }
            } else if (match_count > 1 && match_len > line_pos) {
                /* Multiple matches but common prefix - complete to common prefix */
                int add_len = match_len - line_pos;
                char common[256];
                strncpy(common, match, match_len);
                common[match_len] = '\0';
                fprintf(client_fp, "%s", common + line_pos);
                strncpy(line_buffer + line_pos, common + line_pos, add_len);
                line_pos = match_len;
                line_buffer[line_pos] = '\0';
                fflush(client_fp);
            } else if (match_count > 1) {
                /* Multiple matches, show options */
                fprintf(client_fp, "\r\n");
                int saved_stdout = dup(STDOUT_FILENO);
                dup2(fileno(client_fp), STDOUT_FILENO);
                extern void show_context_help(const char *prefix);
                show_context_help(line_pos > 0 ? line_buffer : NULL);
                fflush(stdout);
                dup2(saved_stdout, STDOUT_FILENO);
                close(saved_stdout);
                fprintf(client_fp, "yesrouter# %s", line_buffer);
                fflush(client_fp);
            }
            /* Else no matches - do nothing (like Cisco) */
        } else if (c == '?') {
            /* Immediate context-sensitive help (Cisco-style) */
            line_buffer[line_pos] = '\0';

            fprintf(client_fp, "?\r\n"); /* Echo the ? */

            /* Redirect stdout and show help */
            int saved_stdout = dup(STDOUT_FILENO);
            dup2(fileno(client_fp), STDOUT_FILENO);
            extern void show_context_help(const char *prefix);
            show_context_help(line_pos > 0 ? line_buffer : NULL);
            fflush(stdout);
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);

            /* Redisplay prompt with current input */
            fprintf(client_fp, "yesrouter# %s", line_buffer);
            fflush(client_fp);
        } else if (c >= 32 && c < 127) {
            /* Printable character */
            if (line_pos < (int)sizeof(line_buffer) - 1) {
                line_buffer[line_pos++] = c;
                fprintf(client_fp, "%c", c); /* Echo */
                fflush(client_fp);
            }
        }
        /* Ignore other control characters (arrows, etc.) */
    }

cleanup:
    YLOG_INFO("CLI session %d disconnected", session->session_id);

    if (client_fp) {
        fclose(client_fp);
    }

    close(session->socket_fd);

    pthread_mutex_lock(&g_session_lock);
    session->active = false;
    pthread_mutex_unlock(&g_session_lock);

    return NULL;
}

/**
 * Accept incoming connections
 */
static void *cli_socket_acceptor(void *arg)
{
    (void)arg;

    YLOG_INFO("CLI socket acceptor thread started");

    while (g_server_running) {
        struct sockaddr_un client_addr;
        socklen_t addr_len = sizeof(client_addr);

        /* Accept connection (blocking) */
        int client_fd = accept(g_server_fd, (struct sockaddr *)&client_addr, &addr_len);

        if (client_fd < 0) {
            if (g_server_running) {
                YLOG_ERROR("Accept failed on CLI socket: %s", strerror(errno));
            }
            continue;
        }

        /* Find free session slot */
        pthread_mutex_lock(&g_session_lock);

        struct cli_socket_session *session = NULL;
        int session_id = -1;

        for (int i = 0; i < CLI_SOCKET_MAX_SESSIONS; i++) {
            if (!g_sessions[i].active) {
                session = &g_sessions[i];
                session_id = i;
                break;
            }
        }

        if (session) {
            /* Initialize session */
            session->socket_fd = client_fd;
            session->active = true;
            session->connect_time = time(NULL);
            session->last_activity = time(NULL);
            session->session_id = session_id;
            snprintf(session->client_info, sizeof(session->client_info), "unix-socket-%d",
                     session_id);

            /* Create handler thread */
            if (pthread_create(&session->thread, NULL, cli_session_handler, session) != 0) {
                YLOG_ERROR("Failed to create session handler thread");
                close(client_fd);
                session->active = false;
            } else {
                pthread_detach(session->thread);
            }
        } else {
            /* No free slots */
            const char *msg = "ERROR: Maximum CLI sessions reached\n";
            ssize_t res = write(client_fd, msg, strlen(msg));
            (void)res; /* Ignore result, best effort */
            close(client_fd);
            YLOG_WARNING("CLI connection rejected: max sessions reached");
        }

        pthread_mutex_unlock(&g_session_lock);
    }

    YLOG_INFO("CLI socket acceptor thread stopped");
    return NULL;
}

/**
 * Start CLI socket server
 */
int cli_socket_server_start(void)
{
    if (g_server_fd < 0) {
        YLOG_ERROR("CLI socket server not initialized");
        return -1;
    }

    g_server_running = true;

    /* Start acceptor thread */
    if (pthread_create(&g_acceptor_thread, NULL, cli_socket_acceptor, NULL) != 0) {
        YLOG_ERROR("Failed to create CLI acceptor thread");
        g_server_running = false;
        return -1;
    }

    pthread_detach(g_acceptor_thread);

    YLOG_INFO("CLI socket server started");
    return 0;
}

/**
 * Stop CLI socket server
 */
void cli_socket_server_stop(void)
{
    if (!g_server_running) {
        return;
    }

    YLOG_INFO("Stopping CLI socket server...");

    g_server_running = false;

    /* Close all active sessions */
    pthread_mutex_lock(&g_session_lock);
    for (int i = 0; i < CLI_SOCKET_MAX_SESSIONS; i++) {
        if (g_sessions[i].active) {
            close(g_sessions[i].socket_fd);
            g_sessions[i].active = false;
        }
    }
    pthread_mutex_unlock(&g_session_lock);

    /* Close server socket */
    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }

    /* Remove socket file */
    unlink(g_socket_path);

    YLOG_INFO("CLI socket server stopped");
}

/**
 * Get number of active sessions
 */
int cli_socket_get_session_count(void)
{
    int count = 0;

    pthread_mutex_lock(&g_session_lock);
    for (int i = 0; i < CLI_SOCKET_MAX_SESSIONS; i++) {
        if (g_sessions[i].active) {
            count++;
        }
    }
    pthread_mutex_unlock(&g_session_lock);

    return count;
}

/**
 * Display active CLI sessions
 */
void cli_socket_show_sessions(void)
{
    printf("\nActive CLI Sessions:\n");
    printf("%-5s %-20s %-20s %-20s\n", "ID", "Connected", "Last Activity", "Client");
    printf("-----------------------------------------------------------------------\n");

    pthread_mutex_lock(&g_session_lock);

    int count = 0;
    for (int i = 0; i < CLI_SOCKET_MAX_SESSIONS; i++) {
        if (g_sessions[i].active) {
            char connect_time[32], activity_time[32];
            struct tm *tm_info;

            tm_info = localtime(&g_sessions[i].connect_time);
            strftime(connect_time, sizeof(connect_time), "%Y-%m-%d %H:%M:%S", tm_info);

            tm_info = localtime(&g_sessions[i].last_activity);
            strftime(activity_time, sizeof(activity_time), "%Y-%m-%d %H:%M:%S", tm_info);

            printf("%-5d %-20s %-20s %-20s\n", i, connect_time, activity_time,
                   g_sessions[i].client_info);
            count++;
        }
    }

    pthread_mutex_unlock(&g_session_lock);

    if (count == 0) {
        printf("  (no active sessions)\n");
    }
    printf("\nTotal: %d session(s)\n\n", count);
}
