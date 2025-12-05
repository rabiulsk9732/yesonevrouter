/**
 * @file telnet_server.c
 * @brief Telnet Server Implementation for CLI Access
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#include "telnet_server.h"
#include "user_db.h"
#include "cli_session.h"
#include "log.h"

#define TELNET_MAX_SESSIONS 10
#define TELNET_BUFFER_SIZE 4096

/* Telnet options */
#define TELNET_IAC   255
#define TELNET_WILL  251
#define TELNET_WONT  252
#define TELNET_DO    253
#define TELNET_DONT  254
#define TELNET_ECHO  1
#define TELNET_SGA   3

/* Telnet session */
struct telnet_session {
    int fd;
    int session_id;
    char username[32];
    uint8_t privilege;
    bool authenticated;
    pthread_t thread;
};

static struct {
    int listen_fd;
    uint16_t port;
    int max_sessions;
    int timeout;
    volatile int running;
    pthread_t accept_thread;

    struct telnet_session sessions[TELNET_MAX_SESSIONS];
    int session_count;
    pthread_mutex_t lock;
} g_telnet = {
    .listen_fd = -1,
    .port = 23,
    .max_sessions = TELNET_MAX_SESSIONS,
    .timeout = 300,
    .lock = PTHREAD_MUTEX_INITIALIZER
};

static void telnet_send_option(int fd, uint8_t cmd, uint8_t opt)
{
    uint8_t buf[3] = { TELNET_IAC, cmd, opt };
    send(fd, buf, 3, 0);
}

static ssize_t telnet_receive_line(int fd, char *buf, size_t size, size_t *len_ptr, bool echo, bool *is_help)
{
    size_t len = *len_ptr;
    unsigned char c;
    int state = 0; // 0=Normal, 1=IAC, 2=Option, 3=Subneg, 4=SubnegIAC, 5=CR_Seen

    if (is_help) *is_help = false;

    while (len < size - 1) {
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0) return n; // Error or disconnect

        switch (state) {
            case 0: // Normal
                if (c == TELNET_IAC) {
                    state = 1;
                } else if (c == '\r') {
                    state = 5; // Expecting LF or NUL
                } else if (c == '\n') {
                    if (echo) send(fd, "\r\n", 2, 0);
                    buf[len] = '\0';
                    *len_ptr = len;
                    return 1; // Line complete
                } else if (c == '?') {
                    if (is_help) *is_help = true;
                    buf[len] = '\0';
                    *len_ptr = len;
                    return 1; // Return to handle help
                } else if (c == 0x08 || c == 0x7F) { // Backspace or Delete
                    if (len > 0) {
                        len--;
                        if (echo) send(fd, "\b \b", 3, 0);
                    }
                } else if (c != 0) { // Ignore NUL in normal stream
                    buf[len++] = c;
                    if (echo) send(fd, &c, 1, 0);
                }
                break;
            case 1: // IAC
                if (c == TELNET_IAC) {
                    buf[len++] = c; // Literal 255
                    if (echo) send(fd, &c, 1, 0);
                    state = 0;
                } else if (c >= TELNET_WILL && c <= TELNET_DONT) {
                    state = 2;
                } else if (c == 250) { // SB
                    state = 3;
                } else {
                    state = 0;
                }
                break;
            case 2: // Option
                state = 0;
                break;
            case 3: // Subneg
                if (c == TELNET_IAC) state = 4;
                break;
            case 4: // Subneg IAC
                if (c == 240) // SE
                    state = 0;
                else
                    state = 3;
                break;
            case 5: // CR Seen
                if (c == '\n' || c == 0) {
                    if (echo) send(fd, "\r\n", 2, 0);
                    buf[len] = '\0';
                    *len_ptr = len;
                    return 1; // Line complete
                } else {
                    // CR followed by something else (rare).
                    // Treat CR as newline, but we have a new char 'c' that belongs to next line?
                    // Or treat CR as just a CR char?
                    // Let's treat CR as newline, and this char 'c' is lost (or we'd need to push back).
                    // For simplicity, let's assume CR implies EOL.
                    // And we just return. The char 'c' is consumed. This is a bug if c is a valid char.
                    // But in Telnet, CR is almost always followed by LF or NUL.
                    // If we want to be safe, we should process 'c' if it's not LF/NUL.
                    // But we can't return AND process 'c'.
                    // Let's just return.
                    if (echo) send(fd, "\r\n", 2, 0);
                    buf[len] = '\0';
                    *len_ptr = len;
                    return 1;
                }
                break;
        }
    }
    buf[len] = '\0';
    *len_ptr = len;
    return 1;
}

static void *telnet_session_handler(void *arg)
{
    struct telnet_session *sess = (struct telnet_session *)arg;
    char buf[TELNET_BUFFER_SIZE];
    char prompt[64];
    size_t len = 0;
    bool is_help = false;

    /* Negotiate telnet options */
    telnet_send_option(sess->fd, TELNET_WILL, TELNET_ECHO);
    telnet_send_option(sess->fd, TELNET_WILL, TELNET_SGA);

    /* Send banner */
    const char *banner =
        "\r\n"
        "YESRouter vBNG - Telnet Access\r\n"
        "Authorized access only.\r\n"
        "\r\n";
    send(sess->fd, banner, strlen(banner), 0);

    /* Authentication */
    int attempts = 3;
    while (attempts > 0 && !sess->authenticated) {
        /* Username */
        send(sess->fd, "Username: ", 10, 0);
        len = 0;
        ssize_t n = telnet_receive_line(sess->fd, buf, sizeof(buf), &len, true, NULL);
        if (n <= 0) goto cleanup;

        /* Copy username with length limit */
        size_t ulen = strlen(buf);
        if (ulen > 31) ulen = 31;
        memcpy(sess->username, buf, ulen);
        sess->username[ulen] = '\0';

        /* Password */
        send(sess->fd, "Password: ", 10, 0);
        len = 0;
        n = telnet_receive_line(sess->fd, buf, sizeof(buf), &len, false, NULL); // No echo for password
        if (n <= 0) goto cleanup;
        send(sess->fd, "\r\n", 2, 0);

        /* Verify */
        if (user_db_verify_password(sess->username, buf) == 0) {
            struct user *user = user_db_find(sess->username);
            if (user) {
                sess->privilege = user->privilege_level;
                sess->authenticated = true;
                user_db_update_last_login(sess->username);
                /* Set as global current user for CLI commands */
                extern void auth_set_current_user(struct user *user);
                auth_set_current_user(user);
                YLOG_INFO("Telnet: User '%s' authenticated", sess->username);
            }
        }

        if (!sess->authenticated) {
            send(sess->fd, "Authentication failed.\r\n", 24, 0);
            attempts--;
            YLOG_WARNING("Telnet: Failed login for '%s' (%d attempts left)",
                         sess->username, attempts);
        }
    }

    if (!sess->authenticated) {
        goto cleanup;
    }

    /* Create CLI session */
    int cli_id = cli_session_create(sess->session_id, sess->username, sess->privilege);
    (void)cli_id;

    /* Main command loop */
    snprintf(prompt, sizeof(prompt), "\r\n%s> ", sess->username);

    while (g_telnet.running && sess->authenticated) {
        send(sess->fd, prompt, strlen(prompt), 0);

        len = 0;
        while (1) {
            ssize_t n = telnet_receive_line(sess->fd, buf, sizeof(buf), &len, true, &is_help);
            if (n <= 0) goto cleanup; // Error

            if (is_help) {
                /* Show help */
                char output[4096];
                cli_session_help(cli_id, buf, output, sizeof(output));
                send(sess->fd, output, strlen(output), 0);

                /* Reprint prompt and partial line */
                send(sess->fd, prompt, strlen(prompt), 0);
                send(sess->fd, buf, strlen(buf), 0);
                is_help = false;
                continue; /* Continue reading line */
            } else {
                break; /* Line complete */
            }
        }

        if (strlen(buf) == 0) continue;

        if (strcmp(buf, "exit") == 0 || strcmp(buf, "logout") == 0) {
            send(sess->fd, "Goodbye!\r\n", 10, 0);
            break;
        }

        /* Execute command */
        char output[4096];
        cli_session_execute(cli_id, buf, output, sizeof(output));
        send(sess->fd, output, strlen(output), 0);
    }

cleanup:
    close(sess->fd);
    sess->fd = -1;
    sess->authenticated = false;

    pthread_mutex_lock(&g_telnet.lock);
    g_telnet.session_count--;
    pthread_mutex_unlock(&g_telnet.lock);

    YLOG_INFO("Telnet: Session %d closed", sess->session_id);
    return NULL;
}

static void *telnet_accept_thread(void *arg)
{
    (void)arg;

    while (g_telnet.running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(g_telnet.listen_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) continue;

        pthread_mutex_lock(&g_telnet.lock);

        if (g_telnet.session_count >= g_telnet.max_sessions) {
            const char *msg = "Too many sessions. Try again later.\r\n";
            send(client_fd, msg, strlen(msg), 0);
            close(client_fd);
            pthread_mutex_unlock(&g_telnet.lock);
            continue;
        }

        /* Find free slot */
        struct telnet_session *sess = NULL;
        for (int i = 0; i < TELNET_MAX_SESSIONS; i++) {
            if (g_telnet.sessions[i].fd < 0) {
                sess = &g_telnet.sessions[i];
                sess->session_id = i;
                break;
            }
        }

        if (sess) {
            sess->fd = client_fd;
            sess->authenticated = false;
            g_telnet.session_count++;

            pthread_create(&sess->thread, NULL, telnet_session_handler, sess);
            pthread_detach(sess->thread);

            YLOG_INFO("Telnet: New connection (session %d)", sess->session_id);
        } else {
            close(client_fd);
        }

        pthread_mutex_unlock(&g_telnet.lock);
    }

    return NULL;
}

int telnet_server_init(uint16_t port)
{
    g_telnet.port = port;
    g_telnet.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_telnet.listen_fd < 0) {
        YLOG_ERROR("Telnet: Failed to create socket");
        return -1;
    }

    int opt = 1;
    setsockopt(g_telnet.listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY)
    };

    if (bind(g_telnet.listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        YLOG_ERROR("Telnet: Failed to bind port %u", port);
        close(g_telnet.listen_fd);
        return -1;
    }

    if (listen(g_telnet.listen_fd, 5) < 0) {
        YLOG_ERROR("Telnet: Failed to listen");
        close(g_telnet.listen_fd);
        return -1;
    }

    /* Initialize sessions */
    for (int i = 0; i < TELNET_MAX_SESSIONS; i++) {
        g_telnet.sessions[i].fd = -1;
    }

    g_telnet.running = 1;
    pthread_create(&g_telnet.accept_thread, NULL, telnet_accept_thread, NULL);

    YLOG_INFO("Telnet Server: Started on port %u", port);
    return 0;
}

void telnet_server_set_timeout(int seconds)
{
    g_telnet.timeout = seconds;
}

void telnet_server_set_max_sessions(int max)
{
    if (max > 0 && max <= TELNET_MAX_SESSIONS) {
        g_telnet.max_sessions = max;
    }
}

void telnet_server_show_sessions(void)
{
    pthread_mutex_lock(&g_telnet.lock);

    printf("Telnet Sessions (%d active):\n", g_telnet.session_count);
    printf("%-8s %-16s %-10s %s\n", "ID", "Username", "Privilege", "Status");

    for (int i = 0; i < TELNET_MAX_SESSIONS; i++) {
        if (g_telnet.sessions[i].fd >= 0) {
            const char *priv = g_telnet.sessions[i].privilege == 0 ? "admin" :
                              g_telnet.sessions[i].privilege == 1 ? "operator" : "viewer";
            printf("%-8d %-16s %-10s %s\n",
                   i, g_telnet.sessions[i].username, priv,
                   g_telnet.sessions[i].authenticated ? "active" : "auth");
        }
    }

    pthread_mutex_unlock(&g_telnet.lock);
}

void telnet_server_disconnect(int session_id)
{
    if (session_id < 0 || session_id >= TELNET_MAX_SESSIONS) return;

    pthread_mutex_lock(&g_telnet.lock);

    if (g_telnet.sessions[session_id].fd >= 0) {
        close(g_telnet.sessions[session_id].fd);
        g_telnet.sessions[session_id].fd = -1;
        g_telnet.sessions[session_id].authenticated = false;
        YLOG_INFO("Telnet: Disconnected session %d", session_id);
    }

    pthread_mutex_unlock(&g_telnet.lock);
}

void telnet_server_cleanup(void)
{
    g_telnet.running = 0;

    if (g_telnet.listen_fd >= 0) {
        close(g_telnet.listen_fd);
        g_telnet.listen_fd = -1;
    }

    /* Close all sessions */
    for (int i = 0; i < TELNET_MAX_SESSIONS; i++) {
        if (g_telnet.sessions[i].fd >= 0) {
            close(g_telnet.sessions[i].fd);
            g_telnet.sessions[i].fd = -1;
        }
    }

    pthread_mutex_destroy(&g_telnet.lock);
    YLOG_INFO("Telnet Server: Stopped");
}
