/**
 * @file ssh_server.c
 * @brief SSH Server Implementation for CLI Access
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#include "ssh_server.h"
#include "user_db.h"
#include "cli_session.h"
#include "log.h"

#define SSH_MAX_SESSIONS 10
#define SSH_BUFFER_SIZE 4096

/* SSH session */
struct ssh_session {
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

    struct ssh_session sessions[SSH_MAX_SESSIONS];
    int session_count;
    pthread_mutex_t lock;
} g_ssh = {
    .listen_fd = -1,
    .port = 22,
    .max_sessions = SSH_MAX_SESSIONS,
    .timeout = 300,
    .lock = PTHREAD_MUTEX_INITIALIZER
};

static void *ssh_session_handler(void *arg)
{
    struct ssh_session *sess = (struct ssh_session *)arg;
    char buf[SSH_BUFFER_SIZE];
    char prompt[64];

    /* Send banner */
    const char *banner =
        "\r\n"
        "YESRouter vBNG - SSH Access\r\n"
        "Authorized access only.\r\n"
        "\r\n";
    send(sess->fd, banner, strlen(banner), 0);

    /* Authentication */
    int attempts = 3;
    while (attempts > 0 && !sess->authenticated) {
        /* Username */
        send(sess->fd, "Username: ", 10, 0);
        ssize_t n = recv(sess->fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) goto cleanup;
        buf[n] = '\0';
        /* Strip newline */
        char *nl = strchr(buf, '\r');
        if (nl) *nl = '\0';
        nl = strchr(buf, '\n');
        if (nl) *nl = '\0';
        /* Copy username with length limit */
        size_t ulen = strlen(buf);
        if (ulen > 31) ulen = 31;
        memcpy(sess->username, buf, ulen);
        sess->username[ulen] = '\0';

        /* Password (disable echo) */
        send(sess->fd, "Password: ", 10, 0);
        n = recv(sess->fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) goto cleanup;
        buf[n] = '\0';
        nl = strchr(buf, '\r');
        if (nl) *nl = '\0';
        nl = strchr(buf, '\n');
        if (nl) *nl = '\0';
        send(sess->fd, "\r\n", 2, 0);

        /* Verify */
        if (user_db_verify_password(sess->username, buf) == 0) {
            struct user *user = user_db_find(sess->username);
            if (user) {
                sess->privilege = user->privilege_level;
                sess->authenticated = true;
                user_db_update_last_login(sess->username);
                YLOG_INFO("SSH: User '%s' authenticated", sess->username);
            }
        }

        if (!sess->authenticated) {
            send(sess->fd, "Authentication failed.\r\n", 24, 0);
            attempts--;
            YLOG_WARNING("SSH: Failed login for '%s' (%d attempts left)",
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

    while (g_ssh.running && sess->authenticated) {
        send(sess->fd, prompt, strlen(prompt), 0);

        ssize_t n = recv(sess->fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = '\0';

        /* Strip newlines */
        char *nl = strchr(buf, '\r');
        if (nl) *nl = '\0';
        nl = strchr(buf, '\n');
        if (nl) *nl = '\0';

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

    pthread_mutex_lock(&g_ssh.lock);
    g_ssh.session_count--;
    pthread_mutex_unlock(&g_ssh.lock);

    YLOG_INFO("SSH: Session %d closed", sess->session_id);
    return NULL;
}

static void *ssh_accept_thread(void *arg)
{
    (void)arg;

    while (g_ssh.running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(g_ssh.listen_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) continue;

        pthread_mutex_lock(&g_ssh.lock);

        if (g_ssh.session_count >= g_ssh.max_sessions) {
            const char *msg = "Too many sessions. Try again later.\r\n";
            send(client_fd, msg, strlen(msg), 0);
            close(client_fd);
            pthread_mutex_unlock(&g_ssh.lock);
            continue;
        }

        /* Find free slot */
        struct ssh_session *sess = NULL;
        for (int i = 0; i < SSH_MAX_SESSIONS; i++) {
            if (g_ssh.sessions[i].fd < 0) {
                sess = &g_ssh.sessions[i];
                sess->session_id = i;
                break;
            }
        }

        if (sess) {
            sess->fd = client_fd;
            sess->authenticated = false;
            g_ssh.session_count++;

            pthread_create(&sess->thread, NULL, ssh_session_handler, sess);
            pthread_detach(sess->thread);

            YLOG_INFO("SSH: New connection (session %d)", sess->session_id);
        } else {
            close(client_fd);
        }

        pthread_mutex_unlock(&g_ssh.lock);
    }

    return NULL;
}

int ssh_server_init(uint16_t port)
{
    g_ssh.port = port;
    g_ssh.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_ssh.listen_fd < 0) {
        YLOG_ERROR("SSH: Failed to create socket");
        return -1;
    }

    int opt = 1;
    setsockopt(g_ssh.listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY)
    };

    if (bind(g_ssh.listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        YLOG_ERROR("SSH: Failed to bind port %u", port);
        close(g_ssh.listen_fd);
        return -1;
    }

    if (listen(g_ssh.listen_fd, 5) < 0) {
        YLOG_ERROR("SSH: Failed to listen");
        close(g_ssh.listen_fd);
        return -1;
    }

    /* Initialize sessions */
    for (int i = 0; i < SSH_MAX_SESSIONS; i++) {
        g_ssh.sessions[i].fd = -1;
    }

    g_ssh.running = 1;
    pthread_create(&g_ssh.accept_thread, NULL, ssh_accept_thread, NULL);

    YLOG_INFO("SSH Server: Started on port %u", port);
    return 0;
}

void ssh_server_set_timeout(int seconds)
{
    g_ssh.timeout = seconds;
}

void ssh_server_set_max_sessions(int max)
{
    if (max > 0 && max <= SSH_MAX_SESSIONS) {
        g_ssh.max_sessions = max;
    }
}

void ssh_server_show_sessions(void)
{
    pthread_mutex_lock(&g_ssh.lock);

    printf("SSH Sessions (%d active):\n", g_ssh.session_count);
    printf("%-8s %-16s %-10s %s\n", "ID", "Username", "Privilege", "Status");

    for (int i = 0; i < SSH_MAX_SESSIONS; i++) {
        if (g_ssh.sessions[i].fd >= 0) {
            const char *priv = g_ssh.sessions[i].privilege == 0 ? "admin" :
                              g_ssh.sessions[i].privilege == 1 ? "operator" : "viewer";
            printf("%-8d %-16s %-10s %s\n",
                   i, g_ssh.sessions[i].username, priv,
                   g_ssh.sessions[i].authenticated ? "active" : "auth");
        }
    }

    pthread_mutex_unlock(&g_ssh.lock);
}

void ssh_server_disconnect(int session_id)
{
    if (session_id < 0 || session_id >= SSH_MAX_SESSIONS) return;

    pthread_mutex_lock(&g_ssh.lock);

    if (g_ssh.sessions[session_id].fd >= 0) {
        close(g_ssh.sessions[session_id].fd);
        g_ssh.sessions[session_id].fd = -1;
        g_ssh.sessions[session_id].authenticated = false;
        YLOG_INFO("SSH: Disconnected session %d", session_id);
    }

    pthread_mutex_unlock(&g_ssh.lock);
}

void ssh_server_cleanup(void)
{
    g_ssh.running = 0;

    if (g_ssh.listen_fd >= 0) {
        close(g_ssh.listen_fd);
        g_ssh.listen_fd = -1;
    }

    /* Close all sessions */
    for (int i = 0; i < SSH_MAX_SESSIONS; i++) {
        if (g_ssh.sessions[i].fd >= 0) {
            close(g_ssh.sessions[i].fd);
            g_ssh.sessions[i].fd = -1;
        }
    }

    pthread_mutex_destroy(&g_ssh.lock);
    YLOG_INFO("SSH Server: Stopped");
}
