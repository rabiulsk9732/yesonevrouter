/**
 * @file cli_session.c
 * @brief CLI Session Management with Command Authorization
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

#include "cli_session.h"
#include "audit_log.h"
#include "log.h"

#define MAX_CLI_SESSIONS 32

/* CLI session */
struct cli_session {
    int id;
    int transport_id;  /* SSH/Telnet session ID */
    char username[32];
    uint8_t privilege;
    time_t created;
    time_t last_activity;
    bool active;
};

/* Command authorization rules */
struct cmd_auth_rule {
    const char *command;
    uint8_t min_privilege;  /* Minimum privilege required */
};

static struct cmd_auth_rule g_auth_rules[] = {
    /* Level 2 (Viewer) - Read only */
    { "show", 2 },
    { "ping", 2 },
    { "traceroute", 2 },
    { "help", 2 },
    { "?", 2 },
    { "exit", 2 },
    { "logout", 2 },

    /* Level 1 (Operator) - Configuration */
    { "interface", 1 },
    { "ip", 1 },
    { "route", 1 },
    { "pppoe", 1 },
    { "radius", 1 },
    { "qos", 1 },
    { "clear", 1 },
    { "debug", 1 },
    { "no", 1 },

    /* Level 0 (Admin) - Full access */
    { "username", 0 },
    { "enable", 0 },
    { "configure", 0 },
    { "shutdown", 0 },
    { "reload", 0 },
    { "copy", 0 },
    { "write", 0 },

    { NULL, 0 }
};

static struct {
    struct cli_session sessions[MAX_CLI_SESSIONS];
    int count;
    pthread_mutex_t lock;
} g_cli = {
    .lock = PTHREAD_MUTEX_INITIALIZER
};

int cli_session_init(void)
{
    memset(&g_cli.sessions, 0, sizeof(g_cli.sessions));
    g_cli.count = 0;
    pthread_mutex_init(&g_cli.lock, NULL);

    YLOG_INFO("CLI Session: Initialized");
    return 0;
}

int cli_session_create(int transport_id, const char *username, uint8_t privilege)
{
    pthread_mutex_lock(&g_cli.lock);

    /* Find free slot */
    int id = -1;
    for (int i = 0; i < MAX_CLI_SESSIONS; i++) {
        if (!g_cli.sessions[i].active) {
            id = i;
            break;
        }
    }

    if (id < 0) {
        pthread_mutex_unlock(&g_cli.lock);
        return -1;
    }

    struct cli_session *s = &g_cli.sessions[id];
    s->id = id;
    s->transport_id = transport_id;
    snprintf(s->username, sizeof(s->username), "%s", username);
    s->privilege = privilege;
    s->created = time(NULL);
    s->last_activity = s->created;
    s->active = true;

    g_cli.count++;

    pthread_mutex_unlock(&g_cli.lock);

    audit_log_event("SESSION_START", username, "CLI session created");
    YLOG_INFO("CLI Session: Created session %d for user '%s' (priv=%d)",
              id, username, privilege);
    return id;
}

void cli_session_destroy(int session_id)
{
    if (session_id < 0 || session_id >= MAX_CLI_SESSIONS) return;

    pthread_mutex_lock(&g_cli.lock);

    if (g_cli.sessions[session_id].active) {
        audit_log_event("SESSION_END", g_cli.sessions[session_id].username,
                        "CLI session ended");
        g_cli.sessions[session_id].active = false;
        g_cli.count--;
    }

    pthread_mutex_unlock(&g_cli.lock);
}

int cli_session_check_auth(int session_id, const char *command)
{
    if (session_id < 0 || session_id >= MAX_CLI_SESSIONS) return -1;
    if (!command) return -1;

    pthread_mutex_lock(&g_cli.lock);

    struct cli_session *s = &g_cli.sessions[session_id];
    if (!s->active) {
        pthread_mutex_unlock(&g_cli.lock);
        return -1;
    }

    uint8_t user_priv = s->privilege;
    pthread_mutex_unlock(&g_cli.lock);

    /* Get first word of command */
    char cmd_word[64];
    const char *space = strchr(command, ' ');
    if (space) {
        size_t len = space - command;
        if (len >= sizeof(cmd_word)) len = sizeof(cmd_word) - 1;
        strncpy(cmd_word, command, len);
        cmd_word[len] = '\0';
    } else {
        strncpy(cmd_word, command, sizeof(cmd_word) - 1);
        cmd_word[sizeof(cmd_word) - 1] = '\0';
    }

    /* Check authorization rules */
    for (int i = 0; g_auth_rules[i].command != NULL; i++) {
        if (strcmp(g_auth_rules[i].command, cmd_word) == 0) {
            if (user_priv <= g_auth_rules[i].min_privilege) {
                return 0; /* Authorized */
            } else {
                return -1; /* Not authorized */
            }
        }
    }

    /* Unknown command - allow for viewer and above */
    return (user_priv <= 2) ? 0 : -1;
}

int cli_session_execute(int session_id, const char *command, char *output, size_t output_size)
{
    if (!command || !output) return -1;

    /* Update activity */
    if (session_id >= 0 && session_id < MAX_CLI_SESSIONS) {
        pthread_mutex_lock(&g_cli.lock);
        if (g_cli.sessions[session_id].active) {
            g_cli.sessions[session_id].last_activity = time(NULL);
        }
        pthread_mutex_unlock(&g_cli.lock);
    }

    /* Check authorization */
    if (cli_session_check_auth(session_id, command) != 0) {
        snprintf(output, output_size,
                 "\r\n%% Authorization denied. Insufficient privilege level.\r\n");

        /* Audit log */
        pthread_mutex_lock(&g_cli.lock);
        if (g_cli.sessions[session_id].active) {
            audit_log_event("AUTH_DENIED", g_cli.sessions[session_id].username, command);
        }
        pthread_mutex_unlock(&g_cli.lock);

        return -1;
    }

    /* Audit log command execution */
    pthread_mutex_lock(&g_cli.lock);
    if (g_cli.sessions[session_id].active) {
        audit_log_event("COMMAND", g_cli.sessions[session_id].username, command);
    }
    pthread_mutex_unlock(&g_cli.lock);

    /* Execute command via CLI */
    extern int cli_execute(const char *cmdline);

    /* Capture output by redirecting stdout temporarily */
    fflush(stdout);
    int old_stdout = dup(STDOUT_FILENO);
    int pipefd[2];
    if (pipe(pipefd) == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        cli_execute(command);
        fflush(stdout);

        dup2(old_stdout, STDOUT_FILENO);
        close(old_stdout);

        /* Read from pipe */
        ssize_t n = read(pipefd[0], output, output_size - 1);
        close(pipefd[0]);
        if (n > 0) {
            output[n] = '\0';
        } else {
            snprintf(output, output_size, "\r\n");
        }
    } else {
        close(old_stdout);
        cli_execute(command);
        snprintf(output, output_size, "\r\n");
    }

    return 0;
}

int cli_session_help(int session_id, const char *partial, char *output, size_t output_size)
{
    if (!output) return -1;

    /* Update activity */
    if (session_id >= 0 && session_id < MAX_CLI_SESSIONS) {
        pthread_mutex_lock(&g_cli.lock);
        if (g_cli.sessions[session_id].active) {
            g_cli.sessions[session_id].last_activity = time(NULL);
        }
        pthread_mutex_unlock(&g_cli.lock);
    }

    /* Capture output by redirecting stdout temporarily */
    fflush(stdout);
    int old_stdout = dup(STDOUT_FILENO);
    int pipefd[2];
    if (pipe(pipefd) == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        extern void show_context_help(const char *partial);
        show_context_help(partial);
        fflush(stdout);

        dup2(old_stdout, STDOUT_FILENO);
        close(old_stdout);

        /* Read from pipe */
        ssize_t n = read(pipefd[0], output, output_size - 1);
        close(pipefd[0]);
        if (n > 0) {
            output[n] = '\0';
        } else {
            snprintf(output, output_size, "\r\n");
        }
    } else {
        close(old_stdout);
        extern void show_context_help(const char *partial);
        show_context_help(partial);
        snprintf(output, output_size, "\r\n");
    }

    return 0;
}

void cli_session_show_all(void)
{
    pthread_mutex_lock(&g_cli.lock);

    printf("CLI Sessions (%d active):\n", g_cli.count);
    printf("%-6s %-16s %-10s %-20s %s\n", "ID", "Username", "Privilege", "Created", "Last Activity");

    for (int i = 0; i < MAX_CLI_SESSIONS; i++) {
        struct cli_session *s = &g_cli.sessions[i];
        if (s->active) {
            char created[32], activity[32];
            struct tm *tm = localtime(&s->created);
            strftime(created, sizeof(created), "%H:%M:%S", tm);
            tm = localtime(&s->last_activity);
            strftime(activity, sizeof(activity), "%H:%M:%S", tm);

            const char *priv = s->privilege == 0 ? "admin" :
                              s->privilege == 1 ? "operator" : "viewer";

            printf("%-6d %-16s %-10s %-20s %s\n",
                   s->id, s->username, priv, created, activity);
        }
    }

    pthread_mutex_unlock(&g_cli.lock);
}

void cli_session_cleanup(void)
{
    pthread_mutex_destroy(&g_cli.lock);
    g_cli.count = 0;
    YLOG_INFO("CLI Session: Cleanup complete");
}
