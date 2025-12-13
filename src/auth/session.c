/**
 * @file session.c
 * @brief Session Management Implementation
 */

#include "session.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

static struct session *g_sessions[SESSION_MAX_SESSIONS] = {0};
static uint32_t g_next_session_id = 1;
static pthread_mutex_t g_session_lock = PTHREAD_MUTEX_INITIALIZER;

/**
 * Initialize session management
 */
int session_init(void)
{
    memset(g_sessions, 0, sizeof(g_sessions));
    g_next_session_id = 1;
    YLOG_INFO("Session management initialized");
    return 0;
}

/**
 * Cleanup session management
 */
void session_cleanup(void)
{
    pthread_mutex_lock(&g_session_lock);

    for (int i = 0; i < SESSION_MAX_SESSIONS; i++) {
        struct session *sess = g_sessions[i];
        while (sess) {
            struct session *next = sess->next;
            free(sess);
            sess = next;
        }
        g_sessions[i] = NULL;
    }

    pthread_mutex_unlock(&g_session_lock);
}

/**
 * Hash function for session ID
 */
static uint32_t session_hash(uint32_t session_id)
{
    return session_id % SESSION_MAX_SESSIONS;
}

/**
 * Create a new session
 */
uint32_t session_create(session_type_t type, struct user *user, const char *remote_addr)
{
    if (!user) {
        return 0;
    }

    struct session *sess = calloc(1, sizeof(*sess));
    if (!sess) {
        return 0;
    }

    pthread_mutex_lock(&g_session_lock);

    sess->session_id = g_next_session_id++;
    sess->type = type;
    sess->state = SESSION_STATE_ACTIVE;
    sess->user = user;
    sess->login_time = time(NULL);
    sess->last_activity = sess->login_time;
    sess->idle_timeout = 600;  /* Default 10 minutes */

    if (remote_addr) {
        strncpy(sess->remote_addr, remote_addr, sizeof(sess->remote_addr) - 1);
    } else {
        strncpy(sess->remote_addr, "local", sizeof(sess->remote_addr) - 1);
    }

    /* Insert into hash table */
    uint32_t hash = session_hash(sess->session_id);
    sess->next = g_sessions[hash];
    g_sessions[hash] = sess;

    pthread_mutex_unlock(&g_session_lock);

    YLOG_INFO("Session %u created for user %s (%s)", sess->session_id, user->username, remote_addr);
    return sess->session_id;
}

/**
 * Destroy a session
 */
int session_destroy(uint32_t session_id)
{
    if (session_id == 0) {
        return -1;
    }

    pthread_mutex_lock(&g_session_lock);

    uint32_t hash = session_hash(session_id);
    struct session *sess = g_sessions[hash];
    struct session *prev = NULL;

    while (sess) {
        if (sess->session_id == session_id) {
            if (prev) {
                prev->next = sess->next;
            } else {
                g_sessions[hash] = sess->next;
            }

            YLOG_INFO("Session %u destroyed for user %s", session_id, sess->user->username);
            free(sess);
            pthread_mutex_unlock(&g_session_lock);
            return 0;
        }
        prev = sess;
        sess = sess->next;
    }

    pthread_mutex_unlock(&g_session_lock);
    return -1;
}

/**
 * Find session by ID
 */
struct session *session_find(uint32_t session_id)
{
    if (session_id == 0) {
        return NULL;
    }

    pthread_mutex_lock(&g_session_lock);

    uint32_t hash = session_hash(session_id);
    struct session *sess = g_sessions[hash];

    while (sess) {
        if (sess->session_id == session_id) {
            pthread_mutex_unlock(&g_session_lock);
            return sess;
        }
        sess = sess->next;
    }

    pthread_mutex_unlock(&g_session_lock);
    return NULL;
}

/**
 * Update session activity
 */
void session_update_activity(uint32_t session_id)
{
    struct session *sess = session_find(session_id);
    if (sess) {
        sess->last_activity = time(NULL);
        if (sess->state == SESSION_STATE_IDLE) {
            sess->state = SESSION_STATE_ACTIVE;
        }
    }
}

/**
 * Check for idle timeouts
 */
uint32_t session_check_timeouts(void)
{
    time_t now = time(NULL);
    uint32_t timed_out = 0;

    pthread_mutex_lock(&g_session_lock);

    for (int i = 0; i < SESSION_MAX_SESSIONS; i++) {
        struct session *sess = g_sessions[i];
        while (sess) {
            struct session *next = sess->next;

            if (sess->state == SESSION_STATE_ACTIVE) {
                time_t idle = now - sess->last_activity;
                if (idle > sess->idle_timeout) {
                    sess->state = SESSION_STATE_IDLE;
                    timed_out++;
                    YLOG_INFO("Session %u timed out (idle %ld seconds)", sess->session_id, idle);
                }
            }

            sess = next;
        }
    }

    pthread_mutex_unlock(&g_session_lock);
    return timed_out;
}

/**
 * Get session count
 */
uint32_t session_get_count(void)
{
    uint32_t count = 0;

    pthread_mutex_lock(&g_session_lock);

    for (int i = 0; i < SESSION_MAX_SESSIONS; i++) {
        struct session *sess = g_sessions[i];
        while (sess) {
            if (sess->state != SESSION_STATE_CLOSED) {
                count++;
            }
            sess = sess->next;
        }
    }

    pthread_mutex_unlock(&g_session_lock);
    return count;
}

/**
 * Print all sessions
 */
void session_print_all(void)
{
    printf("\n%-8s %-10s %-20s %-15s %-20s %-20s %s\n",
           "ID", "Type", "Username", "State", "Login Time", "Last Activity", "Remote");
    printf("--------------------------------------------------------------------------------\n");

    pthread_mutex_lock(&g_session_lock);

    for (int i = 0; i < SESSION_MAX_SESSIONS; i++) {
        struct session *sess = g_sessions[i];
        while (sess) {
            if (sess->state != SESSION_STATE_CLOSED) {
                const char *type_str = "Unknown";
                switch (sess->type) {
                    case SESSION_TYPE_CONSOLE: type_str = "Console"; break;
                    case SESSION_TYPE_SSH: type_str = "SSH"; break;
                    case SESSION_TYPE_TELNET: type_str = "Telnet"; break;
                }

                const char *state_str = "Unknown";
                switch (sess->state) {
                    case SESSION_STATE_ACTIVE: state_str = "Active"; break;
                    case SESSION_STATE_IDLE: state_str = "Idle"; break;
                    case SESSION_STATE_CLOSED: state_str = "Closed"; break;
                }

                char login_str[32] = "-";
                char activity_str[32] = "-";

                if (sess->login_time) {
                    struct tm *tm = localtime(&sess->login_time);
                    strftime(login_str, sizeof(login_str), "%Y-%m-%d %H:%M:%S", tm);
                }

                if (sess->last_activity) {
                    struct tm *tm = localtime(&sess->last_activity);
                    strftime(activity_str, sizeof(activity_str), "%Y-%m-%d %H:%M:%S", tm);
                }

                printf("%-8u %-10s %-20s %-15s %-20s %-20s %s\n",
                       sess->session_id,
                       type_str,
                       sess->user->username,
                       state_str,
                       login_str,
                       activity_str,
                       sess->remote_addr);
            }
            sess = sess->next;
        }
    }

    pthread_mutex_unlock(&g_session_lock);
    printf("\n");
}

/**
 * Print session details
 */
void session_print(uint32_t session_id)
{
    struct session *sess = session_find(session_id);
    if (!sess) {
        printf("Session %u not found\n", session_id);
        return;
    }

    printf("\nSession %u:\n", session_id);
    printf("  Type: ");
    switch (sess->type) {
        case SESSION_TYPE_CONSOLE: printf("Console\n"); break;
        case SESSION_TYPE_SSH: printf("SSH\n"); break;
        case SESSION_TYPE_TELNET: printf("Telnet\n"); break;
        default: printf("Unknown\n"); break;
    }
    printf("  User: %s\n", sess->user->username);
    printf("  State: ");
    switch (sess->state) {
        case SESSION_STATE_ACTIVE: printf("Active\n"); break;
        case SESSION_STATE_IDLE: printf("Idle\n"); break;
        case SESSION_STATE_CLOSED: printf("Closed\n"); break;
        default: printf("Unknown\n"); break;
    }
    printf("  Remote: %s\n", sess->remote_addr);
    printf("  Idle Timeout: %u seconds\n", sess->idle_timeout);

    if (sess->login_time) {
        char buf[64];
        struct tm *tm = localtime(&sess->login_time);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
        printf("  Login Time: %s\n", buf);
    }

    if (sess->last_activity) {
        char buf[64];
        struct tm *tm = localtime(&sess->last_activity);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
        printf("  Last Activity: %s\n", buf);
    }

    printf("\n");
}
