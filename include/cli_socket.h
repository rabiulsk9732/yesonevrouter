/**
 * @file cli_socket.h
 * @brief Unix Socket CLI Server Interface
 *
 * Provides VPP-style CLI access via Unix domain socket.
 * Allows multiple concurrent CLI sessions without shutting down daemon.
 */

#ifndef CLI_SOCKET_H
#define CLI_SOCKET_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define CLI_SOCKET_MAX_SESSIONS 16
#define CLI_SOCKET_DEFAULT_PATH "/run/yesrouter/cli.sock"

/**
 * CLI Session state
 */
struct cli_socket_session {
    int socket_fd;        /* Client socket file descriptor */
    pthread_t thread;     /* Session handler thread */
    bool active;          /* Session is active */
    time_t connect_time;  /* Connection timestamp */
    time_t last_activity; /* Last command timestamp */
    char client_info[64]; /* Client identification */
    int session_id;       /* Unique session ID */
};

/**
 * Initialize CLI socket server
 * @param socket_path Path to Unix socket (NULL for default)
 * @return 0 on success, -1 on error
 */
int cli_socket_server_init(const char *socket_path);

/**
 * Start CLI socket server (non-blocking)
 * Creates acceptor thread to handle incoming connections
 * @return 0 on success, -1 on error
 */
int cli_socket_server_start(void);

/**
 * Stop CLI socket server
 * Closes all active sessions and removes socket file
 */
void cli_socket_server_stop(void);

/**
 * Get number of active CLI sessions
 * @return Number of active sessions
 */
int cli_socket_get_session_count(void);

/**
 * Display active CLI sessions
 * Used by 'show cli-sessions' command
 */
void cli_socket_show_sessions(void);

#endif /* CLI_SOCKET_H */
