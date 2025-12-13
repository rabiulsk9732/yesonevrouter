/**
 * @file daemon.h
 * @brief YESRouter Daemon - Main Service Controller
 *
 * Manages:
 * - Daemonization
 * - PID file
 * - Control plane thread
 * - Data plane (DPDK) thread
 * - Graceful shutdown
 * - systemd notification
 */

#ifndef _DAEMON_H
#define _DAEMON_H

#include <stdint.h>
#include <stdbool.h>

/* Daemon state */
typedef enum {
    DAEMON_STATE_INIT,
    DAEMON_STATE_STARTING,
    DAEMON_STATE_RUNNING,
    DAEMON_STATE_RELOADING,
    DAEMON_STATE_STOPPING,
    DAEMON_STATE_STOPPED
} daemon_state_t;

/* Daemon configuration */
struct daemon_config {
    const char *config_file;        /* Main config file */
    const char *pid_file;           /* PID file path */
    const char *cli_socket;         /* CLI socket path */
    bool daemonize;                 /* Run as daemon */
    bool foreground;                /* Stay in foreground */
    int log_level;                  /* Log verbosity */
};

/* Daemon context */
struct daemon_ctx {
    daemon_state_t state;
    pid_t pid;

    /* Threads */
    pthread_t control_thread;
    pthread_t dpdk_thread;

    /* Configuration */
    struct daemon_config config;

    /* Statistics */
    uint64_t start_time;
    uint64_t uptime_sec;
};

/* Global daemon context */
extern struct daemon_ctx g_daemon;

/* Initialization */
int daemon_init(struct daemon_config *config);
void daemon_cleanup(void);

/* Main entry */
int daemon_run(void);
void daemon_stop(void);

/* State management */
daemon_state_t daemon_get_state(void);
const char *daemon_state_str(daemon_state_t state);

/* PID file */
int daemon_write_pid(const char *path);
int daemon_remove_pid(const char *path);

/* systemd notification */
void daemon_notify_ready(void);
void daemon_notify_stopping(void);
void daemon_notify_reloading(void);
void daemon_notify_status(const char *status);

/* Config reload */
int daemon_reload_config(void);

#endif /* _DAEMON_H */
