/**
 * @file daemon.c
 * @brief YESRouter Daemon Implementation
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "daemon.h"
#include "control_plane.h"
#include "log.h"

/* Try to include systemd if available */
#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#else
#define sd_notify(x, y) (0)
#define sd_notifyf(x, ...) (0)
#endif

/* Global daemon context */
struct daemon_ctx g_daemon = {0};

/* Forward declarations */
static void *control_plane_thread(void *arg);
static void *dpdk_thread(void *arg);

/* External DPDK main loop */
extern int dpdk_main_loop(void);
extern void dpdk_stop(void);

/*============================================================================
 * State Management
 *============================================================================*/

const char *daemon_state_str(daemon_state_t state)
{
    static const char *names[] = {
        "INIT", "STARTING", "RUNNING", "RELOADING", "STOPPING", "STOPPED"
    };
    if (state <= DAEMON_STATE_STOPPED)
        return names[state];
    return "UNKNOWN";
}

daemon_state_t daemon_get_state(void)
{
    return g_daemon.state;
}

/*============================================================================
 * PID File Management
 *============================================================================*/

int daemon_write_pid(const char *path)
{
    if (!path) return -1;

    /* Create directory if needed */
    char *dir = strdup(path);
    char *last_slash = strrchr(dir, '/');
    if (last_slash) {
        *last_slash = '\0';
        mkdir(dir, 0755);
    }
    free(dir);

    FILE *f = fopen(path, "w");
    if (!f) {
        YLOG_ERROR("Failed to create PID file %s: %s", path, strerror(errno));
        return -1;
    }

    fprintf(f, "%d\n", getpid());
    fclose(f);

    YLOG_DEBUG("PID file written: %s", path);
    return 0;
}

int daemon_remove_pid(const char *path)
{
    if (!path) return -1;
    unlink(path);
    return 0;
}

/*============================================================================
 * systemd Notification
 *============================================================================*/

void daemon_notify_ready(void)
{
    sd_notify(0, "READY=1");
    YLOG_INFO("Daemon ready");
}

void daemon_notify_stopping(void)
{
    sd_notify(0, "STOPPING=1");
    YLOG_INFO("Daemon stopping");
}

void daemon_notify_reloading(void)
{
    sd_notify(0, "RELOADING=1");
    YLOG_INFO("Daemon reloading");
}

void daemon_notify_status(const char *status)
{
    sd_notifyf(0, "STATUS=%s", status);
}

/*============================================================================
 * Initialization
 *============================================================================*/

int daemon_init(struct daemon_config *config)
{
    memset(&g_daemon, 0, sizeof(g_daemon));

    if (config) {
        g_daemon.config = *config;
    }

    g_daemon.state = DAEMON_STATE_INIT;
    g_daemon.pid = getpid();
    g_daemon.start_time = time(NULL);

    /* Initialize control plane */
    if (cp_init() < 0) {
        YLOG_ERROR("Failed to initialize control plane");
        return -1;
    }

    /* Write PID file */
    if (g_daemon.config.pid_file) {
        daemon_write_pid(g_daemon.config.pid_file);
    }

    YLOG_INFO("Daemon initialized (PID=%d)", g_daemon.pid);
    return 0;
}

void daemon_cleanup(void)
{
    g_daemon.state = DAEMON_STATE_STOPPED;

    /* Remove PID file */
    if (g_daemon.config.pid_file) {
        daemon_remove_pid(g_daemon.config.pid_file);
    }

    /* Cleanup control plane */
    cp_cleanup();

    YLOG_INFO("Daemon cleanup complete");
}

/*============================================================================
 * Thread Functions
 *============================================================================*/

static void *control_plane_thread(void *arg)
{
    (void)arg;

    YLOG_INFO("Control plane thread started");

    /* Run the event loop */
    cp_run();

    YLOG_INFO("Control plane thread exiting");
    return NULL;
}

static void *dpdk_thread(void *arg)
{
    (void)arg;

    YLOG_INFO("DPDK thread started");

    /* Run DPDK main loop */
    dpdk_main_loop();

    YLOG_INFO("DPDK thread exiting");
    return NULL;
}

/*============================================================================
 * Main Run Loop
 *============================================================================*/

int daemon_run(void)
{
    int ret = 0;

    g_daemon.state = DAEMON_STATE_STARTING;

    /* Start control plane thread */
    if (pthread_create(&g_daemon.control_thread, NULL,
                       control_plane_thread, NULL) != 0) {
        YLOG_ERROR("Failed to create control plane thread");
        return -1;
    }

    /* Note: DPDK runs on main thread or its own lcores */
    /* For now, we run control plane in background */

    g_daemon.state = DAEMON_STATE_RUNNING;
    daemon_notify_ready();
    daemon_notify_status("Running");

    /* Wait for control plane thread */
    pthread_join(g_daemon.control_thread, NULL);

    g_daemon.state = DAEMON_STATE_STOPPING;
    daemon_notify_stopping();

    return ret;
}

void daemon_stop(void)
{
    YLOG_INFO("Daemon stop requested");

    g_daemon.state = DAEMON_STATE_STOPPING;

    /* Stop control plane */
    cp_stop();

    /* Stop DPDK */
    dpdk_stop();
}

/*============================================================================
 * Config Reload
 *============================================================================*/

int daemon_reload_config(void)
{
    daemon_state_t prev_state = g_daemon.state;

    g_daemon.state = DAEMON_STATE_RELOADING;
    daemon_notify_reloading();

    YLOG_INFO("Reloading configuration...");

    /* TODO: Implement actual config reload */
    /* 1. Parse new config file */
    /* 2. Apply changes that can be applied at runtime */
    /* 3. Log what changed */

    g_daemon.state = prev_state;
    daemon_notify_ready();
    daemon_notify_status("Running (config reloaded)");

    YLOG_INFO("Configuration reload complete");
    return 0;
}
