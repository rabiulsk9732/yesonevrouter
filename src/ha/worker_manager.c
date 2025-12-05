/**
 * @file worker_manager.c
 * @brief Worker Process Management with Auto-Respawn
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>

#include "worker_manager.h"
#include "log.h"

#define MAX_WORKERS 16
#define RESPAWN_DELAY_SEC 2
#define MAX_RESPAWN_ATTEMPTS 5

/* Worker state */
typedef enum {
    WORKER_STOPPED,
    WORKER_STARTING,
    WORKER_RUNNING,
    WORKER_CRASHED,
    WORKER_DISABLED
} worker_state_t;

/* Worker info */
struct worker {
    int id;
    pid_t pid;
    worker_state_t state;
    worker_func_t func;
    void *arg;
    int respawn_count;
    time_t last_crash;
    char name[32];
};

static struct {
    struct worker workers[MAX_WORKERS];
    int count;
    volatile int running;
    pthread_t monitor_thread;
    pthread_mutex_t lock;
} g_wm = {
    .lock = PTHREAD_MUTEX_INITIALIZER
};

static void *worker_wrapper(void *arg)
{
    struct worker *w = (struct worker *)arg;

    YLOG_INFO("Worker: %s (id=%d) starting", w->name, w->id);

    if (w->func) {
        w->func(w->id, w->arg);
    }

    return NULL;
}

static void *monitor_thread_func(void *arg)
{
    (void)arg;

    while (g_wm.running) {
        pthread_mutex_lock(&g_wm.lock);

        for (int i = 0; i < g_wm.count; i++) {
            struct worker *w = &g_wm.workers[i];

            if (w->state == WORKER_RUNNING && w->pid > 0) {
                /* Check if process is still alive (for fork-based workers) */
                int status;
                pid_t result = waitpid(w->pid, &status, WNOHANG);

                if (result == w->pid) {
                    /* Worker exited */
                    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                        YLOG_INFO("Worker: %s exited normally", w->name);
                        w->state = WORKER_STOPPED;
                    } else {
                        YLOG_WARNING("Worker: %s crashed (status=%d)", w->name, status);
                        w->state = WORKER_CRASHED;
                        w->last_crash = time(NULL);
                    }
                }
            }

            /* Auto-respawn crashed workers */
            if (w->state == WORKER_CRASHED && w->respawn_count < MAX_RESPAWN_ATTEMPTS) {
                time_t now = time(NULL);
                if (now - w->last_crash >= RESPAWN_DELAY_SEC) {
                    w->respawn_count++;
                    YLOG_INFO("Worker: Respawning %s (attempt %d/%d)",
                              w->name, w->respawn_count, MAX_RESPAWN_ATTEMPTS);

                    /* Fork new worker */
                    pid_t pid = fork();
                    if (pid == 0) {
                        /* Child */
                        worker_wrapper(w);
                        exit(0);
                    } else if (pid > 0) {
                        w->pid = pid;
                        w->state = WORKER_RUNNING;
                    } else {
                        YLOG_ERROR("Worker: Failed to respawn %s", w->name);
                    }
                }
            }

            /* Disable worker after too many respawns */
            if (w->respawn_count >= MAX_RESPAWN_ATTEMPTS && w->state == WORKER_CRASHED) {
                YLOG_ERROR("Worker: %s disabled after %d respawn attempts",
                           w->name, MAX_RESPAWN_ATTEMPTS);
                w->state = WORKER_DISABLED;
            }
        }

        pthread_mutex_unlock(&g_wm.lock);

        sleep(1);
    }

    return NULL;
}

int worker_manager_init(void)
{
    memset(&g_wm, 0, sizeof(g_wm) - sizeof(pthread_mutex_t));
    pthread_mutex_init(&g_wm.lock, NULL);

    g_wm.running = 1;
    pthread_create(&g_wm.monitor_thread, NULL, monitor_thread_func, NULL);

    YLOG_INFO("Worker Manager: Initialized");
    return 0;
}

int worker_create(const char *name, worker_func_t func, void *arg)
{
    pthread_mutex_lock(&g_wm.lock);

    if (g_wm.count >= MAX_WORKERS) {
        pthread_mutex_unlock(&g_wm.lock);
        return -1;
    }

    struct worker *w = &g_wm.workers[g_wm.count];
    w->id = g_wm.count;
    w->func = func;
    w->arg = arg;
    w->state = WORKER_STOPPED;
    w->respawn_count = 0;
    snprintf(w->name, sizeof(w->name), "%s", name ? name : "worker");

    g_wm.count++;

    pthread_mutex_unlock(&g_wm.lock);

    YLOG_INFO("Worker Manager: Created worker '%s' (id=%d)", w->name, w->id);
    return w->id;
}

int worker_start(int worker_id)
{
    if (worker_id < 0 || worker_id >= g_wm.count) return -1;

    pthread_mutex_lock(&g_wm.lock);

    struct worker *w = &g_wm.workers[worker_id];

    if (w->state == WORKER_RUNNING) {
        pthread_mutex_unlock(&g_wm.lock);
        return 0; /* Already running */
    }

    pid_t pid = fork();
    if (pid == 0) {
        /* Child process */
        worker_wrapper(w);
        exit(0);
    } else if (pid > 0) {
        w->pid = pid;
        w->state = WORKER_RUNNING;
        YLOG_INFO("Worker Manager: Started '%s' (pid=%d)", w->name, pid);
    } else {
        pthread_mutex_unlock(&g_wm.lock);
        return -1;
    }

    pthread_mutex_unlock(&g_wm.lock);
    return 0;
}

int worker_stop(int worker_id)
{
    if (worker_id < 0 || worker_id >= g_wm.count) return -1;

    pthread_mutex_lock(&g_wm.lock);

    struct worker *w = &g_wm.workers[worker_id];

    if (w->state == WORKER_RUNNING && w->pid > 0) {
        kill(w->pid, SIGTERM);
        usleep(100000); /* 100ms grace */
        kill(w->pid, SIGKILL);
        waitpid(w->pid, NULL, 0);
        w->state = WORKER_STOPPED;
        YLOG_INFO("Worker Manager: Stopped '%s'", w->name);
    }

    pthread_mutex_unlock(&g_wm.lock);
    return 0;
}

void worker_restart(int worker_id)
{
    worker_stop(worker_id);
    usleep(100000);
    worker_start(worker_id);
}

void worker_reset_respawn_count(int worker_id)
{
    if (worker_id < 0 || worker_id >= g_wm.count) return;

    pthread_mutex_lock(&g_wm.lock);
    g_wm.workers[worker_id].respawn_count = 0;
    if (g_wm.workers[worker_id].state == WORKER_DISABLED) {
        g_wm.workers[worker_id].state = WORKER_STOPPED;
    }
    pthread_mutex_unlock(&g_wm.lock);
}

void worker_show_status(void)
{
    pthread_mutex_lock(&g_wm.lock);

    printf("Worker Status (%d workers):\n", g_wm.count);
    printf("%-8s %-16s %-10s %-8s %s\n", "ID", "Name", "State", "PID", "Respawns");

    for (int i = 0; i < g_wm.count; i++) {
        struct worker *w = &g_wm.workers[i];
        const char *state = w->state == WORKER_RUNNING ? "RUNNING" :
                           w->state == WORKER_STOPPED ? "STOPPED" :
                           w->state == WORKER_CRASHED ? "CRASHED" :
                           w->state == WORKER_DISABLED ? "DISABLED" : "UNKNOWN";
        printf("%-8d %-16s %-10s %-8d %d/%d\n",
               w->id, w->name, state, w->pid, w->respawn_count, MAX_RESPAWN_ATTEMPTS);
    }

    pthread_mutex_unlock(&g_wm.lock);
}

void worker_manager_cleanup(void)
{
    g_wm.running = 0;
    pthread_join(g_wm.monitor_thread, NULL);

    /* Stop all workers */
    for (int i = 0; i < g_wm.count; i++) {
        worker_stop(i);
    }

    pthread_mutex_destroy(&g_wm.lock);
    YLOG_INFO("Worker Manager: Cleanup complete");
}
