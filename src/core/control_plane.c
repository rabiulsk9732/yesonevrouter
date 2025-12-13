/**
 * @file control_plane.c
 * @brief Control Plane Implementation - epoll-based event loop
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <time.h>

#include "control_plane.h"
#include "log.h"

/* Global control plane instance */
struct control_plane g_control_plane = {0};

/* Forward declarations */
static void cp_handle_signal(int fd);
static void cp_handle_timer(struct cp_timer *timer);

/*============================================================================
 * Utility Functions
 *============================================================================*/

uint64_t cp_get_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*============================================================================
 * Initialization
 *============================================================================*/

int cp_init(void)
{
    struct control_plane *cp = &g_control_plane;
    sigset_t mask;

    memset(cp, 0, sizeof(*cp));

    /* Create epoll instance */
    cp->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (cp->epoll_fd < 0) {
        YLOG_ERROR("Failed to create epoll: %s", strerror(errno));
        return -1;
    }

    /* Block signals we want to handle via signalfd */
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL) < 0) {
        YLOG_ERROR("Failed to block signals: %s", strerror(errno));
        close(cp->epoll_fd);
        return -1;
    }

    /* Create signalfd */
    cp->signal_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (cp->signal_fd < 0) {
        YLOG_ERROR("Failed to create signalfd: %s", strerror(errno));
        close(cp->epoll_fd);
        return -1;
    }

    /* Register signalfd with epoll */
    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.fd = cp->signal_fd
    };
    if (epoll_ctl(cp->epoll_fd, EPOLL_CTL_ADD, cp->signal_fd, &ev) < 0) {
        YLOG_ERROR("Failed to add signalfd to epoll: %s", strerror(errno));
        close(cp->signal_fd);
        close(cp->epoll_fd);
        return -1;
    }

    cp->running = false;
    YLOG_INFO("Control plane initialized");

    return 0;
}

void cp_cleanup(void)
{
    struct control_plane *cp = &g_control_plane;

    /* Stop all timers */
    for (int i = 0; i < cp->timer_count; i++) {
        if (cp->timers[i].active) {
            cp_timer_stop(&cp->timers[i]);
        }
        if (cp->timers[i].fd >= 0) {
            close(cp->timers[i].fd);
        }
    }

    /* Close signal fd */
    if (cp->signal_fd >= 0) {
        close(cp->signal_fd);
        cp->signal_fd = -1;
    }

    /* Close epoll fd */
    if (cp->epoll_fd >= 0) {
        close(cp->epoll_fd);
        cp->epoll_fd = -1;
    }

    YLOG_INFO("Control plane cleanup complete");
}

/*============================================================================
 * FD Registration
 *============================================================================*/

int cp_register_fd(int fd, cp_event_type_t type, cp_fd_cb_t read_cb,
                   cp_fd_cb_t write_cb, void *arg)
{
    struct control_plane *cp = &g_control_plane;

    if (cp->fd_handler_count >= CP_MAX_FDS) {
        YLOG_ERROR("Too many FD handlers");
        return -1;
    }

    /* Find empty slot */
    int idx = -1;
    for (int i = 0; i < CP_MAX_FDS; i++) {
        if (!cp->fd_handlers[i].active) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        YLOG_ERROR("No free FD handler slot");
        return -1;
    }

    struct cp_fd_handler *h = &cp->fd_handlers[idx];
    h->fd = fd;
    h->type = type;
    h->read_cb = read_cb;
    h->write_cb = write_cb;
    h->arg = arg;
    h->active = true;

    /* Add to epoll */
    struct epoll_event ev = {
        .events = 0,
        .data.ptr = h
    };

    if (read_cb) ev.events |= EPOLLIN;
    if (write_cb) ev.events |= EPOLLOUT;

    if (epoll_ctl(cp->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        YLOG_ERROR("Failed to add fd %d to epoll: %s", fd, strerror(errno));
        h->active = false;
        return -1;
    }

    cp->fd_handler_count++;
    return 0;
}

int cp_unregister_fd(int fd)
{
    struct control_plane *cp = &g_control_plane;

    for (int i = 0; i < CP_MAX_FDS; i++) {
        if (cp->fd_handlers[i].active && cp->fd_handlers[i].fd == fd) {
            epoll_ctl(cp->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
            cp->fd_handlers[i].active = false;
            cp->fd_handler_count--;
            return 0;
        }
    }

    return -1;
}

int cp_modify_fd(int fd, bool enable_read, bool enable_write)
{
    struct control_plane *cp = &g_control_plane;

    for (int i = 0; i < CP_MAX_FDS; i++) {
        if (cp->fd_handlers[i].active && cp->fd_handlers[i].fd == fd) {
            struct epoll_event ev = {
                .events = 0,
                .data.ptr = &cp->fd_handlers[i]
            };

            if (enable_read) ev.events |= EPOLLIN;
            if (enable_write) ev.events |= EPOLLOUT;

            return epoll_ctl(cp->epoll_fd, EPOLL_CTL_MOD, fd, &ev);
        }
    }

    return -1;
}

/*============================================================================
 * Timer Management
 *============================================================================*/

struct cp_timer *cp_timer_create(const char *name, uint64_t interval_ms,
                                  cp_timer_cb_t callback, void *arg)
{
    struct control_plane *cp = &g_control_plane;

    if (cp->timer_count >= CP_MAX_TIMERS) {
        YLOG_ERROR("Too many timers");
        return NULL;
    }

    /* Find empty slot */
    int idx = -1;
    for (int i = 0; i < CP_MAX_TIMERS; i++) {
        if (cp->timers[i].fd <= 0) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        YLOG_ERROR("No free timer slot");
        return NULL;
    }

    struct cp_timer *timer = &cp->timers[idx];

    /* Create timerfd */
    timer->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timer->fd < 0) {
        YLOG_ERROR("Failed to create timerfd: %s", strerror(errno));
        return NULL;
    }

    timer->callback = callback;
    timer->arg = arg;
    timer->interval_ms = interval_ms;
    timer->active = false;
    timer->name = name;

    /* Add to epoll */
    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.ptr = timer
    };

    if (epoll_ctl(cp->epoll_fd, EPOLL_CTL_ADD, timer->fd, &ev) < 0) {
        YLOG_ERROR("Failed to add timer to epoll: %s", strerror(errno));
        close(timer->fd);
        timer->fd = -1;
        return NULL;
    }

    cp->timer_count++;
    return timer;
}

int cp_timer_start(struct cp_timer *timer)
{
    if (!timer || timer->fd < 0) return -1;

    struct itimerspec its = {0};

    /* Initial expiry */
    its.it_value.tv_sec = timer->interval_ms / 1000;
    its.it_value.tv_nsec = (timer->interval_ms % 1000) * 1000000;

    /* Periodic interval (0 = one-shot) */
    if (timer->interval_ms > 0) {
        its.it_interval = its.it_value;
    }

    if (timerfd_settime(timer->fd, 0, &its, NULL) < 0) {
        YLOG_ERROR("Failed to arm timer %s: %s",
                   timer->name ? timer->name : "unknown", strerror(errno));
        return -1;
    }

    timer->active = true;
    return 0;
}

int cp_timer_stop(struct cp_timer *timer)
{
    if (!timer || timer->fd < 0) return -1;

    struct itimerspec its = {0};
    timerfd_settime(timer->fd, 0, &its, NULL);
    timer->active = false;

    return 0;
}

int cp_timer_reset(struct cp_timer *timer, uint64_t interval_ms)
{
    if (!timer) return -1;
    timer->interval_ms = interval_ms;
    return cp_timer_start(timer);
}

void cp_timer_destroy(struct cp_timer *timer)
{
    struct control_plane *cp = &g_control_plane;

    if (!timer || timer->fd < 0) return;

    cp_timer_stop(timer);
    epoll_ctl(cp->epoll_fd, EPOLL_CTL_DEL, timer->fd, NULL);
    close(timer->fd);
    timer->fd = -1;
    timer->callback = NULL;
    cp->timer_count--;
}

/*============================================================================
 * Signal Handling
 *============================================================================*/

static void cp_handle_signal(int fd)
{
    struct control_plane *cp = &g_control_plane;
    struct signalfd_siginfo si;
    ssize_t n;

    while ((n = read(fd, &si, sizeof(si))) == sizeof(si)) {
        cp->signals_received++;

        switch (si.ssi_signo) {
        case SIGINT:
        case SIGTERM:
            YLOG_INFO("Received signal %d, initiating shutdown", si.ssi_signo);
            cp->running = false;
            break;

        case SIGHUP:
            YLOG_INFO("Received SIGHUP, scheduling config reload");
            cp->reload_pending = true;
            break;

        case SIGUSR1:
            YLOG_INFO("Received SIGUSR1, dumping statistics");
            /* TODO: Dump stats */
            break;

        case SIGUSR2:
            YLOG_INFO("Received SIGUSR2, toggling debug");
            /* TODO: Toggle debug */
            break;

        default:
            YLOG_DEBUG("Received signal %d", si.ssi_signo);
            break;
        }
    }
}

void cp_request_reload(void)
{
    g_control_plane.reload_pending = true;
}

void cp_request_shutdown(void)
{
    g_control_plane.running = false;
}

/*============================================================================
 * Timer Event Handler
 *============================================================================*/

static void cp_handle_timer(struct cp_timer *timer)
{
    struct control_plane *cp = &g_control_plane;
    uint64_t expirations;

    /* Read to clear the timer */
    if (read(timer->fd, &expirations, sizeof(expirations)) > 0) {
        cp->timers_fired += expirations;

        if (timer->callback) {
            timer->callback(timer->arg);
        }
    }
}

/*============================================================================
 * Main Event Loop
 *============================================================================*/

int cp_run(void)
{
    struct control_plane *cp = &g_control_plane;
    struct epoll_event events[CP_MAX_EVENTS];
    int nfds;

    cp->running = true;
    YLOG_INFO("Control plane starting event loop");

    while (cp->running) {
        /* Handle pending config reload */
        if (cp->reload_pending) {
            YLOG_INFO("Reloading configuration...");
            /* TODO: Call config reload */
            cp->reload_pending = false;
        }

        /* Wait for events */
        nfds = epoll_wait(cp->epoll_fd, events, CP_MAX_EVENTS, 100);

        if (nfds < 0) {
            if (errno == EINTR) continue;
            YLOG_ERROR("epoll_wait failed: %s", strerror(errno));
            break;
        }

        /* Process events */
        for (int i = 0; i < nfds; i++) {
            cp->events_processed++;

            /* Check if it's the signal fd */
            if (events[i].data.fd == cp->signal_fd) {
                cp_handle_signal(cp->signal_fd);
                continue;
            }

            /* Check if it's a timer */
            struct cp_timer *timer = NULL;
            for (int j = 0; j < CP_MAX_TIMERS; j++) {
                if (cp->timers[j].fd > 0 &&
                    events[i].data.ptr == &cp->timers[j]) {
                    timer = &cp->timers[j];
                    break;
                }
            }

            if (timer) {
                cp_handle_timer(timer);
                continue;
            }

            /* Must be an FD handler */
            struct cp_fd_handler *h = events[i].data.ptr;
            if (h && h->active) {
                if ((events[i].events & EPOLLIN) && h->read_cb) {
                    h->read_cb(h->fd, events[i].events, h->arg);
                }
                if ((events[i].events & EPOLLOUT) && h->write_cb) {
                    h->write_cb(h->fd, events[i].events, h->arg);
                }
                if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                    if (h->read_cb) {
                        h->read_cb(h->fd, events[i].events, h->arg);
                    }
                }
            }
        }
    }

    YLOG_INFO("Control plane event loop stopped (events=%lu, timers=%lu, signals=%lu)",
              cp->events_processed, cp->timers_fired, cp->signals_received);

    return 0;
}

void cp_stop(void)
{
    g_control_plane.running = false;
}
