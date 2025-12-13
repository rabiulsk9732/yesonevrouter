/**
 * @file control_plane.h
 * @brief Control Plane Thread - Event Loop for CLI, RADIUS, Timers
 *
 * Separate from DPDK data plane for:
 * - CLI socket handling
 * - RADIUS client (UDP)
 * - Timer management
 * - Signal handling
 */

#ifndef _CONTROL_PLANE_H
#define _CONTROL_PLANE_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <signal.h>

#define CP_MAX_EVENTS       64
#define CP_MAX_TIMERS       1024
#define CP_MAX_FDS          256

/* Event types */
typedef enum {
    CP_EVENT_CLI,           /* CLI socket */
    CP_EVENT_RADIUS,        /* RADIUS UDP */
    CP_EVENT_TIMER,         /* Timer expiry */
    CP_EVENT_SIGNAL,        /* Signal received */
    CP_EVENT_CUSTOM         /* Custom handler */
} cp_event_type_t;

/* Timer callback */
typedef void (*cp_timer_cb_t)(void *arg);

/* FD event callback */
typedef void (*cp_fd_cb_t)(int fd, uint32_t events, void *arg);

/* Timer structure */
struct cp_timer {
    int fd;                     /* timerfd */
    cp_timer_cb_t callback;
    void *arg;
    uint64_t interval_ms;       /* 0 = one-shot */
    bool active;
    const char *name;           /* For debugging */
};

/* FD handler structure */
struct cp_fd_handler {
    int fd;
    cp_event_type_t type;
    cp_fd_cb_t read_cb;
    cp_fd_cb_t write_cb;
    void *arg;
    bool active;
};

/* Control plane context */
struct control_plane {
    int epoll_fd;
    int signal_fd;
    volatile bool running;
    volatile bool reload_pending;

    /* Registered handlers */
    struct cp_fd_handler fd_handlers[CP_MAX_FDS];
    int fd_handler_count;

    /* Timers */
    struct cp_timer timers[CP_MAX_TIMERS];
    int timer_count;

    /* Statistics */
    uint64_t events_processed;
    uint64_t timers_fired;
    uint64_t signals_received;
};

/* Global control plane instance */
extern struct control_plane g_control_plane;

/* Initialization */
int cp_init(void);
void cp_cleanup(void);

/* Main loop */
int cp_run(void);
void cp_stop(void);

/* FD registration */
int cp_register_fd(int fd, cp_event_type_t type, cp_fd_cb_t read_cb,
                   cp_fd_cb_t write_cb, void *arg);
int cp_unregister_fd(int fd);
int cp_modify_fd(int fd, bool enable_read, bool enable_write);

/* Timer management */
struct cp_timer *cp_timer_create(const char *name, uint64_t interval_ms,
                                  cp_timer_cb_t callback, void *arg);
int cp_timer_start(struct cp_timer *timer);
int cp_timer_stop(struct cp_timer *timer);
int cp_timer_reset(struct cp_timer *timer, uint64_t interval_ms);
void cp_timer_destroy(struct cp_timer *timer);

/* Signal handling */
void cp_request_reload(void);
void cp_request_shutdown(void);

/* Utility */
uint64_t cp_get_time_ms(void);

#endif /* _CONTROL_PLANE_H */
