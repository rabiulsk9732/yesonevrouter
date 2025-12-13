/**
 * @file metrics.c
 * @brief Prometheus Metrics and Stats Export
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>

#include "metrics.h"
#include "log.h"

/* Metrics storage */
static struct {
    /* Session stats */
    uint64_t sessions_total;
    uint64_t sessions_active;
    uint64_t sessions_auth_success;
    uint64_t sessions_auth_failed;

    /* Packet stats */
    uint64_t packets_rx;
    uint64_t packets_tx;
    uint64_t bytes_rx;
    uint64_t bytes_tx;

    /* PPPoE stats */
    uint64_t padi_received;
    uint64_t pado_sent;
    uint64_t padr_received;
    uint64_t pads_sent;
    uint64_t padt_sent;
    uint64_t padt_received;

    /* Errors */
    uint64_t packets_dropped;
    uint64_t auth_timeouts;
    uint64_t radius_errors;

    /* System */
    time_t start_time;

    pthread_mutex_t lock;
} g_metrics = {
    .lock = PTHREAD_MUTEX_INITIALIZER
};

int metrics_init(void)
{
    memset(&g_metrics, 0, sizeof(g_metrics) - sizeof(pthread_mutex_t));
    g_metrics.start_time = time(NULL);
    pthread_mutex_init(&g_metrics.lock, NULL);

    YLOG_INFO("Prometheus metrics initialized");
    return 0;
}

void metrics_cleanup(void)
{
    pthread_mutex_destroy(&g_metrics.lock);
}

/* Increment functions */
void metrics_inc_sessions_total(void) { __sync_fetch_and_add(&g_metrics.sessions_total, 1); }
void metrics_inc_sessions_active(void) { __sync_fetch_and_add(&g_metrics.sessions_active, 1); }
void metrics_dec_sessions_active(void) { __sync_fetch_and_sub(&g_metrics.sessions_active, 1); }
void metrics_inc_auth_success(void) { __sync_fetch_and_add(&g_metrics.sessions_auth_success, 1); }
void metrics_inc_auth_failed(void) { __sync_fetch_and_add(&g_metrics.sessions_auth_failed, 1); }
void metrics_add_packets_rx(uint64_t n) { __sync_fetch_and_add(&g_metrics.packets_rx, n); }
void metrics_add_packets_tx(uint64_t n) { __sync_fetch_and_add(&g_metrics.packets_tx, n); }
void metrics_add_bytes_rx(uint64_t n) { __sync_fetch_and_add(&g_metrics.bytes_rx, n); }
void metrics_add_bytes_tx(uint64_t n) { __sync_fetch_and_add(&g_metrics.bytes_tx, n); }
void metrics_inc_padi(void) { __sync_fetch_and_add(&g_metrics.padi_received, 1); }
void metrics_inc_pado(void) { __sync_fetch_and_add(&g_metrics.pado_sent, 1); }
void metrics_inc_padr(void) { __sync_fetch_and_add(&g_metrics.padr_received, 1); }
void metrics_inc_pads(void) { __sync_fetch_and_add(&g_metrics.pads_sent, 1); }
void metrics_inc_padt_sent(void) { __sync_fetch_and_add(&g_metrics.padt_sent, 1); }
void metrics_inc_padt_recv(void) { __sync_fetch_and_add(&g_metrics.padt_received, 1); }
void metrics_inc_dropped(void) { __sync_fetch_and_add(&g_metrics.packets_dropped, 1); }

/* Generate Prometheus text format */
int metrics_export_prometheus(char *buf, size_t buf_size)
{
    int n = 0;

    n += snprintf(buf + n, buf_size - n,
        "# HELP yesrouter_sessions_total Total PPPoE sessions created\n"
        "# TYPE yesrouter_sessions_total counter\n"
        "yesrouter_sessions_total %lu\n\n",
        g_metrics.sessions_total);

    n += snprintf(buf + n, buf_size - n,
        "# HELP yesrouter_sessions_active Currently active sessions\n"
        "# TYPE yesrouter_sessions_active gauge\n"
        "yesrouter_sessions_active %lu\n\n",
        g_metrics.sessions_active);

    n += snprintf(buf + n, buf_size - n,
        "# HELP yesrouter_auth_success Successful authentications\n"
        "# TYPE yesrouter_auth_success counter\n"
        "yesrouter_auth_success %lu\n\n",
        g_metrics.sessions_auth_success);

    n += snprintf(buf + n, buf_size - n,
        "# HELP yesrouter_auth_failed Failed authentications\n"
        "# TYPE yesrouter_auth_failed counter\n"
        "yesrouter_auth_failed %lu\n\n",
        g_metrics.sessions_auth_failed);

    n += snprintf(buf + n, buf_size - n,
        "# HELP yesrouter_packets_rx Packets received\n"
        "# TYPE yesrouter_packets_rx counter\n"
        "yesrouter_packets_rx %lu\n\n",
        g_metrics.packets_rx);

    n += snprintf(buf + n, buf_size - n,
        "# HELP yesrouter_packets_tx Packets transmitted\n"
        "# TYPE yesrouter_packets_tx counter\n"
        "yesrouter_packets_tx %lu\n\n",
        g_metrics.packets_tx);

    n += snprintf(buf + n, buf_size - n,
        "# HELP yesrouter_bytes_rx Bytes received\n"
        "# TYPE yesrouter_bytes_rx counter\n"
        "yesrouter_bytes_rx %lu\n\n",
        g_metrics.bytes_rx);

    n += snprintf(buf + n, buf_size - n,
        "# HELP yesrouter_bytes_tx Bytes transmitted\n"
        "# TYPE yesrouter_bytes_tx counter\n"
        "yesrouter_bytes_tx %lu\n\n",
        g_metrics.bytes_tx);

    n += snprintf(buf + n, buf_size - n,
        "# HELP yesrouter_pppoe_padi PADI packets received\n"
        "# TYPE yesrouter_pppoe_padi counter\n"
        "yesrouter_pppoe_padi %lu\n\n",
        g_metrics.padi_received);

    n += snprintf(buf + n, buf_size - n,
        "# HELP yesrouter_pppoe_pado PADO packets sent\n"
        "# TYPE yesrouter_pppoe_pado counter\n"
        "yesrouter_pppoe_pado %lu\n\n",
        g_metrics.pado_sent);

    n += snprintf(buf + n, buf_size - n,
        "# HELP yesrouter_packets_dropped Packets dropped\n"
        "# TYPE yesrouter_packets_dropped counter\n"
        "yesrouter_packets_dropped %lu\n\n",
        g_metrics.packets_dropped);

    n += snprintf(buf + n, buf_size - n,
        "# HELP yesrouter_uptime_seconds System uptime\n"
        "# TYPE yesrouter_uptime_seconds gauge\n"
        "yesrouter_uptime_seconds %lu\n",
        (unsigned long)(time(NULL) - g_metrics.start_time));

    return n;
}

/* HTTP server for /metrics endpoint */
static int g_http_sock = -1;
static pthread_t g_http_thread;
static volatile int g_http_running = 0;

static void *http_thread_func(void *arg)
{
    (void)arg;
    char buf[16384];
    char response[32768];

    while (g_http_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(g_http_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) continue;

        /* Read request (minimal parsing) */
        ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';

            /* Check if /metrics */
            if (strstr(buf, "GET /metrics") || strstr(buf, "GET / ")) {
                char metrics_buf[16384];
                int metrics_len = metrics_export_prometheus(metrics_buf, sizeof(metrics_buf));

                int resp_len = snprintf(response, sizeof(response),
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain; version=0.0.4\r\n"
                    "Content-Length: %d\r\n"
                    "Connection: close\r\n"
                    "\r\n%s",
                    metrics_len, metrics_buf);

                ssize_t wret = write(client_fd, response, resp_len);
                (void)wret;
            } else {
                const char *not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                ssize_t wret = write(client_fd, not_found, strlen(not_found));
                (void)wret;
            }
        }

        close(client_fd);
    }

    return NULL;
}

int metrics_start_http_server(uint16_t port)
{
    g_http_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_http_sock < 0) {
        YLOG_ERROR("Metrics: Failed to create HTTP socket");
        return -1;
    }

    int opt = 1;
    setsockopt(g_http_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY)
    };

    if (bind(g_http_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        YLOG_ERROR("Metrics: Failed to bind HTTP server to port %u", port);
        close(g_http_sock);
        g_http_sock = -1;
        return -1;
    }

    if (listen(g_http_sock, 5) < 0) {
        YLOG_ERROR("Metrics: Failed to listen on HTTP socket");
        close(g_http_sock);
        g_http_sock = -1;
        return -1;
    }

    g_http_running = 1;
    pthread_create(&g_http_thread, NULL, http_thread_func, NULL);

    YLOG_INFO("Prometheus metrics HTTP server started on port %u", port);
    return 0;
}

void metrics_stop_http_server(void)
{
    if (g_http_running) {
        g_http_running = 0;
        if (g_http_sock >= 0) {
            close(g_http_sock);
            g_http_sock = -1;
        }
        pthread_join(g_http_thread, NULL);
    }
}
