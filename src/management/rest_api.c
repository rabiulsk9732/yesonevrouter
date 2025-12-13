/**
 * @file rest_api.c
 * @brief Simple REST API for PPPoE Session Management
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#include "rest_api.h"
#include "session_export.h"
#include "metrics.h"
#include "log.h"

static int g_api_sock = -1;
static pthread_t g_api_thread;
static volatile int g_api_running = 0;

/* Simple HTTP response helpers */
static void send_json_response(int fd, int code, const char *body)
{
    char response[32768];
    int len = snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n"
        "\r\n%s",
        code, code == 200 ? "OK" : "Error",
        strlen(body), body);

    ssize_t wret = write(fd, response, len);
    (void)wret;
}

static void handle_api_request(int client_fd, const char *method, const char *path)
{
    char json[32768];

    if (strcmp(method, "GET") == 0) {
        if (strcmp(path, "/api/sessions") == 0 || strcmp(path, "/api/sessions/") == 0) {
            /* List all sessions */
            session_export_json(json, sizeof(json));
            send_json_response(client_fd, 200, json);
        }
        else if (strcmp(path, "/api/stats") == 0 || strcmp(path, "/api/stats/") == 0) {
            /* Get statistics */
            snprintf(json, sizeof(json),
                "{\"status\":\"ok\",\"sessions_active\":0,\"uptime\":0}");
            send_json_response(client_fd, 200, json);
        }
        else if (strcmp(path, "/api/health") == 0 || strcmp(path, "/api/health/") == 0) {
            /* Health check */
            snprintf(json, sizeof(json), "{\"status\":\"healthy\"}");
            send_json_response(client_fd, 200, json);
        }
        else {
            snprintf(json, sizeof(json), "{\"error\":\"Not found\"}");
            send_json_response(client_fd, 404, json);
        }
    }
    else if (strcmp(method, "DELETE") == 0) {
        /* DELETE /api/sessions/{id} - terminate session */
        int session_id;
        if (sscanf(path, "/api/sessions/%d", &session_id) == 1) {
            /* TODO: Call session termination */
            snprintf(json, sizeof(json), "{\"status\":\"terminated\",\"session_id\":%d}", session_id);
            send_json_response(client_fd, 200, json);
        } else {
            snprintf(json, sizeof(json), "{\"error\":\"Invalid session ID\"}");
            send_json_response(client_fd, 400, json);
        }
    }
    else {
        snprintf(json, sizeof(json), "{\"error\":\"Method not allowed\"}");
        send_json_response(client_fd, 405, json);
    }
}

static void *api_thread_func(void *arg)
{
    (void)arg;
    char buf[4096];

    while (g_api_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(g_api_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) continue;

        ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';

            /* Parse HTTP request */
            char method[16], path[256];
            if (sscanf(buf, "%15s %255s", method, path) == 2) {
                handle_api_request(client_fd, method, path);
            }
        }

        close(client_fd);
    }

    return NULL;
}

int rest_api_init(uint16_t port)
{
    g_api_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_api_sock < 0) {
        YLOG_ERROR("REST API: Failed to create socket");
        return -1;
    }

    int opt = 1;
    setsockopt(g_api_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY)
    };

    if (bind(g_api_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        YLOG_ERROR("REST API: Failed to bind to port %u", port);
        close(g_api_sock);
        g_api_sock = -1;
        return -1;
    }

    if (listen(g_api_sock, 10) < 0) {
        YLOG_ERROR("REST API: Failed to listen");
        close(g_api_sock);
        g_api_sock = -1;
        return -1;
    }

    g_api_running = 1;
    pthread_create(&g_api_thread, NULL, api_thread_func, NULL);

    YLOG_INFO("REST API: Started on port %u", port);
    return 0;
}

void rest_api_cleanup(void)
{
    if (g_api_running) {
        g_api_running = 0;
        if (g_api_sock >= 0) {
            close(g_api_sock);
            g_api_sock = -1;
        }
        pthread_join(g_api_thread, NULL);
    }
    YLOG_INFO("REST API: Stopped");
}
