/**
 * @file local_auth.c
 * @brief Local PPPoE User Authentication Module
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "local_auth.h"
#include "log.h"

#define MAX_LOCAL_USERS 1000

/* Local User Entry */
struct local_user {
    char username[64];
    char password[64];      /* Plaintext for now, TODO: bcrypt hash */
    uint32_t static_ip;     /* Host order, 0 = use pool */
    uint64_t rate_limit;    /* bps, 0 = unlimited */
    bool enabled;
};

static struct {
    struct local_user users[MAX_LOCAL_USERS];
    int count;
    bool enabled;
} g_local_auth = {
    .count = 0,
    .enabled = false
};

int local_auth_init(void)
{
    g_local_auth.count = 0;
    g_local_auth.enabled = false;
    YLOG_INFO("Local auth module initialized");
    return 0;
}

void local_auth_enable(bool enable)
{
    g_local_auth.enabled = enable;
    YLOG_INFO("Local auth %s", enable ? "enabled" : "disabled");
}

bool local_auth_is_enabled(void)
{
    return g_local_auth.enabled;
}

int local_auth_add_user(const char *username, const char *password, uint32_t static_ip, uint64_t rate_limit)
{
    if (!username || !password) return -1;
    if (g_local_auth.count >= MAX_LOCAL_USERS) {
        YLOG_ERROR("Local auth: Max users reached (%d)", MAX_LOCAL_USERS);
        return -1;
    }

    /* Check for duplicate */
    for (int i = 0; i < g_local_auth.count; i++) {
        if (strcmp(g_local_auth.users[i].username, username) == 0) {
            YLOG_WARNING("Local auth: User '%s' already exists", username);
            return -1;
        }
    }

    struct local_user *user = &g_local_auth.users[g_local_auth.count];
    snprintf(user->username, sizeof(user->username), "%s", username);
    snprintf(user->password, sizeof(user->password), "%s", password);
    user->static_ip = static_ip;
    user->rate_limit = rate_limit;
    user->enabled = true;

    g_local_auth.count++;

    YLOG_INFO("Local auth: Added user '%s' (IP: %u.%u.%u.%u, Rate: %lu bps)",
              username,
              (static_ip >> 24) & 0xFF, (static_ip >> 16) & 0xFF,
              (static_ip >> 8) & 0xFF, static_ip & 0xFF,
              rate_limit);
    return 0;
}

int local_auth_remove_user(const char *username)
{
    for (int i = 0; i < g_local_auth.count; i++) {
        if (strcmp(g_local_auth.users[i].username, username) == 0) {
            /* Shift remaining users */
            memmove(&g_local_auth.users[i], &g_local_auth.users[i + 1],
                    (g_local_auth.count - i - 1) * sizeof(struct local_user));
            g_local_auth.count--;
            YLOG_INFO("Local auth: Removed user '%s'", username);
            return 0;
        }
    }
    return -1;
}

int local_auth_check(const char *username, const char *password, struct local_auth_result *result)
{
    if (!g_local_auth.enabled) return LOCAL_AUTH_DISABLED;
    if (!username || !password || !result) return LOCAL_AUTH_INVALID;

    memset(result, 0, sizeof(*result));

    for (int i = 0; i < g_local_auth.count; i++) {
        struct local_user *user = &g_local_auth.users[i];

        if (strcmp(user->username, username) == 0) {
            if (!user->enabled) {
                YLOG_WARNING("Local auth: User '%s' is disabled", username);
                return LOCAL_AUTH_DISABLED_USER;
            }

            /* TODO: Use bcrypt_checkpw() for hashed passwords */
            if (strcmp(user->password, password) == 0) {
                result->framed_ip = user->static_ip;
                result->rate_limit = user->rate_limit;
                strncpy(result->username, username, sizeof(result->username) - 1);
                YLOG_INFO("Local auth: User '%s' authenticated", username);
                return LOCAL_AUTH_SUCCESS;
            } else {
                YLOG_WARNING("Local auth: Wrong password for '%s'", username);
                return LOCAL_AUTH_WRONG_PASSWORD;
            }
        }
    }

    return LOCAL_AUTH_NOT_FOUND;
}

int local_auth_check_chap(const char *username, const uint8_t *challenge, uint8_t chal_len,
                          const uint8_t *response, uint8_t resp_len, struct local_auth_result *result)
{
    /* TODO: Implement CHAP verification for local users */
    (void)challenge;
    (void)chal_len;
    (void)response;
    (void)resp_len;

    /* For now, just find the user (partial implementation) */
    if (!g_local_auth.enabled) return LOCAL_AUTH_DISABLED;
    if (!username || !result) return LOCAL_AUTH_INVALID;

    memset(result, 0, sizeof(*result));

    for (int i = 0; i < g_local_auth.count; i++) {
        struct local_user *user = &g_local_auth.users[i];

        if (strcmp(user->username, username) == 0) {
            if (!user->enabled) return LOCAL_AUTH_DISABLED_USER;

            /* TODO: Compute MD5(ID + password + challenge) and compare */
            YLOG_WARNING("Local auth: CHAP not fully implemented, using placeholder");

            result->framed_ip = user->static_ip;
            result->rate_limit = user->rate_limit;
            strncpy(result->username, username, sizeof(result->username) - 1);
            return LOCAL_AUTH_SUCCESS;
        }
    }

    return LOCAL_AUTH_NOT_FOUND;
}

void local_auth_list_users(void)
{
    printf("Local PPPoE Users (%d):\n", g_local_auth.count);
    printf("%-20s %-16s %-15s\n", "Username", "Static IP", "Rate Limit");
    printf("%-20s %-16s %-15s\n", "--------------------", "----------------", "---------------");

    for (int i = 0; i < g_local_auth.count; i++) {
        struct local_user *user = &g_local_auth.users[i];
        char ip_str[16];

        if (user->static_ip) {
            snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                     (user->static_ip >> 24) & 0xFF, (user->static_ip >> 16) & 0xFF,
                     (user->static_ip >> 8) & 0xFF, user->static_ip & 0xFF);
        } else {
            strcpy(ip_str, "(pool)");
        }

        printf("%-20s %-16s %lu bps%s\n",
               user->username, ip_str, user->rate_limit,
               user->enabled ? "" : " [DISABLED]");
    }
}

int local_auth_load_file(const char *filename)
{
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        YLOG_ERROR("Local auth: Cannot open file '%s'", filename);
        return -1;
    }

    char line[256];
    int line_num = 0;
    int added = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        /* Skip comments and empty lines */
        char *p = line;
        while (*p && isspace(*p)) p++;
        if (*p == '#' || *p == '\0' || *p == '\n') continue;

        /* Format: username password [static_ip] [rate_limit] */
        char username[64], password[64], ip_str[32];
        uint64_t rate = 0;
        uint32_t ip = 0;

        int parsed = sscanf(line, "%63s %63s %31s %lu", username, password, ip_str, &rate);
        if (parsed < 2) {
            YLOG_WARNING("Local auth: Invalid line %d in '%s'", line_num, filename);
            continue;
        }

        if (parsed >= 3) {
            /* Parse IP */
            int a, b, c, d;
            if (sscanf(ip_str, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
                ip = (a << 24) | (b << 16) | (c << 8) | d;
            }
        }

        if (local_auth_add_user(username, password, ip, rate) == 0) {
            added++;
        }
    }

    fclose(fp);
    YLOG_INFO("Local auth: Loaded %d users from '%s'", added, filename);
    return added;
}

void local_auth_cleanup(void)
{
    g_local_auth.count = 0;
    g_local_auth.enabled = false;
    YLOG_INFO("Local auth cleanup complete");
}
