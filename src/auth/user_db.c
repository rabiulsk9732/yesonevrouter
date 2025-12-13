/**
 * @file user_db.c
 * @brief User Database Implementation
 */

#define _GNU_SOURCE
#include "user_db.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <pthread.h>

static struct user_db *g_user_db = NULL;
static pthread_mutex_t g_user_db_lock = PTHREAD_MUTEX_INITIALIZER;

/* Simple hash function for username */
static uint32_t user_hash(const char *username)
{
    uint32_t hash = 5381;
    int c;
    while ((c = *username++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % USER_MAX_USERS;
}

/* Hash password using SHA-256 (OpenSSL 1.1.1 compatible) */
static void hash_password(const char *password, char *hash_out)
{
    unsigned char hash[32];  /* SHA-256 produces 32 bytes */
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned int hash_len;

    /* Use EVP_sha256() for OpenSSL 1.1.1 compatibility */
    md = EVP_sha256();
    if (!md) {
        YLOG_ERROR("Failed to get SHA256 digest");
        hash_out[0] = '\0';
        return;
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        hash_out[0] = '\0';
        return;
    }

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1 ||
        EVP_DigestUpdate(mdctx, password, strlen(password)) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        hash_out[0] = '\0';
        return;
    }

    EVP_MD_CTX_free(mdctx);

    /* Convert to hex string */
    for (int i = 0; i < (int)hash_len && i < 32; i++) {
        sprintf(&hash_out[i * 2], "%02x", hash[i]);
    }
    hash_out[USER_HASH_LEN - 1] = '\0';
}

/* Compare password hash */
static bool verify_password_hash(const char *password, const char *stored_hash)
{
    char computed_hash[USER_HASH_LEN];
    hash_password(password, computed_hash);
    return strcmp(computed_hash, stored_hash) == 0;
}

/**
 * Initialize user database
 */
int user_db_init(void)
{
    if (g_user_db) {
        return 0;  /* Already initialized */
    }

    g_user_db = calloc(1, sizeof(*g_user_db));
    if (!g_user_db) {
        return -1;
    }

    g_user_db->max_users = USER_MAX_USERS;
    g_user_db->initialized = true;
    g_user_db->global_enable_password_hash[0] = '\0';  /* No global enable password by default */

    /* Create default admin user */
    user_db_add("admin", "admin", USER_PRIV_LEVEL_ADMIN);

    YLOG_INFO("User database initialized");
    return 0;
}

/**
 * Cleanup user database
 */
void user_db_cleanup(void)
{
    if (!g_user_db) return;

    pthread_mutex_lock(&g_user_db_lock);

    for (uint32_t i = 0; i < USER_MAX_USERS; i++) {
        struct user *user = g_user_db->users[i];
        while (user) {
            struct user *next = user->next;
            free(user);
            user = next;
        }
    }

    free(g_user_db);
    g_user_db = NULL;

    pthread_mutex_unlock(&g_user_db_lock);
}

/**
 * Add a new user
 */
int user_db_add(const char *username, const char *password, uint8_t privilege_level)
{
    if (!g_user_db || !username || !password) {
        return -1;
    }

    if (strlen(username) >= USER_MAX_NAME_LEN) {
        YLOG_ERROR("Username too long");
        return -1;
    }

    if (privilege_level > USER_PRIV_LEVEL_VIEWER) {
        YLOG_ERROR("Invalid privilege level: %u", privilege_level);
        return -1;
    }

    pthread_mutex_lock(&g_user_db_lock);

    /* Check if user already exists */
    struct user *existing = user_db_find(username);
    if (existing) {
        pthread_mutex_unlock(&g_user_db_lock);
        YLOG_ERROR("User %s already exists", username);
        return -1;
    }

    /* Create new user */
    struct user *user = calloc(1, sizeof(*user));
    if (!user) {
        pthread_mutex_unlock(&g_user_db_lock);
        return -1;
    }

    strncpy(user->username, username, sizeof(user->username) - 1);
    hash_password(password, user->password_hash);
    user->enable_password_hash[0] = '\0';  /* No enable password by default */
    user->privilege_level = privilege_level;
    user->created_time = time(NULL);
    user->last_login = 0;
    user->enabled = true;

    /* Insert into hash table */
    uint32_t hash = user_hash(username);
    user->next = g_user_db->users[hash];
    g_user_db->users[hash] = user;
    g_user_db->count++;

    pthread_mutex_unlock(&g_user_db_lock);

    YLOG_INFO("User %s added with privilege level %u", username, privilege_level);
    return 0;
}

/**
 * Delete a user
 */
int user_db_delete(const char *username)
{
    if (!g_user_db || !username) {
        return -1;
    }

    pthread_mutex_lock(&g_user_db_lock);

    uint32_t hash = user_hash(username);
    struct user *user = g_user_db->users[hash];
    struct user *prev = NULL;

    while (user) {
        if (strcmp(user->username, username) == 0) {
            if (prev) {
                prev->next = user->next;
            } else {
                g_user_db->users[hash] = user->next;
            }
            free(user);
            g_user_db->count--;
            pthread_mutex_unlock(&g_user_db_lock);
            YLOG_INFO("User %s deleted", username);
            return 0;
        }
        prev = user;
        user = user->next;
    }

    pthread_mutex_unlock(&g_user_db_lock);
    YLOG_ERROR("User %s not found", username);
    return -1;
}

/**
 * Find user by username
 */
struct user *user_db_find(const char *username)
{
    if (!g_user_db || !username) {
        return NULL;
    }

    uint32_t hash = user_hash(username);
    struct user *user = g_user_db->users[hash];

    while (user) {
        if (strcmp(user->username, username) == 0) {
            return user;
        }
        user = user->next;
    }

    return NULL;
}

/**
 * Verify user password
 */
int user_db_verify_password(const char *username, const char *password)
{
    if (!g_user_db || !username || !password) {
        return -1;
    }

    pthread_mutex_lock(&g_user_db_lock);

    struct user *user = user_db_find(username);
    if (!user || !user->enabled) {
        pthread_mutex_unlock(&g_user_db_lock);
        return -1;
    }

    bool valid = verify_password_hash(password, user->password_hash);
    if (valid) {
        user->last_login = time(NULL);
    }

    pthread_mutex_unlock(&g_user_db_lock);
    return valid ? 0 : -1;
}

/**
 * Update user password
 */
int user_db_update_password(const char *username, const char *new_password)
{
    if (!g_user_db || !username || !new_password) {
        return -1;
    }

    pthread_mutex_lock(&g_user_db_lock);

    struct user *user = user_db_find(username);
    if (!user) {
        pthread_mutex_unlock(&g_user_db_lock);
        return -1;
    }

    hash_password(new_password, user->password_hash);
    pthread_mutex_unlock(&g_user_db_lock);

    YLOG_INFO("Password updated for user %s", username);
    return 0;
}

/**
 * Update user privilege level
 */
int user_db_update_privilege(const char *username, uint8_t privilege_level)
{
    if (!g_user_db || !username) {
        return -1;
    }

    if (privilege_level > USER_PRIV_LEVEL_VIEWER) {
        return -1;
    }

    pthread_mutex_lock(&g_user_db_lock);

    struct user *user = user_db_find(username);
    if (!user) {
        pthread_mutex_unlock(&g_user_db_lock);
        return -1;
    }

    user->privilege_level = privilege_level;
    pthread_mutex_unlock(&g_user_db_lock);

    YLOG_INFO("Privilege level updated for user %s to %u", username, privilege_level);
    return 0;
}

/**
 * Enable/disable user
 */
int user_db_set_enabled(const char *username, bool enabled)
{
    if (!g_user_db || !username) {
        return -1;
    }

    pthread_mutex_lock(&g_user_db_lock);

    struct user *user = user_db_find(username);
    if (!user) {
        pthread_mutex_unlock(&g_user_db_lock);
        return -1;
    }

    user->enabled = enabled;
    pthread_mutex_unlock(&g_user_db_lock);

    YLOG_INFO("User %s %s", username, enabled ? "enabled" : "disabled");
    return 0;
}

/**
 * Update last login time
 */
void user_db_update_last_login(const char *username)
{
    if (!g_user_db || !username) {
        return;
    }

    pthread_mutex_lock(&g_user_db_lock);
    struct user *user = user_db_find(username);
    if (user) {
        user->last_login = time(NULL);
    }
    pthread_mutex_unlock(&g_user_db_lock);
}

/**
 * Print all users
 */
void user_db_print_all(void)
{
    if (!g_user_db) {
        printf("User database not initialized\n");
        return;
    }

    printf("\n%-20s %-12s %-10s %-20s %s\n",
           "Username", "Privilege", "Status", "Created", "Last Login");
    printf("--------------------------------------------------------------------------------\n");

    pthread_mutex_lock(&g_user_db_lock);

    for (uint32_t i = 0; i < USER_MAX_USERS; i++) {
        struct user *user = g_user_db->users[i];
        while (user) {
            char created_str[32] = "-";
            char login_str[32] = "Never";

            if (user->created_time) {
                struct tm *tm = localtime(&user->created_time);
                strftime(created_str, sizeof(created_str), "%Y-%m-%d %H:%M:%S", tm);
            }

            if (user->last_login) {
                struct tm *tm = localtime(&user->last_login);
                strftime(login_str, sizeof(login_str), "%Y-%m-%d %H:%M:%S", tm);
            }

            const char *priv_str = "Unknown";
            switch (user->privilege_level) {
                case USER_PRIV_LEVEL_ADMIN: priv_str = "Admin (0)"; break;
                case USER_PRIV_LEVEL_OPERATOR: priv_str = "Operator (1)"; break;
                case USER_PRIV_LEVEL_VIEWER: priv_str = "Viewer (2)"; break;
            }

            printf("%-20s %-12s %-10s %-20s %s\n",
                   user->username,
                   priv_str,
                   user->enabled ? "Enabled" : "Disabled",
                   created_str,
                   login_str);

            user = user->next;
        }
    }

    pthread_mutex_unlock(&g_user_db_lock);
    printf("\nTotal users: %u\n\n", g_user_db->count);
}

/**
 * Print user details
 */
void user_db_print_user(const char *username)
{
    if (!g_user_db || !username) {
        return;
    }

    pthread_mutex_lock(&g_user_db_lock);
    struct user *user = user_db_find(username);
    if (!user) {
        pthread_mutex_unlock(&g_user_db_lock);
        printf("User %s not found\n", username);
        return;
    }

    printf("\nUser: %s\n", user->username);
    printf("  Privilege Level: %u", user->privilege_level);
    switch (user->privilege_level) {
        case USER_PRIV_LEVEL_ADMIN: printf(" (Administrator)\n"); break;
        case USER_PRIV_LEVEL_OPERATOR: printf(" (Operator)\n"); break;
        case USER_PRIV_LEVEL_VIEWER: printf(" (Viewer)\n"); break;
        default: printf("\n"); break;
    }
    printf("  Status: %s\n", user->enabled ? "Enabled" : "Disabled");

    if (user->created_time) {
        char buf[64];
        struct tm *tm = localtime(&user->created_time);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
        printf("  Created: %s\n", buf);
    }

    if (user->last_login) {
        char buf[64];
        struct tm *tm = localtime(&user->last_login);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
        printf("  Last Login: %s\n", buf);
    } else {
        printf("  Last Login: Never\n");
    }

    pthread_mutex_unlock(&g_user_db_lock);
    printf("\n");
}

/**
 * Get user count
 */
uint32_t user_db_get_count(void)
{
    if (!g_user_db) return 0;
    return g_user_db->count;
}

/**
 * Set user enable password
 */
int user_db_set_enable_password(const char *username, const char *enable_password)
{
    if (!g_user_db || !username || !enable_password) {
        return -1;
    }

    pthread_mutex_lock(&g_user_db_lock);

    struct user *user = user_db_find(username);
    if (!user) {
        pthread_mutex_unlock(&g_user_db_lock);
        return -1;
    }

    hash_password(enable_password, user->enable_password_hash);
    pthread_mutex_unlock(&g_user_db_lock);

    YLOG_INFO("Enable password set for user %s", username);
    return 0;
}

/**
 * Set global enable password
 */
int user_db_set_global_enable_password(const char *enable_password)
{
    if (!g_user_db || !enable_password) {
        return -1;
    }

    pthread_mutex_lock(&g_user_db_lock);
    hash_password(enable_password, g_user_db->global_enable_password_hash);
    pthread_mutex_unlock(&g_user_db_lock);

    YLOG_INFO("Global enable password set");
    return 0;
}

/**
 * Verify enable password for user
 */
int user_db_verify_enable_password(const char *username, const char *enable_password)
{
    if (!g_user_db) {
        return -1;
    }

    /* If no password provided, check if any enable password exists */
    if (!enable_password || enable_password[0] == '\0') {
        pthread_mutex_lock(&g_user_db_lock);
        bool has_enable = false;

        if (username) {
            struct user *user = user_db_find(username);
            if (user && user->enable_password_hash[0] != '\0') {
                has_enable = true;
            }
        }

        if (!has_enable && g_user_db->global_enable_password_hash[0] != '\0') {
            has_enable = true;
        }

        pthread_mutex_unlock(&g_user_db_lock);
        return has_enable ? -1 : 0;  /* Return 0 if no enable password needed */
    }

    pthread_mutex_lock(&g_user_db_lock);

    /* Check user-specific enable password first */
    if (username) {
        struct user *user = user_db_find(username);
        if (user && user->enable_password_hash[0] != '\0') {
            char computed_hash[USER_HASH_LEN];
            hash_password(enable_password, computed_hash);
            bool valid = (strcmp(computed_hash, user->enable_password_hash) == 0);
            pthread_mutex_unlock(&g_user_db_lock);
            return valid ? 0 : -1;
        }
    }

    /* Check global enable password */
    if (g_user_db->global_enable_password_hash[0] != '\0') {
        char computed_hash[USER_HASH_LEN];
        hash_password(enable_password, computed_hash);
        bool valid = (strcmp(computed_hash, g_user_db->global_enable_password_hash) == 0);
        pthread_mutex_unlock(&g_user_db_lock);
        return valid ? 0 : -1;
    }

    pthread_mutex_unlock(&g_user_db_lock);
    return 0;  /* No enable password set, allow access */
}
