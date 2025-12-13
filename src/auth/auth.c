/**
 * @file auth.c
 * @brief Authentication Implementation
 */

#include "auth.h"
#include "user_db.h"
#include "log.h"
#include <string.h>
#include <pthread.h>

static struct user *g_current_user = NULL;
static pthread_mutex_t g_auth_lock = PTHREAD_MUTEX_INITIALIZER;

/**
 * Authenticate user with username and password
 */
struct auth_result auth_login(const char *username, const char *password)
{
    struct auth_result result = {0};

    if (!username || !password) {
        result.success = false;
        strncpy(result.error_msg, "Username and password required", sizeof(result.error_msg) - 1);
        return result;
    }

    pthread_mutex_lock(&g_auth_lock);

    /* Verify password */
    if (user_db_verify_password(username, password) != 0) {
        result.success = false;
        strncpy(result.error_msg, "Invalid username or password", sizeof(result.error_msg) - 1);
        pthread_mutex_unlock(&g_auth_lock);
        return result;
    }

    /* Get user */
    struct user *user = user_db_find(username);
    if (!user || !user->enabled) {
        result.success = false;
        strncpy(result.error_msg, "User not found or disabled", sizeof(result.error_msg) - 1);
        pthread_mutex_unlock(&g_auth_lock);
        return result;
    }

    /* Set as current user */
    g_current_user = user;
    user_db_update_last_login(username);

    result.success = true;
    result.user = user;

    pthread_mutex_unlock(&g_auth_lock);

    YLOG_INFO("User %s logged in (privilege level %u)", username, user->privilege_level);
    return result;
}

/**
 * Logout user
 */
void auth_logout(const char *username)
{
    (void)username;  /* For future use */

    pthread_mutex_lock(&g_auth_lock);
    if (g_current_user) {
        YLOG_INFO("User %s logged out", g_current_user->username);
        g_current_user = NULL;
    }
    pthread_mutex_unlock(&g_auth_lock);
}

/**
 * Check if user is authenticated
 */
bool auth_is_authenticated(const char *username)
{
    pthread_mutex_lock(&g_auth_lock);
    bool authenticated = (g_current_user &&
                         username &&
                         strcmp(g_current_user->username, username) == 0);
    pthread_mutex_unlock(&g_auth_lock);
    return authenticated;
}

/**
 * Get current authenticated user
 */
struct user *auth_get_current_user(void)
{
    pthread_mutex_lock(&g_auth_lock);
    struct user *user = g_current_user;
    pthread_mutex_unlock(&g_auth_lock);
    return user;
}

/**
 * Set current authenticated user
 */
void auth_set_current_user(struct user *user)
{
    pthread_mutex_lock(&g_auth_lock);
    g_current_user = user;
    pthread_mutex_unlock(&g_auth_lock);
}

/**
 * Clear current authenticated user
 */
void auth_clear_current_user(void)
{
    pthread_mutex_lock(&g_auth_lock);
    g_current_user = NULL;
    pthread_mutex_unlock(&g_auth_lock);
}
