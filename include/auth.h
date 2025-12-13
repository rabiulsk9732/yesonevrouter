/**
 * @file auth.h
 * @brief Authentication Interface
 */

#ifndef AUTH_H
#define AUTH_H

#include <stdint.h>
#include <stdbool.h>
#include "user_db.h"

/* Authentication result */
struct auth_result {
    bool success;
    struct user *user;
    char error_msg[128];
};

/**
 * Authenticate user with username and password
 * @param username Username
 * @param password Plaintext password
 * @return Auth result structure
 */
struct auth_result auth_login(const char *username, const char *password);

/**
 * Logout user (cleanup session)
 * @param username Username
 */
void auth_logout(const char *username);

/**
 * Check if user is authenticated
 * @param username Username
 * @return true if authenticated, false otherwise
 */
bool auth_is_authenticated(const char *username);

/**
 * Get current authenticated user
 * @return User pointer or NULL
 */
struct user *auth_get_current_user(void);

/**
 * Set current authenticated user (for session management)
 * @param user User pointer
 */
void auth_set_current_user(struct user *user);

/**
 * Clear current authenticated user
 */
void auth_clear_current_user(void);

#endif /* AUTH_H */
