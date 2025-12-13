/**
 * @file user_db.h
 * @brief User Database Management
 */

#ifndef USER_DB_H
#define USER_DB_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* User privilege levels */
#define USER_PRIV_LEVEL_ADMIN    0  /* Full access */
#define USER_PRIV_LEVEL_OPERATOR 1  /* Write access (no user mgmt) */
#define USER_PRIV_LEVEL_VIEWER   2  /* Read-only */

#define USER_MAX_NAME_LEN    32
#define USER_MAX_PASS_LEN    128
#define USER_HASH_LEN        64  /* SHA-256 hex string */
#define USER_MAX_USERS       256

/* User structure */
struct user {
    char username[USER_MAX_NAME_LEN];
    char password_hash[USER_HASH_LEN];  /* SHA-256 hash */
    char enable_password_hash[USER_HASH_LEN];  /* Enable password hash (optional) */
    uint8_t privilege_level;
    time_t created_time;
    time_t last_login;
    bool enabled;
    struct user *next;
};

/* User database */
struct user_db {
    struct user *users[USER_MAX_USERS];  /* Hash table */
    char global_enable_password_hash[USER_HASH_LEN];  /* Global enable password */
    uint32_t count;
    uint32_t max_users;
    bool initialized;
};

/**
 * Initialize user database
 * @return 0 on success, -1 on error
 */
int user_db_init(void);

/**
 * Cleanup user database
 */
void user_db_cleanup(void);

/**
 * Add a new user
 * @param username Username
 * @param password Plaintext password
 * @param privilege_level Privilege level (0-2)
 * @return 0 on success, -1 on error
 */
int user_db_add(const char *username, const char *password, uint8_t privilege_level);

/**
 * Delete a user
 * @param username Username to delete
 * @return 0 on success, -1 on error
 */
int user_db_delete(const char *username);

/**
 * Find user by username
 * @param username Username to find
 * @return User pointer or NULL if not found
 */
struct user *user_db_find(const char *username);

/**
 * Verify user password
 * @param username Username
 * @param password Plaintext password
 * @return 0 if valid, -1 if invalid
 */
int user_db_verify_password(const char *username, const char *password);

/**
 * Update user password
 * @param username Username
 * @param new_password New plaintext password
 * @return 0 on success, -1 on error
 */
int user_db_update_password(const char *username, const char *new_password);

/**
 * Update user privilege level
 * @param username Username
 * @param privilege_level New privilege level
 * @return 0 on success, -1 on error
 */
int user_db_update_privilege(const char *username, uint8_t privilege_level);

/**
 * Set user enable password
 * @param username Username
 * @param enable_password Enable password (plaintext)
 * @return 0 on success, -1 on error
 */
int user_db_set_enable_password(const char *username, const char *enable_password);

/**
 * Set global enable password
 * @param enable_password Enable password (plaintext)
 * @return 0 on success, -1 on error
 */
int user_db_set_global_enable_password(const char *enable_password);

/**
 * Verify enable password for user
 * @param username Username (NULL to check global)
 * @param enable_password Plaintext enable password
 * @return 0 if valid, -1 if invalid
 */
int user_db_verify_enable_password(const char *username, const char *enable_password);

/**
 * Enable/disable user
 * @param username Username
 * @param enabled true to enable, false to disable
 * @return 0 on success, -1 on error
 */
int user_db_set_enabled(const char *username, bool enabled);

/**
 * Update last login time
 * @param username Username
 */
void user_db_update_last_login(const char *username);

/**
 * Print all users
 */
void user_db_print_all(void);

/**
 * Print user details
 * @param username Username
 */
void user_db_print_user(const char *username);

/**
 * Get user count
 * @return Number of users
 */
uint32_t user_db_get_count(void);

#endif /* USER_DB_H */
