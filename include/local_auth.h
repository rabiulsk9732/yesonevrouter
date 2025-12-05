/**
 * @file local_auth.h
 * @brief Local PPPoE User Authentication API
 */

#ifndef LOCAL_AUTH_H
#define LOCAL_AUTH_H

#include <stdint.h>
#include <stdbool.h>

/* Auth result codes */
#define LOCAL_AUTH_SUCCESS         0
#define LOCAL_AUTH_NOT_FOUND      -1
#define LOCAL_AUTH_WRONG_PASSWORD -2
#define LOCAL_AUTH_DISABLED       -3
#define LOCAL_AUTH_DISABLED_USER  -4
#define LOCAL_AUTH_INVALID        -5

/* Auth result structure */
struct local_auth_result {
    char username[64];
    uint32_t framed_ip;     /* Host order, 0 = use pool */
    uint64_t rate_limit;    /* bps, 0 = unlimited */
};

/**
 * Initialize local auth module
 */
int local_auth_init(void);

/**
 * Cleanup local auth module
 */
void local_auth_cleanup(void);

/**
 * Enable/disable local auth
 */
void local_auth_enable(bool enable);

/**
 * Check if local auth is enabled
 */
bool local_auth_is_enabled(void);

/**
 * Add a local user
 * @param username Username
 * @param password Password (plaintext)
 * @param static_ip Static IP (host order), 0 = use pool
 * @param rate_limit Rate limit in bps, 0 = unlimited
 */
int local_auth_add_user(const char *username, const char *password, uint32_t static_ip, uint64_t rate_limit);

/**
 * Remove a local user
 */
int local_auth_remove_user(const char *username);

/**
 * Check PAP authentication
 * @return LOCAL_AUTH_SUCCESS on success, error code otherwise
 */
int local_auth_check(const char *username, const char *password, struct local_auth_result *result);

/**
 * Check CHAP authentication
 */
int local_auth_check_chap(const char *username, const uint8_t *challenge, uint8_t chal_len,
                          const uint8_t *response, uint8_t resp_len, struct local_auth_result *result);

/**
 * List all local users
 */
void local_auth_list_users(void);

/**
 * Load users from file
 * Format: username password [static_ip] [rate_limit]
 */
int local_auth_load_file(const char *filename);

#endif /* LOCAL_AUTH_H */
