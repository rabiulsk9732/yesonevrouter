/**
 * @file password_hash.h
 * @brief Password Hashing API
 */

#ifndef PASSWORD_HASH_H
#define PASSWORD_HASH_H

#include <stddef.h>

/* Maximum length of hashed password string */
#define PASSWORD_HASH_LEN 128

/**
 * Hash a password using PBKDF2-SHA256
 * @param password Plain text password
 * @param hash_out Output buffer for hash string
 * @param hash_out_len Size of output buffer (must be >= PASSWORD_HASH_LEN)
 * @return 0 on success, -1 on failure
 */
int password_hash(const char *password, char *hash_out, size_t hash_out_len);

/**
 * Verify password against stored hash
 * @param password Plain text password to verify
 * @param stored_hash Previously hashed password
 * @return 0 if password matches, -1 if not
 */
int password_verify(const char *password, const char *stored_hash);

/**
 * Check if string is a hashed password
 * @return 1 if hashed, 0 if plaintext
 */
int password_is_hashed(const char *str);

#endif /* PASSWORD_HASH_H */
