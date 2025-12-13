/**
 * @file password_hash.c
 * @brief bcrypt Password Hashing for Local Authentication
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "password_hash.h"
#include "log.h"

#define BCRYPT_COST 12      /* Work factor (2^12 iterations) */
#define SALT_LENGTH 16
#define HASH_LENGTH 32

/**
 * Generate random salt
 */
static int generate_salt(uint8_t *salt, size_t len)
{
    if (RAND_bytes(salt, (int)len) != 1) {
        return -1;
    }
    return 0;
}

/**
 * PBKDF2-SHA256 based password hashing (OpenSSL compatible alternative to bcrypt)
 */
int password_hash(const char *password, char *hash_out, size_t hash_out_len)
{
    if (!password || !hash_out || hash_out_len < PASSWORD_HASH_LEN) {
        return -1;
    }

    uint8_t salt[SALT_LENGTH];
    uint8_t hash[HASH_LENGTH];

    if (generate_salt(salt, SALT_LENGTH) != 0) {
        YLOG_ERROR("Password hash: Failed to generate salt");
        return -1;
    }

    /* PBKDF2-SHA256 with cost factor iterations */
    int iterations = 1 << BCRYPT_COST;  /* 2^12 = 4096 iterations */

    if (PKCS5_PBKDF2_HMAC(password, strlen(password),
                          salt, SALT_LENGTH,
                          iterations, EVP_sha256(),
                          HASH_LENGTH, hash) != 1) {
        YLOG_ERROR("Password hash: PBKDF2 failed");
        return -1;
    }

    /* Format: $pbkdf2-sha256$iterations$salt$hash (base64) */
    int n = 0;
    n += snprintf(hash_out + n, hash_out_len - n, "$pbkdf2$%d$", iterations);

    /* Encode salt */
    for (int i = 0; i < SALT_LENGTH; i++) {
        n += snprintf(hash_out + n, hash_out_len - n, "%02x", salt[i]);
    }
    n += snprintf(hash_out + n, hash_out_len - n, "$");

    /* Encode hash */
    for (int i = 0; i < HASH_LENGTH; i++) {
        n += snprintf(hash_out + n, hash_out_len - n, "%02x", hash[i]);
    }

    return 0;
}

/**
 * Verify password against stored hash
 */
int password_verify(const char *password, const char *stored_hash)
{
    if (!password || !stored_hash) {
        return -1;
    }

    /* Parse stored hash: $pbkdf2$iterations$salt$hash */
    int iterations;
    char salt_hex[SALT_LENGTH * 2 + 1];
    char hash_hex[HASH_LENGTH * 2 + 1];

    if (sscanf(stored_hash, "$pbkdf2$%d$%32[0-9a-fA-F]$%64[0-9a-fA-F]",
               &iterations, salt_hex, hash_hex) != 3) {
        /* Not a hashed password - compare plaintext (legacy) */
        return strcmp(password, stored_hash) == 0 ? 0 : -1;
    }

    /* Decode salt */
    uint8_t salt[SALT_LENGTH];
    for (int i = 0; i < SALT_LENGTH; i++) {
        unsigned int val;
        sscanf(&salt_hex[i * 2], "%02x", &val);
        salt[i] = val;
    }

    /* Decode stored hash */
    uint8_t stored_hash_bytes[HASH_LENGTH];
    for (int i = 0; i < HASH_LENGTH; i++) {
        unsigned int val;
        sscanf(&hash_hex[i * 2], "%02x", &val);
        stored_hash_bytes[i] = val;
    }

    /* Compute hash with same parameters */
    uint8_t computed_hash[HASH_LENGTH];
    if (PKCS5_PBKDF2_HMAC(password, strlen(password),
                          salt, SALT_LENGTH,
                          iterations, EVP_sha256(),
                          HASH_LENGTH, computed_hash) != 1) {
        return -1;
    }

    /* Constant-time comparison */
    int diff = 0;
    for (int i = 0; i < HASH_LENGTH; i++) {
        diff |= computed_hash[i] ^ stored_hash_bytes[i];
    }

    return diff == 0 ? 0 : -1;
}

/**
 * Check if string is a hashed password
 */
int password_is_hashed(const char *str)
{
    if (!str) return 0;
    return strncmp(str, "$pbkdf2$", 8) == 0;
}
