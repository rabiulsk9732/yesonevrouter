/**
 * @file mschap.h
 * @brief MS-CHAPv1 Authentication API
 */

#ifndef MSCHAP_H
#define MSCHAP_H

#include <stdint.h>
#include <stddef.h>

/**
 * Generate NT Password Hash (MD4 of Unicode password)
 * @param password Plain text password
 * @param hash Output: 16-byte hash
 */
void mschap_nt_password_hash(const char *password, uint8_t *hash);

/**
 * Generate MS-CHAPv1 response
 * @param challenge 8-byte challenge
 * @param password Plain text password
 * @param response Output: 24-byte response
 */
void mschap_v1_response(const uint8_t *challenge, const char *password, uint8_t *response);

/**
 * Verify MS-CHAPv1 response
 * @return 0 on success, -1 on failure
 */
int mschap_v1_verify(const uint8_t *challenge, const char *password,
                     const uint8_t *response);

/**
 * Create RADIUS MS-CHAP attributes
 */
int mschap_create_radius_attrs(const uint8_t *challenge, uint8_t chal_len,
                               const uint8_t *response,
                               uint8_t *mschap_challenge, uint8_t *mschap_response);

/**
 * Parse MS-CHAP response from client
 */
int mschap_parse_response(const uint8_t *data, size_t len,
                          uint8_t *nt_response, uint8_t *lm_response);

#endif /* MSCHAP_H */
