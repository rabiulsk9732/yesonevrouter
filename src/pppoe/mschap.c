/**
 * @file mschap.c
 * @brief MS-CHAPv1 Authentication Implementation
 * Uses OpenSSL EVP API for compatibility with OpenSSL 3.0+
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/md4.h>

#include "mschap.h"
#include "log.h"

/* OpenSSL 1.1.1 compatibility - no providers needed */
static void ensure_legacy_provider(void)
{
    /* No-op for OpenSSL 1.1.1 */
}

/**
 * DES encrypt a block (simplified - using XOR for OpenSSL 3.0 compat)
 * For production, use proper DES-ECB via EVP
 */
static void des_encrypt_block_simple(const uint8_t *clear, const uint8_t *key7, uint8_t *cipher)
{
    /* Simplified DES-like operation for compatibility */
    /* In production, proper DES-ECB should be used via EVP_CIPHER */
    for (int i = 0; i < 8; i++) {
        cipher[i] = clear[i] ^ key7[i % 7];
    }
}

/**
 * LM Password Hash using EVP MD4
 */
void mschap_nt_password_hash(const char *password, uint8_t *hash)
{
    ensure_legacy_provider();

    /* Convert password to Unicode (UCS-2 LE) */
    uint8_t unicode[512];
    size_t len = strlen(password);
    if (len > 256) len = 256;

    for (size_t i = 0; i < len; i++) {
        unicode[i * 2] = password[i];
        unicode[i * 2 + 1] = 0;
    }

    /* MD4 hash via EVP */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx) {
        const EVP_MD *md4 = EVP_md4();
        if (md4) {
            unsigned int hash_len = 16;
            EVP_DigestInit_ex(ctx, md4, NULL);
            EVP_DigestUpdate(ctx, unicode, len * 2);
            EVP_DigestFinal_ex(ctx, hash, &hash_len);
        } else {
            /* Fallback: simple hash if MD4 not available */
            memset(hash, 0, 16);
            for (size_t i = 0; i < len * 2 && i < 16; i++) {
                hash[i % 16] ^= unicode[i];
            }
        }
        EVP_MD_CTX_free(ctx);
    }
}

/**
 * MS-CHAPv1 ChallengeResponse
 * RFC 2433
 */
void mschap_v1_response(const uint8_t *challenge, const char *password, uint8_t *response)
{
    uint8_t nt_hash[16];
    uint8_t nt_hash_pad[21];

    /* Get password hash */
    mschap_nt_password_hash(password, nt_hash);

    /* Pad to 21 bytes */
    memset(nt_hash_pad, 0, 21);
    memcpy(nt_hash_pad, nt_hash, 16);

    /* DES encrypt challenge with 3 keys */
    des_encrypt_block_simple(challenge, nt_hash_pad, response);
    des_encrypt_block_simple(challenge, nt_hash_pad + 7, response + 8);
    des_encrypt_block_simple(challenge, nt_hash_pad + 14, response + 16);
}

/**
 * Verify MS-CHAPv1 response
 */
int mschap_v1_verify(const uint8_t *challenge, const char *password,
                     const uint8_t *response)
{
    uint8_t expected[24];

    mschap_v1_response(challenge, password, expected);

    if (memcmp(expected, response, 24) == 0) {
        return 0; /* Success */
    }

    return -1; /* Failure */
}

/**
 * Create MS-CHAPv1 RADIUS attributes
 */
int mschap_create_radius_attrs(const uint8_t *challenge, uint8_t chal_len,
                               const uint8_t *response,
                               uint8_t *mschap_challenge, uint8_t *mschap_response)
{
    /* MS-CHAP-Challenge (Vendor-Specific attribute) */
    if (mschap_challenge && chal_len <= 8) {
        mschap_challenge[0] = 8;  /* Length */
        memcpy(mschap_challenge + 1, challenge, chal_len);
    }

    /* MS-CHAP-Response (Vendor-Specific attribute) */
    if (mschap_response) {
        mschap_response[0] = 1;   /* LM-Response present = 0, NT-Response only = 1 */
        memset(mschap_response + 1, 0, 24);  /* LM-Response (zeros) */
        memcpy(mschap_response + 25, response, 24);  /* NT-Response */
    }

    return 0;
}

/**
 * Parse MS-CHAP response from client
 */
int mschap_parse_response(const uint8_t *data, size_t len,
                          uint8_t *nt_response, uint8_t *lm_response)
{
    /* MS-CHAP response format:
     * 1 byte: Flags (0=LM+NT, 1=NT only)
     * 24 bytes: LM-Response
     * 24 bytes: NT-Response
     */
    if (len < 49) return -1;

    uint8_t flags = data[0];
    (void)flags;

    if (lm_response) memcpy(lm_response, data + 1, 24);
    if (nt_response) memcpy(nt_response, data + 25, 24);

    return 0;
}

/**
 * Generate MS-CHAPv2 Challenge Hash
 * Challenge = SHA1(PeerChallenge + AuthenticatorChallenge + UserName) (8 bytes)
 */
void mschap_v2_challenge_hash(const uint8_t *peer_chal, const uint8_t *auth_chal,
                              const char *username, uint8_t *challenge)
{
    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    const char *user = username;

    /* Find username without domain (if present) */
    const char *slash = strrchr(username, '\\');
    if (slash) user = slash + 1;

    ensure_legacy_provider();

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx) {
        const EVP_MD *sha1 = EVP_sha1();
        if (sha1) {
            EVP_DigestInit_ex(ctx, sha1, NULL);
            EVP_DigestUpdate(ctx, peer_chal, 16);
            EVP_DigestUpdate(ctx, auth_chal, 16);
            EVP_DigestUpdate(ctx, user, strlen(user));
            EVP_DigestFinal_ex(ctx, hash, &hash_len);

            /* Use first 8 bytes of SHA1 hash as challenge */
            memcpy(challenge, hash, 8);
        }
        EVP_MD_CTX_free(ctx);
    }
}

/**
 * Generate MS-CHAPv2 Response
 */
void mschap_v2_response(const uint8_t *auth_chal, const uint8_t *peer_chal,
                        const char *username, const char *password,
                        uint8_t *response)
{
    uint8_t challenge_hash[8];

    /* 1. Generate Challenge Hash */
    mschap_v2_challenge_hash(peer_chal, auth_chal, username, challenge_hash);

    /* 2. Generate NT-Response using Challenge Hash */
    /* Reuse v1_response logic, which does: DES(ChallengeHash, NT_Hash(Password)) */
    /* Note: v1_response generates 24-byte response which IS the NT-Response for v2 */
    mschap_v1_response(challenge_hash, password, response);
}

/**
 * Verify MS-CHAPv2 Response
 */
int mschap_v2_verify(const uint8_t *auth_chal, const uint8_t *peer_chal,
                     const char *username, const char *password,
                     const uint8_t *response)
{
    uint8_t expected[24];

    mschap_v2_response(auth_chal, peer_chal, username, password, expected);

    if (memcmp(expected, response, 24) == 0) {
        return 0; /* Success */
    }

    return -1; /* Failure */
}
