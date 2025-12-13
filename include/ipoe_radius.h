/**
 * @file ipoe_radius.h
 * @brief IPoE RADIUS Integration - Wrapper for existing radius_client
 *
 * Provides IPoE-specific MAC-auth credential building and session binding
 * Uses existing radius/radius_client.c for actual RADIUS communication
 */

#ifndef IPOE_RADIUS_H
#define IPOE_RADIUS_H

#include <ipoe_session.h>
#include <stdint.h>
#include <stdbool.h>

/* Use existing RADIUS client */
#include <radius.h>

/*============================================================================
 * MAC-Auth Credential Formats
 *============================================================================*/

typedef enum {
    IPOE_MAC_AUTH_FORMAT_LOWER,       /* aa:bb:cc:dd:ee:ff */
    IPOE_MAC_AUTH_FORMAT_UPPER,       /* AA:BB:CC:DD:EE:FF */
    IPOE_MAC_AUTH_FORMAT_NOCOLON,     /* aabbccddeeff */
    IPOE_MAC_AUTH_FORMAT_HYPHEN,      /* aa-bb-cc-dd-ee-ff */
    IPOE_MAC_AUTH_FORMAT_DOMAIN       /* aa:bb:cc:dd:ee:ff@domain */
} ipoe_mac_format_t;

typedef enum {
    IPOE_MAC_PASS_EMPTY,              /* password = "" */
    IPOE_MAC_PASS_MAC,                /* password = MAC */
    IPOE_MAC_PASS_FIXED               /* password = configured value */
} ipoe_password_format_t;

/*============================================================================
 * IPoE RADIUS Configuration
 *============================================================================*/

struct ipoe_radius_config {
    bool     enabled;
    ipoe_mac_format_t mac_format;
    ipoe_password_format_t password_format;
    char     fixed_password[64];
    char     domain_suffix[64];
    uint32_t interim_interval;
};

/*============================================================================
 * IPoE RADIUS API (wrappers around radius_client)
 *============================================================================*/

/* Initialize (uses existing radius_client_init) */
int ipoe_radius_init(void);
void ipoe_radius_cleanup(void);

/* MAC-auth using existing RADIUS client */
int ipoe_radius_mac_auth(struct ipoe_session *sess);

/* RADIUS callbacks for IPoE sessions */
void ipoe_radius_auth_callback(uint8_t request_id, bool success,
                                uint32_t framed_ip, const char *message);
void ipoe_radius_coa_callback(const char *session_id, uint32_t new_timeout);
void ipoe_radius_dm_callback(const char *session_id);

/* Username/password construction */
void ipoe_radius_build_username(const uint8_t *mac, char *username, size_t len);
void ipoe_radius_build_password(const uint8_t *mac, char *password, size_t len);

/* Accounting wrappers */
int ipoe_radius_acct_start(struct ipoe_session *sess);
int ipoe_radius_acct_interim(struct ipoe_session *sess);
int ipoe_radius_acct_stop(struct ipoe_session *sess);

/* Statistics */
void ipoe_radius_print_stats(void);

#endif /* IPOE_RADIUS_H */
