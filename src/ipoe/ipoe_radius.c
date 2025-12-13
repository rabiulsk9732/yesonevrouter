/**
 * @file ipoe_radius.c
 * @brief IPoE RADIUS Integration - Uses existing radius_client
 */

#include <ipoe_radius.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/*============================================================================
 * Configuration
 *============================================================================*/

static struct ipoe_radius_config g_ipoe_radius = {
    .enabled = true,
    .mac_format = IPOE_MAC_AUTH_FORMAT_LOWER,
    .password_format = IPOE_MAC_PASS_EMPTY,
    .interim_interval = 300
};

/*============================================================================
 * Initialization (delegates to existing radius_client)
 *============================================================================*/

int ipoe_radius_init(void)
{
    printf("ipoe_radius: using existing radius_client\n");
    /* radius_client_init() already called by main startup */
    return 0;
}

void ipoe_radius_cleanup(void)
{
    /* radius_client_cleanup() handled by main shutdown */
}

/*============================================================================
 * Username/Password Construction (IPoE-specific logic)
 *============================================================================*/

void ipoe_radius_build_username(const uint8_t *mac, char *username, size_t len)
{
    if (!mac || !username || len == 0) return;

    switch (g_ipoe_radius.mac_format) {
    case IPOE_MAC_AUTH_FORMAT_LOWER:
        snprintf(username, len, "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        break;
    case IPOE_MAC_AUTH_FORMAT_UPPER:
        snprintf(username, len, "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        break;
    case IPOE_MAC_AUTH_FORMAT_NOCOLON:
        snprintf(username, len, "%02x%02x%02x%02x%02x%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        break;
    case IPOE_MAC_AUTH_FORMAT_HYPHEN:
        snprintf(username, len, "%02x-%02x-%02x-%02x-%02x-%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        break;
    case IPOE_MAC_AUTH_FORMAT_DOMAIN:
        snprintf(username, len, "%02x:%02x:%02x:%02x:%02x:%02x@%s",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                 g_ipoe_radius.domain_suffix);
        break;
    }
}

void ipoe_radius_build_password(const uint8_t *mac, char *password, size_t len)
{
    if (!password || len == 0) return;

    switch (g_ipoe_radius.password_format) {
    case IPOE_MAC_PASS_EMPTY:
        password[0] = '\0';
        break;
    case IPOE_MAC_PASS_MAC:
        if (mac) {
            snprintf(password, len, "%02x:%02x:%02x:%02x:%02x:%02x",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }
        break;
    case IPOE_MAC_PASS_FIXED:
        strncpy(password, g_ipoe_radius.fixed_password, len - 1);
        password[len - 1] = '\0';
        break;
    }
}

/*============================================================================
 * MAC Authentication (uses existing radius_client_send_auth)
 *============================================================================*/

int ipoe_radius_mac_auth(struct ipoe_session *sess)
{
    if (!sess) return -1;

    /* Build credentials */
    ipoe_radius_build_username(sess->mac, sess->username, sizeof(sess->username));

    char password[64];
    ipoe_radius_build_password(sess->mac, password, sizeof(password));

    printf("ipoe_radius: MAC-auth for %s\n", sess->username);
    sess->aaa_state = AAA_STATE_PENDING;

    /* Call existing RADIUS client */
    extern int radius_client_send_auth(const char *username, const char *password,
                                        uint32_t nas_port, const char *calling_station_id);

    char calling_station[18];
    ipoe_session_format_mac(sess->mac, calling_station, sizeof(calling_station));

    int ret = radius_client_send_auth(sess->username, password,
                                       sess->ifindex, calling_station);

    if (ret != 0) {
        sess->aaa_state = AAA_STATE_TIMEOUT;
        return -1;
    }

    return 0;
}

/*============================================================================
 * Accounting (uses existing radius_client accounting API)
 *============================================================================*/

int ipoe_radius_acct_start(struct ipoe_session *sess)
{
    if (!sess) return -1;

    printf("ipoe_radius: Acct-Start for session %u\n", sess->session_id);
    sess->flags |= IPOE_FLAG_ACCOUNTING;

    /* Use existing RADIUS accounting */
    extern int radius_send_accounting_start(uint32_t session_id, const char *username,
                                             uint32_t framed_ip, const char *calling_station_id);

    char calling_station[18];
    ipoe_session_format_mac(sess->mac, calling_station, sizeof(calling_station));

    return radius_send_accounting_start(sess->session_id, sess->username,
                                         sess->ip_addr, calling_station);
}

int ipoe_radius_acct_interim(struct ipoe_session *sess)
{
    if (!sess) return -1;

    /* Use existing RADIUS accounting */
    extern int radius_send_accounting_interim(uint32_t session_id,
                                               uint64_t bytes_in, uint64_t bytes_out,
                                               uint64_t packets_in, uint64_t packets_out,
                                               uint32_t session_time);

    uint32_t session_time = (uint32_t)((sess->last_activity - sess->session_start) / 1000000000ULL);

    return radius_send_accounting_interim(sess->session_id,
                                           sess->bytes_in, sess->bytes_out,
                                           sess->packets_in, sess->packets_out,
                                           session_time);
}

int ipoe_radius_acct_stop(struct ipoe_session *sess)
{
    if (!sess) return -1;

    printf("ipoe_radius: Acct-Stop for session %u\n", sess->session_id);
    sess->flags &= ~IPOE_FLAG_ACCOUNTING;

    extern int radius_send_accounting_stop(uint32_t session_id,
                                            uint64_t bytes_in, uint64_t bytes_out,
                                            uint64_t packets_in, uint64_t packets_out,
                                            uint32_t session_time, uint8_t term_cause);

    uint32_t session_time = (uint32_t)((sess->last_activity - sess->session_start) / 1000000000ULL);
    uint8_t term_cause = 1;  /* User-Request */

    return radius_send_accounting_stop(sess->session_id,
                                        sess->bytes_in, sess->bytes_out,
                                        sess->packets_in, sess->packets_out,
                                        session_time, term_cause);
}

/*============================================================================
 * Statistics (delegates to existing radius_client)
 *============================================================================*/

void ipoe_radius_print_stats(void)
{
    printf("\nIPoE RADIUS (using existing radius_client):\n");
    printf("  MAC format: %d\n", g_ipoe_radius.mac_format);
    printf("  Password format: %d\n", g_ipoe_radius.password_format);
    printf("\n");

    /* Delegate to existing stats */
    extern void radius_client_print_stats(void);
    radius_client_print_stats();
}
