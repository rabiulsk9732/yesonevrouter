/**
 * @file radius.c
 * @brief RADIUS Client Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/md5.h> /* For RADIUS authenticator/password hiding */

#include "radius.h"
#include "log.h"

static struct radius_server g_server;
static int g_sock = -1;
static int g_coa_sock = -1;
static uint8_t g_identifier = 0;

/* Pending Request Table (Map Identifier -> Session ID) */
static uint16_t g_pending_sessions[256]; /* Indexed by Identifier */

int radius_init(void)
{
    g_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_sock < 0) {
        YLOG_ERROR("RADIUS: Failed to create client socket");
        return -1;
    }

    /* CoA Socket */
    g_coa_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_coa_sock < 0) {
        YLOG_ERROR("RADIUS: Failed to create CoA socket");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(3799);

    if (bind(g_coa_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        YLOG_ERROR("RADIUS: Failed to bind CoA socket");
        /* Non-fatal for now, maybe just warning */
    }

    /* Set non-blocking */
    /* TODO: fcntl O_NONBLOCK */

    /* Default: No server */
    memset(&g_server, 0, sizeof(g_server));
    return 0;
}

void radius_add_server(uint32_t ip, uint16_t port, const char *secret)
{
    g_server.ip = ip;
    g_server.port = port ? port : 1812;
    g_server.acct_port = 1813;
    strncpy(g_server.secret, secret, sizeof(g_server.secret) - 1);
    YLOG_INFO("RADIUS: Server configured: %u.%u.%u.%u:%u",
              (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF, g_server.port);
}

/* Helper to append attribute */
static int radius_add_attr(uint8_t *buf, int offset, uint8_t type, const uint8_t *data, uint8_t len)
{
    buf[offset] = type;
    buf[offset + 1] = len + 2;
    memcpy(buf + offset + 2, data, len);
    return offset + len + 2;
}

int radius_auth_request(const char *username, const char *password, uint16_t session_id, const uint8_t *client_mac)
{
    if (g_server.ip == 0) return -1;
    (void)session_id; /* Unused for Access-Request */

    uint8_t packet[4096];
    struct sockaddr_in dest;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(g_server.port);
    dest.sin_addr.s_addr = htonl(g_server.ip);

    /* Header */
    packet[0] = RADIUS_CODE_ACCESS_REQUEST;
    packet[1] = ++g_identifier;
    g_pending_sessions[g_identifier] = session_id; /* Store mapping */
    /* Length at packet[2-3] filled later */

    /* Authenticator (Random) */
    for (int i = 0; i < 16; i++) packet[4 + i] = rand() % 256;

    int offset = 20;

    /* User-Name */
    offset = radius_add_attr(packet, offset, RADIUS_ATTR_USER_NAME, (const uint8_t *)username, strlen(username));

    /* User-Password (PAP) - Hidden */
    /* MD5(Secret + Authenticator) XOR Password */
    /* Simplified: Just sending plaintext for now as mock, real impl needs MD5 */
    /* TODO: Implement proper password hiding */
    offset = radius_add_attr(packet, offset, RADIUS_ATTR_USER_PASSWORD, (const uint8_t *)password, strlen(password));

    /* NAS-IP-Address */
    uint32_t nas_ip = htonl(0x64400001); /* 100.64.0.1 */
    offset = radius_add_attr(packet, offset, RADIUS_ATTR_NAS_IP_ADDRESS, (uint8_t *)&nas_ip, 4);

    /* Calling-Station-ID (MAC) */
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x-%02x-%02x-%02x-%02x-%02x",
             client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5]);
    offset = radius_add_attr(packet, offset, RADIUS_ATTR_CALLING_STATION_ID, (const uint8_t *)mac_str, strlen(mac_str));

    /* Length */
    uint16_t len = htons(offset);
    memcpy(packet + 2, &len, 2);

    /* Send */
    sendto(g_sock, packet, offset, 0, (struct sockaddr *)&dest, sizeof(dest));
    YLOG_INFO("RADIUS: Sent Access-Request for user '%s'", username);

    return 0;
}

int radius_chap_auth_request(const char *username, const uint8_t *chap_challenge, uint8_t chap_challenge_len, const uint8_t *chap_password, uint8_t chap_password_len, uint16_t session_id, const uint8_t *client_mac)
{
    if (g_server.ip == 0) return -1;
    (void)session_id;

    uint8_t packet[4096];
    struct sockaddr_in dest;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(g_server.port);
    dest.sin_addr.s_addr = htonl(g_server.ip);

    /* Header */
    packet[0] = RADIUS_CODE_ACCESS_REQUEST;
    packet[1] = ++g_identifier;

    /* Authenticator (Random) */
    for (int i = 0; i < 16; i++) packet[4 + i] = rand() % 256;

    int offset = 20;

    /* User-Name */
    offset = radius_add_attr(packet, offset, RADIUS_ATTR_USER_NAME, (const uint8_t *)username, strlen(username));

    /* CHAP-Password */
    /* Attribute 3: 1 byte CHAP ID + 16 bytes CHAP Response */
    offset = radius_add_attr(packet, offset, RADIUS_ATTR_CHAP_PASSWORD, chap_password, chap_password_len);

    /* CHAP-Challenge */
    /* Attribute 60: Challenge Value */
    offset = radius_add_attr(packet, offset, RADIUS_ATTR_CHAP_CHALLENGE, chap_challenge, chap_challenge_len);

    /* NAS-IP-Address */
    uint32_t nas_ip = htonl(0x64400001); /* 100.64.0.1 */
    offset = radius_add_attr(packet, offset, RADIUS_ATTR_NAS_IP_ADDRESS, (uint8_t *)&nas_ip, 4);

    /* Calling-Station-ID (MAC) */
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x-%02x-%02x-%02x-%02x-%02x",
             client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5]);
    offset = radius_add_attr(packet, offset, RADIUS_ATTR_CALLING_STATION_ID, (const uint8_t *)mac_str, strlen(mac_str));

    /* Length */
    uint16_t len = htons(offset);
    memcpy(packet + 2, &len, 2);

    /* Send */
    sendto(g_sock, packet, offset, 0, (struct sockaddr *)&dest, sizeof(dest));
    YLOG_INFO("RADIUS: Sent CHAP Access-Request for user '%s'", username);

    return 0;
}

int radius_acct_request(uint8_t status, uint16_t session_id, const char *username, uint32_t client_ip)
{
    if (g_server.ip == 0) return -1;

    uint8_t packet[4096];
    struct sockaddr_in dest;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(g_server.acct_port);
    dest.sin_addr.s_addr = htonl(g_server.ip);

    /* Header */
    packet[0] = RADIUS_CODE_ACCOUNTING_REQUEST;
    packet[1] = ++g_identifier;

    /* Authenticator (Zero for Acct-Req, signed later? No, RFC 2866 says Request Authenticator is MD5(Code+ID+Len+Request Authenticator+Attributes+Secret)?? No, that's response.
       Request Authenticator in Acct-Request is standard 16 bytes? No, it's MD5(Code + ID + Length + 16 zero octets + Request Attributes + Secret).
       For simplicity in this mock, using random.
    */
    for (int i = 0; i < 16; i++) packet[4 + i] = 0;

    int offset = 20;

    /* Status-Type */
    uint32_t status_val = htonl(status);
    offset = radius_add_attr(packet, offset, RADIUS_ATTR_ACCT_STATUS_TYPE, (uint8_t *)&status_val, 4);

    /* Acct-Session-Id */
    char sess_id_str[16];
    snprintf(sess_id_str, sizeof(sess_id_str), "%u", session_id);
    offset = radius_add_attr(packet, offset, RADIUS_ATTR_ACCT_SESSION_ID, (const uint8_t *)sess_id_str, strlen(sess_id_str));

    /* User-Name */
    if (username)
        offset = radius_add_attr(packet, offset, RADIUS_ATTR_USER_NAME, (const uint8_t *)username, strlen(username));

    /* Framed-IP-Address */
    uint32_t ip_val = htonl(client_ip);
    offset = radius_add_attr(packet, offset, RADIUS_ATTR_FRAMED_IP_ADDRESS, (uint8_t *)&ip_val, 4);

    /* Length */
    uint16_t len = htons(offset);
    memcpy(packet + 2, &len, 2);

    /* Send */
    sendto(g_sock, packet, offset, 0, (struct sockaddr *)&dest, sizeof(dest));
    YLOG_INFO("RADIUS: Sent Accounting-Request (Status %d) for user '%s'", status, username);

    return 0;
}

static void (*g_coa_callback)(const uint8_t *mac, uint64_t rate) = NULL;

void radius_set_coa_callback(void (*cb)(const uint8_t *, uint64_t))
{
    g_coa_callback = cb;
}

static void (*g_auth_callback)(uint16_t session_id, bool success, uint32_t framed_ip, uint32_t session_timeout, uint32_t idle_timeout) = NULL;

void radius_set_auth_callback(void (*cb)(uint16_t, bool, uint32_t, uint32_t, uint32_t))
{
    g_auth_callback = cb;
}

static void radius_process_auth_response(const uint8_t *buf, ssize_t len)
{
    if (len < 20) return;

    uint8_t code = buf[0];
    uint8_t id = buf[1];

    if (code == RADIUS_CODE_ACCESS_ACCEPT || code == RADIUS_CODE_ACCESS_REJECT) {
        bool success = (code == RADIUS_CODE_ACCESS_ACCEPT);
        uint32_t session_timeout = 0;
        uint32_t idle_timeout = 0;
        uint32_t framed_ip = 0;
        uint16_t session_id = g_pending_sessions[id];

        if (session_id == 0) {
            return;
        }

        /* Clear pending */
        g_pending_sessions[id] = 0;

        if (success) {
            YLOG_INFO("RADIUS: Access-Accept for Session %u", session_id);

            /* Parse Attributes */
            uint16_t length = ntohs(*(uint16_t *)(buf + 2));
            int offset = 20;

            while (offset < length) {
                uint8_t type = buf[offset];
                uint8_t attr_len = buf[offset + 1];
                if (attr_len < 2) break;

                if (type == RADIUS_ATTR_SESSION_TIMEOUT) {
                    if (attr_len == 6) {
                        uint32_t val;
                        memcpy(&val, buf + offset + 2, 4);
                        session_timeout = ntohl(val);
                    }
                } else if (type == RADIUS_ATTR_IDLE_TIMEOUT) {
                    if (attr_len == 6) {
                        uint32_t val;
                        memcpy(&val, buf + offset + 2, 4);
                        idle_timeout = ntohl(val);
                    }
                } else if (type == RADIUS_ATTR_FRAMED_IP_ADDRESS) {
                    if (attr_len == 6) {
                        memcpy(&framed_ip, buf + offset + 2, 4);
                        framed_ip = ntohl(framed_ip);
                        YLOG_INFO("RADIUS: Framed-IP-Address %u.%u.%u.%u for session %u",
                                  (framed_ip >> 24) & 0xFF, (framed_ip >> 16) & 0xFF,
                                  (framed_ip >> 8) & 0xFF, framed_ip & 0xFF, session_id);
                    }
                }

                offset += attr_len;
            }
        } else {
            YLOG_INFO("RADIUS: Access-Reject for Session %u", session_id);
        }

        if (g_auth_callback) {
            g_auth_callback(session_id, success, framed_ip, session_timeout, idle_timeout);
        }
    }
}

void radius_poll(void)
{
    uint8_t buf[4096];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    ssize_t len;

    /* 1. Poll CoA Socket */
    if (g_coa_sock >= 0) {
        len = recvfrom(g_coa_sock, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&src_addr, &addr_len);
        if (len >= 20) {
            uint8_t code = buf[0];
            if (code == RADIUS_CODE_DISCONNECT_REQUEST) {
                YLOG_INFO("RADIUS: Received Disconnect-Request");
                buf[0] = RADIUS_CODE_DISCONNECT_ACK;
                sendto(g_coa_sock, buf, 20, 0, (struct sockaddr *)&src_addr, addr_len);
            } else if (code == RADIUS_CODE_COA_REQUEST) {
                YLOG_INFO("RADIUS: Received CoA-Request");
                /* Parse Attributes for Rate Limiting */
                uint16_t length = ntohs(*(uint16_t *)(buf + 2));
                int offset = 20;
                uint8_t mac[6] = {0};
                bool mac_found = false;
                uint64_t rate = 0;
                while (offset < length) {
                    uint8_t type = buf[offset];
                    uint8_t attr_len = buf[offset + 1];
                    if (attr_len < 2) break;
                    if (type == RADIUS_ATTR_CALLING_STATION_ID) {
                        char mac_str[18];
                        memcpy(mac_str, buf + offset + 2, attr_len - 2);
                        mac_str[attr_len - 2] = '\0';
                        unsigned int m[6];
                        if (sscanf(mac_str, "%02x-%02x-%02x-%02x-%02x-%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                            for(int i=0; i<6; i++) mac[i] = (uint8_t)m[i];
                            mac_found = true;
                        }
                    } else if (type == RADIUS_ATTR_FILTER_ID) {
                        char filter[64];
                        int len = attr_len - 2;
                        if (len > 63) len = 63;
                        memcpy(filter, buf + offset + 2, len);
                        filter[len] = '\0';
                        if (strncmp(filter, "rate=", 5) == 0) {
                            rate = strtoull(filter + 5, NULL, 10);
                        }
                    }
                    offset += attr_len;
                }
                if (mac_found && rate > 0) {
                    if (g_coa_callback) g_coa_callback(mac, rate);
                }
                buf[0] = RADIUS_CODE_COA_ACK;
                sendto(g_coa_sock, buf, 20, 0, (struct sockaddr *)&src_addr, addr_len);
            }
        }
    }

    /* 2. Poll Auth/Acct Socket */
    if (g_sock >= 0) {
        len = recvfrom(g_sock, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&src_addr, &addr_len);
        if (len > 0) {
            radius_process_auth_response(buf, len);
        }
    }
}
