/**
 * @file alg_ftp.c
 * @brief FTP Application Layer Gateway
 *
 * Implements RFC 959 FTP ALG for NAT traversal
 * Handles PORT and PASV command/response rewriting
 */

#include "nat_alg.h"
#include "nat.h"
#include "log.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <rte_mbuf.h>

/* FTP Commands and Responses */
#define FTP_CMD_PORT "PORT "
#define FTP_CMD_EPRT "EPRT "
#define FTP_RSP_PASV "227 "
#define FTP_RSP_EPSV "229 "

/**
 * Parse PORT command: PORT h1,h2,h3,h4,p1,p2
 * Returns IP and port, or -1 on failure
 */
static int ftp_parse_port(const char *cmd, uint32_t *ip_out, uint16_t *port_out)
{
    int h1, h2, h3, h4, p1, p2;

    if (sscanf(cmd, "%d,%d,%d,%d,%d,%d", &h1, &h2, &h3, &h4, &p1, &p2) != 6) {
        return -1;
    }

    *ip_out = (h1 << 24) | (h2 << 16) | (h3 << 8) | h4;
    *port_out = (p1 << 8) | p2;

    return 0;
}

/**
 * Format PORT command with new IP:port
 */
static int ftp_format_port(char *buf, int buf_size, uint32_t ip, uint16_t port)
{
    return snprintf(buf, buf_size, "%d,%d,%d,%d,%d,%d",
                    (ip >> 24) & 0xFF,
                    (ip >> 16) & 0xFF,
                    (ip >> 8) & 0xFF,
                    ip & 0xFF,
                    (port >> 8) & 0xFF,
                    port & 0xFF);
}

/**
 * Parse PASV response: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).
 * Note: Used when handling PASV response rewriting
 */
static int __attribute__((unused)) ftp_parse_pasv(const char *response, uint32_t *ip_out, uint16_t *port_out)
{
    /* Find opening parenthesis */
    const char *start = strchr(response, '(');
    if (!start) return -1;
    start++;

    return ftp_parse_port(start, ip_out, port_out);
}

/**
 * Rewrite PORT command in FTP control connection
 * Client is sending its data port to server
 */
static int ftp_rewrite_port(char *data, int *data_len, int max_len,
                             uint32_t old_ip, uint32_t new_ip,
                             uint16_t old_port, uint16_t new_port,
                             int *delta_out)
{
    (void)old_port; (void)new_port; /* Port rewrite not currently needed for PORT command */
    /* Find PORT command */
    char *port_cmd = strstr(data, FTP_CMD_PORT);
    if (!port_cmd) return -1;

    /* Find the IP,port string */
    char *ip_start = port_cmd + strlen(FTP_CMD_PORT);

    /* Find end of line */
    char *line_end = strstr(ip_start, "\r\n");
    if (!line_end) {
        line_end = strchr(ip_start, '\n');
        if (!line_end) return -1;
    }

    int old_len = line_end - ip_start;

    /* Format new PORT parameters */
    char new_params[32];
    int new_len = ftp_format_port(new_params, sizeof(new_params), new_ip, new_port);

    /* Calculate delta */
    *delta_out = new_len - old_len;

    /* Check if we have space */
    if (*data_len + *delta_out > max_len) {
        YLOG_WARNING("FTP ALG: Not enough space for PORT rewrite");
        return -1;
    }

    /* Shift tail if needed */
    if (*delta_out != 0) {
        int tail_len = *data_len - (line_end - data);
        memmove(ip_start + new_len, line_end, tail_len);
        *data_len += *delta_out;
    }

    /* Write new parameters */
    memcpy(ip_start, new_params, new_len);

    char old_ip_str[16], new_ip_str[16];
    struct in_addr addr;
    addr.s_addr = htonl(old_ip);
    inet_ntop(AF_INET, &addr, old_ip_str, sizeof(old_ip_str));
    addr.s_addr = htonl(new_ip);
    inet_ntop(AF_INET, &addr, new_ip_str, sizeof(new_ip_str));

    YLOG_DEBUG("FTP ALG: Rewrote PORT %s:%u -> %s:%u",
               old_ip_str, old_port, new_ip_str, new_port);

    return 0;
}

/**
 * Rewrite PASV response in FTP control connection
 * Server is telling client its data port
 */
static int ftp_rewrite_pasv(char *data, int *data_len, int max_len,
                             uint32_t old_ip, uint32_t new_ip,
                             uint16_t old_port, uint16_t new_port,
                             int *delta_out)
{
    (void)old_port; (void)new_port; /* Port rewrite not currently needed for PASV response */
    /* Find PASV response */
    char *pasv_rsp = strstr(data, FTP_RSP_PASV);
    if (!pasv_rsp) return -1;

    /* Find opening parenthesis */
    char *paren_start = strchr(pasv_rsp, '(');
    if (!paren_start) return -1;
    paren_start++;

    /* Find closing parenthesis */
    char *paren_end = strchr(paren_start, ')');
    if (!paren_end) return -1;

    int old_len = paren_end - paren_start;

    /* Format new PASV parameters */
    char new_params[32];
    int new_len = ftp_format_port(new_params, sizeof(new_params), new_ip, new_port);

    /* Calculate delta */
    *delta_out = new_len - old_len;

    /* Check if we have space */
    if (*data_len + *delta_out > max_len) {
        YLOG_WARNING("FTP ALG: Not enough space for PASV rewrite");
        return -1;
    }

    /* Shift tail if needed */
    if (*delta_out != 0) {
        int tail_len = *data_len - (paren_end - data);
        memmove(paren_start + new_len, paren_end, tail_len);
        *data_len += *delta_out;
    }

    /* Write new parameters */
    memcpy(paren_start, new_params, new_len);

    char old_ip_str[16], new_ip_str[16];
    struct in_addr addr;
    addr.s_addr = htonl(old_ip);
    inet_ntop(AF_INET, &addr, old_ip_str, sizeof(old_ip_str));
    addr.s_addr = htonl(new_ip);
    inet_ntop(AF_INET, &addr, new_ip_str, sizeof(new_ip_str));

    YLOG_DEBUG("FTP ALG: Rewrote PASV %s:%u -> %s:%u",
               old_ip_str, old_port, new_ip_str, new_port);

    return 0;
}

/**
 * Main FTP ALG processing function
 */
int alg_ftp_process_impl(struct nat_session *session, struct pkt_buf *pkt, bool is_in2out)
{
    if (!session || !pkt || !pkt->mbuf) return -1;

    struct rte_mbuf *mbuf = pkt->mbuf;

    /* Get TCP payload (FTP command/response) */
    uint8_t *l4_data = rte_pktmbuf_mtod_offset(mbuf, uint8_t *, pkt->meta.payload_offset);
    int payload_len = rte_pktmbuf_data_len(mbuf) - pkt->meta.payload_offset;

    if (payload_len <= 0) return 0; /* No payload */

    char *data = (char *)l4_data;
    int data_len = payload_len;
    int max_len = rte_pktmbuf_tailroom(mbuf) + payload_len;

    /* Determine translation direction */
    uint32_t old_ip, new_ip;
    uint16_t old_port, new_port;

    if (is_in2out) {
        /* Client->Server: Rewrite PORT commands */
        old_ip = session->inside_ip;
        new_ip = session->outside_ip;
        old_port = session->inside_port;
        new_port = session->outside_port;
    } else {
        /* Server->Client: Rewrite PASV responses */
        old_ip = session->outside_ip;
        new_ip = session->inside_ip;
        old_port = session->outside_port;
        new_port = session->inside_port;
    }

    int delta = 0;
    int result = 0;

    /* Try PORT rewrite (client->server direction) */
    if (strstr(data, FTP_CMD_PORT)) {
        result = ftp_rewrite_port(data, &data_len, max_len,
                                   old_ip, new_ip, old_port, new_port, &delta);
    }
    /* Try PASV rewrite (server->client direction) */
    else if (strstr(data, FTP_RSP_PASV)) {
        result = ftp_rewrite_pasv(data, &data_len, max_len,
                                   old_ip, new_ip, old_port, new_port, &delta);
    }

    /* Adjust mbuf length if data changed */
    if (delta != 0 && result == 0) {
        if (delta > 0) {
            if (!rte_pktmbuf_append(mbuf, delta)) {
                YLOG_WARNING("FTP ALG: Cannot extend mbuf by %d bytes", delta);
                return -1;
            }
        } else {
            rte_pktmbuf_trim(mbuf, -delta);
        }

        /* TCP sequence number adjustment tracking would go here */
        /* For now, we handle length change; seq tracking is Phase 2 */
    }

    return result;
}
