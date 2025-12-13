/**
 * @file alg_sip.c
 * @brief SIP Application Layer Gateway
 *
 * Implements RFC 3261 SIP ALG for NAT traversal
 * Rewrites SIP headers and SDP body with translated addresses
 */

#include "nat_alg.h"
#include "nat.h"
#include "log.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <rte_mbuf.h>

/* SIP Ports */
#define SIP_PORT 5060
#define SIP_TLS_PORT 5061

/* Maximum line length in SIP message */
#define SIP_MAX_LINE 512

/* SDP media types */
#define SDP_MEDIA_AUDIO "audio"
#define SDP_MEDIA_VIDEO "video"

/**
 * Find a header line in SIP message
 * @param data Start of SIP message
 * @param len Length of message
 * @param header Header name to find (e.g., "Via:")
 * @param value_out Buffer for header value
 * @param value_max Max length of value buffer
 * @return Offset of header value, or -1 if not found
 */
static int __attribute__((unused)) sip_find_header(const char *data, int len, const char *header,
                           char *value_out, int value_max)
{
    int header_len = strlen(header);
    const char *p = data;
    const char *end = data + len;

    while (p < end - header_len) {
        /* Check for header match (case-insensitive for first char) */
        if (strncasecmp(p, header, header_len) == 0) {
            const char *val_start = p + header_len;
            /* Skip whitespace */
            while (val_start < end && (*val_start == ' ' || *val_start == '\t')) {
                val_start++;
            }
            /* Find end of line */
            const char *val_end = val_start;
            while (val_end < end && *val_end != '\r' && *val_end != '\n') {
                val_end++;
            }
            int val_len = val_end - val_start;
            if (val_len > 0 && val_len < value_max) {
                memcpy(value_out, val_start, val_len);
                value_out[val_len] = '\0';
                return val_start - data;
            }
            return -1;
        }
        /* Move to next line */
        while (p < end && *p != '\n') p++;
        if (p < end) p++;
    }
    return -1;
}

/**
 * Find IP address in string and replace it
 * @param data String to search
 * @param len Length of string
 * @param old_ip Old IP address (host order)
 * @param new_ip New IP address (host order)
 * @param delta_out Length change after replacement
 * @return 0 if replaced, -1 if not found
 */
static int sip_replace_ip(char *data, int *len, uint32_t old_ip, uint32_t new_ip,
                          int *delta_out)
{
    char old_ip_str[16], new_ip_str[16];
    struct in_addr addr;

    addr.s_addr = htonl(old_ip);
    inet_ntop(AF_INET, &addr, old_ip_str, sizeof(old_ip_str));

    addr.s_addr = htonl(new_ip);
    inet_ntop(AF_INET, &addr, new_ip_str, sizeof(new_ip_str));

    int old_len = strlen(old_ip_str);
    int new_len = strlen(new_ip_str);

    /* Search for old IP in data */
    char *pos = strstr(data, old_ip_str);
    if (!pos) {
        *delta_out = 0;
        return -1;
    }

    /* Calculate delta */
    *delta_out = new_len - old_len;

    /* Shift data if necessary */
    if (*delta_out != 0) {
        int tail_len = *len - (pos - data) - old_len;
        memmove(pos + new_len, pos + old_len, tail_len + 1);
        *len += *delta_out;
    }

    /* Replace IP */
    memcpy(pos, new_ip_str, new_len);

    return 0;
}

/**
 * Parse and rewrite SDP c= line (connection address)
 * Format: c=IN IP4 <address>
 */
static int sdp_rewrite_connection(char *sdp, int *sdp_len,
                                   uint32_t old_ip, uint32_t new_ip,
                                   int *total_delta)
{
    char *c_line = strstr(sdp, "c=IN IP4 ");
    if (!c_line) {
        c_line = strstr(sdp, "c=IN IP6 ");
        if (!c_line) return -1;
    }

    int delta = 0;
    if (sip_replace_ip(c_line, sdp_len, old_ip, new_ip, &delta) == 0) {
        *total_delta += delta;
        return 0;
    }
    return -1;
}

/**
 * Parse and rewrite SDP o= line (origin address)
 * Format: o=<username> <sess-id> <sess-version> IN IP4 <address>
 */
static int sdp_rewrite_origin(char *sdp, int *sdp_len,
                               uint32_t old_ip, uint32_t new_ip,
                               int *total_delta)
{
    char *o_line = strstr(sdp, "o=");
    if (!o_line) return -1;

    /* Find "IN IP4" in origin line */
    char *in_ip4 = strstr(o_line, "IN IP4 ");
    if (!in_ip4) {
        in_ip4 = strstr(o_line, "IN IP6 ");
    }
    if (!in_ip4) return -1;

    /* Make sure we're on the same line */
    char *line_end = strchr(o_line, '\n');
    if (line_end && in_ip4 > line_end) return -1;

    int delta = 0;
    if (sip_replace_ip(in_ip4, sdp_len, old_ip, new_ip, &delta) == 0) {
        *total_delta += delta;
        return 0;
    }
    return -1;
}

/**
 * Parse and rewrite SDP m= line port
 * Format: m=<media> <port> <transport> <formats>
 * Returns the media port for pinhole creation
 */
static int sdp_parse_media_port(const char *sdp, const char *media_type,
                                 uint16_t *port_out)
{
    char search[32];
    snprintf(search, sizeof(search), "m=%s ", media_type);

    const char *m_line = strstr(sdp, search);
    if (!m_line) return -1;

    /* Parse port after media type */
    const char *port_start = m_line + strlen(search);
    *port_out = (uint16_t)atoi(port_start);

    return 0;
}

/**
 * Rewrite SIP Via header
 * Format: Via: SIP/2.0/UDP <host>:<port>;...
 */
static int sip_rewrite_via(char *msg, int *msg_len,
                            uint32_t old_ip, uint32_t new_ip,
                            uint16_t old_port, uint16_t new_port,
                            int *total_delta)
{
    char *via = strstr(msg, "Via:");
    if (!via) via = strstr(msg, "v:");
    if (!via) return -1;

    int delta = 0;
    sip_replace_ip(via, msg_len, old_ip, new_ip, &delta);
    *total_delta += delta;

    /* TODO: Port replacement if needed */
    (void)old_port;
    (void)new_port;

    return 0;
}

/**
 * Rewrite SIP Contact header
 * Format: Contact: <sip:user@host:port>
 */
static int sip_rewrite_contact(char *msg, int *msg_len,
                                uint32_t old_ip, uint32_t new_ip,
                                int *total_delta)
{
    char *contact = strstr(msg, "Contact:");
    if (!contact) contact = strstr(msg, "m:");
    if (!contact) return -1;

    int delta = 0;
    sip_replace_ip(contact, msg_len, old_ip, new_ip, &delta);
    *total_delta += delta;

    return 0;
}

/**
 * Update Content-Length header after SDP modification
 */
static int sip_update_content_length(char *msg, int msg_len, int sdp_delta)
{
    char *cl = strstr(msg, "Content-Length:");
    if (!cl) cl = strstr(msg, "l:");
    if (!cl) return -1;

    /* Find start of value */
    char *val_start = cl;
    while (*val_start != ':') val_start++;
    val_start++;
    while (*val_start == ' ') val_start++;

    /* Parse current length */
    int old_len = atoi(val_start);
    int new_len = old_len + sdp_delta;
    if (new_len < 0) new_len = 0;

    /* Find end of value */
    char *val_end = val_start;
    while (*val_end >= '0' && *val_end <= '9') val_end++;

    /* Calculate space needed */
    char new_val[16];
    int new_val_len = snprintf(new_val, sizeof(new_val), "%d", new_len);
    int old_val_len = val_end - val_start;

    /* Replace */
    if (new_val_len != old_val_len) {
        int tail_len = msg_len - (val_end - msg);
        memmove(val_start + new_val_len, val_end, tail_len);
    }
    memcpy(val_start, new_val, new_val_len);

    return new_val_len - old_val_len;
}

/**
 * Main SIP ALG processing function
 */
int alg_sip_process_impl(struct nat_session *session, struct pkt_buf *pkt, bool is_in2out)
{
    if (!session || !pkt || !pkt->mbuf) return -1;

    struct rte_mbuf *mbuf = pkt->mbuf;

    /* Get L4 payload (SIP message) */
    uint8_t *l4_data = rte_pktmbuf_mtod_offset(mbuf, uint8_t *, pkt->meta.payload_offset);
    int payload_len = rte_pktmbuf_data_len(mbuf) - pkt->meta.payload_offset;

    if (payload_len <= 0) return 0; /* No payload */

    /* Make payload null-terminated for string ops (temporary) */
    char *msg = (char *)l4_data;
    int msg_len = payload_len;

    /* Determine which IP to rewrite */
    uint32_t old_ip, new_ip;
    if (is_in2out) {
        old_ip = session->inside_ip;
        new_ip = session->outside_ip;
    } else {
        old_ip = session->outside_ip;
        new_ip = session->inside_ip;
    }

    int total_delta = 0;

    /* Rewrite SIP headers */
    sip_rewrite_via(msg, &msg_len, old_ip, new_ip,
                    session->inside_port, session->outside_port, &total_delta);
    sip_rewrite_contact(msg, &msg_len, old_ip, new_ip, &total_delta);

    /* Find SDP body (after blank line) */
    char *sdp = strstr(msg, "\r\n\r\n");
    if (sdp) {
        sdp += 4;
        int sdp_len = msg_len - (sdp - msg);
        int sdp_delta = 0;

        /* Rewrite SDP */
        sdp_rewrite_connection(sdp, &sdp_len, old_ip, new_ip, &sdp_delta);
        sdp_rewrite_origin(sdp, &sdp_len, old_ip, new_ip, &sdp_delta);

        /* Parse media ports for pinhole creation */
        uint16_t audio_port = 0, video_port = 0;
        sdp_parse_media_port(sdp, SDP_MEDIA_AUDIO, &audio_port);
        sdp_parse_media_port(sdp, SDP_MEDIA_VIDEO, &video_port);

        /* Log media ports (pinhole creation would go here) */
        if (audio_port > 0) {
            YLOG_DEBUG("SIP ALG: Audio RTP port %u detected", audio_port);
        }
        if (video_port > 0) {
            YLOG_DEBUG("SIP ALG: Video RTP port %u detected", video_port);
        }

        total_delta += sdp_delta;

        /* Update Content-Length if SDP changed */
        if (sdp_delta != 0) {
            int cl_delta = sip_update_content_length(msg, msg_len, sdp_delta);
            total_delta += cl_delta;
        }
    }

    /* Adjust mbuf length if message size changed */
    if (total_delta != 0) {
        if (total_delta > 0) {
            char *new_tail = rte_pktmbuf_append(mbuf, total_delta);
            if (!new_tail) {
                YLOG_WARNING("SIP ALG: Cannot extend mbuf by %d bytes", total_delta);
                return -1;
            }
        } else {
            rte_pktmbuf_trim(mbuf, -total_delta);
        }

        /* Update IP total length */
        /* This would need to recalculate checksums - handled by caller */
    }

    YLOG_DEBUG("SIP ALG: Processed %s, delta=%d bytes",
               is_in2out ? "in2out" : "out2in", total_delta);

    return 0;
}
