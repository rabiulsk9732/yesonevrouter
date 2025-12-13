/**
 * @file nat_alg.c
 * @brief NAT Application Level Gateway (ALG) framework
 *
 * Dispatches ALG processing to protocol-specific handlers
 */

#include "nat_alg.h"
#include "nat.h"
#include "log.h"
#include <arpa/inet.h>

/* ALG Ports */
#define FTP_PORT 21
#define FTP_DATA_PORT 20
#define SIP_PORT 5060
#define SIP_TLS_PORT 5061
#define RTSP_PORT 554
#define TFTP_PORT 69
#define PPTP_PORT 1723

/* External ALG implementations */
extern int alg_sip_process_impl(struct nat_session *session, struct pkt_buf *pkt, bool is_in2out);
extern int alg_ftp_process_impl(struct nat_session *session, struct pkt_buf *pkt, bool is_in2out);

/**
 * Detect ALG type based on protocol and port
 */
uint8_t nat_alg_detect(uint8_t protocol, uint16_t dst_port)
{
    if (protocol == IPPROTO_TCP) {
        switch (dst_port) {
            case FTP_PORT:
                return NAT_ALG_FTP;
            case PPTP_PORT:
                return NAT_ALG_PPTP;
            case RTSP_PORT:
                return NAT_ALG_RTSP;
            default:
                break;
        }
    } else if (protocol == IPPROTO_UDP) {
        switch (dst_port) {
            case SIP_PORT:
            case SIP_TLS_PORT:
                return NAT_ALG_SIP;
            case TFTP_PORT:
                return NAT_ALG_TFTP;
            default:
                break;
        }
    }

    /* Also check source port for responses */
    if (protocol == IPPROTO_TCP && dst_port == FTP_DATA_PORT) {
        return NAT_ALG_FTP;
    }

    return NAT_ALG_NONE;
}

/**
 * Get ALG name for logging
 */
const char *nat_alg_name(uint8_t alg_type)
{
    switch (alg_type) {
        case NAT_ALG_FTP:  return "FTP";
        case NAT_ALG_SIP:  return "SIP";
        case NAT_ALG_RTSP: return "RTSP";
        case NAT_ALG_TFTP: return "TFTP";
        case NAT_ALG_PPTP: return "PPTP";
        case NAT_ALG_ICMP: return "ICMP";
        default:          return "NONE";
    }
}

/**
 * Main ALG dispatch function
 */
int nat_alg_process(struct nat_session *session, struct pkt_buf *pkt, bool is_in2out)
{
    if (!session || !pkt) return -1;

    int result = 0;

    switch (session->alg_type) {
        case NAT_ALG_FTP:
            result = alg_ftp_process_impl(session, pkt, is_in2out);
            break;

        case NAT_ALG_SIP:
            result = alg_sip_process_impl(session, pkt, is_in2out);
            break;

        case NAT_ALG_RTSP:
            /* RTSP ALG - similar to SIP, uses RTSP describe/setup */
            YLOG_DEBUG("RTSP ALG: Not yet implemented");
            result = 0;
            break;

        case NAT_ALG_TFTP:
            /* TFTP ALG - simple UDP, needs option extension handling */
            YLOG_DEBUG("TFTP ALG: Not yet implemented");
            result = 0;
            break;

        case NAT_ALG_PPTP:
            /* PPTP needs GRE session tracking */
            YLOG_DEBUG("PPTP ALG: Not yet implemented");
            result = 0;
            break;

        case NAT_ALG_ICMP:
            /* ICMP handled by alg_icmp.c separately */
            result = 0;
            break;

        case NAT_ALG_NONE:
        default:
            result = 0;
            break;
    }

    return result;
}

/**
 * Check if a session needs ALG marking
 */
void nat_alg_mark_session(struct nat_session *session, uint8_t protocol,
                          uint16_t dst_port)
{
    if (!session) return;

    uint8_t alg_type = nat_alg_detect(protocol, dst_port);
    if (alg_type != NAT_ALG_NONE) {
        session->alg_type = alg_type;
        session->alg_active = 1;
        YLOG_DEBUG("NAT ALG: Session marked for %s processing",
                   nat_alg_name(alg_type));
    }
}
