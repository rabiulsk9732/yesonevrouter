/**
 * @file pppoe_defs.h
 * @brief PPPoE and PPP Protocol Definitions
 */

#ifndef PPPOE_DEFS_H
#define PPPOE_DEFS_H

#include <stdint.h>

/* EtherTypes */
#define ETH_P_PPPOE_DISC    0x8863  /* PPPoE Discovery Stage */
#define ETH_P_PPPOE_SESS    0x8864  /* PPPoE Session Stage */

/* PPPoE Codes */
#define PPPOE_CODE_PADI     0x09    /* Active Discovery Initiation */
#define PPPOE_CODE_PADO     0x07    /* Active Discovery Offer */
#define PPPOE_CODE_PADR     0x19    /* Active Discovery Request */
#define PPPOE_CODE_PADS     0x65    /* Active Discovery Session-confirmation */
#define PPPOE_CODE_PADT     0xA7    /* Active Discovery Terminate */
#define PPPOE_CODE_SESS     0x00    /* Session Data */

/* PPPoE Tags */
#define PPPOE_TAG_END_OF_LIST       0x0000
#define PPPOE_TAG_SERVICE_NAME      0x0101
#define PPPOE_TAG_AC_NAME           0x0102
#define PPPOE_TAG_HOST_UNIQ         0x0103
#define PPPOE_TAG_AC_COOKIE         0x0104
#define PPPOE_TAG_VENDOR_SPEC       0x0105
#define PPPOE_TAG_RELAY_SESSION_ID  0x0110
#define PPPOE_TAG_SERVICE_NAME_ERR  0x0201
#define PPPOE_TAG_AC_SYSTEM_ERR     0x0202
#define PPPOE_TAG_GENERIC_ERR       0x0203

/* PPP Protocols */
#define PPP_PROTO_IP        0x0021  /* Internet Protocol */
#define PPP_PROTO_LCP       0xC021  /* Link Control Protocol */
#define PPP_PROTO_PAP       0xC023  /* Password Authentication Protocol */
#define PPP_PROTO_CHAP      0xC223  /* Challenge Handshake Authentication Protocol */
#define PPP_PROTO_IPCP      0x8021  /* IP Control Protocol */

/* LCP Codes */
#define LCP_CODE_CONF_REQ   1       /* Configure-Request */
#define LCP_CODE_CONF_ACK   2       /* Configure-Ack */
#define LCP_CODE_CONF_NAK   3       /* Configure-Nak */
#define LCP_CODE_CONF_REJ   4       /* Configure-Reject */
#define LCP_CODE_TERM_REQ   5       /* Terminate-Request */
#define LCP_CODE_TERM_ACK   6       /* Terminate-Ack */
#define LCP_CODE_CODE_REJ   7       /* Code-Reject */
#define LCP_CODE_PROTO_REJ  8       /* Protocol-Reject */
#define LCP_CODE_ECHO_REQ   9       /* Echo-Request */
#define LCP_CODE_ECHO_REPLY 10      /* Echo-Reply */
#define LCP_CODE_DISC_REQ   11      /* Discard-Request */

/* LCP Options */
#define LCP_OPT_MRU         1       /* Maximum Receive Unit */
#define LCP_OPT_AUTH_PROTO  3       /* Authentication Protocol */
#define LCP_OPT_MAGIC_NUM   5       /* Magic Number */
#define LCP_OPT_PFC         7       /* Protocol Field Compression */
#define LCP_OPT_ACFC        8       /* Address/Control Field Compression */

/* IPCP Options */
#define IPCP_OPT_IP_ADDR    3       /* IP Address */
#define IPCP_OPT_DNS_PRI    129     /* Primary DNS Server */
#define IPCP_OPT_DNS_SEC    131     /* Secondary DNS Server */

/* CHAP Algorithms */
#define CHAP_ALG_MD5        5

#endif /* PPPOE_DEFS_H */
