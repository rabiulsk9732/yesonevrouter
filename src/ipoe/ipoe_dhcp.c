/**
 * @file ipoe_dhcp.c
 * @brief IPoE DHCP Engine Implementation
 */

#include <ipoe_dhcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

/*============================================================================
 * Global DHCP Context
 *============================================================================*/

static struct ipoe_dhcp_config g_dhcp_config = {
    .enabled = true,
    .relay_mode = false,
    .server_ip = 0,
    .default_lease_time = 3600,
    .min_lease_time = 300,
    .max_lease_time = 86400,
    .option82_enable = true,
    .rate_limit_per_mac = 100,
    .rogue_server_detect = true
};

/*============================================================================
 * Initialization
 *============================================================================*/

int ipoe_dhcp_init(void)
{
    printf("ipoe_dhcp: initialized (mode=%s, option82=%s)\n",
           g_dhcp_config.relay_mode ? "relay" : "local",
           g_dhcp_config.option82_enable ? "enabled" : "disabled");
    return 0;
}

void ipoe_dhcp_cleanup(void)
{
    printf("ipoe_dhcp: cleanup complete\n");
}

void ipoe_dhcp_set_config(struct ipoe_dhcp_config *config)
{
    if (config) {
        memcpy(&g_dhcp_config, config, sizeof(g_dhcp_config));
    }
}

/*============================================================================
 * Option Parsing
 *============================================================================*/

int ipoe_dhcp_parse_options(const struct dhcp_packet *pkt, struct dhcp_options *opts)
{
    if (!pkt || !opts) return -1;

    memset(opts, 0, sizeof(*opts));

    const uint8_t *p = pkt->options;
    const uint8_t *end = p + sizeof(pkt->options);

    while (p < end && *p != DHCP_OPT_END) {
        if (*p == DHCP_OPT_PAD) {
            p++;
            continue;
        }

        uint8_t opt_type = p[0];
        uint8_t opt_len = p[1];
        const uint8_t *opt_data = p + 2;

        if (p + 2 + opt_len > end) break;

        switch (opt_type) {
        case DHCP_OPT_MSG_TYPE:
            opts->msg_type = opt_data[0];
            break;

        case DHCP_OPT_REQUESTED_IP:
            if (opt_len >= 4) {
                memcpy(&opts->requested_ip, opt_data, 4);
            }
            break;

        case DHCP_OPT_SERVER_ID:
            if (opt_len >= 4) {
                memcpy(&opts->server_id, opt_data, 4);
            }
            break;

        case DHCP_OPT_LEASE_TIME:
            if (opt_len >= 4) {
                memcpy(&opts->lease_time, opt_data, 4);
                opts->lease_time = ntohl(opts->lease_time);
            }
            break;

        case DHCP_OPT_SUBNET_MASK:
            if (opt_len >= 4) {
                memcpy(&opts->subnet_mask, opt_data, 4);
            }
            break;

        case DHCP_OPT_ROUTER:
            if (opt_len >= 4) {
                memcpy(&opts->router, opt_data, 4);
            }
            break;

        case DHCP_OPT_DNS:
            if (opt_len >= 4) {
                memcpy(&opts->dns_primary, opt_data, 4);
            }
            if (opt_len >= 8) {
                memcpy(&opts->dns_secondary, opt_data + 4, 4);
            }
            break;

        case DHCP_OPT_HOSTNAME:
            if (opt_len < sizeof(opts->hostname)) {
                memcpy(opts->hostname, opt_data, opt_len);
                opts->hostname[opt_len] = '\0';
            }
            break;

        case DHCP_OPT_RELAY_INFO:
            /* Parse Option 82 sub-options */
            {
                const uint8_t *sub = opt_data;
                const uint8_t *sub_end = opt_data + opt_len;

                while (sub + 2 <= sub_end) {
                    uint8_t sub_type = sub[0];
                    uint8_t sub_len = sub[1];

                    if (sub + 2 + sub_len > sub_end) break;

                    if (sub_type == DHCP_RELAY_CIRCUIT_ID) {
                        opts->has_circuit_id = true;
                        opts->circuit_id_len = sub_len;
                        memcpy(opts->circuit_id, sub + 2, sub_len);
                    }
                    else if (sub_type == DHCP_RELAY_REMOTE_ID) {
                        opts->has_remote_id = true;
                        opts->remote_id_len = sub_len;
                        memcpy(opts->remote_id, sub + 2, sub_len);
                    }

                    sub += 2 + sub_len;
                }
            }
            break;
        }

        p += 2 + opt_len;
    }

    return 0;
}

/*============================================================================
 * Option 82 Handling
 *============================================================================*/

int ipoe_dhcp_insert_option82(struct dhcp_packet *pkt, struct ipoe_session *sess)
{
    if (!pkt || !sess) return -1;

    /* Find end of options */
    uint8_t *p = pkt->options;
    uint8_t *end = p + sizeof(pkt->options) - 20;  /* Leave room */

    while (p < end && *p != DHCP_OPT_END) {
        if (*p == DHCP_OPT_PAD) {
            p++;
            continue;
        }
        p += 2 + p[1];
    }

    if (p >= end) return -1;  /* No room */

    /* Build Option 82 */
    uint8_t *opt82 = p;
    *p++ = DHCP_OPT_RELAY_INFO;
    uint8_t *len_ptr = p++;

    /* Circuit-ID sub-option */
    char circuit_id[64];
    int cid_len = snprintf(circuit_id, sizeof(circuit_id),
                           "eth%u:%u:%u", sess->ifindex, sess->svlan, sess->cvlan);
    *p++ = DHCP_RELAY_CIRCUIT_ID;
    *p++ = cid_len;
    memcpy(p, circuit_id, cid_len);
    p += cid_len;

    /* Remote-ID sub-option (MAC) */
    char remote_id[18];
    ipoe_session_format_mac(sess->mac, remote_id, sizeof(remote_id));
    int rid_len = strlen(remote_id);
    *p++ = DHCP_RELAY_REMOTE_ID;
    *p++ = rid_len;
    memcpy(p, remote_id, rid_len);
    p += rid_len;

    /* Update length */
    *len_ptr = (p - opt82 - 2);

    /* Add END */
    *p++ = DHCP_OPT_END;

    /* Store in session */
    sess->circuit_id_len = cid_len;
    memcpy(sess->circuit_id, circuit_id, cid_len);
    sess->remote_id_len = rid_len;
    memcpy(sess->remote_id, remote_id, rid_len);
    sess->flags |= IPOE_FLAG_OPTION82;

    return 0;
}

int ipoe_dhcp_remove_option82(struct dhcp_packet *pkt)
{
    if (!pkt) return -1;

    /* Find and remove Option 82 */
    uint8_t *p = pkt->options;
    uint8_t *end = p + sizeof(pkt->options);
    uint8_t *write = p;

    while (p < end && *p != DHCP_OPT_END) {
        if (*p == DHCP_OPT_PAD) {
            *write++ = *p++;
            continue;
        }

        uint8_t opt_type = p[0];
        uint8_t opt_len = p[1];

        if (opt_type == DHCP_OPT_RELAY_INFO) {
            /* Skip Option 82 */
            p += 2 + opt_len;
            continue;
        }

        /* Copy other options */
        memmove(write, p, 2 + opt_len);
        write += 2 + opt_len;
        p += 2 + opt_len;
    }

    *write = DHCP_OPT_END;
    return 0;
}

/*============================================================================
 * Packet Processing
 *============================================================================*/

int ipoe_dhcp_process_packet(const uint8_t *pkt_data, size_t len,
                              uint16_t svlan, uint16_t cvlan,
                              uint32_t ifindex)
{
    if (!pkt_data || len < sizeof(struct dhcp_packet)) {
        return -1;
    }

    const struct dhcp_packet *pkt = (const struct dhcp_packet *)pkt_data;

    /* Validate magic cookie */
    if (ntohl(pkt->magic) != DHCP_MAGIC_COOKIE) {
        return -1;
    }

    /* Parse options */
    struct dhcp_options opts;
    if (ipoe_dhcp_parse_options(pkt, &opts) != 0) {
        return -1;
    }

    /* Get MAC from chaddr */
    const uint8_t *mac = pkt->chaddr;
    struct ipoe_session *sess = NULL;

    char mac_str[18];
    ipoe_session_format_mac(mac, mac_str, sizeof(mac_str));

    switch (opts.msg_type) {
    case DHCP_DISCOVER:
        g_dhcp_config.discovers_rx++;
        printf("ipoe_dhcp: DISCOVER from %s (VLAN %u/%u)\n", mac_str, svlan, cvlan);

        /* Find or create session */
        if (svlan || cvlan) {
            sess = ipoe_session_find_by_vlan_mac(svlan, cvlan, mac);
        } else {
            sess = ipoe_session_find_by_mac(mac);
        }

        if (!sess) {
            sess = ipoe_session_create(mac, svlan, cvlan);
            if (!sess) {
                fprintf(stderr, "ipoe_dhcp: failed to create session\n");
                return -1;
            }
        }

        /* Store XID for tracking */
        ipoe_session_set_xid(sess, ntohl(pkt->xid));
        sess->dhcp_state = DHCP_STATE_SELECTING;
        sess->ifindex = ifindex;

        /* Trigger RADIUS MAC-auth (would call ipoe_radius_mac_auth) */
        ipoe_session_update_state(sess, IPOE_STATE_AUTH_PENDING);

        /* For now, auto-authorize */
        sess->aaa_state = AAA_STATE_AUTHORIZED;
        ipoe_session_update_state(sess, IPOE_STATE_DHCP_PENDING);

        /* TODO: Build and send OFFER or relay to server */
        break;

    case DHCP_REQUEST:
        g_dhcp_config.requests_rx++;
        printf("ipoe_dhcp: REQUEST from %s\n", mac_str);

        /* Find session by XID */
        sess = ipoe_session_find_by_xid(ntohl(pkt->xid));
        if (!sess) {
            fprintf(stderr, "ipoe_dhcp: REQUEST for unknown XID\n");
            return -1;
        }

        /* Verify authorization */
        if (sess->aaa_state != AAA_STATE_AUTHORIZED) {
            fprintf(stderr, "ipoe_dhcp: REQUEST from unauthorized session\n");
            /* TODO: Send NAK */
            return -1;
        }

        sess->dhcp_state = DHCP_STATE_REQUESTING;

        /* TODO: Allocate IP and send ACK or relay */
        break;

    case DHCP_RELEASE:
        g_dhcp_config.releases_rx++;
        printf("ipoe_dhcp: RELEASE from %s\n", mac_str);

        sess = ipoe_session_find_by_mac(mac);
        if (sess) {
            ipoe_session_destroy(sess, IPOE_TERM_USER_REQUEST);
        }
        break;

    case DHCP_DECLINE:
        printf("ipoe_dhcp: DECLINE from %s\n", mac_str);
        /* IP conflict - need to mark IP as unavailable */
        break;

    case DHCP_INFORM:
        printf("ipoe_dhcp: INFORM from %s\n", mac_str);
        /* Client has static IP, just wants config */
        break;
    }

    return 0;
}

/*============================================================================
 * Packet Building
 *============================================================================*/

static void dhcp_add_option(uint8_t **p, uint8_t type, const void *data, uint8_t len)
{
    (*p)[0] = type;
    (*p)[1] = len;
    memcpy(*p + 2, data, len);
    *p += 2 + len;
}

int ipoe_dhcp_build_offer(struct ipoe_session *sess, struct dhcp_packet *pkt)
{
    if (!sess || !pkt) return -1;

    memset(pkt, 0, sizeof(*pkt));

    pkt->op = 2;  /* BOOTREPLY */
    pkt->htype = 1;
    pkt->hlen = 6;
    pkt->xid = htonl(sess->dhcp_xid);
    pkt->yiaddr = htonl(sess->ip_addr);
    pkt->siaddr = htonl(g_dhcp_config.server_ip);
    memcpy(pkt->chaddr, sess->mac, 6);
    pkt->magic = htonl(DHCP_MAGIC_COOKIE);

    uint8_t *p = pkt->options;

    /* Message type */
    uint8_t msg_type = DHCP_OFFER;
    dhcp_add_option(&p, DHCP_OPT_MSG_TYPE, &msg_type, 1);

    /* Server ID */
    uint32_t server_id = htonl(g_dhcp_config.server_ip);
    dhcp_add_option(&p, DHCP_OPT_SERVER_ID, &server_id, 4);

    /* Lease time */
    uint32_t lease = htonl(g_dhcp_config.default_lease_time);
    dhcp_add_option(&p, DHCP_OPT_LEASE_TIME, &lease, 4);

    /* Subnet mask */
    uint32_t mask = htonl(sess->ip_mask ? sess->ip_mask : 0xFFFFFF00);
    dhcp_add_option(&p, DHCP_OPT_SUBNET_MASK, &mask, 4);

    /* Router */
    uint32_t router = htonl(sess->gateway);
    if (router) {
        dhcp_add_option(&p, DHCP_OPT_ROUTER, &router, 4);
    }

    /* DNS */
    if (sess->dns_primary) {
        uint32_t dns[2];
        dns[0] = htonl(sess->dns_primary);
        dns[1] = htonl(sess->dns_secondary);
        int dns_len = sess->dns_secondary ? 8 : 4;
        dhcp_add_option(&p, DHCP_OPT_DNS, dns, dns_len);
    }

    *p = DHCP_OPT_END;

    g_dhcp_config.offers_tx++;
    return 0;
}

int ipoe_dhcp_build_ack(struct ipoe_session *sess, struct dhcp_packet *pkt)
{
    if (!sess || !pkt) return -1;

    /* Start with OFFER format */
    ipoe_dhcp_build_offer(sess, pkt);

    /* Change message type to ACK */
    pkt->options[2] = DHCP_ACK;

    g_dhcp_config.acks_tx++;
    return 0;
}

int ipoe_dhcp_build_nak(struct ipoe_session *sess, struct dhcp_packet *pkt, const char *msg)
{
    if (!sess || !pkt) return -1;

    memset(pkt, 0, sizeof(*pkt));

    pkt->op = 2;
    pkt->htype = 1;
    pkt->hlen = 6;
    pkt->xid = htonl(sess->dhcp_xid);
    memcpy(pkt->chaddr, sess->mac, 6);
    pkt->magic = htonl(DHCP_MAGIC_COOKIE);

    uint8_t *p = pkt->options;

    uint8_t msg_type = DHCP_NAK;
    dhcp_add_option(&p, DHCP_OPT_MSG_TYPE, &msg_type, 1);

    uint32_t server_id = htonl(g_dhcp_config.server_ip);
    dhcp_add_option(&p, DHCP_OPT_SERVER_ID, &server_id, 4);

    if (msg && strlen(msg) > 0) {
        dhcp_add_option(&p, DHCP_OPT_MESSAGE, msg, strlen(msg));
    }

    *p = DHCP_OPT_END;

    g_dhcp_config.naks_tx++;
    return 0;
}

/*============================================================================
 * Statistics
 *============================================================================*/

void ipoe_dhcp_get_stats(struct ipoe_dhcp_config *stats)
{
    if (stats) {
        memcpy(stats, &g_dhcp_config, sizeof(*stats));
    }
}

void ipoe_dhcp_print_stats(void)
{
    printf("\nIPoE DHCP Statistics:\n");
    printf("  Discovers RX:   %lu\n", g_dhcp_config.discovers_rx);
    printf("  Offers TX:      %lu\n", g_dhcp_config.offers_tx);
    printf("  Requests RX:    %lu\n", g_dhcp_config.requests_rx);
    printf("  ACKs TX:        %lu\n", g_dhcp_config.acks_tx);
    printf("  NAKs TX:        %lu\n", g_dhcp_config.naks_tx);
    printf("  Releases RX:    %lu\n", g_dhcp_config.releases_rx);
    printf("  Rate limited:   %lu\n", g_dhcp_config.rate_limited);
    printf("  Rogue detected: %lu\n", g_dhcp_config.rogue_detected);
    printf("\n");
}
