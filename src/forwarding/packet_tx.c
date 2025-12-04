/**
 * @file packet_tx.c
 * @brief Packet Transmission
 */

#include "interface.h"
#include "packet.h"
#include "log.h"
#include <stdio.h>

int packet_tx(struct pkt_buf *pkt)
{
    struct interface *iface;
    int ret;

    if (!pkt) {
        return -1;
    }

    if (pkt->meta.egress_ifindex == 0) {
        YLOG_ERROR("Packet has no egress interface");
        return -1;
    }

    iface = interface_find_by_index(pkt->meta.egress_ifindex);
    if (!iface) {
        YLOG_ERROR("Egress interface %u not found", pkt->meta.egress_ifindex);
        return -1;
    }

    if (iface->state != IF_STATE_UP) {
        YLOG_WARNING("Egress interface %s is down", iface->name);
        return -1;
    }

    /* Send packet */
    ret = interface_send(iface, pkt);
    if (ret != 0) {
        YLOG_ERROR("Failed to send packet on %s", iface->name);
        return -1;
    }

    return 0;
}
