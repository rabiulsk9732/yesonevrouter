/**
 * @file virtual.c
 * @brief Virtual Interface Driver Implementation (VLAN, LAG)
 */

#include "interface.h"
#include "vlan.h"
#include "lacp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

/* Private data for VLAN interface */
struct vlan_priv {
    struct interface *parent;       /* Parent physical interface */
    uint16_t vlan_id;
    bool tag_removal;               /* Remove VLAN tag on egress */
};

/* Private data for LAG interface */
struct lag_priv {
    struct bond_interface *bond;    /* Bond management structure */
    struct interface *members[IF_MAX_VLAN_MEMBERS];
    uint32_t num_members;
    uint8_t mode;                   /* LAG mode */
    uint32_t active_member;         /* Currently active member (for active-backup) */
};

static int vlan_init(struct interface *iface)
{
    struct vlan_priv *priv;

    if (!iface) {
        return -1;
    }

    /* Allocate private data */
    priv = calloc(1, sizeof(*priv));
    if (!priv) {
        fprintf(stderr, "Failed to allocate VLAN interface private data\n");
        return -1;
    }

    priv->parent = NULL;
    priv->vlan_id = iface->config.vlan_id;
    priv->tag_removal = false;

    iface->priv_data = priv;

    /* Set default MTU (same as parent, or 1500) */
    if (iface->config.mtu == 0) {
        iface->config.mtu = 1500;
    }

    printf("VLAN interface %s initialized (VLAN ID: %u)\n",
           iface->name, priv->vlan_id);

    return 0;
}

static int vlan_up(struct interface *iface)
{
    struct vlan_priv *priv;

    if (!iface || !iface->priv_data) {
        return -1;
    }

    priv = (struct vlan_priv *)iface->priv_data;

    /* Parent interface must be up */
    if (priv->parent && priv->parent->state != IF_STATE_UP) {
        fprintf(stderr, "Parent interface %s is not up\n", priv->parent->name);
        return -1;
    }

    /* VLAN interfaces are always "up" if parent is up */
    return 0;
}

static int vlan_down(struct interface *iface)
{
    (void)iface;
    /* VLAN interfaces go down when parent goes down */
    return 0;
}

static int vlan_send(struct interface *iface, struct pkt_buf *pkt)
{
    struct vlan_priv *priv;

    if (!iface || !iface->priv_data || !pkt) {
        return -1;
    }

    priv = (struct vlan_priv *)iface->priv_data;

    if (!priv->parent) {
        fprintf(stderr, "VLAN interface %s has no parent\n", iface->name);
        return -1;
    }

    /* Add VLAN tag to packet */
    fprintf(stderr, "[VLAN_SEND] %s: tagging with VLAN %u (parent=%s)\n",
            iface->name, priv->vlan_id, priv->parent ? priv->parent->name : "NULL");
    if (vlan_tag_packet(pkt, priv->vlan_id, VLAN_PCP_BE) < 0) {
        fprintf(stderr, "Failed to tag packet with VLAN %u\n", priv->vlan_id);
        return -1;
    }

    /* Forward to parent interface */
    return interface_send(priv->parent, pkt);
}

static int vlan_recv(struct interface *iface, struct pkt_buf **pkt)
{
    struct vlan_priv *priv;

    if (!iface || !iface->priv_data || !pkt) {
        return -1;
    }

    priv = (struct vlan_priv *)iface->priv_data;

    if (!priv->parent) {
        return -1;
    }

    /* Receive from parent */
    int ret = interface_recv(priv->parent, pkt);
    if (ret <= 0) {
        return ret;
    }

    /* Filter by VLAN ID */
    if (*pkt && vlan_is_tagged(*pkt)) {
        uint16_t vid = vlan_get_id(*pkt);

        if (vid != priv->vlan_id) {
            /* Not our VLAN, drop it */
            return -1;
        }

        /* Strip VLAN tag */
        if (vlan_untag_packet(*pkt) < 0) {
            fprintf(stderr, "Failed to untag VLAN packet\n");
            return -1;
        }
    }

    return ret;
}

static enum link_state vlan_get_link_state(struct interface *iface)
{
    struct vlan_priv *priv;

    if (!iface || !iface->priv_data) {
        return LINK_STATE_UNKNOWN;
    }

    priv = (struct vlan_priv *)iface->priv_data;

    /* VLAN link state follows parent */
    if (priv->parent) {
        return interface_get_link_state(priv->parent);
    }

    return LINK_STATE_DOWN;
}

static int vlan_get_stats(struct interface *iface, struct interface_stats *stats)
{
    /* VLAN statistics are typically aggregated from parent */
    (void)iface;
    (void)stats;
    return 0;
}

static int vlan_configure(struct interface *iface, const struct interface_config_data *config)
{
    struct vlan_priv *priv;

    if (!iface || !iface->priv_data || !config) {
        return -1;
    }

    priv = (struct vlan_priv *)iface->priv_data;

    /* Set parent interface if specified */
    if (config->parent_ifindex > 0) {
        struct interface *parent = interface_find_by_index(config->parent_ifindex);
        if (!parent) {
            fprintf(stderr, "Parent interface not found (index %u)\n",
                    config->parent_ifindex);
            return -1;
        }
        priv->parent = parent;
    }

    /* Set VLAN ID */
    if (config->vlan_id > 0) {
        priv->vlan_id = config->vlan_id;
    }

    return 0;
}

static void vlan_cleanup(struct interface *iface)
{
    if (!iface || !iface->priv_data) {
        return;
    }

    free(iface->priv_data);
    iface->priv_data = NULL;
}

/* VLAN interface operations */
const struct interface_ops vlan_interface_ops = {
    .init = vlan_init,
    .up = vlan_up,
    .down = vlan_down,
    .send = vlan_send,
    .recv = vlan_recv,
    .get_link_state = vlan_get_link_state,
    .get_stats = vlan_get_stats,
    .configure = vlan_configure,
    .cleanup = vlan_cleanup
};

static int lag_init(struct interface *iface)
{
    struct lag_priv *priv;

    if (!iface) {
        return -1;
    }

    /* Allocate private data */
    priv = calloc(1, sizeof(*priv));
    if (!priv) {
        fprintf(stderr, "Failed to allocate LAG interface private data\n");
        return -1;
    }

    priv->num_members = 0;
    priv->mode = 0;  /* Active-backup by default */
    priv->active_member = 0;

    iface->priv_data = priv;

    printf("LAG interface %s initialized\n", iface->name);

    return 0;
}

static int lag_up(struct interface *iface)
{
    struct lag_priv *priv;
    uint32_t i;

    if (!iface || !iface->priv_data) {
        return -1;
    }

    priv = (struct lag_priv *)iface->priv_data;

    /* At least one member must be up */
    for (i = 0; i < priv->num_members; i++) {
        if (priv->members[i] && priv->members[i]->state == IF_STATE_UP) {
            return 0;
        }
    }

    fprintf(stderr, "LAG interface %s has no active members\n", iface->name);
    return -1;
}

static int lag_down(struct interface *iface)
{
    (void)iface;
    return 0;
}

static int lag_send(struct interface *iface, struct pkt_buf *pkt)
{
    struct lag_priv *priv;
    struct interface *member;

    if (!iface || !iface->priv_data || !pkt) {
        return -1;
    }

    priv = (struct lag_priv *)iface->priv_data;

    if (priv->num_members == 0) {
        return -1;
    }

    /* Select member based on LAG mode */
    if (priv->mode == 0) {
        /* Active-backup: use active member */
        member = priv->members[priv->active_member];
    } else {
        /* Round-robin or other: select based on flow hash */
        uint32_t hash = pkt->meta.flow_hash;
        member = priv->members[hash % priv->num_members];
    }

    if (!member || member->state != IF_STATE_UP) {
        return -1;
    }

    return interface_send(member, pkt);
}

static int lag_recv(struct interface *iface, struct pkt_buf **pkt)
{
    struct lag_priv *priv;
    uint32_t i;

    if (!iface || !iface->priv_data || !pkt) {
        return -1;
    }

    priv = (struct lag_priv *)iface->priv_data;

    /* Receive from any active member */
    for (i = 0; i < priv->num_members; i++) {
        if (priv->members[i] && priv->members[i]->state == IF_STATE_UP) {
            int ret = interface_recv(priv->members[i], pkt);
            if (ret > 0) {
                return ret;
            }
        }
    }

    return -1;
}

static enum link_state lag_get_link_state(struct interface *iface)
{
    struct lag_priv *priv;
    uint32_t i;

    if (!iface || !iface->priv_data) {
        return LINK_STATE_UNKNOWN;
    }

    priv = (struct lag_priv *)iface->priv_data;

    /* LAG is up if at least one member is up */
    for (i = 0; i < priv->num_members; i++) {
        if (priv->members[i] &&
            interface_get_link_state(priv->members[i]) == LINK_STATE_UP) {
            return LINK_STATE_UP;
        }
    }

    return LINK_STATE_DOWN;
}

static int lag_get_stats(struct interface *iface, struct interface_stats *stats)
{
    struct lag_priv *priv;
    struct interface_stats member_stats;
    uint32_t i;

    if (!iface || !iface->priv_data || !stats) {
        return -1;
    }

    priv = (struct lag_priv *)iface->priv_data;

    /* Aggregate statistics from all members */
    memset(stats, 0, sizeof(*stats));

    for (i = 0; i < priv->num_members; i++) {
        if (priv->members[i]) {
            if (interface_get_stats(priv->members[i], &member_stats) == 0) {
                stats->rx_packets += member_stats.rx_packets;
                stats->rx_bytes += member_stats.rx_bytes;
                stats->rx_errors += member_stats.rx_errors;
                stats->rx_dropped += member_stats.rx_dropped;
                stats->tx_packets += member_stats.tx_packets;
                stats->tx_bytes += member_stats.tx_bytes;
                stats->tx_errors += member_stats.tx_errors;
                stats->tx_dropped += member_stats.tx_dropped;
            }
        }
    }

    return 0;
}

static int lag_configure(struct interface *iface, const struct interface_config_data *config)
{
    struct lag_priv *priv;
    uint32_t i;

    if (!iface || !iface->priv_data || !config) {
        return -1;
    }

    priv = (struct lag_priv *)iface->priv_data;

    /* Set LAG mode */
    priv->mode = config->lag_mode;

    /* Add members */
    for (i = 0; i < config->num_members && i < IF_MAX_VLAN_MEMBERS; i++) {
        struct interface *member = interface_find_by_index(config->member_ifindexes[i]);
        if (member) {
            priv->members[priv->num_members++] = member;
        }
    }

    return 0;
}

static void lag_cleanup(struct interface *iface)
{
    if (!iface || !iface->priv_data) {
        return;
    }

    free(iface->priv_data);
    iface->priv_data = NULL;
}

/* LAG interface operations */
const struct interface_ops lag_interface_ops = {
    .init = lag_init,
    .up = lag_up,
    .down = lag_down,
    .send = lag_send,
    .recv = lag_recv,
    .get_link_state = lag_get_link_state,
    .get_stats = lag_get_stats,
    .configure = lag_configure,
    .cleanup = lag_cleanup
};

/* Loopback interface operations (simplified) */
static int loopback_init(struct interface *iface)
{
    /* Loopback interface is always up */
    iface->state = IF_STATE_UP;
    iface->link = LINK_STATE_UP;
    memset(iface->mac_addr, 0, 6);
    return 0;
}

static int loopback_up(struct interface *iface)
{
    (void)iface;
    return 0;
}

static int loopback_down(struct interface *iface)
{
    (void)iface;
    return 0;
}

static int loopback_send(struct interface *iface, struct pkt_buf *pkt)
{
    /* Loopback: packets sent are immediately received */
    (void)iface;
    (void)pkt;
    return 0;
}

static int loopback_recv(struct interface *iface, struct pkt_buf **pkt)
{
    (void)iface;
    (void)pkt;
    return -1;  /* No packets to receive */
}

static enum link_state loopback_get_link_state(struct interface *iface)
{
    (void)iface;
    return LINK_STATE_UP;  /* Loopback is always up */
}

static int loopback_get_stats(struct interface *iface, struct interface_stats *stats)
{
    (void)iface;
    (void)stats;
    return 0;
}

static int loopback_configure(struct interface *iface, const struct interface_config_data *config)
{
    (void)iface;
    (void)config;
    return 0;
}

static void loopback_cleanup(struct interface *iface)
{
    (void)iface;
}

const struct interface_ops loopback_interface_ops = {
    .init = loopback_init,
    .up = loopback_up,
    .down = loopback_down,
    .send = loopback_send,
    .recv = loopback_recv,
    .get_link_state = loopback_get_link_state,
    .get_stats = loopback_get_stats,
    .configure = loopback_configure,
    .cleanup = loopback_cleanup
};

/* Dummy interface operations (same as loopback) */
const struct interface_ops dummy_interface_ops = {
    .init = loopback_init,
    .up = loopback_up,
    .down = loopback_down,
    .send = loopback_send,
    .recv = loopback_recv,
    .get_link_state = loopback_get_link_state,
    .get_stats = loopback_get_stats,
    .configure = loopback_configure,
    .cleanup = loopback_cleanup
};
