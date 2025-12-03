/**
 * @file physical.c
 * @brief Physical Interface Driver Implementation
 */

#define _GNU_SOURCE
#include "interface.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <errno.h>
#include <fcntl.h>

/* Private data for physical interface */
struct physical_priv {
    int sock_fd;                    /* Socket for ioctl operations */
    int if_fd;                      /* Interface file descriptor (if using DPDK) */
    bool link_detection_enabled;
    uint64_t last_link_check;
};

static int physical_init(struct interface *iface)
{
    struct physical_priv *priv;
    struct ifreq ifr;
    int sock;

    if (!iface) {
        return -1;
    }

    /* Allocate private data */
    priv = calloc(1, sizeof(*priv));
    if (!priv) {
        fprintf(stderr, "Failed to allocate physical interface private data\n");
        return -1;
    }

    /* Create socket for ioctl operations */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        free(priv);
        return -1;
    }

    priv->sock_fd = sock;
    priv->link_detection_enabled = true;
    priv->last_link_check = 0;

    /* Get interface index */
    memset(&ifr, 0, sizeof(ifr));
    size_t name_len = strnlen(iface->name, IFNAMSIZ);
    memcpy(ifr.ifr_name, iface->name, name_len < IFNAMSIZ ? name_len : IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sock, SIOCGIFINDEX, &ifr) == 0) {
        iface->ifindex = ifr.ifr_ifindex;
    }

    /* Get MAC address */
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, iface->name, name_len < IFNAMSIZ ? name_len : IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
        memcpy(iface->mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    } else {
        /* Set a default MAC if we can't get it */
        memset(iface->mac_addr, 0, 6);
    }

    /* Get MTU */
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, iface->name, name_len < IFNAMSIZ ? name_len : IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sock, SIOCGIFMTU, &ifr) == 0) {
        iface->config.mtu = ifr.ifr_mtu;
    }

    iface->priv_data = priv;

    printf("Physical interface %s initialized (index %u)\n",
           iface->name, iface->ifindex);

    return 0;
}

static int physical_up(struct interface *iface)
{
    struct physical_priv *priv;
    struct ifreq ifr;

    if (!iface || !iface->priv_data) {
        return -1;
    }

    priv = (struct physical_priv *)iface->priv_data;

    /* Bring interface up using ioctl */
    memset(&ifr, 0, sizeof(ifr));
    size_t name_len = strnlen(iface->name, IFNAMSIZ);
    memcpy(ifr.ifr_name, iface->name, name_len < IFNAMSIZ ? name_len : IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(priv->sock_fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("SIOCGIFFLAGS");
        return -1;
    }

    ifr.ifr_flags |= IFF_UP;
    ifr.ifr_flags |= IFF_RUNNING;

    if (ioctl(priv->sock_fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("SIOCSIFFLAGS");
        return -1;
    }

    return 0;
}

static int physical_down(struct interface *iface)
{
    struct physical_priv *priv;
    struct ifreq ifr;

    if (!iface || !iface->priv_data) {
        return -1;
    }

    priv = (struct physical_priv *)iface->priv_data;

    /* Bring interface down using ioctl */
    memset(&ifr, 0, sizeof(ifr));
    size_t name_len = strnlen(iface->name, IFNAMSIZ);
    memcpy(ifr.ifr_name, iface->name, name_len < IFNAMSIZ ? name_len : IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(priv->sock_fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("SIOCGIFFLAGS");
        return -1;
    }

    ifr.ifr_flags &= ~IFF_UP;

    if (ioctl(priv->sock_fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("SIOCSIFFLAGS");
        return -1;
    }

    return 0;
}

static int physical_send(struct interface *iface, struct pkt_buf *pkt)
{
    /* Physical interface send is typically handled by DPDK or raw sockets */
    /* This is a placeholder - actual implementation depends on DPDK integration */
    (void)iface;
    (void)pkt;

    /* TODO: Implement actual packet sending via DPDK or raw socket */
    return -1;
}

static int physical_recv(struct interface *iface, struct pkt_buf **pkt)
{
    /* Physical interface receive is typically handled by DPDK or raw sockets */
    /* This is a placeholder - actual implementation depends on DPDK integration */
    (void)iface;
    (void)pkt;

    /* TODO: Implement actual packet receiving via DPDK or raw socket */
    return -1;
}

static enum link_state physical_get_link_state(struct interface *iface)
{
    struct physical_priv *priv;
    struct ifreq ifr;

    if (!iface || !iface->priv_data) {
        return LINK_STATE_UNKNOWN;
    }

    priv = (struct physical_priv *)iface->priv_data;

    /* Check link state using ioctl */
    memset(&ifr, 0, sizeof(ifr));
    size_t name_len = strnlen(iface->name, IFNAMSIZ);
    memcpy(ifr.ifr_name, iface->name, name_len < IFNAMSIZ ? name_len : IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(priv->sock_fd, SIOCGIFFLAGS, &ifr) < 0) {
        return LINK_STATE_UNKNOWN;
    }

    if (ifr.ifr_flags & IFF_RUNNING && ifr.ifr_flags & IFF_UP) {
        return LINK_STATE_UP;
    }

    return LINK_STATE_DOWN;
}

static int physical_get_stats(struct interface *iface, struct interface_stats *stats)
{
    if (!iface || !iface->priv_data || !stats) {
        return -1;
    }

    /* Return cached statistics (statistics are updated on packet rx/tx) */
    /* Note: SIOCGIFSTATS doesn't exist - statistics are typically read from
     * /proc/net/dev or updated by the packet processing code */
    memcpy(stats, &iface->stats, sizeof(*stats));

    return 0;
}

static int physical_configure(struct interface *iface, const struct interface_config_data *config)
{
    struct physical_priv *priv;
    struct ifreq ifr;

    if (!iface || !iface->priv_data || !config) {
        return -1;
    }

    priv = (struct physical_priv *)iface->priv_data;

    /* Set MTU */
    if (config->mtu > 0) {
        memset(&ifr, 0, sizeof(ifr));
        size_t name_len = strnlen(iface->name, IFNAMSIZ);
        memcpy(ifr.ifr_name, iface->name, name_len < IFNAMSIZ ? name_len : IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        ifr.ifr_mtu = config->mtu;

        if (ioctl(priv->sock_fd, SIOCSIFMTU, &ifr) < 0) {
            perror("SIOCSIFMTU");
            return -1;
        }
    }

    /* Set promiscuous mode */
    memset(&ifr, 0, sizeof(ifr));
    size_t name_len = strnlen(iface->name, IFNAMSIZ);
    memcpy(ifr.ifr_name, iface->name, name_len < IFNAMSIZ ? name_len : IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(priv->sock_fd, SIOCGIFFLAGS, &ifr) == 0) {
        if (config->promiscuous) {
            ifr.ifr_flags |= IFF_PROMISC;
        } else {
            ifr.ifr_flags &= ~IFF_PROMISC;
        }

        if (ioctl(priv->sock_fd, SIOCSIFFLAGS, &ifr) < 0) {
            perror("SIOCSIFFLAGS (promiscuous)");
            return -1;
        }
    }

    return 0;
}

static void physical_cleanup(struct interface *iface)
{
    struct physical_priv *priv;

    if (!iface || !iface->priv_data) {
        return;
    }

    priv = (struct physical_priv *)iface->priv_data;

    /* Close socket */
    if (priv->sock_fd >= 0) {
        close(priv->sock_fd);
    }

    free(priv);
    iface->priv_data = NULL;
}

/* Physical interface operations */
const struct interface_ops physical_interface_ops = {
    .init = physical_init,
    .up = physical_up,
    .down = physical_down,
    .send = physical_send,
    .recv = physical_recv,
    .get_link_state = physical_get_link_state,
    .get_stats = physical_get_stats,
    .configure = physical_configure,
    .cleanup = physical_cleanup
};
