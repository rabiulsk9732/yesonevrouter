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
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#ifdef HAVE_DPDK
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include "dpdk_init.h"
#endif

/* Private data for physical interface */
struct physical_priv {
    int sock_fd;                    /* Socket for ioctl operations */
    int rx_sock_fd;                 /* Raw socket for packet RX/TX */
    bool link_detection_enabled;
    uint64_t last_link_check;
#ifdef HAVE_DPDK
    uint16_t port_id;               /* DPDK port ID */
    bool dpdk_enabled;              /* Is DPDK enabled for this interface? */
#endif
};

static int physical_init(struct interface *iface)
{
    struct physical_priv *priv;

    if (!iface) {
        return -1;
    }

    /* Allocate private data */
    priv = calloc(1, sizeof(*priv));
    if (!priv) {
        fprintf(stderr, "Failed to allocate physical interface private data\n");
        return -1;
    }

    priv->sock_fd = -1;
    priv->rx_sock_fd = -1;
    priv->link_detection_enabled = true;
    priv->last_link_check = 0;

#ifdef HAVE_DPDK
    /* Check if this is a DPDK interface using flags (VPP-style) */
    /* High bit (0x80000000) indicates DPDK port, lower bits are port_id */
    if (iface->flags & 0x80000000) {
        uint16_t port_id = (uint16_t)(iface->flags & 0x7FFFFFFF);

        priv->port_id = port_id;
        priv->dpdk_enabled = true;

        /* Get MAC address from DPDK */
        struct rte_ether_addr mac_addr;
        if (rte_eth_macaddr_get(port_id, &mac_addr) == 0) {
            memcpy(iface->mac_addr, mac_addr.addr_bytes, 6);
        }

        /* Get MTU from DPDK */
        uint16_t mtu;
        if (rte_eth_dev_get_mtu(port_id, &mtu) == 0) {
            iface->config.mtu = mtu;
        } else {
            iface->config.mtu = 1500;
        }

        iface->priv_data = priv;
        printf("Physical interface %s initialized (index %u)\n",
               iface->name, iface->ifindex);
        return 0;
    }
#endif

#ifndef HAVE_DPDK
    /* Kernel interface path (only compiled when DPDK is disabled) */
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        free(priv);
        return -1;
    }

    priv->sock_fd = sock;

    /* Get interface index */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface->name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(sock, SIOCGIFINDEX, &ifr) == 0) {
        iface->ifindex = ifr.ifr_ifindex;
    }

    /* Get MAC address */
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
        memcpy(iface->mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    }

    /* Get MTU */
    if (ioctl(sock, SIOCGIFMTU, &ifr) == 0) {
        iface->config.mtu = ifr.ifr_mtu;
    }

    iface->priv_data = priv;
    printf("Physical interface %s initialized (index %u)\n",
           iface->name, iface->ifindex);
#else
    /* DPDK-only build: non-DPDK interface requested but not supported */
    iface->config.mtu = 1500;
    iface->priv_data = priv;
    printf("Physical interface %s initialized (DPDK mode)\n", iface->name);
#endif

    return 0;
}

static int physical_up(struct interface *iface)
{
    struct physical_priv *priv;

    if (!iface || !iface->priv_data) {
        return -1;
    }

    priv = (struct physical_priv *)iface->priv_data;

#ifdef HAVE_DPDK
    if (priv->dpdk_enabled) {
        /* DPDK path - configure and start the port */
        struct rte_eth_conf port_conf = {0};
        struct rte_eth_rxconf rxq_conf;
        struct rte_eth_txconf txq_conf;
        struct rte_eth_dev_info dev_info;
        int ret;

        /* Get device info */
        ret = rte_eth_dev_info_get(priv->port_id, &dev_info);
        if (ret != 0) {
            fprintf(stderr, "Error getting device info: %s\n", strerror(-ret));
            return -1;
        }

        /* Configure device */
        ret = rte_eth_dev_configure(priv->port_id, 1, 1, &port_conf);
        if (ret < 0) {
            fprintf(stderr, "Error configuring DPDK port %u: %s\n",
                    priv->port_id, rte_strerror(-ret));
            return -1;
        }

        /* Setup RX queue - need mempool from dpdk_init */
        extern struct dpdk_config g_dpdk_config;
        struct rte_mempool *mp = NULL;
        if (g_dpdk_config.pkt_mempool && g_dpdk_config.pkt_mempool->pool) {
            mp = (struct rte_mempool *)g_dpdk_config.pkt_mempool->pool;
        }
        if (!mp) {
            fprintf(stderr, "No mempool available for RX queue\n");
            return -1;
        }

        rxq_conf = dev_info.default_rxconf;
        rxq_conf.offloads = port_conf.rxmode.offloads;
        ret = rte_eth_rx_queue_setup(priv->port_id, 0, 1024,
                                     rte_eth_dev_socket_id(priv->port_id),
                                     &rxq_conf, mp);
        if (ret < 0) {
            fprintf(stderr, "Error setting up RX queue: %s\n", rte_strerror(-ret));
            return -1;
        }

        /* Setup TX queue */
        txq_conf = dev_info.default_txconf;
        txq_conf.offloads = port_conf.txmode.offloads;
        ret = rte_eth_tx_queue_setup(priv->port_id, 0, 1024,
                                     rte_eth_dev_socket_id(priv->port_id),
                                     &txq_conf);
        if (ret < 0) {
            fprintf(stderr, "Error setting up TX queue: %s\n", rte_strerror(-ret));
            return -1;
        }

        /* Start device */
        ret = rte_eth_dev_start(priv->port_id);
        if (ret < 0) {
            fprintf(stderr, "Error starting DPDK port %u: %s\n",
                    priv->port_id, rte_strerror(-ret));
            return -1;
        }

        /* Enable promiscuous mode */
        rte_eth_promiscuous_enable(priv->port_id);

        printf("DPDK port %u started\n", priv->port_id);
        return 0;
    }
#endif

#ifndef HAVE_DPDK
    /* Kernel interface path (only compiled when DPDK is disabled) */
    struct ifreq ifr;
    struct sockaddr_ll sll;

    /* Bring interface up using ioctl */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface->name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(priv->sock_fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("SIOCGIFFLAGS");
        return -1;
    }

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    if (ioctl(priv->sock_fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("SIOCSIFFLAGS");
        return -1;
    }

    /* Create raw socket for packet capture if not already open */
    if (priv->rx_sock_fd < 0) {
        priv->rx_sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (priv->rx_sock_fd < 0) {
            perror("socket(AF_PACKET)");
            return -1;
        }

        /* Bind to interface */
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = iface->ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);

        if (bind(priv->rx_sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            perror("bind(AF_PACKET)");
            close(priv->rx_sock_fd);
            priv->rx_sock_fd = -1;
            return -1;
        }

        /* Set non-blocking mode */
        int flags = fcntl(priv->rx_sock_fd, F_GETFL, 0);
        if (flags != -1) {
            fcntl(priv->rx_sock_fd, F_SETFL, flags | O_NONBLOCK);
        }
    }
#else
    /* DPDK-only build */
    printf("Interface %s up (DPDK mode)\n", iface->name);
    (void)priv; /* Suppress unused warning */
#endif

    return 0;
}

static int physical_down(struct interface *iface)
{
    struct physical_priv *priv;

    if (!iface || !iface->priv_data) {
        return -1;
    }

    priv = (struct physical_priv *)iface->priv_data;

#ifdef HAVE_DPDK
    if (priv->dpdk_enabled) {
        rte_eth_dev_stop(priv->port_id);
        printf("DPDK port %u stopped\n", priv->port_id);
        return 0;
    }
#endif

#ifndef HAVE_DPDK
    /* Kernel interface path (only compiled when DPDK is disabled) */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface->name, IFNAMSIZ - 1);
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
#else
    /* DPDK-only build */
    printf("Interface %s down (DPDK mode)\n", iface->name);
    (void)priv;
#endif

    /* Close raw socket */
    if (priv->rx_sock_fd >= 0) {
        close(priv->rx_sock_fd);
        priv->rx_sock_fd = -1;
    }

    return 0;
}

static int physical_send(struct interface *iface, struct pkt_buf *pkt)
{
    struct physical_priv *priv;
    ssize_t sent;

    if (!iface || !iface->priv_data || !pkt) {
        return -1;
    }

    priv = (struct physical_priv *)iface->priv_data;

#ifdef HAVE_DPDK
    if (priv->dpdk_enabled) {
        extern struct dpdk_config g_dpdk_config;
        struct rte_mempool *mp = NULL;

        if (g_dpdk_config.pkt_mempool && g_dpdk_config.pkt_mempool->pool) {
            mp = (struct rte_mempool *)g_dpdk_config.pkt_mempool->pool;
        }
        if (!mp) {
            return -1;
        }

        /* Allocate mbuf and copy data */
        struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mp);
        if (!mbuf) {
            iface->stats.tx_dropped++;
            return -1;
        }

        /* Copy packet data to mbuf */
        void *data = rte_pktmbuf_append(mbuf, pkt->len);
        if (!data) {
            rte_pktmbuf_free(mbuf);
            iface->stats.tx_dropped++;
            return -1;
        }
        rte_memcpy(data, pkt->data, pkt->len);

        /* Send packet */
        uint16_t nb_tx = rte_eth_tx_burst(priv->port_id, 0, &mbuf, 1);
        if (nb_tx == 0) {
            rte_pktmbuf_free(mbuf);
            iface->stats.tx_dropped++;
            return -1;
        }

        iface->stats.tx_packets++;
        iface->stats.tx_bytes += pkt->len;
        iface->stats.last_tx_time = time(NULL);
        return 0;
    }
#endif

    if (priv->rx_sock_fd < 0) {
        /* Interface is down or not initialized for TX */
        return -1;
    }

    /* Send packet via raw socket */
    sent = send(priv->rx_sock_fd, pkt->data, pkt->len, 0);
    if (sent < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("send");
            iface->stats.tx_errors++;
        }
        return -1;
    }

    iface->stats.tx_packets++;
    iface->stats.tx_bytes += sent;
    iface->stats.last_tx_time = time(NULL);

    return 0;
}

static int physical_recv(struct interface *iface, struct pkt_buf **pkt)
{
    struct physical_priv *priv;
    ssize_t received;
    struct pkt_buf *new_pkt;

    if (!iface || !iface->priv_data || !pkt) {
        return -1;
    }

    priv = (struct physical_priv *)iface->priv_data;

#ifdef HAVE_DPDK
    if (priv->dpdk_enabled) {
        struct rte_mbuf *mbufs[1];
        uint16_t nb_rx = rte_eth_rx_burst(priv->port_id, 0, mbufs, 1);

        if (nb_rx == 0) {
            return 0;
        }

        /* Convert mbuf to pkt_buf */
        new_pkt = pkt_alloc();
        if (!new_pkt) {
            rte_pktmbuf_free(mbufs[0]);
            iface->stats.rx_dropped++;
            return -1;
        }

        /* Copy data (TODO: Zero-copy) */
        new_pkt->len = rte_pktmbuf_pkt_len(mbufs[0]);
        if (new_pkt->len > new_pkt->buf_size) {
            new_pkt->len = new_pkt->buf_size;
        }
        rte_memcpy(new_pkt->data, rte_pktmbuf_mtod(mbufs[0], void *), new_pkt->len);
        rte_pktmbuf_free(mbufs[0]);

        iface->stats.rx_packets++;
        iface->stats.rx_bytes += new_pkt->len;
        iface->stats.last_rx_time = time(NULL);

        *pkt = new_pkt;
        return 1;
    }
#endif

    if (priv->rx_sock_fd < 0) {
        return -1;
    }

    /* Allocate packet buffer */
    new_pkt = pkt_alloc();
    if (!new_pkt) {
        iface->stats.rx_dropped++;
        return -1;
    }

    /* Receive packet */
    received = recv(priv->rx_sock_fd, new_pkt->data, new_pkt->buf_size, 0);
    if (received < 0) {
        pkt_free(new_pkt);
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; /* No packet available */
        }
        iface->stats.rx_errors++;
        return -1;
    }

    new_pkt->len = received;

    /* Update stats */
    iface->stats.rx_packets++;
    iface->stats.rx_bytes += received;
    iface->stats.last_rx_time = time(NULL);

    *pkt = new_pkt;
    return 1; /* 1 packet received */
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
    memcpy(stats, &iface->stats, sizeof(*stats));

    return 0;
}

static int physical_configure(struct interface *iface, const struct interface_config_data *config)
{
    struct physical_priv *priv;

    if (!iface || !iface->priv_data || !config) {
        return -1;
    }

    priv = (struct physical_priv *)iface->priv_data;

#ifdef HAVE_DPDK
    if (priv->dpdk_enabled) {
        /* Set MTU via DPDK */
        if (config->mtu > 0) {
            int ret = rte_eth_dev_set_mtu(priv->port_id, config->mtu);
            if (ret < 0) {
                fprintf(stderr, "Failed to set MTU on DPDK port %u: %s\n",
                        priv->port_id, rte_strerror(-ret));
                /* Don't fail - some drivers don't support MTU change */
            }
        }

        /* Set promiscuous mode via DPDK */
        if (config->promiscuous) {
            rte_eth_promiscuous_enable(priv->port_id);
        } else {
            rte_eth_promiscuous_disable(priv->port_id);
        }

        /* Store IP configuration (software only - used for routing) */
        iface->config.ipv4_addr = config->ipv4_addr;
        iface->config.ipv4_mask = config->ipv4_mask;

        return 0;
    }
#endif

#ifndef HAVE_DPDK
    /* Kernel interface path (only compiled when DPDK is disabled) */
    struct ifreq ifr;

    /* Set MTU */
    if (config->mtu > 0) {
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface->name, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        ifr.ifr_mtu = config->mtu;

        if (ioctl(priv->sock_fd, SIOCSIFMTU, &ifr) < 0) {
            perror("SIOCSIFMTU");
            return -1;
        }
    }

    /* Set promiscuous mode */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface->name, IFNAMSIZ - 1);
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
#else
    /* DPDK-only build: config already applied via DPDK path */
    (void)priv;
    (void)config;
#endif

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

    if (priv->rx_sock_fd >= 0) {
        close(priv->rx_sock_fd);
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
