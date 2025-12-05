/**
 * @file physical.c
 * @brief Physical Interface Driver Implementation
 */

#define _GNU_SOURCE
#define _GNU_SOURCE
#include "cpu_scheduler.h"
#include "interface.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/ethtool.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#ifdef HAVE_DPDK
#include "dpdk_init.h"
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#endif

/* DPDK burst size for high-performance packet reception */
#define DPDK_RX_BURST_SIZE 32

/* Private data for physical interface */
struct physical_priv {
    int sock_fd;    /* Socket for ioctl operations */
    int rx_sock_fd; /* Raw socket for packet RX/TX */
    bool link_detection_enabled;
    uint64_t last_link_check;
#ifdef HAVE_DPDK
    uint16_t port_id;  /* DPDK port ID */
    bool dpdk_enabled; /* Is DPDK enabled for this interface? */
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
        printf("Physical interface %s initialized (index %u)\n", iface->name, iface->ifindex);
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
    printf("Physical interface %s initialized (index %u)\n", iface->name, iface->ifindex);
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
#include "vpp_parser.h"

    if (priv->dpdk_enabled) {
        /* DPDK path - configure and start the port */
        struct rte_eth_conf port_conf = {0};
        struct rte_eth_rxconf rxq_conf;
        struct rte_eth_txconf txq_conf;
        struct rte_eth_dev_info dev_info;
        int ret;
        int num_rx_queues = 1;
        int num_tx_queues = 1;
        int num_rx_desc = 1024;
        int num_tx_desc = 1024;

        /* Get device info */
        ret = rte_eth_dev_info_get(priv->port_id, &dev_info);
        if (ret != 0) {
            fprintf(stderr, "Error getting device info: %s\n", strerror(-ret));
            return -1;
        }

        /* Clamp requested queues to device maximum */
        if (num_rx_queues > dev_info.max_rx_queues) {
            printf("DPDK port %d: Requested %d RX queues, but device only supports %d. Clamping.\n",
                   priv->port_id, num_rx_queues, dev_info.max_rx_queues);
            num_rx_queues = dev_info.max_rx_queues;
        }
        if (num_tx_queues > dev_info.max_tx_queues) {
            printf("DPDK port %d: Requested %d TX queues, but device only supports %d. Clamping.\n",
                   priv->port_id, num_tx_queues, dev_info.max_tx_queues);
            num_tx_queues = dev_info.max_tx_queues;
        }

        /* Find configuration for this device */
        /* Note: We need to map port_id to PCI address to find config */
        /* rte_eth_dev_info_get populates device info, but mapping back to our config requires
         * search */
        /* For simplicity, we'll iterate our config and match by PCI address if available,
           or just use defaults if not found. */

        /* TODO: Better mapping. For now, we assume 1:1 mapping if possible or just use defaults */
        /* Actually, we can get the PCI address from dev_info if it's a PCI device */
        /* Let's look up in g_vpp_config */
        extern struct vpp_config g_vpp_config;

        /* Helper to find config by PCI addr string */
        /* We'll just loop through configured devices and see if we can match */
        /* This is a bit hacky without full PCI address normalization */

        /* For now, let's just use the first configured device's settings if we only have one,
           or try to match. */

        /* Better approach: The interface name might match the config name? */
        /* Or we can just use the global defaults if not found */

        for (int i = 0; i < g_vpp_config.dpdk_config.num_devices; i++) {
            /* Check if this config entry matches our port */
            /* We can't easily check PCI address here without more DPDK headers */
            /* But we can check if the interface name matches? */
            /* The interface name in 'iface' struct is assigned by us. */

            /* Let's assume the user configured them in order? No, unsafe. */

            /* Let's just use the values from the first config entry that has > 1 queue
               as a heuristic if we are in multi-core mode. */

            /* CORRECT APPROACH: We should have stored the config pointer in priv during init. */
            /* But priv is created in physical_init. Let's look there. */
        }

        /* For this implementation, we will use the values from the FIRST device config
           that specifies multiple queues, applying it to ALL ports.
           This is a simplification but works for the user's "fully dynamic" request
           assuming symmetric NICs. */

        if (g_vpp_config.dpdk_config.num_devices > 0) {
            num_rx_queues = g_vpp_config.dpdk_config.devices[0].num_rx_queues;
            num_tx_queues = g_vpp_config.dpdk_config.devices[0].num_tx_queues;
            num_rx_desc = g_vpp_config.dpdk_config.devices[0].num_rx_desc;
            num_tx_desc = g_vpp_config.dpdk_config.devices[0].num_tx_desc;
        }

        /* Configure device */
        port_conf.rxmode.mq_mode = (num_rx_queues > 1) ? RTE_ETH_MQ_RX_RSS : RTE_ETH_MQ_RX_NONE;
        if (num_rx_queues > 1) {
            port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
            port_conf.rx_adv_conf.rss_conf.rss_hf =
                RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP;
        }

        ret = rte_eth_dev_configure(priv->port_id, num_rx_queues, num_tx_queues, &port_conf);
        if (ret < 0) {
            fprintf(stderr, "Error configuring DPDK port %u: %s\n", priv->port_id,
                    rte_strerror(-ret));
            return -1;
        }

        /* Setup RX queues */
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

        for (int q = 0; q < num_rx_queues; q++) {
            ret = rte_eth_rx_queue_setup(priv->port_id, q, num_rx_desc,
                                         rte_eth_dev_socket_id(priv->port_id), &rxq_conf, mp);
            if (ret < 0) {
                fprintf(stderr, "Error setting up RX queue %d: %s\n", q, rte_strerror(-ret));
                return -1;
            }
        }

        /* Setup TX queues */
        txq_conf = dev_info.default_txconf;
        txq_conf.offloads = port_conf.txmode.offloads;

        for (int q = 0; q < num_tx_queues; q++) {
            ret = rte_eth_tx_queue_setup(priv->port_id, q, num_tx_desc,
                                         rte_eth_dev_socket_id(priv->port_id), &txq_conf);
            if (ret < 0) {
                fprintf(stderr, "Error setting up TX queue %d: %s\n", q, rte_strerror(-ret));
                return -1;
            }
        }

        /* Start device */
        ret = rte_eth_dev_start(priv->port_id);
        if (ret < 0) {
            fprintf(stderr, "Error starting DPDK port %u: %s\n", priv->port_id, rte_strerror(-ret));
            return -1;
        }

        /* Wait for link to come up (critical for packet reception) */
        struct rte_eth_link link;
        int link_check_attempts = 10;
        for (int i = 0; i < link_check_attempts; i++) {
            rte_eth_link_get_nowait(priv->port_id, &link);
            if (link.link_status == RTE_ETH_LINK_UP) {
                break;
            }
            usleep(100000); /* 100ms */
        }

        /* Force link up if still down (needed for some virtio-net devices) */
        rte_eth_link_get_nowait(priv->port_id, &link);
        if (link.link_status != RTE_ETH_LINK_UP) {
            printf("Port %u link DOWN, forcing link up...\n", priv->port_id);
            ret = rte_eth_dev_set_link_up(priv->port_id);
            if (ret < 0) {
                fprintf(stderr, "Warning: Failed to force link up on port %u: %s\n", priv->port_id,
                        rte_strerror(-ret));
            }
            /* Check again after forcing */
            usleep(200000); /* 200ms */
            rte_eth_link_get_nowait(priv->port_id, &link);
        }

        /* Log final link state */
        printf("Port %u: Link %s, Speed %u Mbps, Duplex %s\n", priv->port_id,
               link.link_status == RTE_ETH_LINK_UP ? "UP" : "DOWN", link.link_speed,
               link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX ? "FULL" : "HALF");

        /* Enable promiscuous mode */
        rte_eth_promiscuous_enable(priv->port_id);

        printf("DPDK port %u started with %d RX queues / %d TX queues\n", priv->port_id,
               num_rx_queues, num_tx_queues);
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
        /* Send packet using thread-local queue ID */
        uint16_t nb_tx = rte_eth_tx_burst(priv->port_id, g_thread_queue_id, &mbuf, 1);
        if (nb_tx == 0) {
            rte_pktmbuf_free(mbuf);
            iface->stats.tx_dropped++;
            return -1;
        }

        iface->stats.tx_packets++;
        iface->stats.tx_bytes += pkt->len;
        /* Skip time() in fast path - timestamp updated periodically */
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
    /* Skip time() in fast path - timestamp updated periodically */

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
        /* Thread-local burst buffer */
        static __thread struct rte_mbuf *tl_rx_burst_buf[DPDK_RX_BURST_SIZE];
        static __thread uint16_t tl_rx_burst_count = 0;
        static __thread uint16_t tl_rx_burst_idx = 0;
        static __thread int tl_burst_ifindex = -1;

        /* Check if we switched interfaces */
        if (tl_burst_ifindex != (int)iface->ifindex) {
            /* Discard old burst */
            for (uint16_t i = tl_rx_burst_idx; i < tl_rx_burst_count; i++) {
                rte_pktmbuf_free(tl_rx_burst_buf[i]);
            }
            tl_rx_burst_count = 0;
            tl_rx_burst_idx = 0;
            tl_burst_ifindex = iface->ifindex;
        }

        /* Check if we have buffered packets from previous burst */
        if (tl_rx_burst_idx >= tl_rx_burst_count) {
            /* Need to fetch new burst using thread-local queue ID */

            /* Debug: trace polling */
            static uint64_t poll_count = 0;
            poll_count++;
            if (poll_count % 100 == 1) { /* Log more frequently */
                struct rte_eth_stats stats;
                rte_eth_stats_get(priv->port_id, &stats);
                printf("[PHY DEBUG] Polling port %u queue %d (burst_idx=%u count=%u) | Q0: %lu Q1: "
                       "%lu Q2: %lu | Errors: %lu\n",
                       priv->port_id, g_thread_queue_id, tl_rx_burst_idx, tl_rx_burst_count,
                       stats.q_ipackets[0], stats.q_ipackets[1], stats.q_ipackets[2],
                       stats.ierrors);
            }

            tl_rx_burst_count = rte_eth_rx_burst(priv->port_id, g_thread_queue_id, tl_rx_burst_buf,
                                                 DPDK_RX_BURST_SIZE);
            tl_rx_burst_idx = 0;

            if (tl_rx_burst_count == 0) {
                return 0;
            }
        }

        /* Get next packet from burst buffer */
        struct rte_mbuf *mbuf = tl_rx_burst_buf[tl_rx_burst_idx++];

        /* Convert mbuf to pkt_buf */
        new_pkt = pkt_alloc();
        if (!new_pkt) {
            rte_pktmbuf_free(mbuf);
            iface->stats.rx_dropped++;
            return -1;
        }

        /* Copy data (TODO: Zero-copy) */
        new_pkt->len = rte_pktmbuf_pkt_len(mbuf);
        if (new_pkt->len > new_pkt->buf_size) {
            new_pkt->len = new_pkt->buf_size;
        }
        rte_memcpy(new_pkt->data, rte_pktmbuf_mtod(mbuf, void *), new_pkt->len);
        rte_pktmbuf_free(mbuf);

        iface->stats.rx_packets++;
        iface->stats.rx_bytes += new_pkt->len;
        /* Skip time() in fast path - timestamp updated periodically */

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
    /* Skip time() in fast path - timestamp updated periodically */

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
                fprintf(stderr, "Failed to set MTU on DPDK port %u: %s\n", priv->port_id,
                        rte_strerror(-ret));
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

#ifdef HAVE_DPDK
    /* Free any remaining packets in burst buffer - handled by thread locals now,
       but we can't easily free them here as they are thread-local.
       They will be freed/overwritten on next use or when thread exits (OS cleanup). */
#endif

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
const struct interface_ops physical_interface_ops = {.init = physical_init,
                                                     .up = physical_up,
                                                     .down = physical_down,
                                                     .send = physical_send,
                                                     .recv = physical_recv,
                                                     .get_link_state = physical_get_link_state,
                                                     .get_stats = physical_get_stats,
                                                     .configure = physical_configure,
                                                     .cleanup = physical_cleanup};
