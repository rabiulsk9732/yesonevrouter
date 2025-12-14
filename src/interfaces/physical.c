/**
 * @file physical.c
 * @brief Physical Interface Driver Implementation
 */

#define _GNU_SOURCE
#include "cpu_scheduler.h"
#include "interface.h"
#include "log.h"
#include "env_config.h"
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
#include "env_config.h"
#include "hqos.h"
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#endif


/* Symmetric Toeplitz RSS Key (52 bytes max - supports all NICs)
 * ixgbe: uses 40 bytes, i40e: uses 52 bytes, mlx5: uses 40 bytes
 * Key length is dynamically set from dev_info.hash_key_size
 */
static uint8_t symmetric_rss_key[52] = {
    0x6D, 0x5A, 0x56, 0xDA, 0x25, 0x5B, 0x0E, 0xC2,
    0x41, 0x67, 0x25, 0x3D, 0x43, 0xA3, 0x8F, 0xB0,
    0xD0, 0xCA, 0x2B, 0xCB, 0xAE, 0x7B, 0x30, 0xB4,
    0x77, 0xCB, 0x2D, 0xA3, 0x80, 0x30, 0xF2, 0x0C,
    0x6A, 0x42, 0xB7, 0x3B, 0xBE, 0xAC, 0x01, 0xFA,
    0x6D, 0x5A, 0x56, 0xDA, 0x25, 0x5B, 0x0E, 0xC2,  /* Extra 12 bytes for i40e */
    0x41, 0x67, 0x25, 0x3D
};
/* DPDK burst size - loaded from .env (no hardcoded values) */
#define DPDK_RX_BURST_SIZE_MAX 256  /* Buffer size, actual from env_get_rx_burst_size() */

/* Private data for physical interface */
struct physical_priv {
    int sock_fd;    /* Socket for ioctl operations */
    int rx_sock_fd; /* Raw socket for packet RX/TX */
    bool link_detection_enabled;
    uint64_t last_link_check;
#ifdef HAVE_DPDK
    uint16_t port_id;       /* DPDK port ID */
    bool dpdk_enabled;      /* Is DPDK enabled for this interface? */
    uint16_t num_rx_queues; /* Number of configured RX queues */
    uint16_t num_tx_queues; /* Number of configured TX queues */
    bool port_ready;        /* Flag to track if port is fully initialized and ready for polling */
    rte_spinlock_t lock;    /* Lock for shared queue access (when queues < threads) */
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

        /* Register for O(1) fast lookup (VPP-style) */
        interface_register_fast_lookup(iface, port_id);

        printf("Physical interface %s initialized (index %u, DPDK port %u)\n",
               iface->name, iface->ifindex, port_id);
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
    if (priv->dpdk_enabled) {
        /* Check if port is already started - if so, just return success */
        struct rte_eth_link link;
        rte_eth_link_get_nowait(priv->port_id, &link);
        if ((link.link_status == RTE_ETH_LINK_UP && priv->port_ready) || priv->num_rx_queues > 0) {
            /* Port already configured and started */
            printf("DPDK port %u already configured and up\n", priv->port_id);
            if (!priv->port_ready) {
                priv->port_ready = true; /* Mark as ready if not already */
            }
            return 0;
        }

        /* DPDK path - configure and start the port */
        struct rte_eth_conf port_conf = {0};
        struct rte_eth_rxconf rxq_conf;
        struct rte_eth_txconf txq_conf;
        struct rte_eth_dev_info dev_info;
        int ret;

        /* Bison-style: ALL values from .env - NO HARDCODED DEFAULTS */
        int num_rx_queues = env_get_rx_queues();
        int num_tx_queues = env_get_tx_queues();
        int num_rx_desc = env_get_rx_desc();
        int num_tx_desc = env_get_tx_desc();

        printf("[ENV] Port %s: rx_queues=%d tx_queues=%d rx_desc=%d tx_desc=%d\n",
               iface->name, num_rx_queues, num_tx_queues, num_rx_desc, num_tx_desc);

        /* Get device info FIRST to know device capabilities */
        ret = rte_eth_dev_info_get(priv->port_id, &dev_info);
        if (ret != 0) {
            fprintf(stderr, "Error getting device info: %s\n", strerror(-ret));
            return -1;
        }

        /* Clamp requested queues to device maximum (dynamic based on actual hardware) */
        if (num_rx_queues > dev_info.max_rx_queues) {
            printf("DPDK port %d (%s): Requested %d RX queues, but device only supports %d. "
                   "Clamping.\n",
                   priv->port_id, iface->name, num_rx_queues, dev_info.max_rx_queues);
            num_rx_queues = dev_info.max_rx_queues;
        }
        if (num_tx_queues > dev_info.max_tx_queues) {
            printf("DPDK port %d (%s): Requested %d TX queues, but device only supports %d. "
                   "Clamping.\n",
                   priv->port_id, iface->name, num_tx_queues, dev_info.max_tx_queues);
            num_tx_queues = dev_info.max_tx_queues;
        }

        /* Check if port is already configured - if so, stop it first */
        struct rte_eth_link existing_link;
        rte_eth_link_get_nowait(priv->port_id, &existing_link);
        if (existing_link.link_status == RTE_ETH_LINK_UP) {
            /* Port is already started, stop it first */
            rte_eth_dev_stop(priv->port_id);
            /* Do NOT close the device, as that detaches it and invalidates port_id */
            /* rte_eth_dev_close(priv->port_id); */
        }

        /* Configure device */
        /* For multi-queue: check if device supports RSS hash offload */
        if (num_rx_queues > 1 && dev_info.flow_type_rss_offloads != 0) {
            /* Device supports RSS - enable it */
            port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
            port_conf.rx_adv_conf.rss_conf.rss_key = symmetric_rss_key;
            /* Use device-reported key size (ixgbe=40, i40e=52, mlx5=40) */
            uint8_t key_len = dev_info.hash_key_size;
            if (key_len == 0 || key_len > 52) key_len = 40;  /* Default fallback */
            port_conf.rx_adv_conf.rss_conf.rss_key_len = key_len;
            printf("DPDK port %u: RSS key length=%u (from dev_info)\n", priv->port_id, key_len);

            /* Request IP/TCP/UDP RSS */
            uint64_t rss_hf_wanted = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP;

            /* If NIC supports PPPoE RSS (rare), try it */
            /* Note: RTE_ETH_RSS_PPPOE might not be defined in older DPDK */
#ifdef RTE_ETH_RSS_PPPOE
            if (dev_info.flow_type_rss_offloads & RTE_ETH_RSS_PPPOE) {
                rss_hf_wanted |= RTE_ETH_RSS_PPPOE;
            }
#endif
            /* Mask against what device actually supports */
            port_conf.rx_adv_conf.rss_conf.rss_hf = rss_hf_wanted & dev_info.flow_type_rss_offloads;

            printf("DPDK port %u: RSS Enabled (Symmetric Key, HF=0x%lx)\n",
                   priv->port_id, port_conf.rx_adv_conf.rss_conf.rss_hf);
        } else {
             /* Single queue or no RSS support */
             port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
        }


        bool port_already_configured = false;
        ret = rte_eth_dev_configure(priv->port_id, num_rx_queues, num_tx_queues, &port_conf);
        if (ret < 0) {
            /* If configuration fails, port might already be configured */
            /* Try to start it - if that works, port was already configured */
            int start_ret = rte_eth_dev_start(priv->port_id);
            if (start_ret == 0) {
                printf("DPDK port %u was already configured, started successfully\n",
                       priv->port_id);
                priv->num_rx_queues = num_rx_queues;
                port_already_configured = true;
                /* Skip queue setup - they're already configured */
                /* Add delay for virtio ring initialization before marking ready */
                usleep(200000); /* 200ms delay for virtio ring initialization */
                priv->port_ready = true;
                goto skip_queue_setup;
            } else {
                fprintf(stderr, "Error configuring DPDK port %u: %s (start also failed: %s)\n",
                        priv->port_id, rte_strerror(-ret), rte_strerror(-start_ret));
                return -1;
            }
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

        /* Store number of RX/TX queues for queue_id clamping */
        priv->num_rx_queues = num_rx_queues;
        priv->num_tx_queues = num_tx_queues;

    skip_queue_setup:
        /* Start device (skip if already started above) */
        if (!port_already_configured) {
            ret = rte_eth_dev_start(priv->port_id);
            if (ret < 0) {
                fprintf(stderr, "Error starting DPDK port %u: %s\n", priv->port_id,
                        rte_strerror(-ret));
                return -1;
            }
        }

        /* Wait for link to come up (critical for packet reception) */
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

        /* Initialize HQoS for this port if link is up */
        if (link.link_status == RTE_ETH_LINK_UP) {
            uint64_t link_speed_bps = (uint64_t)link.link_speed * 1000000;
            if (link_speed_bps == 0) link_speed_bps = 1000000000; /* Default 1G if unknown */
            hqos_port_init(priv->port_id, link_speed_bps);
        }

        /* Additional delay for virtio devices to fully initialize ring buffers */
        /* This prevents race conditions where polling starts before virtio rings are ready */
        /* Note: This delay is primarily needed for virtio. Real hardware (Intel/Mellanox) */
        /* initializes faster, but a delay ensures proper initialization for all devices */
        /* Virtio requires ring buffers to be fully initialized before polling */
        usleep(300000); /* 300ms - give virtio driver time to fully initialize ring buffers */

        /* Verify port is actually ready by checking device info (sanity check) */
        struct rte_eth_dev_info verify_dev_info;
        int verify_ret = rte_eth_dev_info_get(priv->port_id, &verify_dev_info);
        if (verify_ret != 0) {
            fprintf(stderr, "Warning: Failed to verify port %u readiness: %s\n", priv->port_id,
                    strerror(-verify_ret));
            /* Continue anyway - might still work */
        }

        /* Mark port as ready for polling AFTER initialization delay and verification */
        /* This is critical for virtio devices which need ring buffer initialization */
        /* The delay ensures virtio ring buffers are fully initialized before polling starts */
        priv->port_ready = true;

        /* Set interface state to UP */
        iface->state = IF_STATE_UP;
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

        /* Copy packet data to mbuf - enforce 60-byte minimum Ethernet frame */
        uint16_t final_len = (pkt->len < 60) ? 60 : pkt->len;
        void *data = rte_pktmbuf_append(mbuf, final_len);
        if (!data) {
            rte_pktmbuf_free(mbuf);
            iface->stats.tx_dropped++;
            return -1;
        }
        rte_memcpy(data, pkt->data, pkt->len);
        /* Zero-pad if needed */
        if (final_len > pkt->len) {
            memset((uint8_t *)data + pkt->len, 0, final_len - pkt->len);
        }

        /* Debug: Log PPPoE Session packet headers */
        {
            struct rte_ether_hdr *d_eth = (struct rte_ether_hdr *)data;
            uint16_t d_type = rte_be_to_cpu_16(d_eth->ether_type);
            uint16_t vlan_id = 0;
            if (d_type == RTE_ETHER_TYPE_VLAN) {
                struct rte_vlan_hdr *d_vlan = (struct rte_vlan_hdr *)(d_eth + 1);
                vlan_id = rte_be_to_cpu_16(d_vlan->vlan_tci) & 0xFFF;
                d_type = rte_be_to_cpu_16(d_vlan->eth_proto);
            }
            if (d_type == 0x8864) {
                YLOG_INFO("LCP TX: len=%u final=%u iface=%s vlan=%u dst=%02x:%02x:%02x:%02x:%02x:%02x",
                          pkt->len, final_len, iface->name, vlan_id,
                          d_eth->dst_addr.addr_bytes[0], d_eth->dst_addr.addr_bytes[1],
                          d_eth->dst_addr.addr_bytes[2], d_eth->dst_addr.addr_bytes[3],
                          d_eth->dst_addr.addr_bytes[4], d_eth->dst_addr.addr_bytes[5]);
            }
        }

        /* HQoS Interception */
        /* HQoS Interception */
        if (hqos_is_active(priv->port_id)) {
            /* Strict Control Plane Bypass Logic */
            /* Default: BYPASS HQoS (Direct TX) */
            bool use_hqos = false;

            /* Parse Headers */
            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
            uint16_t eth_type = rte_be_to_cpu_16(eth->ether_type);
            size_t header_len = sizeof(struct rte_ether_hdr);

            /* Handle VLAN */
            if (eth_type == RTE_ETHER_TYPE_VLAN) {
                struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(eth + 1);
                eth_type = rte_be_to_cpu_16(vlan->eth_proto);
                header_len += sizeof(struct rte_vlan_hdr);
            }

            /* Identify Subscriber Data */
            if (eth_type == 0x8864) { /* PPPoE Session */
                /* Check PPP Protocol */
                /* PPPoE Header (6) + PPP Protocol (2) */
                struct pppoe_hdr *pppoe = (struct pppoe_hdr *)((uint8_t *)eth + header_len);
                /* Ensure packet large enough? Assumed ok for calling pppoe */

                /* PPP Protocol is at offset 6 in PPPoE header */
                /* struct pppoe_hdr usually has 'ver_type', 'code', 'session_id', 'length' */
                /* Then payload starts. First 2 bytes of payload = PPP Protocol */

                uint16_t *proto_ptr = (uint16_t *)((uint8_t *)pppoe + 6);
                uint16_t ppp_proto = rte_be_to_cpu_16(*proto_ptr); // 0th byte of payload? No struct pppoe_hdr is 6 bytes.

                if (ppp_proto == 0x0021 || ppp_proto == 0x0057) {
                    /* IPv4 (0021) or IPv6 (0057) -> Subscriber Data -> HQoS */
                    use_hqos = true;
                }
                /* LCP (C021), IPCP (8021), PAP (C023) -> BYPASS (use_hqos stays false) */
            }
            /* Non-PPPoE (ARP, ICMP, etc) -> BYPASS (use_hqos stays false) */

            if (use_hqos) {
                 /* Classify Packet (TODO: Flow based classification) */
                 uint8_t class_id = 2; /* Default: Best Effort (Class 2) */

                 /* Enqueue to HQoS */
                 if (hqos_enqueue(priv->port_id, class_id, mbuf) == 0) {
                      iface->stats.tx_packets++;
                      iface->stats.tx_bytes += pkt->len;
                      return 0; /* Enqueued successfully */
                 } else {
                      rte_pktmbuf_free(mbuf);
                      iface->stats.tx_dropped++;
                      return -1;
                 }
            }
            /* If !use_hqos, Fallthrough to Direct TX (Bypass) */
        }

        /* Direct Send (Non-HQoS) */
        /* Send packet using thread-local queue ID, clamped to configured TX queues */
        uint16_t num_tx_queues = (priv->num_tx_queues > 0) ? priv->num_tx_queues : 1;
        uint16_t queue_id = 0; /* Default to 0 for PoC/Simple Worker (Assuming single worker per port logic or locked) */

        /* Note: rte_eth_tx_burst is not thread safe on same queue! */
        /* Assuming Worker 0 (which runs both RX and HQoS) is the only one sending on Queue 0 */

        sent = rte_eth_tx_burst(priv->port_id, queue_id, &mbuf, 1);
        if (sent > 0) {
            iface->stats.tx_packets++;
            iface->stats.tx_bytes += pkt->len;
            return 0;
        } else {
            /* Log Silent Drop in Transmission */
            static uint64_t last_log = 0;
            uint64_t now = rte_get_timer_cycles();
            if (now - last_log > rte_get_timer_hz()) {
                 YLOG_INFO("TX-BYPASS DROP: Port %u Queue %d burst returned 0", priv->port_id, queue_id);
                 last_log = now;
            }
            rte_pktmbuf_free(mbuf);
            iface->stats.tx_dropped++;
            return -1;
        }
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
        /* Safety check: ensure interface is fully configured before polling */
        if (priv->num_rx_queues == 0) {
            /* Interface not yet configured, skip polling */
            return 0;
        }

        /* Safety check: verify port is marked as ready (fully initialized) */
        /* This is critical for virtio devices which need ring buffer initialization */
        /* Prevents segfaults from polling before virtio rings are ready */
        if (!priv->port_ready) {
            /* Port not yet ready for polling, skip */
            return 0;
        }

        /* Safety check: verify port is actually started and link is up */
        /* Also important for Mellanox and Intel cards to ensure proper initialization */
        struct rte_eth_link link;
        int link_ret = rte_eth_link_get_nowait(priv->port_id, &link);
        if (link_ret < 0 || link.link_status != RTE_ETH_LINK_UP) {
            /* Port not up yet or error getting link status, skip polling */
            return 0;
        }

        /* Thread-local burst buffer - sized for max, actual burst from .env */
        static __thread struct rte_mbuf *tl_rx_burst_buf[DPDK_RX_BURST_SIZE_MAX];
        int burst_size = env_get_rx_burst_size();
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
            extern __thread int g_thread_queue_id;

            /* Bison-style: Each lcore polls its own dedicated queue (LOCKLESS) */
            /* Queue ID = Worker ID (1:1 mapping for maximum performance) */
            uint16_t num_rx_queues = (priv->num_rx_queues > 0) ? priv->num_rx_queues : 1;
            uint16_t safe_queue_id = (g_thread_queue_id >= 0) ?
                                     (g_thread_queue_id % num_rx_queues) : 0;

            /* Safety: validate port_id before calling DPDK function */
            if (priv->port_id >= RTE_MAX_ETHPORTS) {
                return 0;
            }

            /* LOCKLESS RX: Each lcore has dedicated queue, no lock needed */
            /* Only use lock if queues < workers (shared queue mode) */
            if (num_rx_queues < 4) {
                /* Shared queue mode - need lock */
                rte_spinlock_lock(&priv->lock);
                tl_rx_burst_count =
                    rte_eth_rx_burst(priv->port_id, safe_queue_id, tl_rx_burst_buf, burst_size);
                rte_spinlock_unlock(&priv->lock);
            } else {
                /* Dedicated queue mode - LOCKLESS (Bison-style) */
                tl_rx_burst_count =
                    rte_eth_rx_burst(priv->port_id, safe_queue_id, tl_rx_burst_buf, burst_size);
            }
            tl_rx_burst_idx = 0;

            /* If burst count is 0, no packets available - this is normal */
            if (tl_rx_burst_count == 0) {
                return 0;
            }

            /* Debug: Log when we receive packets */
            static uint64_t rx_debug_count = 0;
            if (rx_debug_count++ < 10) {
                YLOG_INFO("DPDK RX: port=%u queue=%u burst=%u",
                          priv->port_id, safe_queue_id, tl_rx_burst_count);
            }

            /* Safety: validate burst count doesn't exceed buffer size */
            if (tl_rx_burst_count > burst_size) {
                /* This shouldn't happen, but be defensive */
                tl_rx_burst_count = burst_size;
            }

            /* Safety: validate all mbufs in burst are valid (especially for virtio) */
            for (uint16_t i = 0; i < tl_rx_burst_count; i++) {
                if (!tl_rx_burst_buf[i]) {
                    /* Invalid mbuf - free any valid ones and return */
                    for (uint16_t j = 0; j < i; j++) {
                        if (tl_rx_burst_buf[j]) {
                            rte_pktmbuf_free(tl_rx_burst_buf[j]);
                        }
                    }
                    tl_rx_burst_count = 0;
                    return 0;
                }
            }
        }

        /* Get next packet from burst buffer */
        /* Safety: bounds check before accessing buffer */
        if (tl_rx_burst_idx >= tl_rx_burst_count || tl_rx_burst_idx >= DPDK_RX_BURST_SIZE_MAX) {
            return 0;
        }
        struct rte_mbuf *mbuf = tl_rx_burst_buf[tl_rx_burst_idx++];

        /* Safety: validate mbuf pointer */
        if (!mbuf) {
            return 0;
        }

        /* Flow Cache Update - MUST be done BEFORE freeing mbuf */
        extern void flow_cache_update(struct rte_mbuf * m, int direction);
        flow_cache_update(mbuf, 0); /* 0 = Ingress */

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
        /* CRITICAL: Update mbuf metadata for PPPoE/other consumers */
        new_pkt->mbuf->data_len = new_pkt->len;
        new_pkt->mbuf->pkt_len = new_pkt->len;
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
