/**
 * @file dpdk_init.c
 * @brief DPDK Initialization Implementation
 */

#include "dpdk_init.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HAVE_DPDK
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#endif

/**
 * Bind PCI device to DPDK driver (vfio-pci)
 * Called before EAL init to ensure NICs are available
 */
static int dpdk_bind_device(const char *pci_addr)
{
    char path[256];
    char driver_path[256];
    FILE *f;

    /* Check if device exists */
    snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s", pci_addr);
    if (access(path, F_OK) != 0) {
        fprintf(stderr, "[DPDK] PCI device %s not found\n", pci_addr);
        return -1;
    }

    /* Check if already bound to vfio-pci */
    snprintf(driver_path, sizeof(driver_path), "/sys/bus/pci/devices/%s/driver", pci_addr);
    char driver_link[256] = {0};
    ssize_t len = readlink(driver_path, driver_link, sizeof(driver_link) - 1);
    if (len > 0) {
        char *drv_name = strrchr(driver_link, '/');
        if (drv_name && strcmp(drv_name + 1, "vfio-pci") == 0) {
            printf("[DPDK] %s already bound to vfio-pci\n", pci_addr);
            return 0;
        }
    }

    printf("[DPDK] Binding %s to vfio-pci...\n", pci_addr);

    /* Load vfio-pci module */
    system("modprobe vfio-pci 2>/dev/null");

    /* Enable no-iommu mode */
    f = fopen("/sys/module/vfio/parameters/enable_unsafe_noiommu_mode", "w");
    if (f) {
        fprintf(f, "1");
        fclose(f);
    }

    /* Use driver_override (safer method) */
    snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/driver_override", pci_addr);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "vfio-pci");
        fclose(f);
    }

    /* Bind to vfio-pci */
    f = fopen("/sys/bus/pci/drivers/vfio-pci/bind", "w");
    if (f) {
        fprintf(f, "%s", pci_addr);
        fclose(f);
    }

    printf("[DPDK] %s bound to vfio-pci\n", pci_addr);
    return 0;
}

/**
 * Auto-bind NICs from env file before EAL init
 */
static void dpdk_auto_bind_nics(void)
{
    /* Read PCI addresses from env file */
    FILE *f = fopen("/etc/yesrouter/yesrouter.env", "r");
    if (!f)
        return;

    char line[256];
    int in_pci_block = 0;

    while (fgets(line, sizeof(line), f)) {
        /* Skip comments */
        if (line[0] == '#')
            continue;

        /* Check for PCI=( start */
        if (strstr(line, "PCI=(")) {
            in_pci_block = 1;
            continue;
        }

        /* Check for ) end */
        if (in_pci_block && strchr(line, ')')) {
            in_pci_block = 0;
            continue;
        }

        /* Parse PCI address */
        if (in_pci_block) {
            char pci_addr[32] = {0};
            /* Extract PCI address (format: "    0000:06:13.0  # comment") */
            if (sscanf(line, " %31[0-9a-fA-F:.]", pci_addr) == 1 && strlen(pci_addr) > 5) {
                dpdk_bind_device(pci_addr);
            }
        }
    }
    fclose(f);
}

/* Global DPDK configuration */
struct dpdk_config g_dpdk_config = {.enabled = false,
                                    .num_lcores = 0,
                                    .socket_id = 0,
                                    .num_mbufs = DPDK_NUM_MBUFS,
                                    .pkt_mempool = NULL};

int dpdk_init(int argc, char *argv[])
{
#ifdef HAVE_DPDK
    int ret;

    /* Check for valid arguments - DPDK EAL requires at least program name */
    if (argc < 1 || argv == NULL || argv[0] == NULL) {
        printf("DPDK EAL requires valid arguments, running without DPDK\n");
        g_dpdk_config.enabled = false;
        return 0;
    }

    /* Auto-bind NICs from env file before EAL init */
    dpdk_auto_bind_nics();

    printf("Initializing DPDK EAL...\n");

    /* Initialize DPDK EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "DPDK EAL initialization failed: %s\n", rte_strerror(rte_errno));
        /* Don't fail completely - run without DPDK */
        g_dpdk_config.enabled = false;
        return 0;
    }

    /* Get number of available lcores */
    g_dpdk_config.num_lcores = rte_lcore_count();
    g_dpdk_config.socket_id = rte_socket_id();
    g_dpdk_config.enabled = true;

    printf("DPDK initialized successfully\n");
    printf("  Logical cores: %u\n", g_dpdk_config.num_lcores);
    printf("  Socket ID: %u\n", g_dpdk_config.socket_id);

    /* Create default packet memory pool */
    g_dpdk_config.pkt_mempool =
        dpdk_mempool_create("PKT_MBUF_POOL", g_dpdk_config.num_mbufs, g_dpdk_config.socket_id);

    if (!g_dpdk_config.pkt_mempool) {
        fprintf(stderr, "Failed to create packet memory pool\n");
        dpdk_cleanup();
        return -1;
    }

    return 0;
#else
    (void)argc;
    (void)argv;
    printf("DPDK support not compiled, running without DPDK\n");
    g_dpdk_config.enabled = false;
    return 0;
#endif
}

struct dpdk_mempool *dpdk_mempool_create(const char *name, uint32_t num_elements,
                                         uint32_t socket_id)
{
#ifdef HAVE_DPDK
    struct dpdk_mempool *mp;
    struct rte_mempool *rte_mp;

    mp = calloc(1, sizeof(*mp));
    if (!mp) {
        fprintf(stderr, "Failed to allocate memory pool structure\n");
        return NULL;
    }

    /* Create DPDK mempool */
    rte_mp = rte_pktmbuf_pool_create(name, num_elements, DPDK_MBUF_CACHE_SIZE, 0,
                                     RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);

    if (!rte_mp) {
        fprintf(stderr, "Failed to create mempool: %s\n", rte_strerror(rte_errno));
        free(mp);
        return NULL;
    }

    mp->pool = rte_mp;
    strncpy(mp->name, name, sizeof(mp->name) - 1);
    mp->num_elements = num_elements;
    mp->element_size = RTE_MBUF_DEFAULT_BUF_SIZE;
    mp->cache_size = DPDK_MBUF_CACHE_SIZE;

    printf("Created memory pool: %s (%u elements)\n", name, num_elements);

    return mp;
#else
    (void)name;
    (void)num_elements;
    (void)socket_id;
    return NULL;
#endif
}

void dpdk_mempool_free(struct dpdk_mempool *mp)
{
#ifdef HAVE_DPDK
    if (mp && mp->pool) {
        rte_mempool_free((struct rte_mempool *)mp->pool);
        free(mp);
    }
#else
    (void)mp;
#endif
}

int dpdk_set_lcore_affinity(uint32_t lcore_id)
{
#ifdef HAVE_DPDK
    if (lcore_id >= g_dpdk_config.num_lcores) {
        fprintf(stderr, "Invalid lcore ID: %u\n", lcore_id);
        return -1;
    }

    /* DPDK handles core affinity internally */
    printf("CPU affinity set for lcore %u\n", lcore_id);
    return 0;
#else
    (void)lcore_id;
    return 0;
#endif
}

uint32_t dpdk_get_lcore_count(void)
{
#ifdef HAVE_DPDK
    if (g_dpdk_config.enabled) {
        return rte_lcore_count();
    }
#endif
    return 1; /* Return 1 if DPDK not available */
}

uint32_t dpdk_get_socket_id(void)
{
#ifdef HAVE_DPDK
    if (g_dpdk_config.enabled) {
        return rte_socket_id();
    }
#endif
    return 0;
}

void dpdk_cleanup(void)
{
#ifdef HAVE_DPDK
    if (g_dpdk_config.enabled) {
        printf("Cleaning up DPDK...\n");

        /* Free memory pool */
        if (g_dpdk_config.pkt_mempool) {
            dpdk_mempool_free(g_dpdk_config.pkt_mempool);
            g_dpdk_config.pkt_mempool = NULL;
        }

        /* Cleanup EAL */
        rte_eal_cleanup();

        g_dpdk_config.enabled = false;
        printf("DPDK cleanup complete\n");
    }
#endif
}

bool dpdk_is_enabled(void)
{
    return g_dpdk_config.enabled;
}

struct rte_mempool *dpdk_get_mempool(void)
{
#ifdef HAVE_DPDK
    if (g_dpdk_config.enabled && g_dpdk_config.pkt_mempool) {
        return (struct rte_mempool *)g_dpdk_config.pkt_mempool->pool;
    }
#endif
    return NULL;
}
