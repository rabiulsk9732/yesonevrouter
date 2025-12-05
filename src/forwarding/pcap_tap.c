/**
 * @file pcap_tap.c
 * @brief DPDK Packet Capture to PCAP File
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

#include "pcap_tap.h"
#include "log.h"

/* PCAP file header */
struct pcap_file_header {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
};

/* PCAP packet header */
struct pcap_pkthdr {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
};

#define PCAP_MAGIC      0xA1B2C3D4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define DLT_EN10MB      1   /* Ethernet */
#define DLT_RAW         101 /* Raw IP */

static struct {
    FILE *file;
    char filename[256];
    uint32_t snaplen;
    uint32_t linktype;
    uint64_t packets_captured;
    uint64_t bytes_captured;
    bool enabled;
    pthread_mutex_t lock;

    /* Filter */
    uint16_t filter_session_id;
    uint32_t filter_ip;
    bool filter_enabled;
} g_pcap = {
    .lock = PTHREAD_MUTEX_INITIALIZER
};

int pcap_tap_start(const char *filename, uint32_t snaplen)
{
    pthread_mutex_lock(&g_pcap.lock);

    if (g_pcap.enabled) {
        pthread_mutex_unlock(&g_pcap.lock);
        YLOG_WARNING("PCAP Tap: Already running");
        return -1;
    }

    snprintf(g_pcap.filename, sizeof(g_pcap.filename), "%s", filename);
    g_pcap.snaplen = snaplen > 0 ? snaplen : 65535;
    g_pcap.linktype = DLT_EN10MB;

    g_pcap.file = fopen(filename, "wb");
    if (!g_pcap.file) {
        pthread_mutex_unlock(&g_pcap.lock);
        YLOG_ERROR("PCAP Tap: Failed to open file '%s'", filename);
        return -1;
    }

    /* Write PCAP header */
    struct pcap_file_header hdr = {
        .magic = PCAP_MAGIC,
        .version_major = PCAP_VERSION_MAJOR,
        .version_minor = PCAP_VERSION_MINOR,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = g_pcap.snaplen,
        .linktype = g_pcap.linktype
    };

    fwrite(&hdr, sizeof(hdr), 1, g_pcap.file);
    fflush(g_pcap.file);

    g_pcap.packets_captured = 0;
    g_pcap.bytes_captured = 0;
    g_pcap.enabled = true;

    pthread_mutex_unlock(&g_pcap.lock);

    YLOG_INFO("PCAP Tap: Started capturing to '%s' (snaplen=%u)", filename, g_pcap.snaplen);
    return 0;
}

void pcap_tap_stop(void)
{
    pthread_mutex_lock(&g_pcap.lock);

    if (g_pcap.file) {
        fclose(g_pcap.file);
        g_pcap.file = NULL;
    }
    g_pcap.enabled = false;

    YLOG_INFO("PCAP Tap: Stopped (%lu packets, %lu bytes)",
              g_pcap.packets_captured, g_pcap.bytes_captured);

    pthread_mutex_unlock(&g_pcap.lock);
}

int pcap_tap_write(const uint8_t *data, uint32_t len)
{
    if (!g_pcap.enabled || !g_pcap.file || !data) {
        return 0;
    }

    pthread_mutex_lock(&g_pcap.lock);

    if (!g_pcap.file) {
        pthread_mutex_unlock(&g_pcap.lock);
        return 0;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    uint32_t caplen = len > g_pcap.snaplen ? g_pcap.snaplen : len;

    struct pcap_pkthdr pkt_hdr = {
        .ts_sec = (uint32_t)ts.tv_sec,
        .ts_usec = (uint32_t)(ts.tv_nsec / 1000),
        .caplen = caplen,
        .len = len
    };

    fwrite(&pkt_hdr, sizeof(pkt_hdr), 1, g_pcap.file);
    fwrite(data, caplen, 1, g_pcap.file);

    g_pcap.packets_captured++;
    g_pcap.bytes_captured += caplen;

    /* Flush periodically */
    if (g_pcap.packets_captured % 100 == 0) {
        fflush(g_pcap.file);
    }

    pthread_mutex_unlock(&g_pcap.lock);
    return 1;
}

int pcap_tap_write_pppoe(uint16_t session_id, const uint8_t *data, uint32_t len)
{
    /* Apply session filter if enabled */
    if (g_pcap.filter_enabled && g_pcap.filter_session_id != 0) {
        if (g_pcap.filter_session_id != session_id) {
            return 0; /* Filtered out */
        }
    }

    return pcap_tap_write(data, len);
}

void pcap_tap_set_filter(uint16_t session_id, uint32_t ip)
{
    g_pcap.filter_session_id = session_id;
    g_pcap.filter_ip = ip;
    g_pcap.filter_enabled = (session_id != 0 || ip != 0);

    YLOG_INFO("PCAP Tap: Filter set (session=%u, ip=%u.%u.%u.%u)",
              session_id,
              (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
              (ip >> 8) & 0xFF, ip & 0xFF);
}

void pcap_tap_clear_filter(void)
{
    g_pcap.filter_enabled = false;
    g_pcap.filter_session_id = 0;
    g_pcap.filter_ip = 0;
}

void pcap_tap_stats(uint64_t *packets, uint64_t *bytes)
{
    if (packets) *packets = g_pcap.packets_captured;
    if (bytes) *bytes = g_pcap.bytes_captured;
}

bool pcap_tap_is_running(void)
{
    return g_pcap.enabled;
}
