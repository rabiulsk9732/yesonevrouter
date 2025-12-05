/**
 * @file nat_netflow.c
 * @brief NetFlow v9 NAT Event Logging Implementation
 *
 * Exports NAT session create/delete events to a NetFlow v9 collector via UDP.
 * Provides backward compatibility with legacy collectors (nfcapd, etc.)
 */

#include "nat_netflow.h"
#include "log.h"
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* Buffer size for batching records */
#define NF9_BUFFER_SIZE 1400 /* Stay under typical MTU */
#define NF9_MAX_RECORDS 50   /* Max records per packet */

/* Template refresh interval (seconds) */
#define TEMPLATE_REFRESH_INTERVAL 600 /* 10 minutes */

/* Exporter state */
static struct {
    bool enabled;
    int socket_fd;
    struct sockaddr_in collector_addr;
    uint32_t source_id;
    uint32_t sequence_number;
    time_t boot_time;
    time_t last_template_time;

    /* Send buffer */
    uint8_t buffer[NF9_BUFFER_SIZE];
    size_t buffer_offset;
    int record_count;
    int flowset_count;

    /* Statistics */
    struct netflow9_stats stats;

    /* Thread safety */
    pthread_mutex_t lock;
} g_netflow = {.enabled = false,
               .socket_fd = -1,
               .sequence_number = 0,
               .buffer_offset = 0,
               .record_count = 0,
               .flowset_count = 0,
               .lock = PTHREAD_MUTEX_INITIALIZER};

/* Get system uptime in milliseconds */
static uint32_t get_uptime_ms(void)
{
    time_t now = time(NULL);
    return (uint32_t)((now - g_netflow.boot_time) * 1000);
}

/* Build and send template FlowSet */
static int send_template_flowset(void)
{
    uint8_t packet[512];
    size_t offset = 0;

    /* NetFlow v9 Header */
    struct netflow9_header *hdr = (struct netflow9_header *)packet;
    hdr->version = htons(NETFLOW_V9_VERSION);
    hdr->count = htons(1); /* One FlowSet */
    hdr->sys_uptime = htonl(get_uptime_ms());
    hdr->unix_secs = htonl((uint32_t)time(NULL));
    hdr->sequence = htonl(g_netflow.sequence_number++);
    hdr->source_id = htonl(g_netflow.source_id);
    offset += sizeof(struct netflow9_header);

    /* Template FlowSet Header */
    struct netflow9_flowset_header *fs_hdr = (struct netflow9_flowset_header *)(packet + offset);
    fs_hdr->flowset_id = htons(NF9_FLOWSET_TEMPLATE);
    size_t fs_start = offset;
    offset += sizeof(struct netflow9_flowset_header);

    /* Template Record for NAT44 Session */
    struct netflow9_template_header *tmpl = (struct netflow9_template_header *)(packet + offset);
    tmpl->template_id = htons(NF9_TEMPLATE_NAT44_SESSION);
    tmpl->field_count = htons(9); /* 9 fields */
    offset += sizeof(struct netflow9_template_header);

    /* Field Definitions */
    struct netflow9_field_def fields[] = {
        {htons(NF9_FIELD_OBSERVATION_TIME_MS), htons(4)}, /* 4 bytes timestamp */
        {htons(NF9_FIELD_NAT_EVENT), htons(1)},           /* 1 byte event */
        {htons(NF9_FIELD_IPV4_SRC_ADDR), htons(4)},       /* 4 bytes inside IP */
        {htons(NF9_FIELD_L4_SRC_PORT), htons(2)},         /* 2 bytes inside port */
        {htons(NF9_FIELD_POST_NAT_SRC_ADDR), htons(4)},   /* 4 bytes outside IP */
        {htons(NF9_FIELD_POST_NAT_SRC_PORT), htons(2)},   /* 2 bytes outside port */
        {htons(NF9_FIELD_IPV4_DST_ADDR), htons(4)},       /* 4 bytes dest IP */
        {htons(NF9_FIELD_L4_DST_PORT), htons(2)},         /* 2 bytes dest port */
        {htons(NF9_FIELD_PROTOCOL), htons(1)},            /* 1 byte protocol */
    };

    memcpy(packet + offset, fields, sizeof(fields));
    offset += sizeof(fields);

    /* Pad to 4-byte boundary if needed */
    while ((offset - fs_start) % 4 != 0) {
        packet[offset++] = 0;
    }

    /* Update FlowSet length */
    fs_hdr->length = htons(offset - fs_start);

    /* Send packet */
    ssize_t sent =
        sendto(g_netflow.socket_fd, packet, offset, 0, (struct sockaddr *)&g_netflow.collector_addr,
               sizeof(g_netflow.collector_addr));

    if (sent < 0) {
        g_netflow.stats.send_errors++;
        YLOG_ERROR("NetFlow v9 template send failed: %s", strerror(errno));
        return -1;
    }

    g_netflow.stats.templates_sent++;
    g_netflow.stats.packets_sent++;
    g_netflow.stats.bytes_sent += sent;
    g_netflow.last_template_time = time(NULL);

    YLOG_DEBUG("NetFlow v9 template sent (%zu bytes)", offset);
    return 0;
}

/* Flush buffered records */
static int flush_buffer(void)
{
    if (g_netflow.record_count == 0) {
        return 0;
    }

    /* Finalize NetFlow v9 header */
    struct netflow9_header *hdr = (struct netflow9_header *)g_netflow.buffer;
    hdr->version = htons(NETFLOW_V9_VERSION);
    hdr->count = htons(g_netflow.flowset_count);
    hdr->sys_uptime = htonl(get_uptime_ms());
    hdr->unix_secs = htonl((uint32_t)time(NULL));
    hdr->sequence = htonl(g_netflow.sequence_number++);
    hdr->source_id = htonl(g_netflow.source_id);

    /* Send packet */
    ssize_t sent =
        sendto(g_netflow.socket_fd, g_netflow.buffer, g_netflow.buffer_offset, 0,
               (struct sockaddr *)&g_netflow.collector_addr, sizeof(g_netflow.collector_addr));

    if (sent < 0) {
        g_netflow.stats.send_errors++;
        YLOG_ERROR("NetFlow v9 data send failed: %s", strerror(errno));
        return -1;
    }

    g_netflow.stats.data_records_sent += g_netflow.record_count;
    g_netflow.stats.packets_sent++;
    g_netflow.stats.bytes_sent += sent;

    /* Reset buffer */
    g_netflow.buffer_offset = 0;
    g_netflow.record_count = 0;
    g_netflow.flowset_count = 0;

    return 0;
}

/* Initialize buffer with headers */
static void init_buffer(void)
{
    g_netflow.buffer_offset = sizeof(struct netflow9_header);

    /* Data FlowSet Header */
    struct netflow9_flowset_header *fs_hdr =
        (struct netflow9_flowset_header *)(g_netflow.buffer + g_netflow.buffer_offset);
    fs_hdr->flowset_id = htons(NF9_TEMPLATE_NAT44_SESSION);
    fs_hdr->length = 0; /* Will be filled on flush */
    g_netflow.buffer_offset += sizeof(struct netflow9_flowset_header);

    g_netflow.record_count = 0;
    g_netflow.flowset_count = 1;
}

int nat_netflow_init(uint32_t collector_ip, uint16_t collector_port, uint32_t source_id)
{
    pthread_mutex_lock(&g_netflow.lock);

    if (g_netflow.enabled) {
        pthread_mutex_unlock(&g_netflow.lock);
        return 0; /* Already initialized */
    }

    /* Create UDP socket */
    g_netflow.socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_netflow.socket_fd < 0) {
        YLOG_ERROR("Failed to create NetFlow socket: %s", strerror(errno));
        pthread_mutex_unlock(&g_netflow.lock);
        return -1;
    }

    /* Set up collector address */
    memset(&g_netflow.collector_addr, 0, sizeof(g_netflow.collector_addr));
    g_netflow.collector_addr.sin_family = AF_INET;
    g_netflow.collector_addr.sin_port = htons(collector_port);
    g_netflow.collector_addr.sin_addr.s_addr = htonl(collector_ip);

    g_netflow.source_id = source_id;
    g_netflow.boot_time = time(NULL);
    g_netflow.sequence_number = 0;
    memset(&g_netflow.stats, 0, sizeof(g_netflow.stats));

    /* Initialize buffer */
    init_buffer();

    g_netflow.enabled = true;

    pthread_mutex_unlock(&g_netflow.lock);

    /* Send initial template */
    nat_netflow_send_template();

    YLOG_INFO("NetFlow v9 exporter initialized (collector: %u.%u.%u.%u:%u, source: %u)",
              (collector_ip >> 24) & 0xFF, (collector_ip >> 16) & 0xFF, (collector_ip >> 8) & 0xFF,
              collector_ip & 0xFF, collector_port, source_id);

    return 0;
}

int nat_netflow_send_template(void)
{
    pthread_mutex_lock(&g_netflow.lock);

    if (!g_netflow.enabled) {
        pthread_mutex_unlock(&g_netflow.lock);
        return -1;
    }

    /* Flush any pending data first */
    flush_buffer();

    int ret = send_template_flowset();

    pthread_mutex_unlock(&g_netflow.lock);
    return ret;
}

int nat_netflow_log_session(uint8_t event_type, uint32_t inside_ip, uint16_t inside_port,
                            uint32_t outside_ip, uint16_t outside_port, uint32_t dest_ip,
                            uint16_t dest_port, uint8_t protocol)
{
    pthread_mutex_lock(&g_netflow.lock);

    if (!g_netflow.enabled) {
        pthread_mutex_unlock(&g_netflow.lock);
        return -1;
    }

    /* Check if template refresh needed */
    time_t now = time(NULL);
    if (now - g_netflow.last_template_time > TEMPLATE_REFRESH_INTERVAL) {
        flush_buffer();
        send_template_flowset();
        init_buffer();
    }

    /* Check buffer space */
    size_t record_size = sizeof(struct netflow9_nat44_record);
    if (g_netflow.buffer_offset + record_size > NF9_BUFFER_SIZE ||
        g_netflow.record_count >= NF9_MAX_RECORDS) {
        flush_buffer();
        init_buffer();
    }

    /* If buffer was just flushed, reinitialize */
    if (g_netflow.buffer_offset == 0) {
        init_buffer();
    }

    /* Add data record */
    struct netflow9_nat44_record *record =
        (struct netflow9_nat44_record *)(g_netflow.buffer + g_netflow.buffer_offset);

    record->observation_time = htonl((uint32_t)now);
    record->nat_event = event_type;
    record->ipv4_src_addr = htonl(inside_ip);
    record->l4_src_port = htons(inside_port);
    record->post_nat_src_addr = htonl(outside_ip);
    record->post_nat_src_port = htons(outside_port);
    record->ipv4_dst_addr = htonl(dest_ip);
    record->l4_dst_port = htons(dest_port);
    record->protocol = protocol;

    g_netflow.buffer_offset += record_size;
    g_netflow.record_count++;

    /* Update FlowSet length */
    struct netflow9_flowset_header *fs_hdr =
        (struct netflow9_flowset_header *)(g_netflow.buffer + sizeof(struct netflow9_header));
    fs_hdr->length = htons(g_netflow.buffer_offset - sizeof(struct netflow9_header));

    pthread_mutex_unlock(&g_netflow.lock);
    return 0;
}

void nat_netflow_flush(void)
{
    pthread_mutex_lock(&g_netflow.lock);

    if (g_netflow.enabled) {
        flush_buffer();
    }

    pthread_mutex_unlock(&g_netflow.lock);
}

void nat_netflow_get_stats(struct netflow9_stats *stats)
{
    if (!stats)
        return;

    pthread_mutex_lock(&g_netflow.lock);
    memcpy(stats, &g_netflow.stats, sizeof(*stats));
    pthread_mutex_unlock(&g_netflow.lock);
}

bool nat_netflow_is_enabled(void)
{
    return g_netflow.enabled;
}

void nat_netflow_cleanup(void)
{
    pthread_mutex_lock(&g_netflow.lock);

    if (g_netflow.enabled) {
        /* Flush remaining records */
        flush_buffer();

        /* Close socket */
        if (g_netflow.socket_fd >= 0) {
            close(g_netflow.socket_fd);
            g_netflow.socket_fd = -1;
        }

        g_netflow.enabled = false;
        YLOG_INFO("NetFlow v9 exporter stopped");
    }

    pthread_mutex_unlock(&g_netflow.lock);
}
