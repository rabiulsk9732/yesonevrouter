/**
 * @file nat_ipfix.c
 * @brief IPFIX NAT Event Logging Implementation (RFC 7011, RFC 8158)
 *
 * Exports NAT session create/delete events to an IPFIX collector via UDP.
 * Implements RFC 8158 NAT44 Session Logging.
 */

#include "nat_ipfix.h"
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
#define IPFIX_BUFFER_SIZE 1400 /* Stay under typical MTU */
#define IPFIX_MAX_RECORDS 50   /* Max records per packet */

/* Template refresh interval (seconds) */
#define TEMPLATE_REFRESH_INTERVAL 600 /* 10 minutes */

/* Exporter state */
static struct {
    bool enabled;
    int socket_fd;
    struct sockaddr_in collector_addr;
    uint32_t observation_domain_id;
    uint32_t sequence_number;
    time_t boot_time;
    time_t last_template_time;

    /* Send buffer */
    uint8_t buffer[IPFIX_BUFFER_SIZE];
    size_t buffer_offset;
    int record_count;

    /* Statistics */
    struct ipfix_stats stats;

    /* Thread safety */
    pthread_mutex_t lock;
} g_ipfix = {.enabled = false,
             .socket_fd = -1,
             .sequence_number = 0,
             .buffer_offset = 0,
             .record_count = 0,
             .lock = PTHREAD_MUTEX_INITIALIZER};

/* Get current time in milliseconds since epoch */
static uint64_t get_time_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* Build and send template set */
static int send_template_set(void)
{
    uint8_t packet[512];
    size_t offset = 0;

    /* IPFIX Header */
    struct ipfix_header *hdr = (struct ipfix_header *)packet;
    hdr->version = htons(IPFIX_VERSION);
    hdr->export_time = htonl((uint32_t)time(NULL));
    hdr->sequence_number = htonl(g_ipfix.sequence_number);
    hdr->observation_domain_id = htonl(g_ipfix.observation_domain_id);
    offset += sizeof(struct ipfix_header);

    /* Template Set Header */
    struct ipfix_set_header *set_hdr = (struct ipfix_set_header *)(packet + offset);
    set_hdr->set_id = htons(IPFIX_SET_TEMPLATE);
    offset += sizeof(struct ipfix_set_header);

    /* Template Header for NAT44 Session */
    struct ipfix_template_header *tmpl = (struct ipfix_template_header *)(packet + offset);
    tmpl->template_id = htons(IPFIX_TEMPLATE_NAT44_SESSION);
    tmpl->field_count = htons(9); /* 9 fields */
    offset += sizeof(struct ipfix_template_header);

    /* Field Specifiers for NAT44 Session Template */
    struct ipfix_field_specifier fields[] = {
        {htons(IPFIX_IE_OBSERVATION_TIME_MS), htons(8)},        /* 8 bytes timestamp */
        {htons(IPFIX_IE_NAT_EVENT), htons(1)},                  /* 1 byte event */
        {htons(IPFIX_IE_SOURCE_IPV4_ADDRESS), htons(4)},        /* 4 bytes inside IP */
        {htons(IPFIX_IE_SOURCE_TRANSPORT_PORT), htons(2)},      /* 2 bytes inside port */
        {htons(IPFIX_IE_POST_NAT_SOURCE_IPV4), htons(4)},       /* 4 bytes outside IP */
        {htons(IPFIX_IE_POST_NAT_SOURCE_PORT), htons(2)},       /* 2 bytes outside port */
        {htons(IPFIX_IE_DESTINATION_IPV4_ADDRESS), htons(4)},   /* 4 bytes dest IP */
        {htons(IPFIX_IE_DESTINATION_TRANSPORT_PORT), htons(2)}, /* 2 bytes dest port */
        {htons(IPFIX_IE_PROTOCOL_IDENTIFIER), htons(1)},        /* 1 byte protocol */
    };

    memcpy(packet + offset, fields, sizeof(fields));
    offset += sizeof(fields);

    /* Update Set Header length */
    set_hdr->length = htons(offset - sizeof(struct ipfix_header));

    /* Update IPFIX Header length */
    hdr->length = htons(offset);

    /* Send packet */
    ssize_t sent =
        sendto(g_ipfix.socket_fd, packet, offset, 0, (struct sockaddr *)&g_ipfix.collector_addr,
               sizeof(g_ipfix.collector_addr));

    if (sent < 0) {
        g_ipfix.stats.send_errors++;
        YLOG_ERROR("IPFIX template send failed: %s", strerror(errno));
        return -1;
    }

    g_ipfix.stats.templates_sent++;
    g_ipfix.stats.packets_sent++;
    g_ipfix.stats.bytes_sent += sent;
    g_ipfix.last_template_time = time(NULL);

    YLOG_DEBUG("IPFIX template sent (%zu bytes)", offset);
    return 0;
}

/* Flush buffered records */
static int flush_buffer(void)
{
    if (g_ipfix.record_count == 0) {
        return 0;
    }

    /* Finalize IPFIX header */
    struct ipfix_header *hdr = (struct ipfix_header *)g_ipfix.buffer;
    hdr->version = htons(IPFIX_VERSION);
    hdr->length = htons(g_ipfix.buffer_offset);
    hdr->export_time = htonl((uint32_t)time(NULL));
    hdr->sequence_number = htonl(g_ipfix.sequence_number);
    hdr->observation_domain_id = htonl(g_ipfix.observation_domain_id);

    /* Update sequence for next packet */
    g_ipfix.sequence_number += g_ipfix.record_count;

    /* Send packet */
    ssize_t sent =
        sendto(g_ipfix.socket_fd, g_ipfix.buffer, g_ipfix.buffer_offset, 0,
               (struct sockaddr *)&g_ipfix.collector_addr, sizeof(g_ipfix.collector_addr));

    if (sent < 0) {
        g_ipfix.stats.send_errors++;
        YLOG_ERROR("IPFIX data send failed: %s", strerror(errno));
        return -1;
    }

    g_ipfix.stats.data_records_sent += g_ipfix.record_count;
    g_ipfix.stats.packets_sent++;
    g_ipfix.stats.bytes_sent += sent;

    /* Reset buffer */
    g_ipfix.buffer_offset = 0;
    g_ipfix.record_count = 0;

    return 0;
}

/* Initialize buffer with headers */
static void init_buffer(void)
{
    g_ipfix.buffer_offset = sizeof(struct ipfix_header);

    /* Data Set Header */
    struct ipfix_set_header *set_hdr =
        (struct ipfix_set_header *)(g_ipfix.buffer + g_ipfix.buffer_offset);
    set_hdr->set_id = htons(IPFIX_TEMPLATE_NAT44_SESSION);
    set_hdr->length = 0; /* Will be filled on flush */
    g_ipfix.buffer_offset += sizeof(struct ipfix_set_header);

    g_ipfix.record_count = 0;
}

int nat_ipfix_init(uint32_t collector_ip, uint16_t collector_port, uint32_t observation_domain_id)
{
    pthread_mutex_lock(&g_ipfix.lock);

    if (g_ipfix.enabled) {
        pthread_mutex_unlock(&g_ipfix.lock);
        return 0; /* Already initialized */
    }

    /* Create UDP socket */
    g_ipfix.socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_ipfix.socket_fd < 0) {
        YLOG_ERROR("Failed to create IPFIX socket: %s", strerror(errno));
        pthread_mutex_unlock(&g_ipfix.lock);
        return -1;
    }

    /* Set up collector address */
    memset(&g_ipfix.collector_addr, 0, sizeof(g_ipfix.collector_addr));
    g_ipfix.collector_addr.sin_family = AF_INET;
    g_ipfix.collector_addr.sin_port = htons(collector_port);
    g_ipfix.collector_addr.sin_addr.s_addr = htonl(collector_ip);

    g_ipfix.observation_domain_id = observation_domain_id;
    g_ipfix.boot_time = time(NULL);
    g_ipfix.sequence_number = 0;
    memset(&g_ipfix.stats, 0, sizeof(g_ipfix.stats));

    /* Initialize buffer */
    init_buffer();

    g_ipfix.enabled = true;

    pthread_mutex_unlock(&g_ipfix.lock);

    /* Send initial template */
    nat_ipfix_send_template();

    YLOG_INFO("IPFIX exporter initialized (collector: %u.%u.%u.%u:%u, domain: %u)",
              (collector_ip >> 24) & 0xFF, (collector_ip >> 16) & 0xFF, (collector_ip >> 8) & 0xFF,
              collector_ip & 0xFF, collector_port, observation_domain_id);

    return 0;
}

int nat_ipfix_send_template(void)
{
    pthread_mutex_lock(&g_ipfix.lock);

    if (!g_ipfix.enabled) {
        pthread_mutex_unlock(&g_ipfix.lock);
        return -1;
    }

    /* Flush any pending data first */
    flush_buffer();

    int ret = send_template_set();

    pthread_mutex_unlock(&g_ipfix.lock);
    return ret;
}

int nat_ipfix_log_session(uint8_t event_type, uint32_t inside_ip, uint16_t inside_port,
                          uint32_t outside_ip, uint16_t outside_port, uint32_t dest_ip,
                          uint16_t dest_port, uint8_t protocol)
{
    pthread_mutex_lock(&g_ipfix.lock);

    if (!g_ipfix.enabled) {
        pthread_mutex_unlock(&g_ipfix.lock);
        return -1;
    }

    /* Check if template refresh needed */
    time_t now = time(NULL);
    if (now - g_ipfix.last_template_time > TEMPLATE_REFRESH_INTERVAL) {
        flush_buffer();
        send_template_set();
        init_buffer();
    }

    /* Check buffer space */
    size_t record_size = sizeof(struct ipfix_nat44_session_record);
    if (g_ipfix.buffer_offset + record_size > IPFIX_BUFFER_SIZE ||
        g_ipfix.record_count >= IPFIX_MAX_RECORDS) {
        flush_buffer();
        init_buffer();
    }

    /* If buffer was just flushed, reinitialize */
    if (g_ipfix.buffer_offset == 0) {
        init_buffer();
    }

    /* Add data record */
    struct ipfix_nat44_session_record *record =
        (struct ipfix_nat44_session_record *)(g_ipfix.buffer + g_ipfix.buffer_offset);

    uint64_t ts_ms = get_time_ms();

    /* Network byte order for multi-byte fields */
    record->observation_time_ms = htobe64(ts_ms);
    record->nat_event = event_type;
    record->source_ipv4 = htonl(inside_ip);
    record->source_port = htons(inside_port);
    record->post_nat_source_ipv4 = htonl(outside_ip);
    record->post_nat_source_port = htons(outside_port);
    record->destination_ipv4 = htonl(dest_ip);
    record->destination_port = htons(dest_port);
    record->protocol = protocol;

    g_ipfix.buffer_offset += record_size;
    g_ipfix.record_count++;

    /* Update Data Set Header length */
    struct ipfix_set_header *set_hdr =
        (struct ipfix_set_header *)(g_ipfix.buffer + sizeof(struct ipfix_header));
    set_hdr->length = htons(g_ipfix.buffer_offset - sizeof(struct ipfix_header));

    pthread_mutex_unlock(&g_ipfix.lock);
    return 0;
}

int nat_ipfix_log_quota_exceeded(uint32_t inside_ip)
{
    return nat_ipfix_log_session(NAT44_EVENT_QUOTA_EXCEEDED, inside_ip, 0, 0, 0, 0, 0, 0);
}

void nat_ipfix_flush(void)
{
    pthread_mutex_lock(&g_ipfix.lock);

    if (g_ipfix.enabled) {
        flush_buffer();
    }

    pthread_mutex_unlock(&g_ipfix.lock);
}

void nat_ipfix_get_stats(struct ipfix_stats *stats)
{
    if (!stats)
        return;

    pthread_mutex_lock(&g_ipfix.lock);
    memcpy(stats, &g_ipfix.stats, sizeof(*stats));
    pthread_mutex_unlock(&g_ipfix.lock);
}

bool nat_ipfix_is_enabled(void)
{
    return g_ipfix.enabled;
}

void nat_ipfix_cleanup(void)
{
    pthread_mutex_lock(&g_ipfix.lock);

    if (g_ipfix.enabled) {
        /* Flush remaining records */
        flush_buffer();

        /* Close socket */
        if (g_ipfix.socket_fd >= 0) {
            close(g_ipfix.socket_fd);
            g_ipfix.socket_fd = -1;
        }

        g_ipfix.enabled = false;
        YLOG_INFO("IPFIX exporter stopped");
    }

    pthread_mutex_unlock(&g_ipfix.lock);
}
