/**
 * @file reassembly.c
 * @brief IP Packet Reassembly Implementation (RFC 791)
 */

#include "reassembly.h"
#include "packet.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_DPDK
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#endif

/* Global reassembly table */
static struct fragment_entry *g_reassembly_table[REASSEMBLY_TABLE_SIZE];
static struct reassembly_stats g_stats = {0};

/**
 * @brief Hash function for fragment identification
 */
static uint32_t fragment_hash(uint32_t src_ip, uint32_t dst_ip,
                              uint8_t protocol, uint16_t id)
{
    uint32_t hash = src_ip ^ dst_ip ^ ((uint32_t)protocol << 16) ^ id;
    return hash % REASSEMBLY_TABLE_SIZE;
}

/**
 * @brief Find fragment entry
 */
static struct fragment_entry *find_entry(uint32_t src_ip, uint32_t dst_ip,
                                         uint8_t protocol, uint16_t id)
{
    uint32_t hash = fragment_hash(src_ip, dst_ip, protocol, id);
    struct fragment_entry *entry = g_reassembly_table[hash];

    while (entry) {
        if (entry->src_ip == src_ip &&
            entry->dst_ip == dst_ip &&
            entry->protocol == protocol &&
            entry->id == id) {
            return entry;
        }
        entry = entry->next;
    }

    return NULL;
}

/**
 * @brief Create new fragment entry
 */
static struct fragment_entry *create_entry(uint32_t src_ip, uint32_t dst_ip,
                                           uint8_t protocol, uint16_t id)
{
    if (g_stats.current_entries >= REASSEMBLY_MAX_ENTRIES) {
        YLOG_ERROR("Reassembly table full");
        return NULL;
    }

    struct fragment_entry *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        return NULL;
    }

    entry->src_ip = src_ip;
    entry->dst_ip = dst_ip;
    entry->protocol = protocol;
    entry->id = id;
    entry->created = time(NULL);
    entry->last_update = time(NULL);

    /* Allocate maximum size buffer */
    entry->buffer = malloc(MAX_FRAGMENT_SIZE);
    if (!entry->buffer) {
        free(entry);
        return NULL;
    }
    entry->buffer_size = MAX_FRAGMENT_SIZE;

    /* Allocate bitmap (1 bit per 8 bytes = 8192 bits max) */
    entry->bitmap = calloc(8192 / 8, 1);
    if (!entry->bitmap) {
        free(entry->buffer);
        free(entry);
        return NULL;
    }
    entry->bitmap_size = 8192 / 8;

    /* Add to hash table */
    uint32_t hash = fragment_hash(src_ip, dst_ip, protocol, id);
    entry->next = g_reassembly_table[hash];
    g_reassembly_table[hash] = entry;

    g_stats.current_entries++;
    return entry;
}

/**
 * @brief Delete fragment entry
 */
static void delete_entry(struct fragment_entry *entry)
{
    if (!entry) return;

    uint32_t hash = fragment_hash(entry->src_ip, entry->dst_ip,
                                  entry->protocol, entry->id);

    struct fragment_entry **ptr = &g_reassembly_table[hash];
    while (*ptr) {
        if (*ptr == entry) {
            *ptr = entry->next;
            break;
        }
        ptr = &(*ptr)->next;
    }

    if (entry->buffer) free(entry->buffer);
    if (entry->bitmap) free(entry->bitmap);
    free(entry);

    g_stats.current_entries--;
}

/**
 * @brief Set bits in bitmap for fragment
 */
static void set_bitmap_bits(struct fragment_entry *entry, uint16_t offset,
                            uint16_t length)
{
    /* offset and length are in bytes, bitmap is in 8-byte units */
    uint16_t start_bit = offset / 8;
    uint16_t end_bit = (offset + length + 7) / 8;

    for (uint16_t bit = start_bit; bit < end_bit; bit++) {
        uint16_t byte_idx = bit / 8;
        uint8_t bit_idx = bit % 8;
        if (byte_idx < entry->bitmap_size) {
            entry->bitmap[byte_idx] |= (1 << bit_idx);
        }
    }
}

/**
 * @brief Check if all fragments received
 */
static bool is_complete(struct fragment_entry *entry)
{
    if (!entry->have_last_fragment) {
        return false;
    }

    /* Check if all bits from 0 to total_length are set */
    uint16_t total_bits = (entry->total_length + 7) / 8;

    for (uint16_t bit = 0; bit < total_bits; bit++) {
        uint16_t byte_idx = bit / 8;
        uint8_t bit_idx = bit % 8;
        if (byte_idx >= entry->bitmap_size) {
            return false;
        }
        if (!(entry->bitmap[byte_idx] & (1 << bit_idx))) {
            return false;
        }
    }

    return true;
}

/**
 * @brief Initialize reassembly subsystem
 */
int ip_reassembly_init(void)
{
    memset(g_reassembly_table, 0, sizeof(g_reassembly_table));
    memset(&g_stats, 0, sizeof(g_stats));
    printf("IP Reassembly subsystem initialized\n");
    return 0;
}

#ifdef HAVE_DPDK

/**
 * @brief Process received IP fragment
 */
int ip_reassembly_process(struct pkt_buf *pkt, struct pkt_buf **reassembled)
{
    if (!pkt || !reassembled) {
        return -1;
    }

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pkt->data + pkt->meta.l3_offset);

    /* Get fragment info */
    uint16_t frag_offset_be = ip->fragment_offset;
    uint16_t frag_info = rte_be_to_cpu_16(frag_offset_be);
    bool more_fragments = (frag_info & RTE_IPV4_HDR_MF_FLAG) != 0;
    uint16_t offset = (frag_info & RTE_IPV4_HDR_OFFSET_MASK) * 8;  /* In bytes */

    /* Check if this is a fragment */
    if (offset == 0 && !more_fragments) {
        /* Not fragmented */
        *reassembled = pkt;
        return 1;
    }

    g_stats.fragments_received++;

    /* Extract fragment identification */
    uint32_t src_ip = ip->src_addr;
    uint32_t dst_ip = ip->dst_addr;
    uint8_t protocol = ip->next_proto_id;
    uint16_t id = rte_be_to_cpu_16(ip->packet_id);

    /* Find or create entry */
    struct fragment_entry *entry = find_entry(src_ip, dst_ip, protocol, id);
    if (!entry) {
        entry = create_entry(src_ip, dst_ip, protocol, id);
        if (!entry) {
            YLOG_ERROR("Failed to create reassembly entry");
            g_stats.reassembly_failures++;
            return -1;
        }
    }

    entry->last_update = time(NULL);

    /* Calculate payload offset and length */
    uint8_t ip_hdr_len = (ip->version_ihl & 0x0F) * 4;
    uint16_t total_len = rte_be_to_cpu_16(ip->total_length);
    uint16_t payload_len = total_len - ip_hdr_len;
    uint8_t *payload = (uint8_t *)ip + ip_hdr_len;

    /* Copy fragment data to buffer */
    if (offset + payload_len > entry->buffer_size) {
        YLOG_ERROR("Fragment offset exceeds buffer size");
        delete_entry(entry);
        g_stats.reassembly_failures++;
        return -1;
    }

    memcpy(entry->buffer + offset, payload, payload_len);
    entry->received_bytes += payload_len;

    /* Mark bits as received */
    set_bitmap_bits(entry, offset, payload_len);

    /* If this is the last fragment, record total length */
    if (!more_fragments) {
        entry->have_last_fragment = true;
        entry->total_length = offset + payload_len;
    }

    /* Check if reassembly is complete */
    if (is_complete(entry)) {
        /* Reassemble packet */
        struct pkt_buf *new_pkt = pkt_alloc();
        if (!new_pkt) {
            delete_entry(entry);
            g_stats.reassembly_failures++;
            return -1;
        }

        /* Build complete IP packet */
        struct rte_ether_hdr *orig_eth = (struct rte_ether_hdr *)(pkt->data);
        struct rte_ether_hdr *new_eth = (struct rte_ether_hdr *)new_pkt->data;
        memcpy(new_eth, orig_eth, sizeof(struct rte_ether_hdr));

        struct rte_ipv4_hdr *new_ip = (struct rte_ipv4_hdr *)(new_pkt->data + sizeof(struct rte_ether_hdr));
        memcpy(new_ip, ip, ip_hdr_len);

        /* Update fields */
        new_ip->total_length = rte_cpu_to_be_16(ip_hdr_len + entry->total_length);
        new_ip->fragment_offset = 0;  /* No fragmentation */
        new_ip->hdr_checksum = 0;
        new_ip->hdr_checksum = rte_ipv4_cksum(new_ip);

        /* Copy reassembled payload */
        memcpy(new_pkt->data + sizeof(struct rte_ether_hdr) + ip_hdr_len,
               entry->buffer, entry->total_length);

        new_pkt->len = sizeof(struct rte_ether_hdr) + ip_hdr_len + entry->total_length;

        /* Update metadata */
        new_pkt->meta.l2_offset = 0;
        new_pkt->meta.l3_offset = sizeof(struct rte_ether_hdr);

        *reassembled = new_pkt;

        YLOG_INFO("Packet reassembled: %u bytes from %u fragments",
                  entry->total_length, entry->received_bytes / 256);

        g_stats.packets_reassembled++;
        delete_entry(entry);

        return 1;  /* Complete */
    }

    return 0;  /* Waiting for more fragments */
}

#else /* !HAVE_DPDK */

int ip_reassembly_process(struct pkt_buf *pkt, struct pkt_buf **reassembled)
{
    /* Without DPDK, just pass through */
    *reassembled = pkt;
    return 1;
}

#endif /* HAVE_DPDK */

/**
 * @brief Timeout old fragments
 */
uint32_t ip_reassembly_timeout(void)
{
    uint32_t timed_out = 0;
    time_t now = time(NULL);

    for (int i = 0; i < REASSEMBLY_TABLE_SIZE; i++) {
        struct fragment_entry **ptr = &g_reassembly_table[i];
        while (*ptr) {
            struct fragment_entry *entry = *ptr;
            if (now - entry->created >= REASSEMBLY_TIMEOUT) {
                YLOG_INFO("Fragment entry timed out (ID=%u)", entry->id);
                *ptr = entry->next;
                if (entry->buffer) free(entry->buffer);
                if (entry->bitmap) free(entry->bitmap);
                free(entry);
                g_stats.current_entries--;
                g_stats.reassembly_timeouts++;
                timed_out++;
            } else {
                ptr = &entry->next;
            }
        }
    }

    return timed_out;
}

/**
 * @brief Get reassembly statistics
 */
void ip_reassembly_get_stats(struct reassembly_stats *stats)
{
    if (stats) {
        memcpy(stats, &g_stats, sizeof(g_stats));
    }
}

/**
 * @brief Cleanup reassembly subsystem
 */
void ip_reassembly_cleanup(void)
{
    for (int i = 0; i < REASSEMBLY_TABLE_SIZE; i++) {
        struct fragment_entry *entry = g_reassembly_table[i];
        while (entry) {
            struct fragment_entry *next = entry->next;
            if (entry->buffer) free(entry->buffer);
            if (entry->bitmap) free(entry->bitmap);
            free(entry);
            entry = next;
        }
        g_reassembly_table[i] = NULL;
    }
    g_stats.current_entries = 0;
    printf("IP Reassembly subsystem cleaned up\n");
}
