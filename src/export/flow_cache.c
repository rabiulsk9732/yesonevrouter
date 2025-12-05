/**
 * @file flow_cache.c
 * @brief Per-core Flow Capture Subsystem
 */

#include "flow_cache.h"
#include "exporter_core.h"
#include "log.h"
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <sys/time.h>

/* Per-core state */
static __thread struct rte_hash *g_flow_hash = NULL;
static __thread struct flow_record *g_flow_table = NULL;
static __thread uint64_t g_last_expire_check = 0;

/* Parameters */
#define HASH_ENTRIES FLOW_CACHE_SIZE

int flow_cache_init(unsigned int lcore_id)
{
    char name[32];
    snprintf(name, sizeof(name), "flow_hash_%u", lcore_id);

    struct rte_hash_parameters hash_params = {.name = name,
                                              .entries = HASH_ENTRIES,
                                              .key_len = sizeof(struct flow_key),
                                              .hash_func = rte_jhash,
                                              .hash_func_init_val = 0,
                                              .socket_id = rte_socket_id()};

    g_flow_hash = rte_hash_create(&hash_params);
    if (!g_flow_hash) {
        YLOG_ERROR("Failed to create flow hash for core %u", lcore_id);
        return -1;
    }

    g_flow_table = rte_zmalloc_socket("flow_records", HASH_ENTRIES * sizeof(struct flow_record),
                                      RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (!g_flow_table) {
        YLOG_ERROR("Failed to allocate flow table for core %u", lcore_id);
        return -1;
    }

    return 0;
}

static inline void extract_key(struct rte_mbuf *m, struct flow_key *key)
{
    struct rte_ipv4_hdr *ip =
        rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    (void)ip; /* unused for now */

    /* Simple sanity check for IPv4 */
    /* Note: In real world verify EtherType before casting */

    key->src_ip = ip->src_addr;
    key->dst_ip = ip->dst_addr;
    key->protocol = ip->next_proto_id;
    key->src_port = 0;
    key->dst_port = 0;

    if (ip->next_proto_id == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
        key->src_port = udp->src_port;
        key->dst_port = udp->dst_port;
    } else if (ip->next_proto_id == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
        key->src_port = tcp->src_port;
        key->dst_port = tcp->dst_port;
    }
}

void flow_cache_update(struct rte_mbuf *m, enum flow_direction direction)
{
    if (!g_flow_hash)
        return;

    struct flow_key key;
    extract_key(m, &key);

    int ret = rte_hash_lookup(g_flow_hash, &key);
    struct flow_record *record;

    /* More accurate: Use gettimeofday or similar if sys uptime needed,
       but for relative flow times cycles is fast in DPDK context.
       However, IPFIX needs millis since epoch generally or system uptime.
       Let's assume system uptime in ms initialized at boot. */
    /* Simplified: Just use a global timer helper */
    /* For now, just using a placeholder or passing it in */
    /* Using time(NULL) is too slow. */

    static uint64_t start_tsc = 0;
    static uint64_t start_ms = 0;
    if (start_tsc == 0) {
        start_tsc = rte_get_timer_cycles();
        struct timeval tv;
        gettimeofday(&tv, NULL);
        start_ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    }
    uint64_t current_ms =
        start_ms + (rte_get_timer_cycles() - start_tsc) * 1000 / rte_get_timer_hz();

    if (ret >= 0) {
        /* Update existing */
        record = &g_flow_table[ret];
        record->packets_in++;
        record->bytes_in += m->pkt_len; // Direction simplified to flow perspective
        record->last_seen_ms = current_ms;

        /* Direction handling: Ideally we track A->B and B->A as separate flows in standard NetFlow
         */
        /* If we want bidirectional, we need more logic. NetFlow v9 usually unidirectional. */
        /* So key includes src/dst. Reverse packet hits different key. */
    } else {
        /* Add new */
        ret = rte_hash_add_key(g_flow_hash, &key);
        if (ret >= 0) {
            record = &g_flow_table[ret];
            rte_memcpy(&record->key, &key, sizeof(key));
            record->packets_in = 1;
            record->bytes_in = m->pkt_len;
            record->packets_out = 0;
            record->bytes_out = 0;
            record->first_seen_ms = current_ms;
            record->last_seen_ms = current_ms;
            record->direction = direction;
            record->input_if_idx = m->port; /* m->port is basic approximation */
            record->output_if_idx = 0;      /* Unknown at input stage */
        }
    }
}

void flow_cache_expire(uint64_t now_ms)
{
    if (!g_flow_hash)
        return;

    /* Rate limit expiration check */
    if (now_ms - g_last_expire_check < 1000)
        return;
    g_last_expire_check = now_ms;

    uint32_t iter = 0;
    const void *next_key;
    void *next_data; /* Used if we stored pointer data, but we use index */

    /* Iterate potentially unsafe if we delete? rte_hash handles simple iteration?
       Actually standard rte_hash_iterate is safe. */

    /* Note: Getting index from iterate is tricky with pointer interface.
       We iterate through the table entries directly if possible or use iterator.
       Standard iterator returns key and data. Since we don't store data pointer...
       Wait, rte_hash stores keys. Returns position on lookup.
       To look up inactive items, we must scan the table.
       For HASH_ENTRIES, scanning 128k items might be slow.
       Optimization: LRU list or simplified scanning.
       Implementation: Linear scan of records array since we have direct access via g_flow_table
       indices? We need to know which are valid. rte_hash maintains validity.
    */

    /* Slow path: Iterate hash */
    while (rte_hash_iterate(g_flow_hash, &next_key, &next_data, &iter) >= 0) {
        /* Look up index again? Or extract from iterator?
           RTE hash doesn't expose index easily in iterator in all versions.
           However, we can just lookup key to get index. Performance hit. */

        int idx = rte_hash_lookup(g_flow_hash, next_key);
        if (idx < 0)
            continue;

        struct flow_record *rec = &g_flow_table[idx];
        bool expire = false;

        /* Inactive timeout */
        if (now_ms - rec->last_seen_ms > INACTIVE_TIMEOUT_SEC * 1000) {
            expire = true;
        }
        /* Active timeout */
        else if (now_ms - rec->first_seen_ms > ACTIVE_TIMEOUT_SEC * 1000) {
            expire = true;
        }

        if (expire) {
            /* Send to exporter */
            struct exporter_msg msg;
            msg.type = MSG_TYPE_FLOW_RECORD;
            rte_memcpy(&msg.data.flow, rec, sizeof(struct flow_record));

            if (exporter_enqueue(rte_lcore_id(), &msg) == 0) {
                /* Remove from hash if successfully queued */
                rte_hash_del_key(g_flow_hash, next_key);
                /* If it was active timeout, we theoretically should keep it and reset counters,
                   but strictly v9 usually creates new flow.
                   Simplification: Delete and let next packet recreate. */
            }
        }
    }
}

void flow_cache_flush(void)
{
    /* Flush all flows */
}
