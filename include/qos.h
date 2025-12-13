/**
 * @file qos.h
 * @brief Quality of Service (QoS) - Token Bucket Shaper, CIR/MIR, Policing
 */

#ifndef YESROUTER_QOS_H
#define YESROUTER_QOS_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Policing actions */
typedef enum {
    QOS_ACTION_PASS,        /* Packet passes */
    QOS_ACTION_DROP,        /* Drop packet */
    QOS_ACTION_MARK_YELLOW, /* Mark as yellow (excess) */
    QOS_ACTION_MARK_RED     /* Mark as red (violating) */
} qos_action_t;

/* Token bucket for single-rate */
struct token_bucket {
    uint64_t rate;          /* Rate in bytes per second */
    uint64_t burst;         /* Burst size in bytes */
    uint64_t tokens;        /* Current tokens */
    uint64_t last_update;   /* Last update timestamp (ns) */
};

/* Two-Rate Three-Color Marker (trTCM) for CIR/MIR */
struct qos_meter {
    /* Committed Information Rate */
    uint64_t cir;           /* CIR in bps */
    uint64_t cbs;           /* Committed Burst Size in bytes */
    uint64_t c_tokens;      /* Committed tokens (green) */

    /* Peak/Maximum Information Rate */
    uint64_t pir;           /* PIR/MIR in bps */
    uint64_t pbs;           /* Peak Burst Size in bytes */
    uint64_t p_tokens;      /* Peak tokens (yellow) */

    uint64_t last_update;   /* Last update timestamp (ns) */

    /* Policing action on exceed */
    qos_action_t exceed_action;  /* Action when CIR exceeded */
    qos_action_t violate_action; /* Action when PIR exceeded */
};

/* Per-session QoS profile */
struct qos_session {
    uint16_t session_id;

    /* Uplink (subscriber -> network) */
    struct qos_meter uplink;

    /* Downlink (network -> subscriber) */
    struct qos_meter downlink;

    /* Statistics */
    uint64_t green_packets;
    uint64_t yellow_packets;
    uint64_t red_packets;
    uint64_t dropped_packets;

    bool enabled;
};

/* Legacy profile (backward compat) */
struct qos_profile {
    char name[32];
    struct token_bucket uplink;
    struct token_bucket downlink;
};

/**
 * Initialize QoS subsystem
 */
int qos_init(void);

/**
 * Cleanup QoS subsystem
 */
void qos_cleanup(void);

/**
 * Initialize a token bucket
 */
void qos_tb_init(struct token_bucket *tb, uint64_t rate, uint64_t burst);

/**
 * Check if packet conforms to profile (consume tokens)
 * @return 1 if conforming (pass), 0 if non-conforming (drop/shape)
 */
int qos_tb_conform(struct token_bucket *tb, uint32_t pkt_len);

/**
 * Check if tokens available (Peek)
 */
int qos_tb_check(struct token_bucket *tb, uint32_t pkt_len);

/**
 * Consume tokens (Manual)
 */
void qos_tb_consume(struct token_bucket *tb, uint32_t pkt_len);

/**
 * Initialize a CIR/MIR meter
 * @param cir Committed Information Rate (bps)
 * @param cbs Committed Burst Size (bytes)
 * @param pir Peak/Maximum Information Rate (bps)
 * @param pbs Peak Burst Size (bytes)
 */
void qos_meter_init(struct qos_meter *meter, uint64_t cir, uint64_t cbs,
                    uint64_t pir, uint64_t pbs);

/**
 * Meter a packet using trTCM algorithm
 * @return QOS_ACTION_PASS (green), QOS_ACTION_MARK_YELLOW, QOS_ACTION_MARK_RED, or QOS_ACTION_DROP
 */
qos_action_t qos_meter_packet(struct qos_meter *meter, uint32_t pkt_len);

/**
 * Create QoS session
 */
int qos_session_create(uint16_t session_id, uint64_t cir_up, uint64_t cir_down,
                       uint64_t mir_up, uint64_t mir_down);

/**
 * Delete QoS session
 */
void qos_session_delete(uint16_t session_id);

/**
 * Apply QoS to uplink packet
 */
qos_action_t qos_apply_uplink(uint16_t session_id, uint32_t pkt_len);

/**
 * Apply QoS to downlink packet
 */
qos_action_t qos_apply_downlink(uint16_t session_id, uint32_t pkt_len);

/**
 * Update session rates (for CoA)
 */
void qos_session_update_rates(uint16_t session_id, uint64_t cir_down, uint64_t mir_down);

#endif /* YESROUTER_QOS_H */
