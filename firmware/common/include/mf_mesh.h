/*
 * meshfind -- store-and-forward gradient routing over a broadcast link
 * (ESP-NOW). Portable, allocation-free; the radio is abstracted away:
 * feed received frames to mf_mesh_on_rx() and broadcast whatever
 * mf_mesh_poll() returns. Mirrors meshfind/mesh.py; see docs/PROTOCOL.md.
 */
#ifndef MF_MESH_H
#define MF_MESH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mf_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MF_MESH_MAGIC 0x4D
#define MF_MESH_VERSION 1
#define MF_MESH_HDR_LEN 12
#define MF_MESH_MAX_FRAME 250
#define MF_T_REPORT 1
#define MF_T_BEACON 2
#define MF_T_ACK 3
#define MF_DIST_NONE 255
#define MF_DEFAULT_TTL 10
#define MF_BEACON_TTL 16
#define MF_BEACON_PAYLOAD_LEN 12

#ifndef MF_DEDUP_SLOTS
#define MF_DEDUP_SLOTS 128
#endif
#ifndef MF_QUEUE_SLOTS
#define MF_QUEUE_SLOTS 24
#endif
#ifndef MF_MAX_GATEWAYS
#define MF_MAX_GATEWAYS 4
#endif
#ifndef MF_ORIGIN_SLOTS
#define MF_ORIGIN_SLOTS 32
#endif

typedef struct {
    uint8_t type, ttl, sender_dist;
    uint8_t msg_id[8];
    const uint8_t *payload;
    size_t payload_len;
} mf_frame_t;

int mf_frame_encode(const mf_frame_t *f, uint8_t *out, size_t cap, size_t *out_len);
int mf_frame_decode(const uint8_t *in, size_t len, mf_frame_t *f); /* payload points into in */
void mf_report_msg_id(const uint8_t env[MF_ENVELOPE_LEN], uint8_t out[8]);
void mf_beacon_msg_id(uint32_t gw_id, uint32_t seq, uint8_t out[8]);
void mf_beacon_payload(uint32_t gw_id, uint32_t seq, uint32_t unix_time, uint8_t out[12]);
void mf_beacon_parse(const uint8_t in[12], uint32_t *gw_id, uint32_t *seq, uint32_t *unix_time);
bool mf_mesh_should_forward(bool is_gateway, uint8_t my_dist, uint8_t sender_dist, uint8_t ttl);

/* Dedup: ring of recent msg_ids with a lifetime (FIFO eviction). */
typedef struct {
    uint8_t id[MF_DEDUP_SLOTS][8];
    uint32_t t_ms[MF_DEDUP_SLOTS];
    uint8_t used[MF_DEDUP_SLOTS];
    uint16_t next;
    uint32_t lifetime_ms;
} mf_dedup_t;
void mf_dedup_init(mf_dedup_t *d, uint32_t lifetime_ms);
bool mf_dedup_seen(mf_dedup_t *d, const uint8_t id[8], uint32_t now_ms); /* records if new */
bool mf_dedup_contains(const mf_dedup_t *d, const uint8_t id[8], uint32_t now_ms);

/* Token bucket in milli-tokens. */
typedef struct {
    uint32_t rate_per_s, burst, milli, last_ms;
} mf_bucket_t;
void mf_bucket_init(mf_bucket_t *b, uint32_t rate_per_s, uint32_t burst);
bool mf_bucket_take(mf_bucket_t *b, uint32_t now_ms);

typedef struct {
    uint32_t tx_rate, tx_burst, max_retries, retry_ms, jitter_ms, max_hold_ms, beacon_stale_ms,
        origin_min_interval_ms, dedup_lifetime_ms;
} mf_mesh_cfg_t;
void mf_mesh_default_cfg(mf_mesh_cfg_t *c);

typedef struct {
    uint8_t frame[MF_MESH_HDR_LEN + MF_ENVELOPE_LEN];
    uint8_t len;
    uint8_t used, needs_ack, retries_left;
    uint32_t next_tx_ms, queued_ms;
} mf_pending_t;

typedef struct {
    uint32_t gw_id, seq, rx_ms;
    uint8_t dist, prev_dist, used;
} mf_route_t;

typedef void (*mf_deliver_fn)(void *ctx, const uint8_t env[MF_ENVELOPE_LEN]);
typedef uint32_t (*mf_rand_fn)(void *ctx);

typedef struct {
    uint32_t node_id;
    bool is_gateway;
    mf_mesh_cfg_t cfg;
    mf_dedup_t dedup;
    mf_bucket_t bucket;
    mf_pending_t q[MF_QUEUE_SLOTS];
    mf_route_t routes[MF_MAX_GATEWAYS];
    uint8_t origin_kh[MF_ORIGIN_SLOTS][8];
    uint32_t origin_t[MF_ORIGIN_SLOTS];
    uint8_t origin_used[MF_ORIGIN_SLOTS];
    uint16_t origin_next;
    uint32_t beacon_seq;
    bool clock_valid;
    int64_t clock_offset_ms; /* unix_ms = now_ms + offset */
    mf_deliver_fn deliver;
    void *deliver_ctx;
    mf_rand_fn rand;
    void *rand_ctx;
    struct { uint32_t tx, rx, dup, dropped_queue, dropped_ttl, rate_limited; } stats;
} mf_mesh_node_t;

void mf_mesh_init(mf_mesh_node_t *n, uint32_t node_id, bool is_gateway, const mf_mesh_cfg_t *cfg,
                  mf_rand_fn rnd, void *rnd_ctx, mf_deliver_fn deliver, void *deliver_ctx);
uint8_t mf_mesh_dist(const mf_mesh_node_t *n, uint32_t now_ms);
/* Returns false if rate-limited for this tag key or the queue is unusable. */
bool mf_mesh_originate(mf_mesh_node_t *n, const uint8_t env[MF_ENVELOPE_LEN], uint32_t now_ms);
void mf_mesh_emit_beacon(mf_mesh_node_t *n, uint32_t unix_time, uint32_t now_ms);
void mf_mesh_on_rx(mf_mesh_node_t *n, const uint8_t *raw, size_t len, uint32_t now_ms);
/* Fills out (>= 120 bytes) with the next frame to broadcast; returns its length or 0. */
size_t mf_mesh_poll(mf_mesh_node_t *n, uint32_t now_ms, uint8_t *out, size_t cap);
bool mf_mesh_unix_time(const mf_mesh_node_t *n, uint32_t now_ms, uint32_t *unix_time);

#ifdef __cplusplus
}
#endif
#endif /* MF_MESH_H */
