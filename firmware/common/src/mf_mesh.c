/* meshfind -- mesh routing core. See mf_mesh.h; mirrors meshfind/mesh.py. */
#include "mf_mesh.h"

#include <string.h>

#include "mf_crypto.h"

/* wrap-safe "a is at or after b" for uint32 millisecond clocks */
#define AFTER_EQ(a, b) ((int32_t)((a) - (b)) >= 0)

/* ------------------------------------------------------------------- codec */

int mf_frame_encode(const mf_frame_t *f, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t n = MF_MESH_HDR_LEN + f->payload_len;
    if (n > MF_MESH_MAX_FRAME || n > cap) return MF_ERR_ARG;
    out[0] = MF_MESH_MAGIC;
    out[1] = (uint8_t)((MF_MESH_VERSION << 4) | (f->type & 0x0F));
    out[2] = f->ttl;
    out[3] = f->sender_dist;
    memcpy(out + 4, f->msg_id, 8);
    if (f->payload_len) memcpy(out + MF_MESH_HDR_LEN, f->payload, f->payload_len);
    *out_len = n;
    return MF_OK;
}

int mf_frame_decode(const uint8_t *in, size_t len, mf_frame_t *f)
{
    if (len < MF_MESH_HDR_LEN || len > MF_MESH_MAX_FRAME) return MF_ERR_FORMAT;
    if (in[0] != MF_MESH_MAGIC || (in[1] >> 4) != MF_MESH_VERSION) return MF_ERR_FORMAT;
    f->type = in[1] & 0x0F;
    f->ttl = in[2];
    f->sender_dist = in[3];
    memcpy(f->msg_id, in + 4, 8);
    f->payload = in + MF_MESH_HDR_LEN;
    f->payload_len = len - MF_MESH_HDR_LEN;
    switch (f->type) {
    case MF_T_REPORT: return f->payload_len == MF_ENVELOPE_LEN ? MF_OK : MF_ERR_FORMAT;
    case MF_T_BEACON: return f->payload_len == MF_BEACON_PAYLOAD_LEN ? MF_OK : MF_ERR_FORMAT;
    case MF_T_ACK: return f->payload_len == 0 ? MF_OK : MF_ERR_FORMAT;
    default: return MF_ERR_FORMAT;
    }
}

void mf_report_msg_id(const uint8_t env[MF_ENVELOPE_LEN], uint8_t out[8])
{
    uint8_t h[32];
    mf_sha256(env, MF_ENVELOPE_LEN, h);
    memcpy(out, h, 8);
}

static void put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

void mf_beacon_msg_id(uint32_t gw_id, uint32_t seq, uint8_t out[8])
{
    uint8_t m[11] = {'b', 'c', 'n'}, h[32];
    put32(m + 3, gw_id);
    put32(m + 7, seq);
    mf_sha256(m, sizeof m, h);
    memcpy(out, h, 8);
}

void mf_beacon_payload(uint32_t gw_id, uint32_t seq, uint32_t unix_time, uint8_t out[12])
{
    put32(out, gw_id);
    put32(out + 4, seq);
    put32(out + 8, unix_time);
}

void mf_beacon_parse(const uint8_t in[12], uint32_t *gw_id, uint32_t *seq, uint32_t *unix_time)
{
    *gw_id = get32(in);
    *seq = get32(in + 4);
    *unix_time = get32(in + 8);
}

bool mf_mesh_should_forward(bool is_gateway, uint8_t my_dist, uint8_t sender_dist, uint8_t ttl)
{
    if (is_gateway || ttl <= 1) return false;
    if (my_dist == MF_DIST_NONE) return sender_dist == MF_DIST_NONE;
    return my_dist < sender_dist;
}

/* ------------------------------------------------------------ dedup/bucket */

void mf_dedup_init(mf_dedup_t *d, uint32_t lifetime_ms)
{
    memset(d, 0, sizeof *d);
    d->lifetime_ms = lifetime_ms;
}

bool mf_dedup_contains(const mf_dedup_t *d, const uint8_t id[8], uint32_t now_ms)
{
    for (int i = 0; i < MF_DEDUP_SLOTS; i++)
        if (d->used[i] && memcmp(d->id[i], id, 8) == 0 && (uint32_t)(now_ms - d->t_ms[i]) < d->lifetime_ms)
            return true;
    return false;
}

bool mf_dedup_seen(mf_dedup_t *d, const uint8_t id[8], uint32_t now_ms)
{
    if (mf_dedup_contains(d, id, now_ms)) return true;
    memcpy(d->id[d->next], id, 8);
    d->t_ms[d->next] = now_ms;
    d->used[d->next] = 1;
    d->next = (uint16_t)((d->next + 1) % MF_DEDUP_SLOTS);
    return false;
}

void mf_bucket_init(mf_bucket_t *b, uint32_t rate_per_s, uint32_t burst)
{
    b->rate_per_s = rate_per_s;
    b->burst = burst;
    b->milli = burst * 1000;
    b->last_ms = 0;
}

bool mf_bucket_take(mf_bucket_t *b, uint32_t now_ms)
{
    uint64_t add = (uint64_t)(uint32_t)(now_ms - b->last_ms) * b->rate_per_s; /* milli-tokens */
    uint64_t m = b->milli + add;
    if (m > (uint64_t)b->burst * 1000) m = (uint64_t)b->burst * 1000;
    b->milli = (uint32_t)m;
    b->last_ms = now_ms;
    if (b->milli >= 1000) {
        b->milli -= 1000;
        return true;
    }
    return false;
}

/* --------------------------------------------------------------------- node */

void mf_mesh_default_cfg(mf_mesh_cfg_t *c)
{
    c->tx_rate = 20;
    c->tx_burst = 20;
    c->max_retries = 5;
    c->retry_ms = 600;
    c->jitter_ms = 150;
    c->max_hold_ms = 3600u * 1000u;
    c->beacon_stale_ms = 35000;
    c->origin_min_interval_ms = 300u * 1000u;
    c->dedup_lifetime_ms = 600u * 1000u;
}

void mf_mesh_init(mf_mesh_node_t *n, uint32_t node_id, bool is_gateway, const mf_mesh_cfg_t *cfg,
                  mf_rand_fn rnd, void *rnd_ctx, mf_deliver_fn deliver, void *deliver_ctx)
{
    memset(n, 0, sizeof *n);
    n->node_id = node_id;
    n->is_gateway = is_gateway;
    if (cfg) n->cfg = *cfg;
    else mf_mesh_default_cfg(&n->cfg);
    mf_dedup_init(&n->dedup, n->cfg.dedup_lifetime_ms);
    mf_bucket_init(&n->bucket, n->cfg.tx_rate, n->cfg.tx_burst);
    n->rand = rnd;
    n->rand_ctx = rnd_ctx;
    n->deliver = deliver;
    n->deliver_ctx = deliver_ctx;
}

uint8_t mf_mesh_dist(const mf_mesh_node_t *n, uint32_t now_ms)
{
    uint8_t best = MF_DIST_NONE;
    if (n->is_gateway) return 0;
    for (int i = 0; i < MF_MAX_GATEWAYS; i++) {
        const mf_route_t *r = &n->routes[i];
        uint8_t d;
        if (!r->used || (uint32_t)(now_ms - r->rx_ms) > n->cfg.beacon_stale_ms) continue;
        d = r->dist < r->prev_dist ? r->dist : r->prev_dist;
        if (d < best) best = d;
    }
    return best;
}

static uint32_t jitter(mf_mesh_node_t *n)
{
    return (n->rand && n->cfg.jitter_ms) ? n->rand(n->rand_ctx) % (n->cfg.jitter_ms + 1) : 0;
}

static void enqueue(mf_mesh_node_t *n, const mf_frame_t *f, uint32_t now_ms, bool needs_ack, bool immediate)
{
    int slot = -1, oldest = 0;
    size_t len;
    for (int i = 0; i < MF_QUEUE_SLOTS; i++) {
        if (!n->q[i].used) { slot = i; break; }
        if (!AFTER_EQ(n->q[i].queued_ms, n->q[oldest].queued_ms)) oldest = i;
    }
    if (slot < 0) {
        slot = oldest;
        n->stats.dropped_queue++;
    }
    mf_pending_t *p = &n->q[slot];
    if (mf_frame_encode(f, p->frame, sizeof p->frame, &len) != MF_OK) {
        p->used = 0;
        return;
    }
    p->len = (uint8_t)len;
    p->used = 1;
    p->needs_ack = needs_ack;
    p->retries_left = (uint8_t)(needs_ack ? n->cfg.max_retries : 1);
    p->queued_ms = now_ms;
    p->next_tx_ms = now_ms + (immediate ? 0 : jitter(n));
}

static void ack(mf_mesh_node_t *n, const uint8_t id[8])
{
    for (int i = 0; i < MF_QUEUE_SLOTS; i++)
        if (n->q[i].used && n->q[i].needs_ack && memcmp(n->q[i].frame + 4, id, 8) == 0) n->q[i].used = 0;
}

static void send_ack(mf_mesh_node_t *n, const uint8_t id[8], uint32_t now_ms)
{
    mf_frame_t a = {MF_T_ACK, 1, 0, {0}, NULL, 0};
    memcpy(a.msg_id, id, 8);
    enqueue(n, &a, now_ms, false, true);
}

bool mf_mesh_originate(mf_mesh_node_t *n, const uint8_t env[MF_ENVELOPE_LEN], uint32_t now_ms)
{
    mf_frame_t f;
    int slot = -1;
    for (int i = 0; i < MF_ORIGIN_SLOTS; i++) {
        if (n->origin_used[i] && memcmp(n->origin_kh[i], env + 2, 8) == 0) {
            if ((uint32_t)(now_ms - n->origin_t[i]) < n->cfg.origin_min_interval_ms) {
                n->stats.rate_limited++;
                return false;
            }
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        slot = n->origin_next;
        n->origin_next = (uint16_t)((n->origin_next + 1) % MF_ORIGIN_SLOTS);
        memcpy(n->origin_kh[slot], env + 2, 8);
        n->origin_used[slot] = 1;
    }
    n->origin_t[slot] = now_ms;
    mf_report_msg_id(env, f.msg_id);
    mf_dedup_seen(&n->dedup, f.msg_id, now_ms);
    if (n->is_gateway) {
        if (n->deliver) n->deliver(n->deliver_ctx, env);
        return true;
    }
    f.type = MF_T_REPORT;
    f.ttl = MF_DEFAULT_TTL;
    f.sender_dist = MF_DIST_NONE;
    f.payload = env;
    f.payload_len = MF_ENVELOPE_LEN;
    enqueue(n, &f, now_ms, true, false);
    return true;
}

void mf_mesh_emit_beacon(mf_mesh_node_t *n, uint32_t unix_time, uint32_t now_ms)
{
    uint8_t pl[MF_BEACON_PAYLOAD_LEN];
    mf_frame_t f = {MF_T_BEACON, MF_BEACON_TTL, 0, {0}, pl, sizeof pl};
    n->beacon_seq++;
    mf_beacon_payload(n->node_id, n->beacon_seq, unix_time, pl);
    mf_beacon_msg_id(n->node_id, n->beacon_seq, f.msg_id);
    enqueue(n, &f, now_ms, false, true);
}

static void on_beacon(mf_mesh_node_t *n, const mf_frame_t *f, uint32_t now_ms)
{
    uint32_t gw, seq, ut;
    mf_route_t *r = NULL;
    uint8_t cand;
    if (n->is_gateway) return;
    mf_beacon_parse(f->payload, &gw, &seq, &ut);
    cand = f->sender_dist >= MF_DIST_NONE - 1 ? MF_DIST_NONE - 1 : (uint8_t)(f->sender_dist + 1);
    for (int i = 0; i < MF_MAX_GATEWAYS && !r; i++)
        if (n->routes[i].used && n->routes[i].gw_id == gw) r = &n->routes[i];
    if (!r) { /* new gateway: free slot or the least recently refreshed one */
        int victim = 0;
        for (int i = 0; i < MF_MAX_GATEWAYS; i++) {
            if (!n->routes[i].used) { victim = i; break; }
            if (!AFTER_EQ(n->routes[i].rx_ms, n->routes[victim].rx_ms)) victim = i;
        }
        r = &n->routes[victim];
        r->used = 1;
        r->gw_id = gw;
        r->seq = seq;
        r->dist = cand;
        r->prev_dist = MF_DIST_NONE;
    } else if (seq > r->seq) {
        r->prev_dist = (seq == r->seq + 1) ? r->dist : MF_DIST_NONE;
        r->seq = seq;
        r->dist = cand;
    } else if (seq == r->seq && cand < r->dist) {
        r->dist = cand;
    } else {
        return; /* old or not better: do not rebroadcast */
    }
    r->rx_ms = now_ms;
    if (ut != 0) { /* 0 = gateway has no wall-clock time yet */
        n->clock_valid = true;
        n->clock_offset_ms = (int64_t)ut * 1000 - (int64_t)now_ms;
    }
    if (f->ttl > 1) {
        mf_frame_t fw = *f;
        fw.ttl = (uint8_t)(f->ttl - 1);
        fw.sender_dist = cand;
        enqueue(n, &fw, now_ms, false, false);
    }
}

void mf_mesh_on_rx(mf_mesh_node_t *n, const uint8_t *raw, size_t len, uint32_t now_ms)
{
    mf_frame_t f;
    uint8_t my;
    if (mf_frame_decode(raw, len, &f) != MF_OK) return;
    n->stats.rx++;
    my = mf_mesh_dist(n, now_ms);
    if (f.type == MF_T_BEACON) {
        on_beacon(n, &f, now_ms);
        return;
    }
    if (f.type == MF_T_ACK) {
        ack(n, f.msg_id);
        return;
    }
    /* REPORT */
    if (f.sender_dist < my) ack(n, f.msg_id); /* passive ack: a closer node carried it */
    if (mf_dedup_seen(&n->dedup, f.msg_id, now_ms)) {
        n->stats.dup++;
        if (n->is_gateway) send_ack(n, f.msg_id, now_ms);
        return;
    }
    if (n->is_gateway) {
        if (n->deliver) n->deliver(n->deliver_ctx, f.payload);
        send_ack(n, f.msg_id, now_ms);
        return;
    }
    if (f.ttl <= 1) {
        n->stats.dropped_ttl++;
        return;
    }
    if (mf_mesh_should_forward(false, my, f.sender_dist, f.ttl)) {
        mf_frame_t fw = f;
        fw.ttl = (uint8_t)(f.ttl - 1);
        fw.sender_dist = MF_DIST_NONE; /* filled in at transmit time */
        enqueue(n, &fw, now_ms, true, false);
    }
}

size_t mf_mesh_poll(mf_mesh_node_t *n, uint32_t now_ms, uint8_t *out, size_t cap)
{
    uint8_t my = mf_mesh_dist(n, now_ms);
    int pick = -1;
    for (int i = 0; i < MF_QUEUE_SLOTS; i++) {
        mf_pending_t *p = &n->q[i];
        if (!p->used) continue;
        if ((uint32_t)(now_ms - p->queued_ms) > n->cfg.max_hold_ms) {
            p->used = 0;
            continue;
        }
        if (!AFTER_EQ(now_ms, p->next_tx_ms)) continue;
        if ((p->frame[1] & 0x0F) == MF_T_REPORT && my == MF_DIST_NONE) continue; /* store */
        if (pick < 0 || !AFTER_EQ(p->queued_ms, n->q[pick].queued_ms)) pick = i;
    }
    if (pick < 0 || cap < n->q[pick].len) return 0;
    if (!mf_bucket_take(&n->bucket, now_ms)) return 0;
    mf_pending_t *p = &n->q[pick];
    memcpy(out, p->frame, p->len);
    if ((p->frame[1] & 0x0F) == MF_T_REPORT) out[3] = my;
    n->stats.tx++;
    if (--p->retries_left == 0) {
        p->used = 0;
    } else {
        uint32_t r = n->rand ? n->rand(n->rand_ctx) % (n->cfg.retry_ms + 1) : 0;
        p->next_tx_ms = now_ms + n->cfg.retry_ms + r;
    }
    return p->len;
}

bool mf_mesh_unix_time(const mf_mesh_node_t *n, uint32_t now_ms, uint32_t *unix_time)
{
    if (!n->clock_valid) return false;
    *unix_time = (uint32_t)(((int64_t)now_ms + n->clock_offset_ms) / 1000);
    return true;
}
