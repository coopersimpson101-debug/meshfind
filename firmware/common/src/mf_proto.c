/* meshfind -- portable protocol layer. See mf_proto.h and docs/PROTOCOL.md. */
#include "mf_proto.h"

#include <string.h>

#include "mf_crypto.h"

#define INFO(s) (const uint8_t *)(s), (sizeof(s) - 1)

/* ------------------------------------------------------------------ ratchet */

void mf_chain_init(const uint8_t master[32], bool separated, uint8_t out[32])
{
    if (separated)
        mf_hkdf_sha256(master, 32, NULL, 0, INFO("meshfind/v1/sep-chain-init"), out, 32);
    else
        mf_hkdf_sha256(master, 32, NULL, 0, INFO("meshfind/v1/chain-init"), out, 32);
}

void mf_chain_step(const uint8_t sk[32], uint8_t out[32])
{
    uint8_t tmp[32];
    mf_hkdf_sha256(sk, 32, NULL, 0, INFO("meshfind/v1/chain-step"), tmp, 32);
    memcpy(out, tmp, 32);
    mf_wipe(tmp, sizeof tmp);
}

void mf_epoch_private(const uint8_t sk[32], uint8_t priv[32])
{
    mf_hkdf_sha256(sk, 32, NULL, 0, INFO("meshfind/v1/epoch-priv"), priv, 32);
    mf_x25519_clamp(priv);
}

int mf_epoch_public(const uint8_t sk[32], uint8_t pub[32])
{
    uint8_t priv[32];
    int rc;
    mf_epoch_private(sk, priv);
    rc = mf_x25519_base(pub, priv);
    mf_wipe(priv, sizeof priv);
    return rc == 0 ? MF_OK : MF_ERR_KEY;
}

void mf_key_hash(const uint8_t pub[32], uint8_t out[32]) { mf_sha256(pub, 32, out); }

void mf_presence_key(const uint8_t master[32], uint8_t out[32])
{
    mf_hkdf_sha256(master, 32, NULL, 0, INFO("meshfind/v1/presence"), out, 32);
}

void mf_presence_token(const uint8_t pkey[32], uint32_t epoch, uint8_t out[16])
{
    uint8_t msg[12] = {'p', 'r', 'e', 's', 'e', 'n', 'c', 'e'}, mac[32];
    msg[8] = (uint8_t)epoch;
    msg[9] = (uint8_t)(epoch >> 8);
    msg[10] = (uint8_t)(epoch >> 16);
    msg[11] = (uint8_t)(epoch >> 24);
    mf_hmac_sha256(pkey, 32, msg, sizeof msg, mac);
    memcpy(out, mac, 16);
    mf_wipe(mac, sizeof mac);
}

void mf_presence_encode(const uint8_t token[16], uint8_t out[MF_PRESENCE_ADV_LEN])
{
    out[0] = 0x14;
    out[1] = 0xFF;
    out[2] = MF_COMPANY_ID & 0xFF;
    out[3] = MF_COMPANY_ID >> 8;
    out[4] = 0x50;
    memcpy(out + 5, token, 16);
}

int mf_presence_find(const uint8_t pkey[32], const uint8_t *d, size_t len, uint32_t cur, uint32_t window,
                     uint32_t *epoch)
{
    size_t i = 0;
    while (i + 1 < len) {
        size_t l = d[i];
        if (l == 0 || i + 1 + l > len) break;
        if (l == 0x14 && d[i + 1] == 0xFF && d[i + 2] == 0xFF && d[i + 3] == 0xFF && d[i + 4] == 0x50) {
            uint32_t lo = cur > window ? cur - window : 0;
            for (uint32_t e = lo; e <= cur + window; e++) {
                uint8_t tok[16];
                mf_presence_token(pkey, e, tok);
                if (mf_ct_memcmp(tok, d + i + 5, 16) == 0) {
                    *epoch = e;
                    return MF_OK;
                }
            }
        }
        i += 1 + l;
    }
    return MF_ERR_AUTH;
}

int mf_epoch_index(uint32_t t, uint32_t epoch0, uint32_t seconds, uint32_t *index)
{
    if (t < epoch0 || seconds == 0) return MF_ERR_TIME;
    *index = (t - epoch0) / seconds;
    return MF_OK;
}

void mf_tag_init(mf_tag_state_t *st, const uint8_t sk0[32], const uint8_t sep_sk0[32],
                 const uint8_t presence_key[32], uint32_t epoch0, uint32_t epoch_seconds)
{
    memcpy(st->sk, sk0, 32);
    memcpy(st->sep_sk, sep_sk0, 32);
    memcpy(st->presence_key, presence_key, 32);
    st->index = 0;
    st->sep_index = 0;
    st->epoch0 = epoch0;
    st->epoch_seconds = epoch_seconds ? epoch_seconds : MF_EPOCH_SECONDS;
}

void mf_tag_provision(mf_tag_state_t *st, const uint8_t master[32], uint32_t epoch0, uint32_t epoch_seconds)
{
    uint8_t a[32], b[32], c[32];
    mf_chain_init(master, false, a);
    mf_chain_init(master, true, b);
    mf_presence_key(master, c);
    mf_tag_init(st, a, b, c, epoch0, epoch_seconds);
    mf_wipe(a, 32);
    mf_wipe(b, 32);
    mf_wipe(c, 32);
}

int mf_tag_advance(mf_tag_state_t *st, uint32_t index)
{
    if (index < st->index) return MF_ERR_ARG;
    while (st->index < index) {
        mf_chain_step(st->sk, st->sk);
        st->index++;
    }
    return MF_OK;
}

int mf_tag_advance_sep(mf_tag_state_t *st, uint32_t day)
{
    if (day < st->sep_index) return MF_ERR_ARG;
    while (st->sep_index < day) {
        mf_chain_step(st->sep_sk, st->sep_sk);
        st->sep_index++;
    }
    return MF_OK;
}

int mf_tag_current_public(mf_tag_state_t *st, uint32_t now, bool separated, uint8_t pub[32])
{
    uint32_t idx;
    int rc;
    if (separated) {
        if ((rc = mf_epoch_index(now, st->epoch0, MF_DAY_SECONDS, &idx)) != MF_OK) return rc;
        if ((rc = mf_tag_advance_sep(st, idx)) != MF_OK) return rc;
        return mf_epoch_public(st->sep_sk, pub);
    }
    if ((rc = mf_epoch_index(now, st->epoch0, st->epoch_seconds, &idx)) != MF_OK) return rc;
    if ((rc = mf_tag_advance(st, idx)) != MF_OK) return rc;
    return mf_epoch_public(st->sk, pub);
}

/* ------------------------------------------------------------ advertisement */

uint8_t mf_adv_status_bits(const mf_adv_t *a)
{
    return (uint8_t)(((a->battery & 3) << 4) | ((a->separated ? 1 : 0) << 3) | MF_PROTO_VERSION);
}

int mf_adv_encode(const mf_adv_t *a, uint8_t addr[6], uint8_t payload[31])
{
    if (a->battery > 3) return MF_ERR_ARG;
    addr[0] = a->pub[0] | 0xC0;
    memcpy(addr + 1, a->pub + 1, 5);
    payload[0] = 0x1E;
    payload[1] = 0xFF;
    payload[2] = MF_COMPANY_ID & 0xFF;
    payload[3] = MF_COMPANY_ID >> 8;
    payload[4] = (uint8_t)((a->pub[0] & 0xC0) | mf_adv_status_bits(a));
    memcpy(payload + 5, a->pub + 6, 26);
    return MF_OK;
}

int mf_adv_decode(const uint8_t addr[6], const uint8_t *p, size_t len, mf_adv_t *out)
{
    if (len != MF_ADV_LEN) return MF_ERR_FORMAT;
    if (p[0] != 0x1E || p[1] != 0xFF) return MF_ERR_FORMAT;
    if ((p[2] | (p[3] << 8)) != MF_COMPANY_ID) return MF_ERR_FORMAT;
    if ((addr[0] & 0xC0) != 0xC0) return MF_ERR_FORMAT;
    if ((p[4] & 0x07) != MF_PROTO_VERSION) return MF_ERR_FORMAT;
    out->pub[0] = (uint8_t)((addr[0] & 0x3F) | (p[4] & 0xC0));
    memcpy(out->pub + 1, addr + 1, 5);
    memcpy(out->pub + 6, p + 5, 26);
    out->battery = (p[4] >> 4) & 3;
    out->separated = (p[4] & 0x08) != 0;
    return MF_OK;
}

uint8_t mf_battery_level(int percent)
{
    if (percent >= 60) return MF_BATT_FULL;
    if (percent >= 30) return MF_BATT_MEDIUM;
    if (percent >= 10) return MF_BATT_LOW;
    return MF_BATT_CRITICAL;
}

uint32_t mf_adv_interval_ms(int percent, bool separated)
{
    static const uint32_t base[4] = {2000, 2000, 4000, 8000};
    uint32_t ms = base[mf_battery_level(percent)];
    if (separated) {
        ms /= 2;
        if (ms < 1000) ms = 1000;
    }
    return ms;
}

uint32_t mf_adv_sleep_ms(uint32_t interval_ms, uint32_t tx_ms)
{
    if (interval_ms == 0) return 0;
    if (tx_ms >= interval_ms) return 0;
    return interval_ms - tx_ms;
}

uint32_t mf_adv_avg_current_ua(uint32_t interval_ms, uint32_t tx_ua, uint32_t sleep_ua, uint32_t tx_ms)
{
    uint32_t sleep_ms;
    uint64_t sum;
    if (interval_ms == 0) return tx_ua;
    if (tx_ms > interval_ms) tx_ms = interval_ms;
    sleep_ms = interval_ms - tx_ms;
    /* (tx_ua * tx_ms + sleep_ua * sleep_ms) / interval_ms, rounded nearest */
    sum = (uint64_t)tx_ua * tx_ms + (uint64_t)sleep_ua * sleep_ms;
    return (uint32_t)((sum + interval_ms / 2) / interval_ms);
}

uint32_t mf_presence_avg_current_ua(uint32_t period_s, uint32_t scan_ms, uint32_t scan_ua, uint32_t base_ua)
{
    uint64_t period_ms, idle_ms, sum;
    if (period_s == 0) return base_ua;
    period_ms = (uint64_t)period_s * 1000u;
    if (scan_ms > period_ms) scan_ms = (uint32_t)period_ms;
    idle_ms = period_ms - scan_ms;
    sum = (uint64_t)scan_ua * scan_ms + (uint64_t)base_ua * idle_ms;
    return (uint32_t)((sum + period_ms / 2) / period_ms);
}

/* ------------------------------------------------------------------- report */

static void put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

void mf_sighting_pack(const mf_sighting_t *s, uint8_t o[MF_PLAINTEXT_LEN])
{
    o[0] = s->version;
    o[1] = s->flags;
    put32(o + 2, s->seen_ts);
    put32(o + 6, s->node_id);
    put32(o + 10, (uint32_t)s->x);
    put32(o + 14, (uint32_t)s->y);
    put32(o + 18, (uint32_t)s->z);
    o[22] = (uint8_t)s->accuracy_cm;
    o[23] = (uint8_t)(s->accuracy_cm >> 8);
    o[24] = (uint8_t)s->rssi;
    o[25] = s->tag_status;
}

int mf_sighting_unpack(const uint8_t in[MF_PLAINTEXT_LEN], mf_sighting_t *s)
{
    if (in[0] != 1) return MF_ERR_FORMAT;
    s->version = in[0];
    s->flags = in[1];
    s->seen_ts = get32(in + 2);
    s->node_id = get32(in + 6);
    s->x = (int32_t)get32(in + 10);
    s->y = (int32_t)get32(in + 14);
    s->z = (int32_t)get32(in + 18);
    s->accuracy_cm = (uint16_t)(in[22] | in[23] << 8);
    s->rssi = (int8_t)in[24];
    s->tag_status = in[25];
    return MF_OK;
}

static void report_kdf(const uint8_t shared[32], const uint8_t eph_pub[32], const uint8_t tag_pub[32],
                       uint8_t key[32], uint8_t nonce[12])
{
    uint8_t salt[64], okm[44];
    memcpy(salt, eph_pub, 32);
    memcpy(salt + 32, tag_pub, 32);
    mf_hkdf_sha256(shared, 32, salt, 64, INFO("meshfind/v1/report"), okm, 44);
    memcpy(key, okm, 32);
    memcpy(nonce, okm + 32, 12);
    mf_wipe(okm, sizeof okm);
}

int mf_report_seal(const uint8_t tag_pub[32], const mf_sighting_t *s, const uint8_t eph_secret[32],
                   uint8_t out[MF_ENVELOPE_LEN])
{
    uint8_t e[32], shared[32], key[32], nonce[12], pt[MF_PLAINTEXT_LEN];
    int rc = MF_OK;
    memcpy(e, eph_secret, 32);
    mf_x25519_clamp(e);
    out[0] = 1;
    out[1] = 0;
    mf_key_hash(tag_pub, out + 2);
    if (mf_x25519_base(out + 34, e) != 0 || mf_x25519(shared, e, tag_pub) != 0) {
        rc = MF_ERR_KEY; /* low-order / invalid tag key */
        goto done;
    }
    report_kdf(shared, out + 34, tag_pub, key, nonce);
    mf_sighting_pack(s, pt);
    mf_aead_encrypt(key, nonce, out, MF_ENV_HEADER_LEN, pt, MF_PLAINTEXT_LEN, out + MF_ENV_HEADER_LEN,
                    out + MF_ENV_HEADER_LEN + MF_PLAINTEXT_LEN);
done:
    mf_wipe(e, sizeof e);
    mf_wipe(shared, sizeof shared);
    mf_wipe(key, sizeof key);
    mf_wipe(pt, sizeof pt);
    if (rc != MF_OK) memset(out, 0, MF_ENVELOPE_LEN);
    return rc;
}

int mf_report_open(const uint8_t tag_priv[32], const uint8_t tag_pub[32], const uint8_t env[MF_ENVELOPE_LEN],
                   mf_sighting_t *out)
{
    uint8_t kh[32], shared[32], key[32], nonce[12], pt[MF_PLAINTEXT_LEN];
    int rc;
    if (env[0] != 1) return MF_ERR_FORMAT;
    mf_key_hash(tag_pub, kh);
    if (mf_ct_memcmp(kh, env + 2, 32) != 0) return MF_ERR_KEY;
    if (mf_x25519(shared, tag_priv, env + 34) != 0) return MF_ERR_KEY;
    report_kdf(shared, env + 34, tag_pub, key, nonce);
    rc = mf_aead_decrypt(key, nonce, env, MF_ENV_HEADER_LEN, env + MF_ENV_HEADER_LEN, MF_PLAINTEXT_LEN,
                         env + MF_ENV_HEADER_LEN + MF_PLAINTEXT_LEN, pt);
    if (rc == 0) rc = mf_sighting_unpack(pt, out);
    else rc = MF_ERR_AUTH;
    mf_wipe(shared, sizeof shared);
    mf_wipe(key, sizeof key);
    mf_wipe(pt, sizeof pt);
    return rc;
}
