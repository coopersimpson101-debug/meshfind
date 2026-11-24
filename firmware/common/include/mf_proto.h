/*
 * meshfind -- portable protocol layer: key ratchet, BLE advertisement codec,
 * encrypted report (ECIES) seal/open. Mirrors the Python reference in
 * meshfind/{ratchet,adv,report}.py byte for byte; see docs/PROTOCOL.md.
 * No dynamic allocation, no platform dependencies beyond mf_crypto.h.
 */
#ifndef MF_PROTO_H
#define MF_PROTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MF_KEY_LEN 32
#define MF_HASH_LEN 32
#define MF_ADDR_LEN 6
#define MF_ADV_LEN 31
#define MF_PLAINTEXT_LEN 26
#define MF_ENV_HEADER_LEN 66
#define MF_ENVELOPE_LEN 108 /* 66 header + 26 ciphertext + 16 tag */
#define MF_PROTO_VERSION 1
#define MF_COMPANY_ID 0xFFFF
#define MF_EPOCH_SECONDS 900u
#define MF_DAY_SECONDS 86400u

#define MF_BATT_FULL 0
#define MF_BATT_MEDIUM 1
#define MF_BATT_LOW 2
#define MF_BATT_CRITICAL 3

#define MF_PT_FLAG_TIME_SYNCED 0x01
#define MF_PT_FLAG_LOCAL_FRAME 0x02

enum { MF_OK = 0, MF_ERR_ARG = -1, MF_ERR_FORMAT = -2, MF_ERR_AUTH = -3, MF_ERR_KEY = -4, MF_ERR_TIME = -5 };

/* ---- ratchet ---- */
typedef struct {
    uint8_t sk[32];
    uint32_t index;
    uint8_t sep_sk[32];
    uint32_t sep_index;
    uint8_t presence_key[32];
    uint32_t epoch0;
    uint32_t epoch_seconds;
} mf_tag_state_t;

void mf_chain_init(const uint8_t master[32], bool separated, uint8_t out[32]);
void mf_chain_step(const uint8_t sk[32], uint8_t out[32]); /* out may alias sk */
void mf_epoch_private(const uint8_t sk[32], uint8_t priv[32]);
int mf_epoch_public(const uint8_t sk[32], uint8_t pub[32]);
void mf_key_hash(const uint8_t pub[32], uint8_t out[32]);
void mf_presence_key(const uint8_t master[32], uint8_t out[32]);
void mf_presence_token(const uint8_t pkey[32], uint32_t epoch, uint8_t out[16]);
int mf_epoch_index(uint32_t t, uint32_t epoch0, uint32_t seconds, uint32_t *index);

/* Owner-presence beacon: AD structure [0x14][0xFF][0xFF 0xFF][0x50][token16].
 * mf_presence_find walks raw advertising data and returns MF_OK with the
 * matching epoch if it carries a valid token for any epoch in
 * [cur - window, cur + window]. */
#define MF_PRESENCE_ADV_LEN 21
void mf_presence_encode(const uint8_t token[16], uint8_t out[MF_PRESENCE_ADV_LEN]);
int mf_presence_find(const uint8_t pkey[32], const uint8_t *adv, size_t len, uint32_t cur, uint32_t window,
                     uint32_t *epoch);

/* Tags are provisioned with chain seeds only (never the master secret). */
void mf_tag_init(mf_tag_state_t *st, const uint8_t sk0[32], const uint8_t sep_sk0[32],
                 const uint8_t presence_key[32], uint32_t epoch0, uint32_t epoch_seconds);
void mf_tag_provision(mf_tag_state_t *st, const uint8_t master[32], uint32_t epoch0, uint32_t epoch_seconds);
/* One-way: returns MF_ERR_ARG if asked to go backwards. Wipes old chain values. */
int mf_tag_advance(mf_tag_state_t *st, uint32_t index);
int mf_tag_advance_sep(mf_tag_state_t *st, uint32_t day);
int mf_tag_current_public(mf_tag_state_t *st, uint32_t now, bool separated, uint8_t pub[32]);

/* ---- advertisement ---- */
typedef struct {
    uint8_t pub[32];
    uint8_t battery; /* MF_BATT_* */
    bool separated;
} mf_adv_t;

uint8_t mf_adv_status_bits(const mf_adv_t *a); /* status byte without the 2 key bits */
/* addr is MSB-first (as printed; ESP-IDF bluedroid order). NimBLE stores
 * addresses LSB-first: reverse before ble_hs_id_set_rnd(). */
int mf_adv_encode(const mf_adv_t *a, uint8_t addr[6], uint8_t payload[31]);
int mf_adv_decode(const uint8_t addr[6], const uint8_t *payload, size_t len, mf_adv_t *out);
uint8_t mf_battery_level(int percent);
uint32_t mf_adv_interval_ms(int percent, bool separated);

/* ---- report ---- */
typedef struct {
    uint8_t version;
    uint8_t flags;
    uint32_t seen_ts;
    uint32_t node_id;
    int32_t x, y, z;
    uint16_t accuracy_cm;
    int8_t rssi;
    uint8_t tag_status;
} mf_sighting_t;

void mf_sighting_pack(const mf_sighting_t *s, uint8_t out[MF_PLAINTEXT_LEN]);
int mf_sighting_unpack(const uint8_t in[MF_PLAINTEXT_LEN], mf_sighting_t *s);
/* eph_secret: 32 fresh random bytes (clamped internally, wiped by caller). */
int mf_report_seal(const uint8_t tag_pub[32], const mf_sighting_t *s, const uint8_t eph_secret[32],
                   uint8_t out[MF_ENVELOPE_LEN]);
int mf_report_open(const uint8_t tag_priv[32], const uint8_t tag_pub[32], const uint8_t env[MF_ENVELOPE_LEN],
                   mf_sighting_t *out);

#ifdef __cplusplus
}
#endif
#endif /* MF_PROTO_H */
