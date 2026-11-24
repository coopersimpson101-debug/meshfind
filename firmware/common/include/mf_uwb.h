/*
 * meshfind -- UWB (Qorvo DW3000) last-metre ranging: INTERFACE ONLY.
 *
 * Roadmap item; nothing implements this header yet. It fixes the message
 * layouts and the driver boundary so a DW3000 port (Qorvo's DW3000 API or
 * the Zephyr/ESP-IDF community drivers) can be dropped in. The protocol maths
 * (ranging-request MAC, STS key, DS-TWR estimator) is implemented and tested
 * in meshfind/uwb.py. Full design: docs/UWB.md.
 */
#ifndef MF_UWB_H
#define MF_UWB_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* BLE wake-up: owner -> tag, AD structure (29 bytes)
 *   [0x1C][0xFF][0xFF 0xFF][0x51][nonce 8][HMAC(HKDF(SK_i,"meshfind/v1/uwb-req"), u32 epoch | nonce)[:16]] */
#define MF_UWB_REQ_MARKER 0x51
#define MF_UWB_REQ_LEN 29

/* UWB frames (IEEE 802.15.4z HRP, STS mode 1 keyed with
 * HKDF(SK_i, salt=nonce, "meshfind/v1/uwb-sts")[:16]). All little-endian. */
enum { MF_UWB_POLL = 0x61, MF_UWB_RESP = 0x62, MF_UWB_FINAL = 0x63, MF_UWB_REPORT = 0x64 };

typedef struct {
    uint8_t type;      /* MF_UWB_POLL */
    uint8_t session[4]; /* first 4 bytes of the request nonce */
    uint8_t seq;
} mf_uwb_poll_t;

typedef struct {
    uint8_t type;      /* MF_UWB_RESP */
    uint8_t session[4];
    uint8_t seq;
} mf_uwb_resp_t;

typedef struct {
    uint8_t type;      /* MF_UWB_FINAL: initiator's Ra and Da in DW3000 ticks (40-bit) */
    uint8_t session[4];
    uint8_t seq;
    uint8_t round_a[5];
    uint8_t reply_a[5];
} mf_uwb_final_t;

typedef struct {
    uint8_t type;      /* MF_UWB_REPORT: responder's Rb, Db so the owner computes ToF */
    uint8_t session[4];
    uint8_t seq;
    uint8_t round_b[5];
    uint8_t reply_b[5];
} mf_uwb_report_t;

/* Driver boundary. Timestamps are 40-bit DW3000 device-time ticks (~15.65 ps). */
typedef struct {
    int (*init)(void *ctx, const uint8_t sts_key[16], const uint8_t sts_iv[16]);
    int (*tx)(void *ctx, const uint8_t *frame, uint8_t len, uint64_t delayed_tx_ticks, uint64_t *tx_ts);
    int (*rx)(void *ctx, uint8_t *frame, uint8_t *len, uint32_t timeout_us, uint64_t *rx_ts, bool *sts_ok);
    void (*sleep)(void *ctx);
    void *ctx;
} mf_uwb_driver_t;

/* To be implemented: responder state machine on the tag, initiator on the
 * owner device. Returns distance in millimetres or a negative error. */
int32_t mf_uwb_range_as_initiator(const mf_uwb_driver_t *drv, const uint8_t nonce[8]);
int mf_uwb_serve_as_responder(const mf_uwb_driver_t *drv, const uint8_t nonce[8], uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
#endif /* MF_UWB_H */
