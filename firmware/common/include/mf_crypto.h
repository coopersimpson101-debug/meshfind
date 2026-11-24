/*
 * meshfind -- crypto primitive interface.
 *
 * Two interchangeable backends implement this header:
 *   - MF_CRYPTO_BACKEND_REF     (default) portable C in src/mf_crypto_ref.c:
 *                               SHA-256, ChaCha20-Poly1305 and X25519
 *                               (X25519 field arithmetic derived from the
 *                               public-domain TweetNaCl). Used for host tests
 *                               and, by default, on the ESP32.
 *   - MF_CRYPTO_BACKEND_MBEDTLS src/mf_crypto_mbedtls.c, wraps the mbedTLS
 *                               shipped with ESP-IDF (hardware SHA on ESP32).
 * HMAC/HKDF/wipe live in src/mf_crypto_common.c on top of the SHA-256 context.
 */
#ifndef MF_CRYPTO_H
#define MF_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MF_CRYPTO_BACKEND_MBEDTLS)
#include "mbedtls/sha256.h"
typedef struct {
    mbedtls_sha256_context c;
} mf_sha256_ctx;
#else
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buf[64];
    size_t buflen;
} mf_sha256_ctx;
#endif

void mf_sha256_init(mf_sha256_ctx *ctx);
void mf_sha256_update(mf_sha256_ctx *ctx, const uint8_t *data, size_t len);
void mf_sha256_final(mf_sha256_ctx *ctx, uint8_t out[32]);
void mf_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

void mf_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32]);

/* RFC 5869. Returns 0, or -1 if out_len > 255*32. An empty salt means 32 zero bytes. */
int mf_hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,
                   const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len);

/* RFC 7748 X25519. Returns 0, or -1 if the result is all zero (low-order point)
 * or the backend rejected the point. */
int mf_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u[32]);
int mf_x25519_base(uint8_t out[32], const uint8_t scalar[32]);
void mf_x25519_clamp(uint8_t scalar[32]);

/* RFC 8439 ChaCha20-Poly1305 (12-byte nonce, 16-byte tag). ct may alias pt. */
void mf_aead_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                     const uint8_t *pt, size_t len, uint8_t *ct, uint8_t tag[16]);
/* Returns 0 on success, -1 on authentication failure (pt is zeroed then). */
int mf_aead_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t len, const uint8_t tag[16], uint8_t *pt);

/* Constant-time compare (0 if equal) and a wipe the compiler cannot elide. */
int mf_ct_memcmp(const void *a, const void *b, size_t n);
void mf_wipe(void *p, size_t n);

#ifdef __cplusplus
}
#endif
#endif /* MF_CRYPTO_H */
