/*
 * meshfind -- mbedTLS crypto backend (ESP-IDF v5.x ships mbedTLS 3.x).
 *
 * Enable with CONFIG_MESHFIND_CRYPTO_MBEDTLS=y; requires in sdkconfig:
 *   CONFIG_MBEDTLS_CHACHA20_C=y CONFIG_MBEDTLS_POLY1305_C=y
 *   CONFIG_MBEDTLS_CHACHAPOLY_C=y CONFIG_MBEDTLS_ECP_DP_CURVE25519_ENABLED=y
 *
 * Status: compiled by CI only; NOT yet run on hardware or checked against
 * the vectors on-target (see README "Hardware validation").
 */
#if defined(MF_CRYPTO_BACKEND_MBEDTLS)

#include <string.h>

#include "mbedtls/chachapoly.h"
#include "mbedtls/ecp.h"
#include "mf_crypto.h"

#if defined(ESP_PLATFORM)
#include "esp_random.h"
static int mf_rng(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    esp_fill_random(out, len);
    return 0;
}
#else
#error "mbedTLS backend needs an RNG for mbedtls_ecp_mul blinding; provide mf_rng"
#endif

void mf_sha256_init(mf_sha256_ctx *ctx)
{
    mbedtls_sha256_init(&ctx->c);
    mbedtls_sha256_starts(&ctx->c, 0);
}

void mf_sha256_update(mf_sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    if (len) mbedtls_sha256_update(&ctx->c, data, len);
}

void mf_sha256_final(mf_sha256_ctx *ctx, uint8_t out[32])
{
    mbedtls_sha256_finish(&ctx->c, out);
    mbedtls_sha256_free(&ctx->c);
}

void mf_aead_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                     const uint8_t *pt, size_t len, uint8_t *ct, uint8_t tag[16])
{
    mbedtls_chachapoly_context c;
    mbedtls_chachapoly_init(&c);
    mbedtls_chachapoly_setkey(&c, key);
    mbedtls_chachapoly_encrypt_and_tag(&c, len, nonce, aad, aad_len, pt, ct, tag);
    mbedtls_chachapoly_free(&c);
}

int mf_aead_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t len, const uint8_t tag[16], uint8_t *pt)
{
    mbedtls_chachapoly_context c;
    int rc;
    mbedtls_chachapoly_init(&c);
    mbedtls_chachapoly_setkey(&c, key);
    rc = mbedtls_chachapoly_auth_decrypt(&c, len, nonce, aad, aad_len, tag, ct, pt);
    mbedtls_chachapoly_free(&c);
    if (rc != 0) {
        memset(pt, 0, len);
        return -1;
    }
    return 0;
}

int mf_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u[32])
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P, R;
    mbedtls_mpi d;
    uint8_t k[32], acc = 0;
    size_t olen = 0;
    int rc;

    memcpy(k, scalar, 32);
    mf_x25519_clamp(k); /* mbedtls_ecp_mul rejects unclamped Montgomery scalars */
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&P);
    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&d);
    rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (rc == 0) rc = mbedtls_mpi_read_binary_le(&d, k, 32);
    if (rc == 0) rc = mbedtls_ecp_point_read_binary(&grp, &P, u, 32); /* clears bit 255 per RFC 7748 */
    if (rc == 0) rc = mbedtls_ecp_mul(&grp, &R, &d, &P, mf_rng, NULL);
    if (rc == 0) rc = mbedtls_ecp_point_write_binary(&grp, &R, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, out, 32);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&P);
    mbedtls_ecp_group_free(&grp);
    mf_wipe(k, sizeof k);
    if (rc != 0 || olen != 32) {
        memset(out, 0, 32);
        return -1;
    }
    for (int i = 0; i < 32; i++) acc |= out[i];
    return acc ? 0 : -1;
}

int mf_x25519_base(uint8_t out[32], const uint8_t scalar[32])
{
    static const uint8_t nine[32] = {9};
    return mf_x25519(out, scalar, nine);
}

#endif /* MF_CRYPTO_BACKEND_MBEDTLS */
