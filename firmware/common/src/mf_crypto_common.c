/* meshfind -- backend-independent helpers: HMAC-SHA256, HKDF, wipe, compare. */
#include <string.h>

#include "mf_crypto.h"

void mf_wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

int mf_ct_memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= x[i] ^ y[i];
    return d != 0;
}

void mf_x25519_clamp(uint8_t s[32])
{
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
}

void mf_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    mf_sha256_ctx c;
    mf_sha256_init(&c);
    mf_sha256_update(&c, data, len);
    mf_sha256_final(&c, out);
}

typedef struct {
    mf_sha256_ctx inner, outer;
} hmac_ctx;

static void hmac_init(hmac_ctx *h, const uint8_t *key, size_t key_len)
{
    uint8_t k[64], pad[64];
    memset(k, 0, sizeof k);
    if (key_len > 64)
        mf_sha256(key, key_len, k);
    else if (key_len)
        memcpy(k, key, key_len);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    mf_sha256_init(&h->inner);
    mf_sha256_update(&h->inner, pad, 64);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    mf_sha256_init(&h->outer);
    mf_sha256_update(&h->outer, pad, 64);
    mf_wipe(k, sizeof k);
    mf_wipe(pad, sizeof pad);
}

static void hmac_final(hmac_ctx *h, uint8_t out[32])
{
    uint8_t ih[32];
    mf_sha256_final(&h->inner, ih);
    mf_sha256_update(&h->outer, ih, 32);
    mf_sha256_final(&h->outer, out);
    mf_wipe(ih, sizeof ih);
}

void mf_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    hmac_ctx h;
    hmac_init(&h, key, key_len);
    mf_sha256_update(&h.inner, msg, msg_len);
    hmac_final(&h, out);
}

int mf_hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,
                   const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len)
{
    static const uint8_t zero_salt[32] = {0};
    uint8_t prk[32], t[32];
    size_t done = 0, tlen = 0;
    uint8_t counter = 1;
    if (out_len > 255 * 32) return -1;
    if (salt_len == 0) {
        salt = zero_salt;
        salt_len = sizeof zero_salt;
    }
    mf_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    while (done < out_len) {
        hmac_ctx h;
        size_t n;
        hmac_init(&h, prk, 32);
        mf_sha256_update(&h.inner, t, tlen);
        mf_sha256_update(&h.inner, info, info_len);
        mf_sha256_update(&h.inner, &counter, 1);
        hmac_final(&h, t);
        tlen = 32;
        n = out_len - done < 32 ? out_len - done : 32;
        memcpy(out + done, t, n);
        done += n;
        counter++;
    }
    mf_wipe(prk, sizeof prk);
    mf_wipe(t, sizeof t);
    return 0;
}
