/*
 * meshfind -- portable reference crypto backend.
 *
 *  - SHA-256: straightforward FIPS 180-4 implementation.
 *  - ChaCha20 / Poly1305 / AEAD: RFC 8439. Poly1305 uses the well-known
 *    26-bit-limb approach popularised by poly1305-donna (public domain).
 *  - X25519: Montgomery ladder and GF(2^255-19) arithmetic derived from
 *    TweetNaCl (D. J. Bernstein, B. van Gastel, W. Janssen, T. Lange,
 *    P. Schwabe, S. Smetsers; public domain, https://tweetnacl.cr.yp.to/).
 *    Constant-time: no secret-dependent branches or table lookups.
 *
 * Verified on the host against RFC test vectors and the Python reference
 * (see firmware/common/test). Not side-channel evaluated on ESP32 hardware.
 */
#if !defined(MF_CRYPTO_BACKEND_MBEDTLS)

#include <string.h>

#include "mf_crypto.h"

/* ------------------------------------------------------------------ SHA-256 */

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(mf_sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64], a, b, d, e, f, g, h, cc, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3];
    e = c->state[4]; f = c->state[5]; g = c->state[6]; h = c->state[7];
    for (i = 0; i < 64; i++) {
        t1 = h + (ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        t2 = (ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22)) + ((a & b) ^ (a & cc) ^ (b & cc));
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

void mf_sha256_init(mf_sha256_ctx *c)
{
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(c->state, iv, sizeof iv);
    c->bitlen = 0;
    c->buflen = 0;
}

void mf_sha256_update(mf_sha256_ctx *c, const uint8_t *data, size_t len)
{
    while (len > 0) {
        size_t n = 64 - c->buflen;
        if (n > len) n = len;
        memcpy(c->buf + c->buflen, data, n);
        c->buflen += n;
        data += n;
        len -= n;
        c->bitlen += (uint64_t)n * 8;
        if (c->buflen == 64) {
            sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

void mf_sha256_final(mf_sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->bitlen;
    uint8_t pad = 0x80, zero = 0, lenb[8];
    int i;
    mf_sha256_update(c, &pad, 1);
    while (c->buflen != 56) mf_sha256_update(c, &zero, 1);
    for (i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (56 - 8 * i));
    mf_sha256_update(c, lenb, 8);
    for (i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(c->state[i] >> 24);
        out[4 * i + 1] = (uint8_t)(c->state[i] >> 16);
        out[4 * i + 2] = (uint8_t)(c->state[i] >> 8);
        out[4 * i + 3] = (uint8_t)c->state[i];
    }
    mf_wipe(c, sizeof *c);
}

/* ----------------------------------------------------------------- ChaCha20 */

static uint32_t ld32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static void st32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QR(a, b, c, d)                       \
    a += b; d ^= a; d = ROL32(d, 16);        \
    c += d; b ^= c; b = ROL32(b, 12);        \
    a += b; d ^= a; d = ROL32(d, 8);         \
    c += d; b ^= c; b = ROL32(b, 7)

static void chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64])
{
    uint32_t s[16], x[16];
    int i;
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (i = 0; i < 8; i++) s[4 + i] = ld32(key + 4 * i);
    s[12] = counter;
    for (i = 0; i < 3; i++) s[13 + i] = ld32(nonce + 4 * i);
    memcpy(x, s, sizeof s);
    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8], x[12]); QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]); QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]); QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]); QR(x[3], x[4], x[9], x[14]);
    }
    for (i = 0; i < 16; i++) st32(out + 4 * i, x[i] + s[i]);
    mf_wipe(x, sizeof x);
    mf_wipe(s, sizeof s);
}

static void chacha20_xor(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                         const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t ks[64];
    size_t i;
    while (len > 0) {
        size_t n = len < 64 ? len : 64;
        chacha20_block(key, counter++, nonce, ks);
        for (i = 0; i < n; i++) out[i] = in[i] ^ ks[i];
        in += n;
        out += n;
        len -= n;
    }
    mf_wipe(ks, sizeof ks);
}

/* ----------------------------------------------------------------- Poly1305 */

typedef struct {
    uint32_t r[5], h[5], pad[4];
    size_t leftover;
    uint8_t buffer[16];
    int final;
} poly1305_t;

static void poly1305_init(poly1305_t *st, const uint8_t key[32])
{
    st->r[0] = (ld32(key + 0)) & 0x3ffffff;
    st->r[1] = (ld32(key + 3) >> 2) & 0x3ffff03;
    st->r[2] = (ld32(key + 6) >> 4) & 0x3ffc0ff;
    st->r[3] = (ld32(key + 9) >> 6) & 0x3f03fff;
    st->r[4] = (ld32(key + 12) >> 8) & 0x00fffff;
    memset(st->h, 0, sizeof st->h);
    for (int i = 0; i < 4; i++) st->pad[i] = ld32(key + 16 + 4 * i);
    st->leftover = 0;
    st->final = 0;
}

static void poly1305_blocks(poly1305_t *st, const uint8_t *m, size_t bytes)
{
    const uint32_t hibit = st->final ? 0 : (1UL << 24);
    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    while (bytes >= 16) {
        uint64_t d0, d1, d2, d3, d4;
        uint32_t c;
        h0 += (ld32(m + 0)) & 0x3ffffff;
        h1 += (ld32(m + 3) >> 2) & 0x3ffffff;
        h2 += (ld32(m + 6) >> 4) & 0x3ffffff;
        h3 += (ld32(m + 9) >> 6) & 0x3ffffff;
        h4 += (ld32(m + 12) >> 8) | hibit;
        d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;
        m += 16;
        bytes -= 16;
    }
    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

static void poly1305_update(poly1305_t *st, const uint8_t *m, size_t bytes)
{
    if (st->leftover) {
        size_t want = 16 - st->leftover;
        if (want > bytes) want = bytes;
        memcpy(st->buffer + st->leftover, m, want);
        bytes -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < 16) return;
        poly1305_blocks(st, st->buffer, 16);
        st->leftover = 0;
    }
    if (bytes >= 16) {
        size_t want = bytes & ~(size_t)15;
        poly1305_blocks(st, m, want);
        m += want;
        bytes -= want;
    }
    if (bytes) {
        memcpy(st->buffer + st->leftover, m, bytes);
        st->leftover += bytes;
    }
}

static void poly1305_finish(poly1305_t *st, uint8_t mac[16])
{
    uint32_t h0, h1, h2, h3, h4, c, g0, g1, g2, g3, g4, mask;
    uint64_t f;
    if (st->leftover) {
        size_t i = st->leftover;
        st->buffer[i++] = 1;
        for (; i < 16; i++) st->buffer[i] = 0;
        st->final = 1;
        poly1305_blocks(st, st->buffer, 16);
    }
    h0 = st->h[0]; h1 = st->h[1]; h2 = st->h[2]; h3 = st->h[3]; h4 = st->h[4];
    c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - ((uint32_t)1 << 26);
    mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;
    h0 = (h0 | (h1 << 26));
    h1 = ((h1 >> 6) | (h2 << 20));
    h2 = ((h2 >> 12) | (h3 << 14));
    h3 = ((h3 >> 18) | (h4 << 8));
    f = (uint64_t)h0 + st->pad[0]; h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->pad[3] + (f >> 32); h3 = (uint32_t)f;
    st32(mac + 0, h0); st32(mac + 4, h1); st32(mac + 8, h2); st32(mac + 12, h3);
    mf_wipe(st, sizeof *st);
}

/* --------------------------------------------------------- AEAD (RFC 8439) */

static void aead_mac(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                     const uint8_t *ct, size_t len, uint8_t tag[16])
{
    static const uint8_t zeros[16] = {0};
    uint8_t block0[64], lens[16];
    poly1305_t st;
    chacha20_block(key, 0, nonce, block0);
    poly1305_init(&st, block0);
    poly1305_update(&st, aad, aad_len);
    if (aad_len % 16) poly1305_update(&st, zeros, 16 - aad_len % 16);
    poly1305_update(&st, ct, len);
    if (len % 16) poly1305_update(&st, zeros, 16 - len % 16);
    for (int i = 0; i < 8; i++) {
        lens[i] = (uint8_t)((uint64_t)aad_len >> (8 * i));
        lens[8 + i] = (uint8_t)((uint64_t)len >> (8 * i));
    }
    poly1305_update(&st, lens, 16);
    poly1305_finish(&st, tag);
    mf_wipe(block0, sizeof block0);
}

void mf_aead_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                     const uint8_t *pt, size_t len, uint8_t *ct, uint8_t tag[16])
{
    chacha20_xor(key, 1, nonce, pt, ct, len);
    aead_mac(key, nonce, aad, aad_len, ct, len, tag);
}

int mf_aead_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t len, const uint8_t tag[16], uint8_t *pt)
{
    uint8_t expect[16];
    aead_mac(key, nonce, aad, aad_len, ct, len, expect);
    if (mf_ct_memcmp(expect, tag, 16) != 0) {
        memset(pt, 0, len);
        return -1;
    }
    chacha20_xor(key, 1, nonce, ct, pt, len);
    return 0;
}

/* ------------------------------------------------- X25519 (from TweetNaCl) */

typedef int64_t gf[16];
static const gf gf_121665 = {0xDB41, 1};

static void car25519(gf o)
{
    int64_t c;
    for (int i = 0; i < 16; i++) {
        o[i] += ((int64_t)1 << 16);
        c = o[i] >> 16; /* arithmetic shift on all supported compilers */
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c * ((int64_t)1 << 16);
    }
}

static void sel25519(gf p, gf q, int64_t b)
{
    int64_t t, c = ~(b - 1);
    for (int i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t *o, const gf n)
{
    int64_t b;
    gf m, t;
    for (int i = 0; i < 16; i++) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; i++) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void unpack25519(gf o, const uint8_t *n)
{
    for (int i = 0; i < 16; i++) o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void gf_add(gf o, const gf a, const gf b) { for (int i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
static void gf_sub(gf o, const gf a, const gf b) { for (int i = 0; i < 16; i++) o[i] = a[i] - b[i]; }

static void gf_mul(gf o, const gf a, const gf b)
{
    int64_t t[31];
    for (int i = 0; i < 31; i++) t[i] = 0;
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void gf_sq(gf o, const gf a) { gf_mul(o, a, a); }

static void inv25519(gf o, const gf in)
{
    gf c;
    for (int a = 0; a < 16; a++) c[a] = in[a];
    for (int a = 253; a >= 0; a--) {
        gf_sq(c, c);
        if (a != 2 && a != 4) gf_mul(c, c, in);
    }
    for (int a = 0; a < 16; a++) o[a] = c[a];
}

static void scalarmult(uint8_t *q, const uint8_t *n, const uint8_t *p)
{
    uint8_t z[32];
    int64_t r;
    gf x, a, b, c, d, e, f;
    for (int i = 0; i < 32; i++) z[i] = n[i];
    z[31] = (n[31] & 127) | 64;
    z[0] &= 248;
    unpack25519(x, p);
    for (int i = 0; i < 16; i++) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (int i = 254; i >= 0; --i) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, r);
        sel25519(c, d, r);
        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_add(c, b, d);
        gf_sub(b, b, d);
        gf_sq(d, e);
        gf_sq(f, a);
        gf_mul(a, c, a);
        gf_mul(c, b, e);
        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_sq(b, a);
        gf_sub(c, d, f);
        gf_mul(a, c, gf_121665);
        gf_add(a, a, d);
        gf_mul(c, c, a);
        gf_mul(a, d, f);
        gf_mul(d, b, x);
        gf_sq(b, e);
        sel25519(a, b, r);
        sel25519(c, d, r);
    }
    inv25519(c, c);
    gf_mul(a, a, c);
    pack25519(q, a);
    mf_wipe(z, sizeof z);
}

int mf_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u[32])
{
    uint8_t acc = 0;
    scalarmult(out, scalar, u);
    for (int i = 0; i < 32; i++) acc |= out[i];
    return acc ? 0 : -1;
}

int mf_x25519_base(uint8_t out[32], const uint8_t scalar[32])
{
    static const uint8_t nine[32] = {9};
    return mf_x25519(out, scalar, nine);
}

#endif /* !MF_CRYPTO_BACKEND_MBEDTLS */
