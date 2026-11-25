#include "pbkdf2_fast.h"

#include <stdbool.h>
#include <string.h>

#ifdef ESP_PLATFORM
#include "hal/sha_hal.h"
#include "sha/sha_dma.h"
#endif

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static const uint32_t IV[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void compress(uint32_t st[8], const uint32_t in[16], uint32_t w[64]) {
    for (int i = 0; i < 16; i++) w[i] = in[i];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    st[0] += a;
    st[1] += b;
    st[2] += c;
    st[3] += d;
    st[4] += e;
    st[5] += f;
    st[6] += g;
    st[7] += h;
}

static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

static void finish(uint32_t st[8], uint64_t prefix_bytes, const uint8_t *data, size_t len, uint32_t out[8]) {
    uint32_t s[8], blk[16], w[64];
    uint8_t buf[64];
    memcpy(s, st, sizeof(s));
    size_t off = 0;
    while (len - off >= 64) {
        for (int i = 0; i < 16; i++) blk[i] = be32(data + off + 4 * i);
        compress(s, blk, w);
        off += 64;
    }
    size_t rest = len - off;
    memset(buf, 0, sizeof(buf));
    memcpy(buf, data + off, rest);
    buf[rest] = 0x80;
    if (rest >= 56) {
        for (int i = 0; i < 16; i++) blk[i] = be32(buf + 4 * i);
        compress(s, blk, w);
        memset(buf, 0, sizeof(buf));
    }
    uint64_t bits = (prefix_bytes + len) * 8;
    for (int i = 0; i < 8; i++) buf[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
    for (int i = 0; i < 16; i++) blk[i] = be32(buf + 4 * i);
    compress(s, blk, w);
    memcpy(out, s, 32);
    memset(buf, 0, sizeof(buf));
    memset(blk, 0, sizeof(blk));
    memset(w, 0, sizeof(w));
}

#ifdef ESP_PLATFORM
static void words_to_bytes(const uint32_t w[8], uint32_t out[8]) {
    uint8_t *b = (uint8_t *)out;
    for (int i = 0; i < 8; i++) {
        b[4 * i] = (uint8_t)(w[i] >> 24);
        b[4 * i + 1] = (uint8_t)(w[i] >> 16);
        b[4 * i + 2] = (uint8_t)(w[i] >> 8);
        b[4 * i + 3] = (uint8_t)w[i];
    }
}

static void bytes_to_words(const uint32_t in[8], uint32_t w[8]) {
    const uint8_t *b = (const uint8_t *)in;
    for (int i = 0; i < 8; i++) w[i] = be32(b + 4 * i);
}

static void hw_rounds(const uint32_t inner_w[8], const uint32_t outer_w[8], uint32_t u_w[8], uint32_t t_w[8],
                      uint32_t rounds) {
    uint32_t inner[8], outer[8], blk[16], h[8], t[8];
    words_to_bytes(inner_w, inner);
    words_to_bytes(outer_w, outer);
    words_to_bytes(t_w, t);
    memset(blk, 0, sizeof(blk));
    words_to_bytes(u_w, blk);
    ((uint8_t *)blk)[32] = 0x80;
    ((uint8_t *)blk)[62] = 0x03;
    esp_sha_acquire_hardware();
    for (uint32_t r = 1; r < rounds; r++) {
        sha_hal_write_digest(SHA2_256, inner);
        sha_hal_hash_block(SHA2_256, blk, 16, false);
        sha_hal_read_digest(SHA2_256, h);
        memcpy(blk, h, 32);
        sha_hal_write_digest(SHA2_256, outer);
        sha_hal_hash_block(SHA2_256, blk, 16, false);
        sha_hal_read_digest(SHA2_256, blk);
        for (int i = 0; i < 8; i++) t[i] ^= blk[i];
    }
    esp_sha_release_hardware();
    bytes_to_words(t, t_w);
    bytes_to_words(blk, u_w);
    memset(inner, 0, sizeof(inner));
    memset(outer, 0, sizeof(outer));
    memset(blk, 0, sizeof(blk));
    memset(h, 0, sizeof(h));
    memset(t, 0, sizeof(t));
}
#endif

static void pbkdf2_sw(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen, uint32_t rounds,
                      uint8_t out[32], bool use_hw) {
    uint8_t key[64] = {0}, pad[64];
    uint32_t inner[8], outer[8], blk[16], u[8], t[8], w[64];
    if (pwlen > 64) {
        uint32_t h[8];
        finish((uint32_t *)IV, 0, pw, pwlen, h);
        for (int i = 0; i < 8; i++) {
            key[4 * i] = (uint8_t)(h[i] >> 24);
            key[4 * i + 1] = (uint8_t)(h[i] >> 16);
            key[4 * i + 2] = (uint8_t)(h[i] >> 8);
            key[4 * i + 3] = (uint8_t)h[i];
        }
        memset(h, 0, sizeof(h));
    } else {
        memcpy(key, pw, pwlen);
    }
    memcpy(inner, IV, sizeof(inner));
    memcpy(outer, IV, sizeof(outer));
    for (int i = 0; i < 64; i++) pad[i] = key[i] ^ 0x36;
    for (int i = 0; i < 16; i++) blk[i] = be32(pad + 4 * i);
    compress(inner, blk, w);
    for (int i = 0; i < 64; i++) pad[i] = key[i] ^ 0x5c;
    for (int i = 0; i < 16; i++) blk[i] = be32(pad + 4 * i);
    compress(outer, blk, w);

    uint8_t s1[64 + 4];
    size_t sl = saltlen > 64 ? 64 : saltlen;
    memcpy(s1, salt, sl);
    s1[sl] = 0;
    s1[sl + 1] = 0;
    s1[sl + 2] = 0;
    s1[sl + 3] = 1;
    uint32_t ih[8];
    finish(inner, 64, s1, sl + 4, ih);
    uint8_t ib[32];
    for (int i = 0; i < 8; i++) {
        ib[4 * i] = (uint8_t)(ih[i] >> 24);
        ib[4 * i + 1] = (uint8_t)(ih[i] >> 16);
        ib[4 * i + 2] = (uint8_t)(ih[i] >> 8);
        ib[4 * i + 3] = (uint8_t)ih[i];
    }
    finish(outer, 64, ib, 32, u);
    memcpy(t, u, sizeof(t));

#ifdef ESP_PLATFORM
    if (use_hw) {
        hw_rounds(inner, outer, u, t, rounds);
        rounds = 1;
    }
#else
    (void)use_hw;
#endif
    for (uint32_t r = 1; r < rounds; r++) {
        uint32_t s[8];
        for (int i = 0; i < 8; i++) blk[i] = u[i];
        blk[8] = 0x80000000;
        for (int i = 9; i < 15; i++) blk[i] = 0;
        blk[15] = 768;
        memcpy(s, inner, sizeof(s));
        compress(s, blk, w);
        for (int i = 0; i < 8; i++) blk[i] = s[i];
        memcpy(u, outer, sizeof(u));
        compress(u, blk, w);
        for (int i = 0; i < 8; i++) t[i] ^= u[i];
    }
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(t[i] >> 24);
        out[4 * i + 1] = (uint8_t)(t[i] >> 16);
        out[4 * i + 2] = (uint8_t)(t[i] >> 8);
        out[4 * i + 3] = (uint8_t)t[i];
    }
    memset(key, 0, sizeof(key));
    memset(pad, 0, sizeof(pad));
    memset(inner, 0, sizeof(inner));
    memset(outer, 0, sizeof(outer));
    memset(u, 0, sizeof(u));
    memset(t, 0, sizeof(t));
    memset(ib, 0, sizeof(ib));
    memset(ih, 0, sizeof(ih));
    memset(blk, 0, sizeof(blk));
    memset(w, 0, sizeof(w));
}

static int hw_ok = -1;

const char *pbkdf2_path(void) { return hw_ok == 1 ? "hw" : hw_ok == 0 ? "cpu" : "untested"; }

void pbkdf2_sha256_32(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen, uint32_t rounds,
                      uint8_t out[32]) {
#ifdef ESP_PLATFORM
    if (hw_ok < 0) {
        uint8_t a[32], b[32];
        const uint8_t salt0[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        pbkdf2_sw((const uint8_t *)"self-test", 9, salt0, sizeof(salt0), 5, a, false);
        pbkdf2_sw((const uint8_t *)"self-test", 9, salt0, sizeof(salt0), 5, b, true);
        hw_ok = memcmp(a, b, 32) == 0;
    }
    pbkdf2_sw(pw, pwlen, salt, saltlen, rounds, out, hw_ok == 1);
#else
    pbkdf2_sw(pw, pwlen, salt, saltlen, rounds, out, false);
#endif
}
