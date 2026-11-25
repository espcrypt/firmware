#include "crypto.h"

#include <string.h>

#include "esp_random.h"
#include "mbedtls/aes.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

int crypto_rng(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}

bool ct_equal(const void *a, const void *b, size_t len) {
    const uint8_t *x = a, *y = b;
    uint8_t d = 0;
    for (size_t i = 0; i < len; i++) d |= x[i] ^ y[i];
    return d == 0;
}

void sha256(const void *data, size_t len, uint8_t out[32]) { mbedtls_sha256(data, len, out, 0); }

void pk_hmac_sha256(const uint8_t *key, size_t key_len, const void *a, size_t a_len, const void *b, size_t b_len,
                 const void *c, size_t c_len, uint8_t out[32]) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx, key, key_len);
    if (a) mbedtls_md_hmac_update(&ctx, a, a_len);
    if (b) mbedtls_md_hmac_update(&ctx, b, b_len);
    if (c) mbedtls_md_hmac_update(&ctx, c, c_len);
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
}

static bool load_group(mbedtls_ecp_group *grp) {
    mbedtls_ecp_group_init(grp);
    return mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1) == 0;
}

bool p256_private_from_seed(const uint8_t seed[32], uint8_t priv[32]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_mpi_init(&d);
    bool ok = load_group(&grp);
    uint8_t s[32];
    memcpy(s, seed, 32);
    for (int i = 0; ok && i < 16; i++) {
        if (mbedtls_mpi_read_binary(&d, s, 32) != 0) {
            ok = false;
            break;
        }
        if (mbedtls_mpi_cmp_int(&d, 1) >= 0 && mbedtls_mpi_cmp_mpi(&d, &grp.N) < 0) {
            memcpy(priv, s, 32);
            break;
        }
        sha256(s, 32, s);
        if (i == 15) ok = false;
    }
    memset(s, 0, sizeof(s));
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

static bool point_to_xy(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *q, uint8_t pub[64]) {
    uint8_t raw[65];
    size_t n = 0;
    if (mbedtls_ecp_point_write_binary(grp, q, MBEDTLS_ECP_PF_UNCOMPRESSED, &n, raw, sizeof(raw)) != 0 || n != 65) return false;
    memcpy(pub, raw + 1, 64);
    return true;
}

bool p256_public(const uint8_t priv[32], uint8_t pub[64]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point q;
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);
    bool ok = load_group(&grp) && mbedtls_mpi_read_binary(&d, priv, 32) == 0 &&
              mbedtls_ecp_mul(&grp, &q, &d, &grp.G, crypto_rng, NULL) == 0 && point_to_xy(&grp, &q, pub);
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

bool p256_generate(uint8_t priv[32], uint8_t pub[64]) {
    uint8_t seed[32];
    esp_fill_random(seed, sizeof(seed));
    bool ok = p256_private_from_seed(seed, priv) && p256_public(priv, pub);
    memset(seed, 0, sizeof(seed));
    return ok;
}

bool p256_sign(const uint8_t priv[32], const uint8_t digest[32], uint8_t *sig, size_t sig_cap, size_t *sig_len) {
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    bool ok = mbedtls_ecp_group_load(&ctx.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1) == 0 &&
              mbedtls_mpi_read_binary(&ctx.MBEDTLS_PRIVATE(d), priv, 32) == 0 &&
              mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256, digest, 32, sig, sig_cap, sig_len, crypto_rng, NULL) == 0;
    mbedtls_ecdsa_free(&ctx);
    return ok;
}

bool p256_ecdh(const uint8_t priv[32], const uint8_t peer[64], uint8_t x[32]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d, z;
    mbedtls_ecp_point q;
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&q);
    uint8_t raw[65];
    raw[0] = 0x04;
    memcpy(raw + 1, peer, 64);
    bool ok = load_group(&grp) && mbedtls_mpi_read_binary(&d, priv, 32) == 0 &&
              mbedtls_ecp_point_read_binary(&grp, &q, raw, sizeof(raw)) == 0 && mbedtls_ecp_check_pubkey(&grp, &q) == 0 &&
              mbedtls_ecdh_compute_shared(&grp, &z, &q, &d, crypto_rng, NULL) == 0 && mbedtls_mpi_write_binary(&z, x, 32) == 0;
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

bool aes256_cbc(bool encrypt, const uint8_t key[32], const uint8_t *in, uint8_t *out, size_t len) {
    if (len % 16) return false;
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    uint8_t iv[16] = {0};
    bool ok = (encrypt ? mbedtls_aes_setkey_enc(&aes, key, 256) : mbedtls_aes_setkey_dec(&aes, key, 256)) == 0 &&
              mbedtls_aes_crypt_cbc(&aes, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, len, iv, in, out) == 0;
    mbedtls_aes_free(&aes);
    return ok;
}
