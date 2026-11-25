#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void sha256(const void *data, size_t len, uint8_t out[32]);
void pk_hmac_sha256(const uint8_t *key, size_t key_len, const void *a, size_t a_len, const void *b, size_t b_len,
                 const void *c, size_t c_len, uint8_t out[32]);

bool p256_private_from_seed(const uint8_t seed[32], uint8_t priv[32]);
bool p256_generate(uint8_t priv[32], uint8_t pub[64]);
bool p256_public(const uint8_t priv[32], uint8_t pub[64]);
bool p256_sign(const uint8_t priv[32], const uint8_t digest[32], uint8_t *sig, size_t sig_cap, size_t *sig_len);
bool p256_ecdh(const uint8_t priv[32], const uint8_t peer[64], uint8_t x[32]);

bool aes256_cbc(bool encrypt, const uint8_t key[32], const uint8_t *in, uint8_t *out, size_t len);

int crypto_rng(void *ctx, unsigned char *buf, size_t len);
bool ct_equal(const void *a, const void *b, size_t len);
