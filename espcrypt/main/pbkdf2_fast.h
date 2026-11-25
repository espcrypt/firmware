#pragma once
#include <stddef.h>
#include <stdint.h>

void pbkdf2_sha256_32(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen, uint32_t rounds,
                      uint8_t out[32]);

const char *pbkdf2_path(void);
