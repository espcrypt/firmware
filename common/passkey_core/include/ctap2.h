#pragma once
#include <stddef.h>
#include <stdint.h>

#define CTAP2_OK 0x00
#define CTAP1_ERR_INVALID_COMMAND 0x01
#define CTAP1_ERR_INVALID_PARAMETER 0x02
#define CTAP1_ERR_INVALID_LENGTH 0x03
#define CTAP2_ERR_INVALID_CBOR 0x12
#define CTAP2_ERR_MISSING_PARAMETER 0x14
#define CTAP2_ERR_CREDENTIAL_EXCLUDED 0x19
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM 0x26
#define CTAP2_ERR_OPERATION_DENIED 0x27
#define CTAP2_ERR_KEY_STORE_FULL 0x28
#define CTAP2_ERR_UNSUPPORTED_OPTION 0x2B
#define CTAP2_ERR_INVALID_OPTION 0x2C
#define CTAP2_ERR_KEEPALIVE_CANCEL 0x2D
#define CTAP2_ERR_NO_CREDENTIALS 0x2E
#define CTAP2_ERR_USER_ACTION_TIMEOUT 0x2F
#define CTAP2_ERR_NOT_ALLOWED 0x30
#define CTAP2_ERR_PIN_INVALID 0x31
#define CTAP2_ERR_PIN_BLOCKED 0x32
#define CTAP2_ERR_PIN_AUTH_INVALID 0x33
#define CTAP2_ERR_PIN_AUTH_BLOCKED 0x34
#define CTAP2_ERR_PIN_NOT_SET 0x35
#define CTAP2_ERR_PIN_REQUIRED 0x36
#define CTAP2_ERR_PIN_POLICY_VIOLATION 0x37
#define CTAP2_ERR_REQUEST_TOO_LARGE 0x39
#define CTAP1_ERR_OTHER 0x7F

#define CTAP2_MAX_MSG 2048

void ctap2_init(void);
size_t ctap2_handle(const uint8_t *req, size_t len, uint8_t *resp, size_t cap);

int ctap_wait_presence(void);

int ctap2_set_pin(const char *pin, size_t len);
int ctap2_change_pin(const char *old_pin, size_t old_len, const char *new_pin, size_t new_len);
void ctap2_forget_session(void);
