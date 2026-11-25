#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cJSON.h"
#include "freertos/FreeRTOS.h"

typedef struct {
    uint16_t pid;
    const char *product;
} passkey_usb_config_t;

bool passkey_core_start(const passkey_usb_config_t *cfg);
const char *passkey_device_id(void);

size_t passkey_cdc_read(uint8_t *buf, size_t len, TickType_t wait);
void passkey_cdc_write(const char *data, size_t len);

bool passkey_mgmt_handle(const char *cmd, cJSON *q, cJSON **result, bool *ok, const char **error);

void passkey_add_storage(cJSON *obj);

void ctap_lock(void);
void ctap_unlock(void);


typedef enum { PASSKEY_LED_IDLE, PASSKEY_LED_TOUCH, PASSKEY_LED_OK, PASSKEY_LED_WINK } passkey_led_t;
void passkey_led(passkey_led_t mode, int ms);
