#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cJSON.h"

enum { ORIGIN_USB = 0, ORIGIN_WIFI = 1, ORIGIN_BLE = 2 };

#define RADIO_WIFI_MIRROR (1u << 1)
#define RADIO_WIFI_ANY RADIO_WIFI_MIRROR

#define RADIO_TCP_PORT 7531

typedef void (*vault_sink_t)(void *ctx, const char *line, size_t len);

void vault_handle_line(const char *line, int origin, vault_sink_t sink, void *ctx);
bool vault_boot_confirm(int seconds);
const char *vault_device_id(void);
const char *vault_chip_name(void);

void radio_init(void);
void radio_init_later(void);
const char *radio_name(void);
const char *radio_check_remote(int origin, const char *cmd);
bool radio_needs_confirm(int origin, const char *cmd);
void radio_command(const char *cmd, cJSON *q, cJSON **result, bool *ok, const char **error, bool *reboot);
void radio_add_status(cJSON *result);
bool radio_client_key(const uint8_t kid[8], uint8_t key[32]);

typedef void (*rsess_write_t)(void *ctx, const char *line, size_t len);
typedef struct rsess rsess_t;
rsess_t *rsess_new(int origin, rsess_write_t write, void *ctx);
void rsess_free(rsess_t *s);
bool rsess_input(rsess_t *s, const char *line);
bool rsess_ready(const rsess_t *s);

void radio_wifi_start(const char *ssid, const char *password, const char *hostname);
bool radio_wifi_status(char ip[16]);
