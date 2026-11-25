#include "radio.h"

#include <stdio.h>
#include <string.h>

#include "bootloader_random.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_random.h"
#include "mbedtls/base64.h"
#include "nvs.h"

#define NS "radio"
#define MAX_CLIENTS 8
#define LABEL_LEN 32

typedef struct {
    uint8_t kid[8];
    uint8_t key[32];
    char label[LABEL_LEN];
} client_t;

static uint32_t flags;
static char name[24];
static char ssid[33];
static char wpass[65];

static void secure_zero(void *p, size_t n) {
    volatile uint8_t *v = p;
    while (n--) *v++ = 0;
}

static void load(void) {
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) return;
    uint32_t f;
    if (nvs_get_u32(h, "flags", &f) == ESP_OK) flags = f & RADIO_WIFI_MIRROR;
    size_t n = sizeof(name);
    if (nvs_get_str(h, "name", name, &n) != ESP_OK) {
        uint16_t r;
        esp_fill_random(&r, sizeof(r));
        snprintf(name, sizeof(name), "ESP Crypt %04X", r);
        nvs_set_str(h, "name", name);
        nvs_commit(h);
    }
    n = sizeof(ssid);
    if (nvs_get_str(h, "ssid", ssid, &n) != ESP_OK) ssid[0] = 0;
    n = sizeof(wpass);
    if (nvs_get_str(h, "wpass", wpass, &n) != ESP_OK) wpass[0] = 0;
    nvs_close(h);
}

const char *radio_name(void) { return name; }

static bool safe_mode;

static void set_boots(uint8_t v) {
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_u8(h, "boots", v);
    nvs_commit(h);
    nvs_close(h);
}

static void radio_task(void *arg) {
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(1500));
    radio_init();
    vTaskDelay(pdMS_TO_TICKS(30000));
    set_boots(0);
    vTaskDelete(NULL);
}

void radio_init_later(void) {
    load();
    if (!((flags & RADIO_WIFI_ANY) && ssid[0])) return;
    uint8_t boots = 0;
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) == ESP_OK) {
        nvs_get_u8(h, "boots", &boots);
        nvs_close(h);
    }
    esp_reset_reason_t why = esp_reset_reason();
    bool crashed = why == ESP_RST_PANIC || why == ESP_RST_INT_WDT || why == ESP_RST_TASK_WDT || why == ESP_RST_WDT ||
                   why == ESP_RST_BROWNOUT;
    if (!crashed) boots = 0;
    if (boots >= 2) {
        safe_mode = true;
        return;
    }
    set_boots(boots + 1);
    xTaskCreate(radio_task, "radio_start", 6144, NULL, 3, NULL);
}

void radio_init(void) {
    load();
    bool wifi = (flags & RADIO_WIFI_ANY) && ssid[0];
    if (!wifi) return;
    bootloader_random_disable();
    if (wifi) {
        char host[32];
        snprintf(host, sizeof(host), "espcrypt-%s", name + strlen(name) - 4);
        for (char *c = host; *c; c++) if (*c >= 'A' && *c <= 'Z') *c += 32;
        radio_wifi_start(ssid, wpass, host);
    }
}

static bool in(const char *cmd, const char *const *list) {
    for (; *list; list++) if (strcmp(cmd, *list) == 0) return true;
    return false;
}

static const char *const ALWAYS[] = {"status", "lock", NULL};
static const char *const MIRROR[] = {"unlock", "backup_export", "backup_import_begin", "backup_import_write",
                                     "backup_import_end", "passkey_export", "passkey_import", NULL};

const char *radio_check_remote(int origin, const char *cmd) {
    if (in(cmd, ALWAYS)) return NULL;
    if (origin == ORIGIN_WIFI && (flags & RADIO_WIFI_MIRROR) && in(cmd, MIRROR)) return NULL;
    return "only mirror sync works over Wi-Fi; use USB for everything else";
}

bool radio_needs_confirm(int origin, const char *cmd) {
    (void)origin;
    (void)cmd;
    return false;
}

static bool get_client(nvs_handle_t h, int i, client_t *c) {
    char key[4];
    snprintf(key, sizeof(key), "c%d", i);
    size_t n = sizeof(*c);
    return nvs_get_blob(h, key, c, &n) == ESP_OK && n == sizeof(*c);
}

bool radio_client_key(const uint8_t kid[8], uint8_t out[32]) {
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) != ESP_OK) return false;
    bool found = false;
    client_t c;
    for (int i = 0; i < MAX_CLIENTS && !found; i++) {
        if (get_client(h, i, &c) && memcmp(c.kid, kid, 8) == 0) {
            memcpy(out, c.key, 32);
            found = true;
        }
    }
    secure_zero(&c, sizeof(c));
    nvs_close(h);
    return found;
}

static void hex8(const uint8_t *b, char out[17]) {
    for (int i = 0; i < 8; i++) sprintf(out + 2 * i, "%02x", b[i]);
}

static bool unhex8(const char *s, uint8_t out[8]) {
    if (strlen(s) != 16) return false;
    for (int i = 0; i < 8; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

static cJSON *clients_json(void) {
    cJSON *arr = cJSON_CreateArray();
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) != ESP_OK) return arr;
    client_t c;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!get_client(h, i, &c)) continue;
        cJSON *o = cJSON_CreateObject();
        char kid[17];
        hex8(c.kid, kid);
        c.label[LABEL_LEN - 1] = 0;
        cJSON_AddStringToObject(o, "kid", kid);
        cJSON_AddStringToObject(o, "label", c.label);
        cJSON_AddItemToArray(arr, o);
    }
    secure_zero(&c, sizeof(c));
    nvs_close(h);
    return arr;
}

#ifdef VAULT_DEV_LOOPBACK
static cJSON *loop_lines;
static void loop_write(void *ctx, const char *line, size_t len) {
    (void)ctx;
    if (loop_lines) cJSON_AddItemToArray(loop_lines, cJSON_CreateString(line));
    (void)len;
}
#endif

static const struct {
    const char *key;
    uint32_t bit;
} FEATURES[] = {{"wifiMirror", RADIO_WIFI_MIRROR}};
#define NFEATURES (sizeof(FEATURES) / sizeof(FEATURES[0]))

void radio_add_status(cJSON *result) {
    cJSON *r = cJSON_AddObjectToObject(result, "radio");
    cJSON_AddStringToObject(r, "name", name);
    cJSON *f = cJSON_AddObjectToObject(r, "features");
    for (size_t i = 0; i < NFEATURES; i++) cJSON_AddBoolToObject(f, FEATURES[i].key, flags & FEATURES[i].bit);
    char ip[16] = "";
    bool wifi_up = (flags & RADIO_WIFI_ANY) && ssid[0] && radio_wifi_status(ip);
    cJSON_AddStringToObject(r, "ssid", ssid);
    cJSON_AddBoolToObject(r, "wifiConnected", wifi_up);
    cJSON_AddStringToObject(r, "ip", ip);
    cJSON_AddNumberToObject(r, "port", RADIO_TCP_PORT);
    cJSON_AddBoolToObject(r, "safeMode", safe_mode);
    cJSON_AddItemToObject(r, "clients", clients_json());
}

void radio_command(const char *cmd, cJSON *q, cJSON **result, bool *ok, const char **error, bool *reboot) {
    *ok = true;
    if (strcmp(cmd, "radio_get") == 0) {
        cJSON *r = cJSON_CreateObject();
        radio_add_status(r);
        cJSON *inner = cJSON_DetachItemFromObject(r, "radio");
        cJSON_Delete(r);
        *result = inner;
    } else if (strcmp(cmd, "radio_set") == 0) {
        cJSON *dv = cJSON_GetObjectItemCaseSensitive(q, "data");
        cJSON *cfg = cJSON_IsString(dv) ? cJSON_Parse(dv->valuestring) : NULL;
        if (!cfg) {
            *ok = false;
            *error = "radio settings are missing";
            return;
        }
        uint32_t nf = flags;
        cJSON *feat = cJSON_GetObjectItemCaseSensitive(cfg, "features");
        for (size_t i = 0; i < NFEATURES; i++) {
            cJSON *b = cJSON_GetObjectItemCaseSensitive(feat, FEATURES[i].key);
            if (cJSON_IsBool(b)) nf = cJSON_IsTrue(b) ? (nf | FEATURES[i].bit) : (nf & ~FEATURES[i].bit);
        }

        cJSON *sv = cJSON_GetObjectItemCaseSensitive(cfg, "ssid");
        cJSON *pv = cJSON_GetObjectItemCaseSensitive(cfg, "password");
        cJSON *rn = cJSON_GetObjectItemCaseSensitive(cfg, "newName");
        const char *nssid = cJSON_IsString(sv) ? sv->valuestring : ssid;
        bool pass_change = cJSON_IsString(pv);
        if (strlen(nssid) > 32 || (pass_change && strlen(pv->valuestring) > 64)) {
            cJSON_Delete(cfg);
            *ok = false;
            *error = "Wi-Fi name or password is too long";
            return;
        }
        bool escalate = ((nf & ~flags) & RADIO_WIFI_MIRROR) ||
                        strcmp(nssid, ssid) != 0 || pass_change;
        if (escalate && !vault_boot_confirm(30)) {
            cJSON_Delete(cfg);
            *ok = false;
            *error = "not confirmed: press BOOT on the ESP32 within 30 seconds";
            return;
        }
        nvs_handle_t h;
        bool saved = nvs_open(NS, NVS_READWRITE, &h) == ESP_OK;
        if (saved) {
            saved = nvs_set_u32(h, "flags", nf) == ESP_OK && nvs_set_str(h, "ssid", nssid) == ESP_OK &&
                    nvs_set_u8(h, "boots", 0) == ESP_OK;
            if (saved && pass_change) saved = nvs_set_str(h, "wpass", pv->valuestring) == ESP_OK;
            if (saved && cJSON_IsTrue(rn)) {
                uint16_t r;
                esp_fill_random(&r, sizeof(r));
                char nn[24];
                snprintf(nn, sizeof(nn), "ESP Crypt %04X", r);
                saved = nvs_set_str(h, "name", nn) == ESP_OK;
            }
            if (saved) saved = nvs_commit(h) == ESP_OK;
            nvs_close(h);
        }
        if (pass_change) secure_zero(pv->valuestring, strlen(pv->valuestring));
        cJSON_Delete(cfg);
        if (!saved) {
            *ok = false;
            *error = "could not save the radio settings";
            return;
        }
        *reboot = true;
    } else if (strcmp(cmd, "radio_pair") == 0) {
        cJSON *lv = cJSON_GetObjectItemCaseSensitive(q, "label");
        const char *label = cJSON_IsString(lv) ? lv->valuestring : "app";
        nvs_handle_t h;
        if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) {
            *ok = false;
            *error = "storage is not ready";
            return;
        }
        client_t c;
        int slot = -1;
        for (int i = 0; i < MAX_CLIENTS && slot < 0; i++) if (!get_client(h, i, &c)) slot = i;
        if (slot < 0) {
            nvs_close(h);
            *ok = false;
            *error = "8 apps are paired already; remove one first";
            return;
        }
        if (!vault_boot_confirm(30)) {
            nvs_close(h);
            *ok = false;
            *error = "not confirmed: press BOOT on the ESP32 within 30 seconds";
            return;
        }
        memset(&c, 0, sizeof(c));
        esp_fill_random(c.kid, sizeof(c.kid));
        esp_fill_random(c.key, sizeof(c.key));
        strncpy(c.label, label, LABEL_LEN - 1);
        char key[4];
        snprintf(key, sizeof(key), "c%d", slot);
        bool saved = nvs_set_blob(h, key, &c, sizeof(c)) == ESP_OK && nvs_commit(h) == ESP_OK;
        nvs_close(h);
        if (!saved) {
            secure_zero(&c, sizeof(c));
            *ok = false;
            *error = "could not save the pairing";
            return;
        }
        char kid[17], key64[48];
        size_t n = 0;
        hex8(c.kid, kid);
        mbedtls_base64_encode((uint8_t *)key64, sizeof(key64), &n, c.key, 32);
        key64[n] = 0;
        cJSON *r = cJSON_CreateObject();
        cJSON_AddStringToObject(r, "kid", kid);
        cJSON_AddStringToObject(r, "key", key64);
        cJSON_AddStringToObject(r, "id", vault_device_id());
        cJSON_AddStringToObject(r, "name", name);
        *result = r;
        secure_zero(&c, sizeof(c));
        secure_zero(key64, sizeof(key64));
    } else if (strcmp(cmd, "radio_unpair") == 0) {
        cJSON *kv = cJSON_GetObjectItemCaseSensitive(q, "label");
        const char *which = cJSON_IsString(kv) ? kv->valuestring : "";
        uint8_t kid[8];
        bool all = strcmp(which, "all") == 0;
        if (!all && !unhex8(which, kid)) {
            *ok = false;
            *error = "unknown pairing";
            return;
        }
        nvs_handle_t h;
        if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) {
            *ok = false;
            *error = "storage is not ready";
            return;
        }
        client_t c;
        bool removed = false;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!get_client(h, i, &c) || (!all && memcmp(c.kid, kid, 8) != 0)) continue;
            char key[4];
            snprintf(key, sizeof(key), "c%d", i);
            removed = nvs_erase_key(h, key) == ESP_OK || removed;
        }
        nvs_commit(h);
        nvs_close(h);
        secure_zero(&c, sizeof(c));
        if (!removed && !all) {
            *ok = false;
            *error = "unknown pairing";
            return;
        }
        *reboot = true;
#ifdef VAULT_DEV_LOOPBACK
    } else if (strcmp(cmd, "radio_devconfirm") == 0) {
        extern volatile bool vault_dev_confirm_once;
        vault_dev_confirm_once = true;
    } else if (strcmp(cmd, "radio_loop") == 0) {
        static rsess_t *loop;
        cJSON *lv = cJSON_GetObjectItemCaseSensitive(q, "label");
        cJSON *dv = cJSON_GetObjectItemCaseSensitive(q, "data");
        const char *mode = cJSON_IsString(lv) ? lv->valuestring : "";
        cJSON *lines = cJSON_CreateArray();
        if (strcmp(mode, "wifi") == 0) {
            rsess_free(loop);
            loop = rsess_new(ORIGIN_WIFI, loop_write, lines);
        } else if (loop && cJSON_IsString(dv)) {
            loop_lines = lines;
            if (!rsess_input(loop, dv->valuestring)) {
                rsess_free(loop);
                loop = NULL;
            }
            loop_lines = NULL;
        }
        cJSON *r = cJSON_CreateObject();
        cJSON_AddItemToObject(r, "lines", lines);
        *result = r;
#endif
    } else {
        *ok = false;
        *error = "unknown radio command";
    }
}
