#include "board_led.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>

#include "bootloader_random.h"
#include "cJSON.h"
#include "driver/gpio.h"
#if CONFIG_VAULT_WITH_PASSKEY
#include "ctap2.h"
#include "passkey_core.h"
#include "soc/rtc_cntl_reg.h"
#include "store.h"
#else
#include "driver/usb_serial_jtag.h"
#endif
#include "esp_flash_encrypt.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_ota_ops.h"
#include "esp_app_desc.h"
#include "esp_partition.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_secure_boot.h"
#include "esp_system.h"
#include "mbedtls/gcm.h"
#include "mbedtls/base64.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pkcs5.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "radio.h"
#include "pbkdf2_fast.h"

#define PIN_MIN 4
#define PIN_MAX 64
#define MAX_OBJECT_SIZE 4096
#define MAX_OBJECTS 16
#define PBKDF2_ROUNDS 200000
#define SALT_SIZE 16
#define NONCE_SIZE 12
#define TAG_SIZE 16
#define HEADER_SIZE (SALT_SIZE + NONCE_SIZE + 4)
#define MAX_LINE (40 * 1024)
#define MAX_BLOB (96 * 1024)
#define BACKUP_CHUNK 6144

static cJSON *objects;
static uint32_t vault_rev;
static volatile bool container_changed = true;
static uint8_t *import_buf;
static size_t import_size, import_got;
static uint32_t import_rev;
static uint8_t session_key[32];
static uint8_t session_salt[SALT_SIZE];
static bool unlocked;
static bool storage_ready;
static uint8_t pin_failures;
static bool ota_active;
static bool reboot_after_reply;
static esp_ota_handle_t ota_handle;
static const esp_partition_t *ota_partition;
static size_t ota_expected;
static size_t ota_received;
static char device_serial[16];
static char device_id[16];

static SemaphoreHandle_t cmd_lock;
static int cur_origin = ORIGIN_USB;
static vault_sink_t cur_sink;
static void *cur_sink_ctx;

#if CONFIG_SECURE_BOOT || CONFIG_SECURE_FLASH_ENC_ENABLED || CONFIG_NVS_ENCRYPTION
#error "Default Vault firmware must stay reflashable and must not enable eFuse-locking security"
#endif
#if !CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT || !CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME || \
    !CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT || !CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES
#error "Vault OTA requires signed RSA app images without hardware Secure Boot"
#endif

typedef enum { LED_EVT_NONE, LED_EVT_ACTIVITY, LED_EVT_SIGN, LED_EVT_ERROR, LED_EVT_OK } led_event_t;

static bool vault_initialized;
static volatile bool led_busy;
static volatile bool led_ota;
static volatile led_event_t led_event;
static volatile bool led_confirm;
static volatile int64_t led_sync_until;

static void led_set(bool on) { board_led_set(on); }
static void led_rgb(uint8_t r, uint8_t g, uint8_t b) { board_led_rgb(r, g, b); }

#if CONFIG_VAULT_WITH_PASSKEY
static volatile passkey_led_t pk_led = PASSKEY_LED_IDLE;
static volatile int64_t pk_led_until;

void passkey_led(passkey_led_t mode, int ms) {
    pk_led = mode;
    pk_led_until = ms ? esp_timer_get_time() + ms * 1000LL : 0;
}

static bool passkey_led_tick(uint32_t tick) {
    if (pk_led_until && esp_timer_get_time() > pk_led_until) {
        pk_led = PASSKEY_LED_IDLE;
        pk_led_until = 0;
    }
    switch (pk_led) {
    case PASSKEY_LED_TOUCH: board_led_rgb((tick / 12) % 2 ? 40 : 0, (tick / 12) % 2 ? 40 : 0, (tick / 12) % 2 ? 40 : 0); return true;
    case PASSKEY_LED_OK: board_led_rgb(0, 40, 0); return true;
    case PASSKEY_LED_WINK: board_led_rgb(0, (tick / 8) % 2 ? 30 : 0, (tick / 8) % 2 ? 60 : 0); return true;
    default: return false;
    }
}
#endif

static void led_blink_rgb(int times, int on_ms, int off_ms, uint8_t r, uint8_t g, uint8_t b) {
    for (int i = 0; i < times; i++) {
        led_rgb(r, g, b);
        vTaskDelay(pdMS_TO_TICKS(on_ms));
        led_rgb(0, 0, 0);
        vTaskDelay(pdMS_TO_TICKS(off_ms));
    }
}

static void led_task(void *arg) {
    (void)arg;
    uint32_t tick = 0;
    for (;;) {
        led_event_t ev = led_event;
        if (ev != LED_EVT_NONE) {
            led_event = LED_EVT_NONE;
            if (ev == LED_EVT_ERROR) led_blink_rgb(3, 300, 200, 40, 0, 0);
            else if (ev == LED_EVT_SIGN || ev == LED_EVT_OK) {
                led_rgb(0, 40, 0);
                vTaskDelay(pdMS_TO_TICKS(600));
            }
            tick = 0;
            continue;
        }
#if CONFIG_VAULT_WITH_PASSKEY
        if (passkey_led_tick(tick)) {
            vTaskDelay(pdMS_TO_TICKS(10));
            tick++;
            continue;
        }
#endif
        bool fast = (tick / 6) % 2;
        bool slow = (tick % 300) < 150;
        if (led_confirm) {
            bool on = (tick / 12) % 2;
            led_rgb(on ? 40 : 0, on ? 40 : 0, on ? 40 : 0);
        } else if (led_ota) {
            led_rgb(fast ? 40 : 0, fast ? 30 : 0, 0);
        } else if (led_busy) {
            led_rgb(fast ? 40 : 0, fast ? 12 : 0, 0);
        } else if (esp_timer_get_time() < led_sync_until) {
            led_rgb(0, fast ? 40 : 0, 0);
        } else if (storage_ready && vault_initialized && unlocked) {
            led_rgb(0, slow ? 40 : 0, 0);
        } else if (storage_ready && vault_initialized) {
            led_rgb(slow ? 40 : 0, 0, 0);
        } else {
            led_rgb(slow ? 24 : 0, 0, slow ? 40 : 0);
        }
        vTaskDelay(pdMS_TO_TICKS(10));
        tick++;
    }
}

static void led_start(void) {
    board_led_init();
    led_set(false);
    xTaskCreate(led_task, "led", 2048, NULL, 1, NULL);
}

static const char *chip_name(void) {
#if CONFIG_IDF_TARGET_ESP32C3
    return "ESP32-C3";
#elif CONFIG_IDF_TARGET_ESP32C6
    return "ESP32-C6";
#elif CONFIG_IDF_TARGET_ESP32S3
    return "ESP32-S3";
#else
    return "unsupported";
#endif
}

static void secure_zero(void *data, size_t size) {
    volatile uint8_t *p = (volatile uint8_t *)data;
    while (size--) *p++ = 0;
}

static void wipe_json_node(cJSON *item) {
    if (!item) return;
    for (cJSON *child = item->child; child; child = child->next) wipe_json_node(child);
    if (item->valuestring) secure_zero(item->valuestring, strlen(item->valuestring));
    if (item->string) secure_zero(item->string, strlen(item->string));
    item->valueint = 0;
    item->valuedouble = 0;
}

static void wipe_json_tree(cJSON *item) {
    for (; item; item = item->next) wipe_json_node(item);
}

static bool initialize_nvs(void) {
    if (storage_ready) return true;
    esp_err_t err = nvs_flash_init();
    storage_ready = err == ESP_OK;
    return storage_ready;
}

static void erase_session(void) {
    if (objects) {
        wipe_json_tree(objects);
        cJSON_Delete(objects);
        objects = NULL;
    }
    secure_zero(session_key, sizeof(session_key));
    secure_zero(session_salt, sizeof(session_salt));
    unlocked = false;
}

static void abort_ota(void) {
    if (ota_active) (void)esp_ota_abort(ota_handle);
    ota_active = false;
    led_ota = false;
    ota_partition = NULL;
    ota_expected = 0;
    ota_received = 0;
}

static int derive_key(const char *pin, const uint8_t salt[SALT_SIZE], uint8_t key[32]) {
    led_busy = true;
    pbkdf2_sha256_32((const uint8_t *)pin, strlen(pin), salt, SALT_SIZE, PBKDF2_ROUNDS, key);
    led_busy = false;
    return 0;
}

static bool pin_valid(const char *pin) {
    size_t n = pin ? strlen(pin) : 0;
    return n >= PIN_MIN && n <= PIN_MAX;
}

static uint8_t read_pin_failures(void) {
    nvs_handle_t nvs;
    uint8_t count = 0;
    if (nvs_open("vault", NVS_READONLY, &nvs) == ESP_OK) {
        (void)nvs_get_u8(nvs, "pin_fail", &count);
        nvs_close(nvs);
    }
    return count;
}

static void write_pin_failures(uint8_t count) {
    nvs_handle_t nvs;
    if (nvs_open("vault", NVS_READWRITE, &nvs) == ESP_OK) {
        if (nvs_set_u8(nvs, "pin_fail", count) == ESP_OK) (void)nvs_commit(nvs);
        nvs_close(nvs);
    }
}

static uint32_t pin_retry_delay(uint8_t failures) {
    if (failures >= 7) return 60;
    return 1U << (failures - 1);
}

static esp_err_t read_blob(uint8_t **out, size_t *out_len) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("vault", NVS_READONLY, &nvs);
    if (err != ESP_OK) return err;
    size_t n = 0;
    err = nvs_get_blob(nvs, "sealed", NULL, &n);
    if (err != ESP_OK || n < HEADER_SIZE + TAG_SIZE || n > MAX_BLOB) {
        nvs_close(nvs);
        return err == ESP_OK ? ESP_ERR_INVALID_SIZE : err;
    }
    uint8_t *blob = malloc(n);
    if (!blob) {
        nvs_close(nvs);
        return ESP_ERR_NO_MEM;
    }
    err = nvs_get_blob(nvs, "sealed", blob, &n);
    nvs_close(nvs);
    if (err != ESP_OK) {
        free(blob);
        return err;
    }
    *out = blob;
    *out_len = n;
    return ESP_OK;
}

static bool seal_and_save(const char *pin, cJSON *new_objects) {
	if (!pin_valid(pin)) return false;
	cJSON *copy = cJSON_Duplicate(new_objects, 1);
	if (!copy) return false;
    char *plain = cJSON_PrintUnformatted(new_objects);
    if (!plain) { wipe_json_tree(copy); cJSON_Delete(copy); return false; }
    size_t plain_len = strlen(plain);
    if (plain_len == 0 || plain_len + HEADER_SIZE + TAG_SIZE > MAX_BLOB) {
        secure_zero(plain, plain_len);
        free(plain);
		wipe_json_tree(copy);
		cJSON_Delete(copy);
        return false;
    }
    size_t blob_len = HEADER_SIZE + plain_len + TAG_SIZE;
    uint8_t *blob = calloc(1, blob_len);
    if (!blob) {
		wipe_json_tree(copy);
		cJSON_Delete(copy);
        secure_zero(plain, plain_len);
        free(plain);
        return false;
    }
    esp_fill_random(blob, SALT_SIZE + NONCE_SIZE);
    blob[28] = (uint8_t)(plain_len);
    blob[29] = (uint8_t)(plain_len >> 8);
    blob[30] = (uint8_t)(plain_len >> 16);
    blob[31] = (uint8_t)(plain_len >> 24);
    uint8_t key[32];
    bool ok = derive_key(pin, blob, key) == 0;
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if (ok) ok = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) == 0;
    if (ok) ok = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plain_len,
        blob + SALT_SIZE, NONCE_SIZE, NULL, 0, (const uint8_t *)plain,
        blob + HEADER_SIZE, TAG_SIZE, blob + HEADER_SIZE + plain_len) == 0;
    mbedtls_gcm_free(&gcm);
    secure_zero(plain, plain_len);
    free(plain);
    if (ok) {
        nvs_handle_t nvs;
        if (nvs_open("vault", NVS_READWRITE, &nvs) == ESP_OK) {
            ok = (container_changed = true, nvs_set_blob)(nvs, "sealed", blob, blob_len) == ESP_OK &&
                 nvs_set_u32(nvs, "rev", vault_rev + 1) == ESP_OK && nvs_commit(nvs) == ESP_OK;
            if (ok) vault_rev++;
            nvs_close(nvs);
        } else {
            ok = false;
        }
    }
    if (ok) {
        erase_session();
        memcpy(session_key, key, sizeof(session_key));
        memcpy(session_salt, blob, sizeof(session_salt));
        objects = copy;
        unlocked = true;
        vault_initialized = true;
        copy = NULL;
    }
    secure_zero(key, sizeof(key));
    if (copy) wipe_json_tree(copy);
    cJSON_Delete(copy);
    secure_zero(blob, blob_len);
    free(blob);
    return ok;
}

static bool unlock_store(const char *pin) {
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    if (!pin_valid(pin) || read_blob(&blob, &blob_len) != ESP_OK) return false;
    pin_failures = read_pin_failures();
    if (pin_failures > 0) {
        vTaskDelay(pdMS_TO_TICKS(pin_retry_delay(pin_failures) * 1000U));
    }
    uint32_t plain_len = (uint32_t)blob[28] | ((uint32_t)blob[29] << 8) |
                         ((uint32_t)blob[30] << 16) | ((uint32_t)blob[31] << 24);
    if (plain_len == 0 || HEADER_SIZE + plain_len + TAG_SIZE != blob_len) {
        free(blob);
        return false;
    }
    uint8_t key[32];
    bool ok = derive_key(pin, blob, key) == 0;
    uint8_t *plain = malloc(plain_len + 1);
    if (!plain) ok = false;
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if (ok) ok = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) == 0;
    if (ok) ok = mbedtls_gcm_auth_decrypt(&gcm, plain_len, blob + SALT_SIZE, NONCE_SIZE,
        NULL, 0, blob + HEADER_SIZE + plain_len, TAG_SIZE, blob + HEADER_SIZE, plain) == 0;
    mbedtls_gcm_free(&gcm);
    if (ok) {
        plain[plain_len] = 0;
        cJSON *parsed = cJSON_Parse((const char *)plain);
        if (!cJSON_IsArray(parsed)) {
            wipe_json_tree(parsed);
            cJSON_Delete(parsed);
            ok = false;
        } else {
            erase_session();
            objects = parsed;
            memcpy(session_key, key, sizeof(session_key));
            memcpy(session_salt, blob, sizeof(session_salt));
            unlocked = true;
        }
    }
    if (ok) {
        pin_failures = 0;
        write_pin_failures(0);
    } else {
        if (pin_failures < UINT8_MAX) pin_failures++;
        write_pin_failures(pin_failures);
    }
    if (plain) {
        secure_zero(plain, plain_len + 1);
        free(plain);
    }
    secure_zero(key, sizeof(key));
    secure_zero(blob, blob_len);
    free(blob);
    return ok;
}

static bool save_session_objects(cJSON *new_objects) {
    if (!unlocked || !new_objects) return false;
    char *plain = cJSON_PrintUnformatted(new_objects);
    if (!plain) return false;
    size_t plain_len = strlen(plain);
    if (plain_len == 0 || plain_len + HEADER_SIZE + TAG_SIZE > MAX_BLOB) {
        secure_zero(plain, plain_len);
        free(plain);
        return false;
    }
    size_t blob_len = HEADER_SIZE + plain_len + TAG_SIZE;
    uint8_t *blob = calloc(1, blob_len);
    if (!blob) { secure_zero(plain, plain_len); free(plain); return false; }
    memcpy(blob, session_salt, SALT_SIZE);
    esp_fill_random(blob + SALT_SIZE, NONCE_SIZE);
    blob[28] = (uint8_t)(plain_len);
    blob[29] = (uint8_t)(plain_len >> 8);
    blob[30] = (uint8_t)(plain_len >> 16);
    blob[31] = (uint8_t)(plain_len >> 24);
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    bool ok = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, session_key, 256) == 0;
    if (ok) ok = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plain_len,
        blob + SALT_SIZE, NONCE_SIZE, NULL, 0, (const uint8_t *)plain,
        blob + HEADER_SIZE, TAG_SIZE, blob + HEADER_SIZE + plain_len) == 0;
    mbedtls_gcm_free(&gcm);
    secure_zero(plain, plain_len);
    free(plain);
    if (ok) {
        nvs_handle_t nvs;
        if (nvs_open("vault", NVS_READWRITE, &nvs) == ESP_OK) {
            ok = (container_changed = true, nvs_set_blob)(nvs, "sealed", blob, blob_len) == ESP_OK &&
                 nvs_set_u32(nvs, "rev", vault_rev + 1) == ESP_OK && nvs_commit(nvs) == ESP_OK;
            if (ok) vault_rev++;
            nvs_close(nvs);
        } else ok = false;
    }
    secure_zero(blob, blob_len);
    free(blob);
    return ok;
}

static bool commit_session_objects(cJSON *candidate) {
    if (!candidate || !save_session_objects(candidate)) return false;
    cJSON *old = objects;
    objects = candidate;
    wipe_json_tree(old);
    cJSON_Delete(old);
    return true;
}

static void write_all(const char *data, size_t len) {
#if CONFIG_VAULT_WITH_PASSKEY
    passkey_cdc_write(data, len);
#else
    while (len) {
        int n = usb_serial_jtag_write_bytes(data, len, pdMS_TO_TICKS(1000));
        if (n <= 0) return;
        data += n;
        len -= (size_t)n;
    }
#endif
}

static void send_reply_to(vault_sink_t sink, void *sink_ctx, uint32_t id, bool ok, const char *error, cJSON *result);

static void send_reply(uint32_t id, bool ok, const char *error, cJSON *result) {
    send_reply_to(cur_sink, cur_sink_ctx, id, ok, error, result);
}

static void send_reply_to(vault_sink_t sink, void *sink_ctx, uint32_t id, bool ok, const char *error, cJSON *result) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "id", id);
    cJSON_AddBoolToObject(root, "ok", ok);
    if (!ok) cJSON_AddStringToObject(root, "error", error ? error : "operation failed");
    if (result) cJSON_AddItemToObject(root, "result", result);
    else cJSON_AddNullToObject(root, "result");
    char *line = cJSON_PrintUnformatted(root);
    if (line) {
        if (sink) sink(sink_ctx, line, strlen(line));
        else {
            write_all(line, strlen(line));
            write_all("\n", 1);
        }
        secure_zero(line, strlen(line));
        free(line);
    }
    wipe_json_tree(root);
    cJSON_Delete(root);
}

static const char *get_string(cJSON *root, const char *key) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(root, key);
    return cJSON_IsString(v) ? v->valuestring : "";
}

static int get_id(cJSON *root) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(root, "objectId");
    return cJSON_IsNumber(v) ? v->valueint : 0;
}

static size_t base64_decoded_length(const char *encoded) {
    size_t n = strlen(encoded);
    size_t decoded = (n / 4) * 3;
    if (n && encoded[n - 1] == '=') decoded--;
    if (n > 1 && encoded[n - 2] == '=') decoded--;
    return decoded;
}

static cJSON *find_object_in(cJSON *list, int id, int *index) {
    if (!list || id < 1 || id > 255) return NULL;
    int i = 0;
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, list) {
        cJSON *v = cJSON_GetObjectItemCaseSensitive(item, "id");
        if (cJSON_IsNumber(v) && v->valueint == id) {
            if (index) *index = i;
            return item;
        }
        i++;
    }
    return NULL;
}

static cJSON *find_object(int id, int *index) {
    return find_object_in(objects, id, index);
}

static int next_id(void) {
    for (int id = 1; id <= 255; id++) if (!find_object(id, NULL)) return id;
    return 0;
}

static bool is_ssh_item(cJSON *item) {
    return strcmp(get_string(item, "kind"), "ssh") == 0;
}

static int vault_rng(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    esp_fill_random(out, len);
    return 0;
}

static char *b64_encode(const uint8_t *data, size_t len) {
    size_t cap = 4 * ((len + 2) / 3) + 1, out_len = 0;
    char *out = malloc(cap);
    if (out && mbedtls_base64_encode((uint8_t *)out, cap, &out_len, data, len) != 0) {
        free(out);
        out = NULL;
    }
    return out;
}

static bool b64_decode_exact(const char *encoded, uint8_t *out, size_t want) {
    size_t got = 0;
    return base64_decoded_length(encoded) == want &&
           mbedtls_base64_decode(out, want, &got, (const uint8_t *)encoded, strlen(encoded)) == 0 && got == want;
}

static bool ssh_generate_key(uint8_t priv[32], uint8_t pub[65]) {
    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    size_t n = 0, m = 0;
    bool ok = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &key, vault_rng, NULL) == 0 &&
              mbedtls_ecp_write_key_ext(&key, &n, priv, 32) == 0 && n == 32 &&
              mbedtls_ecp_write_public_key(&key, MBEDTLS_ECP_PF_UNCOMPRESSED, &m, pub, 65) == 0 && m == 65;
    mbedtls_ecp_keypair_free(&key);
    return ok;
}

static bool ssh_sign_digest(const uint8_t priv[32], const uint8_t digest[32], uint8_t r_out[32], uint8_t s_out[32]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    bool ok = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
              mbedtls_mpi_read_binary(&d, priv, 32) == 0 &&
              mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d, digest, 32, MBEDTLS_MD_SHA256, vault_rng, NULL) == 0 &&
              mbedtls_mpi_write_binary(&r, r_out, 32) == 0 &&
              mbedtls_mpi_write_binary(&s, s_out, 32) == 0;
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

static void add_storage(cJSON *result) {
    nvs_stats_t st;
    cJSON *s = cJSON_AddObjectToObject(result, "storage");
    if (nvs_get_stats(NULL, &st) == ESP_OK) {
        const esp_partition_t *p = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, NULL);
        cJSON_AddNumberToObject(s, "usedEntries", st.used_entries);
        cJSON_AddNumberToObject(s, "freeEntries", st.free_entries);
        cJSON_AddNumberToObject(s, "totalEntries", st.total_entries);
        cJSON_AddNumberToObject(s, "entryBytes", 32);
        cJSON_AddNumberToObject(s, "partitionBytes", p ? p->size : 0);
    }
    size_t sealed = 0;
    nvs_handle_t nvs;
    if (storage_ready && nvs_open("vault", NVS_READONLY, &nvs) == ESP_OK) {
        if (nvs_get_blob(nvs, "sealed", NULL, &sealed) != ESP_OK) sealed = 0;
        nvs_close(nvs);
    }
    cJSON_AddNumberToObject(s, "containerBytes", sealed);
    cJSON_AddNumberToObject(s, "maxContainerBytes", MAX_BLOB);
    cJSON_AddNumberToObject(s, "maxObjects", MAX_OBJECTS);
    cJSON_AddNumberToObject(s, "maxObjectBytes", MAX_OBJECT_SIZE);
    if (unlocked && objects) cJSON_AddNumberToObject(s, "objects", cJSON_GetArraySize(objects));
}

static char container_hash[17];
static uint32_t container_hash_rev = UINT32_MAX;

static const char *container_digest(void) {
    if (!container_changed && container_hash_rev == vault_rev && container_hash[0]) return container_hash;
    container_changed = false;
    uint8_t *blob = NULL;
    size_t n = 0;
    container_hash[0] = 0;
    if (storage_ready && read_blob(&blob, &n) == ESP_OK) {
        uint8_t d[32];
        mbedtls_sha256(blob, n, d, 0);
        for (int i = 0; i < 8; i++) sprintf(container_hash + 2 * i, "%02x", d[i]);
    }
    free(blob);
    container_hash_rev = vault_rev;
    return container_hash;
}

static cJSON *status_result(int origin, bool busy) {
    cJSON *result = cJSON_CreateObject();
        bool initialized = false;
        if (storage_ready) {
            nvs_handle_t nvs;
        size_t size = 0;
            initialized = nvs_open("vault", NVS_READONLY, &nvs) == ESP_OK;
            if (initialized) {
            initialized = nvs_get_blob(nvs, "sealed", NULL, &size) == ESP_OK && size >= HEADER_SIZE + TAG_SIZE;
            nvs_close(nvs);
            }
        }
		cJSON_AddStringToObject(result, "chip", chip_name());
        cJSON_AddBoolToObject(result, "initialized", initialized);
        cJSON_AddBoolToObject(result, "unlocked", unlocked);
        cJSON_AddStringToObject(result, "serial", device_serial);
        cJSON_AddStringToObject(result, "deviceId", device_id);
        cJSON_AddBoolToObject(result, "secureBoot", esp_secure_boot_enabled());
        cJSON_AddBoolToObject(result, "flashEncrypted", esp_flash_encryption_enabled());
        cJSON_AddBoolToObject(result, "storageReady", storage_ready);
        cJSON_AddNumberToObject(result, "rev", vault_rev);
        if (!busy) cJSON_AddStringToObject(result, "containerHash", container_digest());
        const esp_app_desc_t *app = esp_app_get_description();
        cJSON_AddStringToObject(result, "version", app->version);
        char built[40];
        snprintf(built, sizeof(built), "%s %s", app->date, app->time);
        cJSON_AddStringToObject(result, "built", built);
        cJSON_AddStringToObject(result, "via", origin == ORIGIN_WIFI ? "wifi" : origin == ORIGIN_BLE ? "ble" : "usb");
        cJSON_AddNumberToObject(result, "heapFree", esp_get_free_heap_size());
        cJSON_AddNumberToObject(result, "heapMin", esp_get_minimum_free_heap_size());
        cJSON_AddStringToObject(result, "kdf", pbkdf2_path());
        cJSON_AddNumberToObject(result, "uptime", (double)(esp_timer_get_time() / 1000000));
        static const char *const REASONS[] = {"unknown", "power on", "external", "software", "panic", "interrupt watchdog",
                                              "task watchdog", "watchdog", "deep sleep", "brownout", "sdio", "usb", "jtag",
                                              "efuse", "power glitch", "cpu lockup"};
        esp_reset_reason_t rr = esp_reset_reason();
        cJSON_AddStringToObject(result, "resetReason", rr < sizeof(REASONS) / sizeof(REASONS[0]) ? REASONS[rr] : "other");
        radio_add_status(result);
#if CONFIG_VAULT_WITH_PASSKEY
        cJSON_AddBoolToObject(result, "passkey", true);
        cJSON_AddNumberToObject(result, "passkeyRev", store_rev());
        cJSON_AddStringToObject(result, "firmware", "vaultkey");
#else
        cJSON_AddStringToObject(result, "firmware", "vault");
#endif
    if (busy) cJSON_AddBoolToObject(result, "busy", true);
    else add_storage(result);
    return result;
}

static void handle(cJSON *q) {
    cJSON *idv = cJSON_GetObjectItemCaseSensitive(q, "id");
    uint32_t id = cJSON_IsNumber(idv) ? (uint32_t)idv->valuedouble : 0;
    const char *cmd = get_string(q, "command");
    cJSON *result = NULL;
    const char *error = NULL;
    bool ok = true;
    if (cur_origin != ORIGIN_USB) {
        if (strncmp(cmd, "backup_", 7) == 0 || strncmp(cmd, "passkey_", 8) == 0)
            led_sync_until = esp_timer_get_time() + 1500000;
        const char *why = radio_check_remote(cur_origin, cmd);
        if (why) {
            send_reply(id, false, why, NULL);
            return;
        }
        if (radio_needs_confirm(cur_origin, cmd) && !vault_boot_confirm(30)) {
            send_reply(id, false, "not confirmed: press BOOT on the ESP32 to allow this", NULL);
            return;
        }
    }
#if CONFIG_VAULT_WITH_PASSKEY
    if (strncmp(cmd, "passkey_", 8) == 0) {
        cJSON *r = NULL;
        bool pok;
        const char *perr;
        if (passkey_mgmt_handle(cmd, q, &r, &pok, &perr)) {
            send_reply(id, pok, perr, r);
            return;
        }
    }
    if (strcmp(cmd, "download") == 0) {
        send_reply(id, true, NULL, NULL);
        vTaskDelay(pdMS_TO_TICKS(200));
        REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
        esp_restart();
    }
#endif
	if (strcmp(cmd, "status") != 0 && strcmp(cmd, "init_storage") != 0 && !storage_ready) {
		send_reply(id, false, "Vault storage is not initialized", NULL);
		return;
	}

    if (strcmp(cmd, "status") == 0) {
        result = status_result(cur_origin, false);
    } else if (strncmp(cmd, "radio_", 6) == 0) {
        bool reboot = false;
        radio_command(cmd, q, &result, &ok, &error, &reboot);
        if (reboot) reboot_after_reply = true;
    } else if (strcmp(cmd, "init_storage") == 0) {
        if (!initialize_nvs()) { ok = false; error = "NVS initialization failed; existing data was not erased"; }
    } else if (strcmp(cmd, "ota_begin") == 0) {
        cJSON *v = cJSON_GetObjectItemCaseSensitive(q, "size");
        size_t image_size = cJSON_IsNumber(v) && v->valuedouble > 0 ? (size_t)v->valuedouble : 0;
        if (ota_active) { ok = false; error = "firmware update is already running"; }
        else if (image_size < 32) { ok = false; error = "firmware image is empty or invalid"; }
        else {
            ota_partition = esp_ota_get_next_update_partition(NULL);
            if (!ota_partition || image_size > ota_partition->size) { ok = false; error = "firmware image does not fit the OTA slot"; }
            else {
                esp_err_t e = esp_ota_begin(ota_partition, image_size, &ota_handle);
                if (e != ESP_OK) { ok = false; error = "could not start signed firmware update"; }
                else { ota_expected = image_size; ota_received = 0; ota_active = true; led_ota = true; }
            }
        }
    } else if (strcmp(cmd, "ota_write") == 0) {
        const char *encoded = get_string(q, "data");
        size_t encoded_len = strlen(encoded);
        size_t decoded_len = base64_decoded_length(encoded);
        uint8_t *chunk = malloc(decoded_len ? decoded_len : 1);
        if (!ota_active) { ok = false; error = "no firmware update is running"; }
        else if (!chunk || decoded_len == 0 || ota_received + decoded_len > ota_expected) {
            abort_ota();
            ok = false; error = "invalid firmware chunk";
        }
        else if (mbedtls_base64_decode(chunk, decoded_len, &decoded_len, (const uint8_t *)encoded, encoded_len) != 0 ||
                 esp_ota_write(ota_handle, chunk, decoded_len) != ESP_OK) {
            abort_ota();
            ok = false; error = "writing firmware chunk failed";
        }
        else { ota_received += decoded_len; }
        if (chunk) { secure_zero(chunk, decoded_len); free(chunk); }
    } else if (strcmp(cmd, "ota_abort") == 0) {
        abort_ota();
    } else if (strcmp(cmd, "ota_end") == 0) {
        if (!ota_active) { ok = false; error = "no firmware update is running"; }
        else if (ota_received != ota_expected) { abort_ota(); ok = false; error = "firmware image is incomplete"; }
        else {
            esp_err_t e = esp_ota_end(ota_handle);
            ota_active = false;
            led_ota = false;
            ota_expected = 0;
            ota_received = 0;
            if (e != ESP_OK) { ok = false; error = "firmware signature or image validation failed"; }
            else if (esp_ota_set_boot_partition(ota_partition) != ESP_OK) { ok = false; error = "could not select updated firmware"; }
            else { reboot_after_reply = true; }
        }
    } else if (strcmp(cmd, "setup_pin") == 0) {
        const char *pin = get_string(q, "pin");
        if (!pin_valid(pin)) { ok = false; error = "Vault PIN or passphrase must be 4 to 64 bytes"; }
        else {
            nvs_handle_t nvs;
            size_t size = 0;
            bool already = nvs_open("vault", NVS_READONLY, &nvs) == ESP_OK;
            if (already) {
                already = nvs_get_blob(nvs, "sealed", NULL, &size) == ESP_OK;
                nvs_close(nvs);
            }
            if (already) { ok = false; error = "Vault passphrase is already set"; }
            else {
                cJSON *empty = cJSON_CreateArray();
                ok = seal_and_save(pin, empty);
                cJSON_Delete(empty);
                if (!ok) error = "could not initialize encrypted storage";
            }
        }
    } else if (strcmp(cmd, "unlock") == 0) {
        ok = unlock_store(get_string(q, "pin"));
        if (!ok) error = "incorrect passphrase or damaged encrypted storage";
    } else if (strcmp(cmd, "lock") == 0) {
        erase_session();
    } else if (strcmp(cmd, "change_pin") == 0) {
        const char *old_pin = get_string(q, "pin");
        const char *new_pin = get_string(q, "newPin");
        if (!pin_valid(new_pin)) { ok = false; error = "new Vault PIN or passphrase must be 4 to 64 bytes"; }
        else if (!unlock_store(old_pin)) { ok = false; error = "incorrect passphrase"; }
        else if (!seal_and_save(new_pin, objects)) { ok = false; error = "could not save encrypted storage"; }
    } else if (strcmp(cmd, "list") == 0) {
        if (!unlocked) { ok = false; error = "locked"; }
        else {
            result = cJSON_CreateObject();
            cJSON *list = cJSON_CreateArray();
            cJSON *item = NULL;
            cJSON_ArrayForEach(item, objects) {
                if (is_ssh_item(item)) continue;
                cJSON *idv = cJSON_GetObjectItemCaseSensitive(item, "id");
                int item_id = cJSON_IsNumber(idv) ? idv->valueint : 0;
                char fid[16]; snprintf(fid, sizeof(fid), "EV%04X", item_id);
                cJSON *out = cJSON_CreateObject();
                cJSON_AddNumberToObject(out, "id", item_id);
                cJSON_AddStringToObject(out, "fid", fid);
                cJSON_AddStringToObject(out, "label", get_string(item, "label"));
                cJSON_AddStringToObject(out, "app", get_string(item, "app"));
                cJSON_AddBoolToObject(out, "private", true);
                cJSON *data = cJSON_GetObjectItemCaseSensitive(item, "data");
                size_t encoded_len = cJSON_IsString(data) ? strlen(data->valuestring) : 0;
                size_t decoded_len = encoded_len / 4 * 3;
                if (encoded_len && data->valuestring[encoded_len - 1] == '=') decoded_len--;
                if (encoded_len > 1 && data->valuestring[encoded_len - 2] == '=') decoded_len--;
                cJSON_AddNumberToObject(out, "size", (double)decoded_len);
                cJSON_AddItemToArray(list, out);
            }
            cJSON_AddItemToObject(result, "objects", list);
        }
    } else if (strcmp(cmd, "random") == 0) {
        int size = 0; cJSON *v = cJSON_GetObjectItemCaseSensitive(q, "size");
        if (!unlocked) { ok = false; error = "locked"; }
        else if (cJSON_IsNumber(v)) size = v->valueint;
        if (ok && (size < 1 || size > MAX_OBJECT_SIZE)) { ok = false; error = "size must be 1 to 4096 bytes"; }
        if (ok) {
            uint8_t *bytes = malloc(size);
            size_t encoded_cap = 4 * ((size + 2) / 3) + 1;
            char *encoded = malloc(encoded_cap);
            if (!bytes || !encoded) { ok = false; error = "out of memory"; }
            else {
                esp_fill_random(bytes, size);
                size_t out_len = 0;
                if (mbedtls_base64_encode((uint8_t *)encoded, 4 * ((size + 2) / 3) + 1,
                    &out_len, bytes, size) != 0) { ok = false; error = "base64 encoding failed"; }
                else { result = cJSON_CreateObject(); cJSON_AddStringToObject(result, "data", encoded); }
            }
            if (bytes) { secure_zero(bytes, size); free(bytes); }
            if (encoded) secure_zero(encoded, encoded_cap);
            free(encoded);
        }
    } else if (strcmp(cmd, "create") == 0) {
        if (!unlocked) { ok = false; error = "locked"; }
        else if (cJSON_GetArraySize(objects) >= MAX_OBJECTS) { ok = false; error = "maximum number of keyfiles reached"; }
        else {
            const char *label = get_string(q, "label");
            const char *app = get_string(q, "app");
            const char *encoded = get_string(q, "data");
            int object_id = next_id();
            size_t encoded_len = strlen(encoded);
            size_t decoded_len = encoded_len / 4 * 3;
            if (encoded_len && encoded[encoded_len - 1] == '=') decoded_len--;
            if (encoded_len > 1 && encoded[encoded_len - 2] == '=') decoded_len--;
            uint8_t *decoded = malloc(decoded_len ? decoded_len : 1);
            if (!object_id || !label[0] || decoded_len == 0 || decoded_len > MAX_OBJECT_SIZE || !decoded) {
                ok = false; error = "invalid keyfile, empty name, or storage limit reached";
            } else if (mbedtls_base64_decode(decoded, decoded_len, &decoded_len,
                         (const uint8_t *)encoded, strlen(encoded)) != 0) {
                ok = false; error = "invalid base64 data";
            } else {
                size_t encoded_cap = 4 * ((decoded_len + 2) / 3) + 1;
                char *safe_data = malloc(encoded_cap);
                size_t safe_len = 0;
                if (!safe_data || mbedtls_base64_encode((uint8_t *)safe_data, encoded_cap, &safe_len, decoded, decoded_len) != 0) {
                    ok = false; error = "out of memory";
                } else {
                    cJSON *candidate = cJSON_Duplicate(objects, 1);
                    cJSON *item = cJSON_CreateObject();
                    bool built = candidate && item &&
                        cJSON_AddNumberToObject(item, "id", object_id) &&
                        cJSON_AddStringToObject(item, "label", label) &&
                        cJSON_AddStringToObject(item, "app", app) &&
                        cJSON_AddStringToObject(item, "data", safe_data);
                    if (!built) {
                        wipe_json_node(item);
                        cJSON_Delete(item);
                        wipe_json_tree(candidate);
                        cJSON_Delete(candidate);
                        ok = false; error = "out of memory";
                    } else {
                        cJSON_AddItemToArray(candidate, item);
                        ok = commit_session_objects(candidate);
                        if (!ok) {
                            wipe_json_tree(candidate);
                            cJSON_Delete(candidate);
                            error = "encrypted storage is full";
                        } else {
                            result = cJSON_CreateObject();
                            if (result) cJSON_AddNumberToObject(result, "id", object_id);
                        }
                    }
                }
                if (safe_data) secure_zero(safe_data, encoded_cap);
                free(safe_data);
            }
            if (decoded) { secure_zero(decoded, decoded_len); free(decoded); }
        }
    } else if (strcmp(cmd, "read") == 0) {
        cJSON *item = find_object(get_id(q), NULL);
        if (!unlocked) { ok = false; error = "locked"; }
        else if (!item || is_ssh_item(item)) { ok = false; error = "keyfile not found"; }
        else {
            result = cJSON_CreateObject();
            cJSON_AddStringToObject(result, "data", get_string(item, "data"));
        }
    } else if (strcmp(cmd, "ssh_list") == 0) {
        if (!unlocked) { ok = false; error = "locked"; }
        else {
            result = cJSON_CreateObject();
            cJSON *list = cJSON_CreateArray();
            cJSON *item = NULL;
            cJSON_ArrayForEach(item, objects) {
                if (!is_ssh_item(item)) continue;
                cJSON *idv = cJSON_GetObjectItemCaseSensitive(item, "id");
                cJSON *out = cJSON_CreateObject();
                cJSON_AddNumberToObject(out, "id", cJSON_IsNumber(idv) ? idv->valueint : 0);
                cJSON_AddStringToObject(out, "label", get_string(item, "label"));
                cJSON_AddStringToObject(out, "pub", get_string(item, "pub"));
                cJSON_AddItemToArray(list, out);
            }
            cJSON_AddItemToObject(result, "keys", list);
        }
    } else if (strcmp(cmd, "ssh_generate") == 0) {
        const char *label = get_string(q, "label");
        int object_id = unlocked ? next_id() : 0;
        if (!unlocked) { ok = false; error = "locked"; }
        else if (cJSON_GetArraySize(objects) >= MAX_OBJECTS || !object_id) { ok = false; error = "maximum number of keys reached"; }
        else if (!label[0]) { ok = false; error = "SSH key name is empty"; }
        else {
            uint8_t priv[32], pub[65];
            char *priv64 = NULL, *pub64 = NULL;
            ok = ssh_generate_key(priv, pub);
            if (ok) { priv64 = b64_encode(priv, sizeof(priv)); pub64 = b64_encode(pub, sizeof(pub)); }
            cJSON *candidate = ok ? cJSON_Duplicate(objects, 1) : NULL;
            cJSON *item = ok ? cJSON_CreateObject() : NULL;
            ok = ok && priv64 && pub64 && candidate && item &&
                 cJSON_AddNumberToObject(item, "id", object_id) &&
                 cJSON_AddStringToObject(item, "kind", "ssh") &&
                 cJSON_AddStringToObject(item, "label", label) &&
                 cJSON_AddStringToObject(item, "priv", priv64) &&
                 cJSON_AddStringToObject(item, "pub", pub64);
            if (ok) {
                cJSON_AddItemToArray(candidate, item);
                item = NULL;
                ok = commit_session_objects(candidate);
                if (ok) candidate = NULL;
            }
            if (ok) {
                result = cJSON_CreateObject();
                cJSON_AddNumberToObject(result, "id", object_id);
                cJSON_AddStringToObject(result, "pub", pub64);
            } else {
                error = "could not create SSH key";
            }
            if (item) { wipe_json_node(item); cJSON_Delete(item); }
            if (candidate) { wipe_json_tree(candidate); cJSON_Delete(candidate); }
            secure_zero(priv, sizeof(priv));
            if (priv64) { secure_zero(priv64, strlen(priv64)); free(priv64); }
            free(pub64);
        }
    } else if (strcmp(cmd, "ssh_sign") == 0) {
        cJSON *item = find_object(get_id(q), NULL);
        uint8_t priv[32], digest[32], r[32], s[32];
        if (!unlocked) { ok = false; error = "locked"; }
        else if (!item || !is_ssh_item(item)) { ok = false; error = "SSH key not found"; }
        else if (!b64_decode_exact(get_string(q, "data"), digest, sizeof(digest))) { ok = false; error = "expected a SHA-256 digest"; }
        else if (!b64_decode_exact(get_string(item, "priv"), priv, sizeof(priv)) || !ssh_sign_digest(priv, digest, r, s)) {
            ok = false; error = "signing failed";
        } else {
            char *r64 = b64_encode(r, sizeof(r)), *s64 = b64_encode(s, sizeof(s));
            if (!r64 || !s64) { ok = false; error = "out of memory"; }
            else {
                result = cJSON_CreateObject();
                cJSON_AddStringToObject(result, "r", r64);
                cJSON_AddStringToObject(result, "s", s64);
            }
            free(r64);
            free(s64);
        }
        secure_zero(priv, sizeof(priv));
    } else if (strcmp(cmd, "delete") == 0) {
        int index = 0;
        cJSON *item = find_object(get_id(q), &index);
        if (!unlocked) { ok = false; error = "locked"; }
        else if (!item) { ok = false; error = "keyfile not found"; }
        else {
            cJSON *candidate = cJSON_Duplicate(objects, 1);
            if (!candidate) { ok = false; error = "out of memory"; }
            else {
                cJSON *candidate_item = cJSON_GetArrayItem(candidate, index);
                wipe_json_node(candidate_item);
                cJSON_DeleteItemFromArray(candidate, index);
                ok = commit_session_objects(candidate);
                if (!ok) {
                    wipe_json_tree(candidate);
                    cJSON_Delete(candidate);
                    error = "could not save encrypted storage";
                }
            }
        }
    } else if (strcmp(cmd, "rename") == 0) {
        cJSON *item = find_object(get_id(q), NULL);
        const char *label = get_string(q, "label");
        if (!unlocked) { ok = false; error = "locked"; }
        else if (!item || !label[0]) { ok = false; error = "keyfile not found or name is empty"; }
        else {
            cJSON *candidate = cJSON_Duplicate(objects, 1);
            cJSON *candidate_item = candidate ? find_object_in(candidate, get_id(q), NULL) : NULL;
            cJSON *new_label = cJSON_CreateString(label);
            if (!candidate || !candidate_item || !new_label) {
                cJSON_Delete(new_label);
                wipe_json_tree(candidate);
                cJSON_Delete(candidate);
                ok = false; error = "out of memory";
            } else {
                if (!cJSON_ReplaceItemInObjectCaseSensitive(candidate_item, "label", new_label)) {
                    cJSON_Delete(new_label);
                    wipe_json_tree(candidate);
                    cJSON_Delete(candidate);
                    ok = false; error = "could not rename keyfile";
                } else {
                    ok = commit_session_objects(candidate);
                    if (!ok) {
                        wipe_json_tree(candidate);
                        cJSON_Delete(candidate);
                        error = "could not save encrypted storage";
                    }
                }
            }
        }
    } else if (strcmp(cmd, "backup_export") == 0) {
        cJSON *ov = cJSON_GetObjectItemCaseSensitive(q, "offset");
        size_t off = cJSON_IsNumber(ov) && ov->valuedouble > 0 ? (size_t)ov->valuedouble : 0;
        uint8_t *blob = NULL;
        size_t n = 0;
        if (read_blob(&blob, &n) != ESP_OK) { ok = false; error = "this ESP Crypt has no passphrase-protected container yet"; }
        else if (off > n) { ok = false; error = "invalid backup offset"; }
        else {
            size_t chunk = n - off > BACKUP_CHUNK ? BACKUP_CHUNK : n - off;
            size_t elen = 0;
            mbedtls_base64_encode(NULL, 0, &elen, blob + off, chunk);
            unsigned char *enc = malloc(elen + 1);
            if (!enc || mbedtls_base64_encode(enc, elen + 1, &elen, blob + off, chunk) != 0) { ok = false; error = "out of memory"; }
            else {
                enc[elen] = 0;
                result = cJSON_CreateObject();
                cJSON_AddStringToObject(result, "data", (const char *)enc);
                cJSON_AddNumberToObject(result, "offset", off);
                cJSON_AddNumberToObject(result, "total", n);
                cJSON_AddNumberToObject(result, "rev", vault_rev);
            }
            free(enc);
        }
        free(blob);
    } else if (strcmp(cmd, "backup_import_begin") == 0) {
        cJSON *sv = cJSON_GetObjectItemCaseSensitive(q, "size");
        cJSON *rv = cJSON_GetObjectItemCaseSensitive(q, "rev");
        size_t size = cJSON_IsNumber(sv) && sv->valuedouble > 0 ? (size_t)sv->valuedouble : 0;
        free(import_buf);
        import_buf = NULL;
        if (size < HEADER_SIZE + TAG_SIZE || size > MAX_BLOB) { ok = false; error = "backup size is invalid"; }
        else if (!(import_buf = malloc(size))) { ok = false; error = "out of memory"; }
        else { import_size = size; import_got = 0; import_rev = cJSON_IsNumber(rv) ? (uint32_t)rv->valuedouble : 0; }
    } else if (strcmp(cmd, "backup_import_write") == 0) {
        const char *encoded = get_string(q, "data");
        cJSON *ov = cJSON_GetObjectItemCaseSensitive(q, "offset");
        size_t off = cJSON_IsNumber(ov) ? (size_t)ov->valuedouble : SIZE_MAX;
        size_t dlen = base64_decoded_length(encoded);
        if (!import_buf || off != import_got || dlen == 0 || import_got + dlen > import_size) { ok = false; error = "backup chunk out of order"; }
        else if (mbedtls_base64_decode(import_buf + import_got, import_size - import_got, &dlen,
                                       (const uint8_t *)encoded, strlen(encoded)) != 0) { ok = false; error = "invalid backup chunk"; }
        else import_got += dlen;
    } else if (strcmp(cmd, "backup_import_end") == 0) {
        uint32_t plain_len = import_buf && import_size >= HEADER_SIZE ? ((uint32_t)import_buf[28] | ((uint32_t)import_buf[29] << 8) |
                             ((uint32_t)import_buf[30] << 16) | ((uint32_t)import_buf[31] << 24)) : 0;
        if (!import_buf || import_got != import_size) { ok = false; error = "backup is incomplete"; }
        else if (plain_len == 0 || HEADER_SIZE + plain_len + TAG_SIZE != import_size) { ok = false; error = "this is not an ESP Crypt backup"; }
        else {
            nvs_handle_t nvs;
            ok = nvs_open("vault", NVS_READWRITE, &nvs) == ESP_OK;
            if (ok) {
                ok = (container_changed = true, nvs_set_blob)(nvs, "sealed", import_buf, import_size) == ESP_OK &&
                     nvs_set_u32(nvs, "rev", import_rev) == ESP_OK && nvs_set_u8(nvs, "pin_fail", 0) == ESP_OK &&
                     nvs_commit(nvs) == ESP_OK;
                nvs_close(nvs);
            }
            if (!ok) error = "could not save the backup";
            else {
                bool reloaded = false;
                if (unlocked && memcmp(import_buf, session_salt, SALT_SIZE) == 0) {
                    uint8_t *plain = malloc(plain_len + 1);
                    mbedtls_gcm_context gcm;
                    mbedtls_gcm_init(&gcm);
                    if (plain && mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, session_key, 256) == 0 &&
                        mbedtls_gcm_auth_decrypt(&gcm, plain_len, import_buf + SALT_SIZE, NONCE_SIZE, NULL, 0,
                                                 import_buf + HEADER_SIZE + plain_len, TAG_SIZE,
                                                 import_buf + HEADER_SIZE, plain) == 0) {
                        plain[plain_len] = 0;
                        cJSON *parsed = cJSON_Parse((const char *)plain);
                        if (cJSON_IsArray(parsed)) {
                            cJSON *old = objects;
                            objects = parsed;
                            wipe_json_tree(old);
                            cJSON_Delete(old);
                            reloaded = true;
                        } else {
                            wipe_json_tree(parsed);
                            cJSON_Delete(parsed);
                        }
                    }
                    mbedtls_gcm_free(&gcm);
                    if (plain) { secure_zero(plain, plain_len + 1); free(plain); }
                }
                if (!reloaded) erase_session();
                vault_rev = import_rev;
                vault_initialized = true;
                pin_failures = 0;
                result = cJSON_CreateObject();
                cJSON_AddBoolToObject(result, "unlocked", reloaded);
            }
        }
        if (import_buf) { secure_zero(import_buf, import_size); free(import_buf); }
        import_buf = NULL;
#if CONFIG_VAULT_WITH_PASSKEY
    } else if (strcmp(cmd, "passkey_export") == 0 || strcmp(cmd, "passkey_import") == 0) {
        if (!unlocked) { ok = false; error = "locked"; }
        else if (strcmp(cmd, "passkey_export") == 0) {
            size_t cap = store_state_max_size(), n = 0;
            uint8_t *st = malloc(cap), *out = malloc(NONCE_SIZE + cap + TAG_SIZE);
            if (!st || !out || !store_export(st, cap, &n)) { ok = false; error = "could not export the passkeys"; }
            else {
                esp_fill_random(out, NONCE_SIZE);
                mbedtls_gcm_context gcm;
                mbedtls_gcm_init(&gcm);
                ok = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, session_key, 256) == 0 &&
                     mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, n, out, NONCE_SIZE, (const uint8_t *)"PKS1", 4,
                                               st, out + NONCE_SIZE, TAG_SIZE, out + NONCE_SIZE + n) == 0;
                mbedtls_gcm_free(&gcm);
                size_t total = NONCE_SIZE + n + TAG_SIZE, elen = 0;
                mbedtls_base64_encode(NULL, 0, &elen, out, total);
                unsigned char *enc = ok ? malloc(elen + 1) : NULL;
                if (!enc || mbedtls_base64_encode(enc, elen + 1, &elen, out, total) != 0) { ok = false; error = "out of memory"; }
                else {
                    enc[elen] = 0;
                    result = cJSON_CreateObject();
                    cJSON_AddStringToObject(result, "data", (const char *)enc);
                    cJSON_AddNumberToObject(result, "rev", store_rev());
                }
                free(enc);
            }
            if (st) { secure_zero(st, cap); free(st); }
            free(out);
        } else {
            const char *encoded = get_string(q, "data");
            size_t dlen = base64_decoded_length(encoded);
            uint8_t *in = malloc(dlen ? dlen : 1), *st = malloc(dlen ? dlen : 1);
            if (!in || !st || dlen < NONCE_SIZE + TAG_SIZE + 4 ||
                mbedtls_base64_decode(in, dlen, &dlen, (const uint8_t *)encoded, strlen(encoded)) != 0) { ok = false; error = "invalid passkey backup"; }
            else {
                size_t n = dlen - NONCE_SIZE - TAG_SIZE;
                mbedtls_gcm_context gcm;
                mbedtls_gcm_init(&gcm);
                ok = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, session_key, 256) == 0 &&
                     mbedtls_gcm_auth_decrypt(&gcm, n, in, NONCE_SIZE, (const uint8_t *)"PKS1", 4, in + NONCE_SIZE + n,
                                              TAG_SIZE, in + NONCE_SIZE, st) == 0;
                mbedtls_gcm_free(&gcm);
                if (!ok) error = "this passkey backup belongs to another Vault container";
                else if (!store_import(st, n)) { ok = false; error = "could not save the passkeys"; }
                else ctap2_forget_session();
                secure_zero(st, dlen);
            }
            free(in);
            free(st);
        }
#endif
    } else {
        ok = false; error = "unknown command";
    }
    send_reply(id, ok, error, result);
    if (strcmp(cmd, "status") != 0 && strcmp(cmd, "ota_write") != 0) {
        if (!ok && (strcmp(cmd, "unlock") == 0 || strcmp(cmd, "change_pin") == 0)) led_event = LED_EVT_ERROR;
        else if (strcmp(cmd, "ssh_sign") == 0) led_event = LED_EVT_SIGN;
        else if (strcmp(cmd, "unlock") != 0 && strcmp(cmd, "lock") != 0 && strcmp(cmd, "setup_pin") != 0 &&
                 strcmp(cmd, "change_pin") != 0 && strcmp(cmd, "ota_begin") != 0) {  }
    }
    if (reboot_after_reply) {
        vTaskDelay(pdMS_TO_TICKS(500));
        esp_restart();
    }
}

#if CONFIG_IDF_TARGET_ESP32S3
#define BOOT_GPIO GPIO_NUM_0
#else
#define BOOT_GPIO GPIO_NUM_9
#endif

#ifdef VAULT_DEV_LOOPBACK
volatile bool vault_dev_confirm_once;
#endif

bool vault_boot_confirm(int seconds) {
#ifdef VAULT_DEV_LOOPBACK
    if (vault_dev_confirm_once) {
        vault_dev_confirm_once = false;
        return true;
    }
#endif
#ifdef VAULT_DEV_AUTOCONFIRM
    led_confirm = true;
    vTaskDelay(pdMS_TO_TICKS(1500));
    led_confirm = false;
    led_event = LED_EVT_OK;
    return true;
#endif
    gpio_config_t btn = {.pin_bit_mask = 1ULL << BOOT_GPIO, .mode = GPIO_MODE_INPUT, .pull_up_en = GPIO_PULLUP_ENABLE};
    gpio_config(&btn);
    led_confirm = true;
    bool released = gpio_get_level(BOOT_GPIO) != 0;
    bool pressed = false;
    for (int64_t end = esp_timer_get_time() + seconds * 1000000LL; esp_timer_get_time() < end;) {
        bool down = gpio_get_level(BOOT_GPIO) == 0;
        if (!down) released = true;
        else if (released) {
            pressed = true;
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    led_confirm = false;
    if (pressed) led_event = LED_EVT_OK;
    return pressed;
}

void vault_handle_line(const char *text, int origin, vault_sink_t sink, void *ctx) {
    if (xSemaphoreTakeRecursive(cmd_lock, 0) != pdTRUE) {
        cJSON *q = cJSON_Parse(text);
        if (q && strcmp(get_string(q, "command"), "status") == 0) {
            cJSON *idv = cJSON_GetObjectItemCaseSensitive(q, "id");
            send_reply_to(sink, ctx, cJSON_IsNumber(idv) ? (uint32_t)idv->valuedouble : 0, true, NULL,
                          status_result(origin, true));
            cJSON_Delete(q);
            return;
        }
        if (q) {
            wipe_json_tree(q);
            cJSON_Delete(q);
        }
        xSemaphoreTakeRecursive(cmd_lock, portMAX_DELAY);
    }
    int prev_origin = cur_origin;
    vault_sink_t prev_sink = cur_sink;
    void *prev_ctx = cur_sink_ctx;
    cur_origin = origin;
    cur_sink = sink;
    cur_sink_ctx = ctx;
    cJSON *q = cJSON_Parse(text);
    if (q) {
        handle(q);
        wipe_json_tree(q);
        cJSON_Delete(q);
    } else {
        send_reply(0, false, "invalid JSON request", NULL);
    }
    cur_origin = prev_origin;
    cur_sink = prev_sink;
    cur_sink_ctx = prev_ctx;
    xSemaphoreGiveRecursive(cmd_lock);
}

const char *vault_device_id(void) { return device_id; }
const char *vault_chip_name(void) { return chip_name(); }

void app_main(void) {
    bootloader_random_enable();
    esp_log_level_set("*", ESP_LOG_NONE);
    cmd_lock = xSemaphoreCreateRecursiveMutex();
    storage_ready = initialize_nvs();
    if (storage_ready) {
        nvs_handle_t nvs;
        size_t size = 0;
        if (nvs_open("vault", NVS_READONLY, &nvs) == ESP_OK) {
            if (nvs_get_u32(nvs, "rev", &vault_rev) != ESP_OK) vault_rev = 0;
            vault_initialized = nvs_get_blob(nvs, "sealed", NULL, &size) == ESP_OK && size >= HEADER_SIZE + TAG_SIZE;
            nvs_close(nvs);
        }
    }
    led_start();
    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(device_serial, sizeof(device_serial), "%02X%02X%02X", mac[3], mac[4], mac[5]);
    snprintf(device_id, sizeof(device_id), "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
#if CONFIG_VAULT_WITH_PASSKEY
    const passkey_usb_config_t usb = {.pid = 0x4AF2, .product = "ESP Crypt + Passkey"};
    if (!passkey_core_start(&usb)) abort();
#else
    usb_serial_jtag_driver_config_t usb_cfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    usb_cfg.rx_buffer_size = 4096;
    usb_cfg.tx_buffer_size = 4096;
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&usb_cfg));
#endif
    if (storage_ready) radio_init_later();
    static char line[MAX_LINE];
    static uint8_t rx[512];
    size_t used = 0;
    for (;;) {
#if CONFIG_VAULT_WITH_PASSKEY
        int got = (int)passkey_cdc_read(rx, sizeof(rx), portMAX_DELAY);
#else
        int got = usb_serial_jtag_read_bytes(rx, sizeof(rx), portMAX_DELAY);
#endif
        for (int i = 0; i < got; i++) {
            int ch = rx[i];
            if (ch == '\r') continue;
            if (ch == '\n') {
                line[used] = 0;
                if (used) vault_handle_line(line, ORIGIN_USB, NULL, NULL);
                secure_zero(line, used);
                used = 0;
            } else if (used + 1 < sizeof(line)) {
                line[used++] = (char)ch;
            } else {
                secure_zero(line, used);
                used = 0;
                send_reply(0, false, "request too large", NULL);
            }
        }
        secure_zero(rx, sizeof(rx));
    }
}
