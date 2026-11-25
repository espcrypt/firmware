#include <stdio.h>
#include <string.h>

#include "ctap2.h"
#include "esp_partition.h"
#include "nvs.h"
#include "passkey_core.h"
#include "store.h"

static void hex(const uint8_t *b, size_t n, char *out) {
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = 0;
}

static bool unhex(const char *s, uint8_t *out, size_t n) {
    if (!s || strlen(s) != 2 * n) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

void passkey_add_storage(cJSON *obj) {
    nvs_stats_t st;
    if (nvs_get_stats(NULL, &st) != ESP_OK) return;
    const esp_partition_t *p = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, NULL);
    cJSON *s = cJSON_AddObjectToObject(obj, "storage");
    cJSON_AddNumberToObject(s, "usedEntries", st.used_entries);
    cJSON_AddNumberToObject(s, "freeEntries", st.free_entries);
    cJSON_AddNumberToObject(s, "totalEntries", st.total_entries);
    cJSON_AddNumberToObject(s, "entryBytes", 32);
    cJSON_AddNumberToObject(s, "partitionBytes", p ? p->size : 0);
}

static const char *ctap_error_text(int st) {
    switch (st) {
    case CTAP2_ERR_PIN_INVALID: return "wrong PIN";
    case CTAP2_ERR_PIN_BLOCKED: return "PIN blocked: reset the security key";
    case CTAP2_ERR_PIN_AUTH_BLOCKED: return "too many wrong PINs: unplug and reconnect the key";
    case CTAP2_ERR_PIN_POLICY_VIOLATION: return "the PIN must be 4 to 63 characters";
    case CTAP2_ERR_NOT_ALLOWED: return "a PIN is already set; change it instead";
    case CTAP2_ERR_USER_ACTION_TIMEOUT: return "no button press on the board";
    case CTAP2_ERR_MISSING_PARAMETER: return "missing PIN";
    default: return "operation failed";
    }
}

bool passkey_mgmt_handle(const char *cmd, cJSON *q, cJSON **result, bool *ok, const char **error) {
    const char *c = strncmp(cmd, "passkey_", 8) == 0 ? cmd + 8 : cmd;
    *ok = true;
    *error = NULL;
    if (!strcmp(c, "status")) {
        cJSON *r = cJSON_CreateObject();
        cJSON_AddStringToObject(r, "deviceId", passkey_device_id());
        cJSON_AddBoolToObject(r, "pinSet", store_pin_set());
        cJSON_AddNumberToObject(r, "pinRetries", store_pin_retries());
        cJSON_AddNumberToObject(r, "credentials", store_resident_count());
        cJSON_AddNumberToObject(r, "maxCredentials", MAX_RESIDENT);
        cJSON_AddNumberToObject(r, "credentialBytes", sizeof(resident_t));
        cJSON_AddStringToObject(r, "touch", store_touch_mode() == TOUCH_AUTO ? "auto" : "button");
        passkey_add_storage(r);
        *result = r;
    } else if (!strcmp(c, "list")) {
        cJSON *r = cJSON_CreateObject();
        cJSON *arr = cJSON_AddArrayToObject(r, "credentials");
        resident_t rec;
        char idhex[2 * CRED_ID_LEN + 1];
        for (int s = 0; s < MAX_RESIDENT; s++) {
            if (!store_resident_get(s, &rec)) continue;
            cJSON *e = cJSON_CreateObject();
            hex(rec.cred_id, CRED_ID_LEN, idhex);
            cJSON_AddStringToObject(e, "id", idhex);
            cJSON_AddStringToObject(e, "rpId", rec.rp_id);
            cJSON_AddStringToObject(e, "userName", rec.user_name);
            cJSON_AddStringToObject(e, "displayName", rec.display_name);
            cJSON_AddNumberToObject(e, "created", rec.created);
            cJSON_AddItemToArray(arr, e);
        }
        *result = r;
    } else if (!strcmp(c, "delete")) {
        uint8_t id[CRED_ID_LEN];
        if (!unhex(cJSON_GetStringValue(cJSON_GetObjectItem(q, "data")), id, CRED_ID_LEN)) { *ok = false; *error = "invalid passkey id"; }
        else if (!store_resident_delete(id)) { *ok = false; *error = "passkey not found"; }
    } else if (!strcmp(c, "set_touch")) {
        const char *mode = cJSON_GetStringValue(cJSON_GetObjectItem(q, "label"));
        if (!mode || (strcmp(mode, "auto") && strcmp(mode, "button"))) { *ok = false; *error = "touch mode must be button or auto"; }
        else store_set_touch_mode(strcmp(mode, "auto") ? TOUCH_BUTTON : TOUCH_AUTO);
    } else if (!strcmp(c, "set_pin") || !strcmp(c, "change_pin")) {
        const char *pin = cJSON_GetStringValue(cJSON_GetObjectItem(q, "pin"));
        const char *new_pin = cJSON_GetStringValue(cJSON_GetObjectItem(q, "newPin"));
        int st;
        if (!strcmp(c, "set_pin")) st = pin ? ctap2_set_pin(pin, strlen(pin)) : CTAP2_ERR_MISSING_PARAMETER;
        else st = pin && new_pin ? ctap2_change_pin(pin, strlen(pin), new_pin, strlen(new_pin)) : CTAP2_ERR_MISSING_PARAMETER;
        if (st != CTAP2_OK) { *ok = false; *error = ctap_error_text(st); }
    } else if (!strcmp(c, "reset")) {
        if (ctap_wait_presence() != CTAP2_OK) { *ok = false; *error = "press the BOOT button on the board to confirm the reset"; }
        else if (!store_wipe()) { *ok = false; *error = "could not erase the passkeys"; }
        else ctap2_forget_session();
    } else if (!strcmp(c, "wink")) {
        passkey_led(PASSKEY_LED_WINK, 1500);
    } else {
        return false;
    }
    return true;
}
