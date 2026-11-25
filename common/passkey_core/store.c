#include "store.h"

#include <stdio.h>
#include <string.h>

#include "esp_random.h"
#include "nvs.h"
#include "nvs_flash.h"

#define NS "passkey"

static uint8_t master[32];
static bool used[MAX_RESIDENT];
static uint32_t created_seq;

static void slot_key(int slot, char key[8]) { snprintf(key, 8, "rk%02d", slot); }

static bool load_master(nvs_handle_t h) {
    size_t n = sizeof(master);
    if (nvs_get_blob(h, "master", master, &n) == ESP_OK && n == sizeof(master)) return true;
    esp_fill_random(master, sizeof(master));
    return nvs_set_blob(h, "master", master, sizeof(master)) == ESP_OK && nvs_commit(h) == ESP_OK;
}

bool store_init(void) {
    if (nvs_flash_init() != ESP_OK) return false;
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) return false;
    bool ok = load_master(h);
    for (int i = 0; i < MAX_RESIDENT; i++) {
        char key[8];
        size_t n = 0;
        slot_key(i, key);
        used[i] = nvs_get_blob(h, key, NULL, &n) == ESP_OK && n == sizeof(resident_t);
        if (used[i]) {
            resident_t r;
            n = sizeof(r);
            if (nvs_get_blob(h, key, &r, &n) == ESP_OK && r.created > created_seq) created_seq = r.created;
        }
    }
    nvs_close(h);
    return ok;
}

const uint8_t *store_master_key(void) { return master; }

static bool get_blob(const char *key, void *out, size_t want) {
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) != ESP_OK) return false;
    size_t n = want;
    bool ok = nvs_get_blob(h, key, out, &n) == ESP_OK && n == want;
    nvs_close(h);
    return ok;
}

static bool set_blob(const char *key, const void *data, size_t len) {
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) return false;
    bool ok = (data ? nvs_set_blob(h, key, data, len) : nvs_erase_key(h, key)) == ESP_OK && nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}

static uint32_t get_u32(const char *key, uint32_t def) {
    nvs_handle_t h;
    uint32_t v = def;
    if (nvs_open(NS, NVS_READONLY, &h) == ESP_OK) {
        if (nvs_get_u32(h, key, &v) != ESP_OK) v = def;
        nvs_close(h);
    }
    return v;
}

static void set_u32(const char *key, uint32_t v) {
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u32(h, key, v);
        nvs_commit(h);
        nvs_close(h);
    }
}

bool store_pin_set(void) {
    uint8_t h[16];
    return store_pin_hash(h);
}

bool store_pin_hash(uint8_t out[16]) { return get_blob("pin", out, 16); }

bool store_set_pin_hash(const uint8_t hash[16]) {
    if (!set_blob("pin", hash, 16)) return false;
    store_set_pin_retries(8);
    store_bump_rev();
    return true;
}

uint8_t store_pin_retries(void) { return (uint8_t)get_u32("retries", 8); }
void store_set_pin_retries(uint8_t retries) { set_u32("retries", retries); }

uint32_t store_next_counter(void) {
    uint32_t c = get_u32("counter", 0) + 1;
    set_u32("counter", c);
    return c;
}

touch_mode_t store_touch_mode(void) { return get_u32("touch", TOUCH_BUTTON) == TOUCH_AUTO ? TOUCH_AUTO : TOUCH_BUTTON; }
void store_set_touch_mode(touch_mode_t mode) {
    set_u32("touch", mode);
    store_bump_rev();
}

uint32_t store_rev(void) { return get_u32("rev", 0); }
void store_bump_rev(void) { set_u32("rev", get_u32("rev", 0) + 1); }

int store_resident_count(void) {
    int n = 0;
    for (int i = 0; i < MAX_RESIDENT; i++) n += used[i];
    return n;
}

bool store_resident_get(int slot, resident_t *out) {
    if (slot < 0 || slot >= MAX_RESIDENT || !used[slot]) return false;
    char key[8];
    slot_key(slot, key);
    return get_blob(key, out, sizeof(*out));
}

bool store_resident_find(const uint8_t cred_id[CRED_ID_LEN], int *slot, resident_t *out) {
    resident_t r;
    for (int i = 0; i < MAX_RESIDENT; i++) {
        if (store_resident_get(i, &r) && memcmp(r.cred_id, cred_id, CRED_ID_LEN) == 0) {
            if (slot) *slot = i;
            if (out) *out = r;
            return true;
        }
    }
    return false;
}

bool store_resident_put(resident_t *rec) {
    int target = -1;
    resident_t r;
    for (int i = 0; i < MAX_RESIDENT; i++) {
        if (!used[i]) {
            if (target < 0) target = i;
            continue;
        }
        if (store_resident_get(i, &r) && memcmp(r.rp_id_hash, rec->rp_id_hash, 32) == 0 &&
            r.user_id_len == rec->user_id_len && memcmp(r.user_id, rec->user_id, r.user_id_len) == 0) {
            target = i;
            break;
        }
    }
    if (target < 0) return false;
    rec->created = ++created_seq;
    char key[8];
    slot_key(target, key);
    if (!set_blob(key, rec, sizeof(*rec))) return false;
    used[target] = true;
    store_bump_rev();
    return true;
}

bool store_resident_delete(const uint8_t cred_id[CRED_ID_LEN]) {
    int slot;
    if (!store_resident_find(cred_id, &slot, NULL)) return false;
    char key[8];
    slot_key(slot, key);
    if (!set_blob(key, NULL, 0)) return false;
    used[slot] = false;
    store_bump_rev();
    return true;
}

bool store_wipe(void) {
    uint32_t rev = store_rev();
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) return false;
    bool ok = nvs_erase_all(h) == ESP_OK && nvs_commit(h) == ESP_OK;
    if (ok) ok = nvs_set_u32(h, "rev", rev + 1) == ESP_OK;
    if (ok) ok = load_master(h);
    nvs_close(h);
    memset(used, 0, sizeof(used));
    created_seq = 0;
    return ok;
}

#define STATE_MAGIC "PKS1"
#define STATE_HEAD (4 + 32 + 1 + 16 + 1 + 1 + 4 + 4 + 1)

size_t store_state_max_size(void) { return STATE_HEAD + MAX_RESIDENT * sizeof(resident_t); }

static void put32(uint8_t *p, uint32_t v) {
    p[0] = v;
    p[1] = v >> 8;
    p[2] = v >> 16;
    p[3] = v >> 24;
}

static uint32_t get32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }

bool store_export(uint8_t *buf, size_t cap, size_t *len) {
    if (cap < store_state_max_size()) return false;
    uint8_t *p = buf;
    memcpy(p, STATE_MAGIC, 4);
    p += 4;
    memcpy(p, master, 32);
    p += 32;
    uint8_t pin[16] = {0};
    *p++ = store_pin_hash(pin) ? 1 : 0;
    memcpy(p, pin, 16);
    p += 16;
    *p++ = store_pin_retries();
    *p++ = (uint8_t)store_touch_mode();
    put32(p, get_u32("counter", 0));
    p += 4;
    put32(p, store_rev());
    p += 4;
    uint8_t *count = p++;
    *count = 0;
    resident_t r;
    for (int i = 0; i < MAX_RESIDENT; i++) {
        if (!store_resident_get(i, &r)) continue;
        memcpy(p, &r, sizeof(r));
        p += sizeof(r);
        (*count)++;
    }
    *len = p - buf;
    memset(pin, 0, sizeof(pin));
    return true;
}

bool store_import(const uint8_t *buf, size_t len) {
    if (len < STATE_HEAD || memcmp(buf, STATE_MAGIC, 4) != 0) return false;
    uint8_t count = buf[STATE_HEAD - 1];
    if (count > MAX_RESIDENT || len != STATE_HEAD + count * sizeof(resident_t)) return false;
    const uint8_t *p = buf + 4;
    uint32_t local_counter = get_u32("counter", 0);
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) return false;
    const uint8_t *new_master = p;
    bool ok = nvs_set_blob(h, "master", p, 32) == ESP_OK;
    p += 32;
    bool pin_set = *p++;
    if (ok && pin_set) ok = nvs_set_blob(h, "pin", p, 16) == ESP_OK;
    else if (ok) {
        esp_err_t e = nvs_erase_key(h, "pin");
        ok = e == ESP_OK || e == ESP_ERR_NVS_NOT_FOUND;
    }
    p += 16;
    if (ok) ok = nvs_set_u32(h, "retries", *p) == ESP_OK;
    p++;
    if (ok) ok = nvs_set_u32(h, "touch", *p) == ESP_OK;
    p++;
    uint32_t counter = get32(p);
    p += 4;
    if (ok) ok = nvs_set_u32(h, "counter", (counter > local_counter ? counter : local_counter) + 1) == ESP_OK;
    if (ok) ok = nvs_set_u32(h, "rev", get32(p)) == ESP_OK;
    p += 4 + 1;
    uint32_t seq = 0;
    for (int i = 0; ok && i < count; i++) {
        resident_t r;
        memcpy(&r, p + i * sizeof(r), sizeof(r));
        char key[8];
        slot_key(i, key);
        ok = nvs_set_blob(h, key, &r, sizeof(r)) == ESP_OK;
        if (r.created > seq) seq = r.created;
    }
    for (int i = count; ok && i < MAX_RESIDENT; i++) {
        char key[8];
        slot_key(i, key);
        esp_err_t e = nvs_erase_key(h, key);
        ok = e == ESP_OK || e == ESP_ERR_NVS_NOT_FOUND;
    }
    if (ok) ok = nvs_commit(h) == ESP_OK;
    nvs_close(h);
    if (!ok) return false;
    memcpy(master, new_master, 32);
    for (int i = 0; i < MAX_RESIDENT; i++) used[i] = i < count;
    created_seq = seq;
    return true;
}
