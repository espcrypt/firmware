#include "ctap2.h"

#include <stdbool.h>
#include <string.h>

#include "cbor.h"
#include "crypto.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "store.h"

#define CMD_MAKE_CREDENTIAL 0x01
#define CMD_GET_ASSERTION 0x02
#define CMD_GET_INFO 0x04
#define CMD_CLIENT_PIN 0x06
#define CMD_RESET 0x07
#define CMD_GET_NEXT_ASSERTION 0x08
#define CMD_SELECTION 0x0B

#define FLAG_UP 0x01
#define FLAG_UV 0x04
#define FLAG_AT 0x40

#define COSE_ES256 (-7)
#define COSE_ECDH_ES_HKDF_256 (-25)

static const uint8_t AAGUID[16] = {0x7a, 0x4e, 0x2c, 0x91, 0x5b, 0x63, 0x4f, 0x0d,
                                   0x9e, 0x21, 0xc4, 0x86, 0x3f, 0xb5, 0x10, 0x58};

static uint8_t pin_token[32];
static uint8_t ka_priv[32], ka_pub[64];
static int pin_fails_since_boot;

static struct {
    bool active;
    int slots[MAX_RESIDENT];
    int count, next;
    uint8_t rp_id_hash[32];
    uint8_t client_data_hash[32];
    uint8_t flags;
    int64_t at;
} next_state;

static void new_key_agreement(void) { p256_generate(ka_priv, ka_pub); }

void ctap2_init(void) {
    esp_fill_random(pin_token, sizeof(pin_token));
    new_key_agreement();
}

void ctap2_forget_session(void) {
    esp_fill_random(pin_token, sizeof(pin_token));
    memset(&next_state, 0, sizeof(next_state));
}

static void make_cred_id(const uint8_t rp_id_hash[32], uint8_t id[CRED_ID_LEN]) {
    uint8_t tag[32];
    id[0] = 0x01;
    esp_fill_random(id + 1, 16);
    pk_hmac_sha256(store_master_key(), 32, "tag", 3, rp_id_hash, 32, id + 1, 16, tag);
    memcpy(id + 17, tag, 16);
}

static bool cred_id_valid(const uint8_t *id, size_t len, const uint8_t rp_id_hash[32]) {
    if (len != CRED_ID_LEN || id[0] != 0x01) return false;
    uint8_t tag[32];
    pk_hmac_sha256(store_master_key(), 32, "tag", 3, rp_id_hash, 32, id + 1, 16, tag);
    return ct_equal(tag, id + 17, 16);
}

static bool cred_private_key(const uint8_t id[CRED_ID_LEN], const uint8_t rp_id_hash[32], uint8_t priv[32]) {
    uint8_t seed[32];
    pk_hmac_sha256(store_master_key(), 32, "key", 3, rp_id_hash, 32, id + 1, 16, seed);
    bool ok = p256_private_from_seed(seed, priv);
    memset(seed, 0, sizeof(seed));
    return ok;
}

static void put_cose_key(cbor_writer_t *w, const uint8_t pub[64], int alg) {
    cbor_put_map(w, 5);
    cbor_put_int(w, 1);
    cbor_put_int(w, 2);
    cbor_put_int(w, 3);
    cbor_put_int(w, alg);
    cbor_put_int(w, -1);
    cbor_put_int(w, 1);
    cbor_put_int(w, -2);
    cbor_put_bytes(w, pub, 32);
    cbor_put_int(w, -3);
    cbor_put_bytes(w, pub + 32, 32);
}

static size_t auth_data(uint8_t *out, const uint8_t rp_id_hash[32], uint8_t flags, uint32_t counter) {
    memcpy(out, rp_id_hash, 32);
    out[32] = flags;
    out[33] = counter >> 24;
    out[34] = counter >> 16;
    out[35] = counter >> 8;
    out[36] = counter;
    return 37;
}

static bool sign_with(const uint8_t priv[32], const uint8_t *ad, size_t ad_len, const uint8_t cdh[32], uint8_t *sig,
                      size_t *sig_len) {
    uint8_t buf[512];
    if (ad_len + 32 > sizeof(buf)) return false;
    memcpy(buf, ad, ad_len);
    memcpy(buf + ad_len, cdh, 32);
    uint8_t digest[32];
    sha256(buf, ad_len + 32, digest);
    return p256_sign(priv, digest, sig, 80, sig_len);
}

static bool pin_auth_ok(const uint8_t *pin_auth, size_t len, const uint8_t cdh[32]) {
    if (len != 16) return false;
    uint8_t mac[32];
    pk_hmac_sha256(pin_token, 32, cdh, 32, NULL, 0, NULL, 0, mac);
    return ct_equal(mac, pin_auth, 16);
}

static int check_new_pin(const uint8_t *padded, size_t len, uint8_t hash_out[16]) {
    size_t n = 0;
    while (n < len && padded[n]) n++;
    if (n < 4 || n > 63) return CTAP2_ERR_PIN_POLICY_VIOLATION;
    uint8_t h[32];
    sha256(padded, n, h);
    memcpy(hash_out, h, 16);
    return CTAP2_OK;
}

int ctap2_set_pin(const char *pin, size_t len) {
    if (store_pin_set()) return CTAP2_ERR_NOT_ALLOWED;
    uint8_t padded[64] = {0};
    if (len < 4 || len > 63) return CTAP2_ERR_PIN_POLICY_VIOLATION;
    memcpy(padded, pin, len);
    uint8_t hash[16];
    int st = check_new_pin(padded, sizeof(padded), hash);
    memset(padded, 0, sizeof(padded));
    if (st != CTAP2_OK) return st;
    return store_set_pin_hash(hash) ? CTAP2_OK : CTAP1_ERR_OTHER;
}

static int verify_pin_hash(const uint8_t given[16]) {
    uint8_t retries = store_pin_retries();
    if (retries == 0) return CTAP2_ERR_PIN_BLOCKED;
    if (pin_fails_since_boot >= 3) return CTAP2_ERR_PIN_AUTH_BLOCKED;
    store_set_pin_retries(retries - 1);
    uint8_t stored[16];
    if (!store_pin_hash(stored)) return CTAP2_ERR_PIN_NOT_SET;
    if (!ct_equal(stored, given, 16)) {
        new_key_agreement();
        pin_fails_since_boot++;
        if (retries - 1 == 0) return CTAP2_ERR_PIN_BLOCKED;
        if (pin_fails_since_boot >= 3) return CTAP2_ERR_PIN_AUTH_BLOCKED;
        return CTAP2_ERR_PIN_INVALID;
    }
    store_set_pin_retries(8);
    pin_fails_since_boot = 0;
    return CTAP2_OK;
}

int ctap2_change_pin(const char *old_pin, size_t old_len, const char *new_pin, size_t new_len) {
    if (!store_pin_set()) return ctap2_set_pin(new_pin, new_len);
    uint8_t h[32];
    sha256(old_pin, old_len, h);
    int st = verify_pin_hash(h);
    if (st != CTAP2_OK) return st;
    uint8_t padded[64] = {0}, hash[16];
    if (new_len < 4 || new_len > 63) return CTAP2_ERR_PIN_POLICY_VIOLATION;
    memcpy(padded, new_pin, new_len);
    st = check_new_pin(padded, sizeof(padded), hash);
    memset(padded, 0, sizeof(padded));
    if (st != CTAP2_OK) return st;
    if (!store_set_pin_hash(hash)) return CTAP1_ERR_OTHER;
    ctap2_forget_session();
    return CTAP2_OK;
}

static bool read_cose_key(cbor_reader_t *r, uint8_t pub[64]) {
    size_t pairs;
    bool have_x = false, have_y = false;
    if (!cbor_get_map(r, &pairs)) return false;
    for (size_t i = 0; i < pairs; i++) {
        int64_t k;
        if (!cbor_get_int(r, &k)) return false;
        const uint8_t *b;
        size_t n;
        if ((k == -2 || k == -3) && cbor_get_bytes(r, &b, &n)) {
            if (n != 32) return false;
            memcpy(pub + (k == -2 ? 0 : 32), b, 32);
            if (k == -2) have_x = true;
            else have_y = true;
        } else if (!cbor_skip(r)) {
            return false;
        }
    }
    return have_x && have_y;
}

static int client_pin(cbor_reader_t *r, cbor_writer_t *w) {
    size_t pairs;
    if (!cbor_get_map(r, &pairs)) return CTAP2_ERR_INVALID_CBOR;
    int64_t protocol = 0, sub = 0;
    uint8_t platform_pub[64];
    bool have_ka = false;
    const uint8_t *pin_auth = NULL, *new_pin_enc = NULL, *pin_hash_enc = NULL;
    size_t pin_auth_len = 0, new_pin_len = 0, pin_hash_len = 0;
    for (size_t i = 0; i < pairs; i++) {
        int64_t k;
        if (!cbor_get_int(r, &k)) return CTAP2_ERR_INVALID_CBOR;
        bool ok = true;
        switch (k) {
        case 1: ok = cbor_get_int(r, &protocol); break;
        case 2: ok = cbor_get_int(r, &sub); break;
        case 3: ok = have_ka = read_cose_key(r, platform_pub); break;
        case 4: ok = cbor_get_bytes(r, &pin_auth, &pin_auth_len); break;
        case 5: ok = cbor_get_bytes(r, &new_pin_enc, &new_pin_len); break;
        case 6: ok = cbor_get_bytes(r, &pin_hash_enc, &pin_hash_len); break;
        default: ok = cbor_skip(r);
        }
        if (!ok) return CTAP2_ERR_INVALID_CBOR;
    }
    if (protocol != 1) return CTAP1_ERR_INVALID_PARAMETER;

    if (sub == 1) {
        cbor_put_map(w, 1);
        cbor_put_int(w, 3);
        cbor_put_uint(w, store_pin_retries());
        return CTAP2_OK;
    }
    if (sub == 2) {
        cbor_put_map(w, 1);
        cbor_put_int(w, 1);
        put_cose_key(w, ka_pub, COSE_ECDH_ES_HKDF_256);
        return CTAP2_OK;
    }
    if (sub < 3 || sub > 5) return CTAP1_ERR_INVALID_PARAMETER;
    if (!have_ka) return CTAP2_ERR_MISSING_PARAMETER;

    uint8_t x[32], shared[32];
    if (!p256_ecdh(ka_priv, platform_pub, x)) return CTAP1_ERR_INVALID_PARAMETER;
    sha256(x, 32, shared);
    int st = CTAP2_OK;

    if (sub == 3 || sub == 4) {
        if (!pin_auth || !new_pin_enc || (sub == 4 && !pin_hash_enc)) { st = CTAP2_ERR_MISSING_PARAMETER; goto out; }
        if (new_pin_len < 64 || new_pin_len % 16 || new_pin_len > 256) { st = CTAP2_ERR_PIN_POLICY_VIOLATION; goto out; }
        if (sub == 3 && store_pin_set()) { st = CTAP2_ERR_NOT_ALLOWED; goto out; }
        if (sub == 4 && !store_pin_set()) { st = CTAP2_ERR_PIN_NOT_SET; goto out; }
        uint8_t mac[32];
        if (sub == 3) pk_hmac_sha256(shared, 32, new_pin_enc, new_pin_len, NULL, 0, NULL, 0, mac);
        else pk_hmac_sha256(shared, 32, new_pin_enc, new_pin_len, pin_hash_enc, pin_hash_len, NULL, 0, mac);
        if (pin_auth_len != 16 || !ct_equal(mac, pin_auth, 16)) { st = CTAP2_ERR_PIN_AUTH_INVALID; goto out; }
        if (sub == 4) {
            uint8_t given[16];
            if (pin_hash_len != 16 || !aes256_cbc(false, shared, pin_hash_enc, given, 16)) { st = CTAP1_ERR_INVALID_PARAMETER; goto out; }
            if ((st = verify_pin_hash(given)) != CTAP2_OK) goto out;
        }
        uint8_t padded[256], hash[16];
        if (!aes256_cbc(false, shared, new_pin_enc, padded, new_pin_len)) { st = CTAP1_ERR_OTHER; goto out; }
        st = check_new_pin(padded, new_pin_len, hash);
        memset(padded, 0, sizeof(padded));
        if (st == CTAP2_OK && !store_set_pin_hash(hash)) st = CTAP1_ERR_OTHER;
        if (st == CTAP2_OK) ctap2_forget_session();
        goto out;
    }

    if (!pin_hash_enc || pin_hash_len != 16) { st = CTAP2_ERR_MISSING_PARAMETER; goto out; }
    if (!store_pin_set()) { st = CTAP2_ERR_PIN_NOT_SET; goto out; }
    uint8_t given[16];
    if (!aes256_cbc(false, shared, pin_hash_enc, given, 16)) { st = CTAP1_ERR_OTHER; goto out; }
    if ((st = verify_pin_hash(given)) != CTAP2_OK) goto out;
    uint8_t enc[32];
    if (!aes256_cbc(true, shared, pin_token, enc, 32)) { st = CTAP1_ERR_OTHER; goto out; }
    cbor_put_map(w, 1);
    cbor_put_int(w, 2);
    cbor_put_bytes(w, enc, 32);
out:
    memset(shared, 0, sizeof(shared));
    memset(x, 0, sizeof(x));
    return st;
}

static int get_info(cbor_writer_t *w) {
    cbor_put_map(w, 5);
    cbor_put_int(w, 1);
    cbor_put_array(w, 1);
    cbor_put_text(w, "FIDO_2_0");
    cbor_put_int(w, 3);
    cbor_put_bytes(w, AAGUID, sizeof(AAGUID));
    cbor_put_int(w, 4);
    cbor_put_map(w, 4);
    cbor_put_text(w, "rk");
    cbor_put_bool(w, true);
    cbor_put_text(w, "up");
    cbor_put_bool(w, true);
    cbor_put_text(w, "plat");
    cbor_put_bool(w, false);
    cbor_put_text(w, "clientPin");
    cbor_put_bool(w, store_pin_set());
    cbor_put_int(w, 5);
    cbor_put_uint(w, CTAP2_MAX_MSG);
    cbor_put_int(w, 6);
    cbor_put_array(w, 1);
    cbor_put_uint(w, 1);
    return CTAP2_OK;
}

static void copy_text(char *dst, size_t cap, const char *s, size_t n) {
    if (n >= cap) n = cap - 1;
    memcpy(dst, s, n);
    dst[n] = 0;
}

static int touch_probe(void) {
    int st = ctap_wait_presence();
    if (st != CTAP2_OK) return st;
    return store_pin_set() ? CTAP2_ERR_PIN_INVALID : CTAP2_ERR_PIN_NOT_SET;
}

static int make_credential(cbor_reader_t *r, cbor_writer_t *w) {
    size_t pairs;
    if (!cbor_get_map(r, &pairs)) return CTAP2_ERR_INVALID_CBOR;
    const uint8_t *cdh = NULL, *pin_auth = NULL;
    size_t cdh_len = 0, pin_auth_len = 0;
    bool have_rp = false, have_user = false, have_params = false, es256 = false, rk = false, uv = false;
    bool have_pin_auth = false;
    int64_t pin_protocol = 0;
    resident_t rec;
    memset(&rec, 0, sizeof(rec));
    cbor_reader_t exclude = {0};
    bool have_exclude = false;

    for (size_t i = 0; i < pairs; i++) {
        int64_t k;
        if (!cbor_get_int(r, &k)) return CTAP2_ERR_INVALID_CBOR;
        if (k == 1) {
            if (!cbor_get_bytes(r, &cdh, &cdh_len) || cdh_len != 32) return CTAP2_ERR_INVALID_CBOR;
        } else if (k == 2) {
            size_t n;
            if (!cbor_get_map(r, &n)) return CTAP2_ERR_INVALID_CBOR;
            for (size_t j = 0; j < n; j++) {
                const char *key, *val;
                size_t kl, vl;
                if (!cbor_get_text(r, &key, &kl)) return CTAP2_ERR_INVALID_CBOR;
                if (cbor_text_eq(key, kl, "id")) {
                    if (!cbor_get_text(r, &val, &vl) || vl == 0 || vl > MAX_RP_ID) return CTAP2_ERR_INVALID_CBOR;
                    copy_text(rec.rp_id, sizeof(rec.rp_id), val, vl);
                    sha256(val, vl, rec.rp_id_hash);
                    have_rp = true;
                } else if (!cbor_skip(r)) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
            }
        } else if (k == 3) {
            size_t n;
            if (!cbor_get_map(r, &n)) return CTAP2_ERR_INVALID_CBOR;
            for (size_t j = 0; j < n; j++) {
                const char *key, *val;
                size_t kl, vl;
                const uint8_t *b;
                if (!cbor_get_text(r, &key, &kl)) return CTAP2_ERR_INVALID_CBOR;
                if (cbor_text_eq(key, kl, "id")) {
                    if (!cbor_get_bytes(r, &b, &vl) || vl > MAX_USER_ID) return CTAP2_ERR_INVALID_CBOR;
                    memcpy(rec.user_id, b, vl);
                    rec.user_id_len = vl;
                    have_user = true;
                } else if (cbor_text_eq(key, kl, "name") && cbor_peek_type(r) == CBOR_TEXT) {
                    cbor_get_text(r, &val, &vl);
                    copy_text(rec.user_name, sizeof(rec.user_name), val, vl);
                } else if (cbor_text_eq(key, kl, "displayName") && cbor_peek_type(r) == CBOR_TEXT) {
                    cbor_get_text(r, &val, &vl);
                    copy_text(rec.display_name, sizeof(rec.display_name), val, vl);
                } else if (!cbor_skip(r)) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
            }
        } else if (k == 4) {
            size_t n;
            if (!cbor_get_array(r, &n)) return CTAP2_ERR_INVALID_CBOR;
            have_params = true;
            for (size_t j = 0; j < n; j++) {
                size_t m;
                int64_t alg = 0;
                bool pk = false;
                if (!cbor_get_map(r, &m)) return CTAP2_ERR_INVALID_CBOR;
                for (size_t q = 0; q < m; q++) {
                    const char *key, *val;
                    size_t kl, vl;
                    if (!cbor_get_text(r, &key, &kl)) return CTAP2_ERR_INVALID_CBOR;
                    if (cbor_text_eq(key, kl, "alg")) {
                        if (!cbor_get_int(r, &alg)) return CTAP2_ERR_INVALID_CBOR;
                    } else if (cbor_text_eq(key, kl, "type")) {
                        if (!cbor_get_text(r, &val, &vl)) return CTAP2_ERR_INVALID_CBOR;
                        pk = cbor_text_eq(val, vl, "public-key");
                    } else if (!cbor_skip(r)) {
                        return CTAP2_ERR_INVALID_CBOR;
                    }
                }
                if (pk && alg == COSE_ES256) es256 = true;
            }
        } else if (k == 5) {
            if (!cbor_get_item(r, &exclude)) return CTAP2_ERR_INVALID_CBOR;
            have_exclude = true;
        } else if (k == 7) {
            size_t n;
            if (!cbor_get_map(r, &n)) return CTAP2_ERR_INVALID_CBOR;
            for (size_t j = 0; j < n; j++) {
                const char *key;
                size_t kl;
                bool v;
                if (!cbor_get_text(r, &key, &kl)) return CTAP2_ERR_INVALID_CBOR;
                if (!cbor_get_bool(r, &v)) return CTAP2_ERR_INVALID_CBOR;
                if (cbor_text_eq(key, kl, "rk")) rk = v;
                else if (cbor_text_eq(key, kl, "uv")) uv = v;
                else if (cbor_text_eq(key, kl, "up") && !v) return CTAP2_ERR_INVALID_OPTION;
            }
        } else if (k == 8) {
            if (!cbor_get_bytes(r, &pin_auth, &pin_auth_len)) return CTAP2_ERR_INVALID_CBOR;
            have_pin_auth = true;
        } else if (k == 9) {
            if (!cbor_get_int(r, &pin_protocol)) return CTAP2_ERR_INVALID_CBOR;
        } else if (!cbor_skip(r)) {
            return CTAP2_ERR_INVALID_CBOR;
        }
    }

    if (have_pin_auth && pin_auth_len == 0) return touch_probe();
    if (!cdh || !have_rp || !have_user || !have_params) return CTAP2_ERR_MISSING_PARAMETER;
    if (!es256) return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
    uint8_t flags = FLAG_UP | FLAG_AT;
    if (have_pin_auth) {
        if (pin_protocol != 1) return CTAP2_ERR_PIN_AUTH_INVALID;
        if (!store_pin_set()) return CTAP2_ERR_PIN_NOT_SET;
        if (!pin_auth_ok(pin_auth, pin_auth_len, cdh)) return CTAP2_ERR_PIN_AUTH_INVALID;
        flags |= FLAG_UV;
    } else {
        if (uv) return CTAP2_ERR_UNSUPPORTED_OPTION;
        if (store_pin_set()) return CTAP2_ERR_PIN_REQUIRED;
    }

    if (have_exclude) {
        size_t n;
        if (!cbor_get_array(&exclude, &n)) return CTAP2_ERR_INVALID_CBOR;
        for (size_t j = 0; j < n; j++) {
            size_t m;
            if (!cbor_get_map(&exclude, &m)) return CTAP2_ERR_INVALID_CBOR;
            for (size_t q = 0; q < m; q++) {
                const char *key;
                size_t kl;
                const uint8_t *id;
                size_t idl;
                if (!cbor_get_text(&exclude, &key, &kl)) return CTAP2_ERR_INVALID_CBOR;
                if (cbor_text_eq(key, kl, "id")) {
                    if (!cbor_get_bytes(&exclude, &id, &idl)) return CTAP2_ERR_INVALID_CBOR;
                    if (cred_id_valid(id, idl, rec.rp_id_hash)) {
                        ctap_wait_presence();
                        return CTAP2_ERR_CREDENTIAL_EXCLUDED;
                    }
                } else if (!cbor_skip(&exclude)) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
            }
        }
    }

    if (rk && store_resident_count() >= MAX_RESIDENT) {
        bool replaces = false;
        resident_t old;
        for (int s = 0; s < MAX_RESIDENT && !replaces; s++)
            replaces = store_resident_get(s, &old) && !memcmp(old.rp_id_hash, rec.rp_id_hash, 32) &&
                       old.user_id_len == rec.user_id_len && !memcmp(old.user_id, rec.user_id, old.user_id_len);
        if (!replaces) return CTAP2_ERR_KEY_STORE_FULL;
    }

    int st = ctap_wait_presence();
    if (st != CTAP2_OK) return st;

    make_cred_id(rec.rp_id_hash, rec.cred_id);
    uint8_t priv[32], pub[64];
    if (!cred_private_key(rec.cred_id, rec.rp_id_hash, priv) || !p256_public(priv, pub)) return CTAP1_ERR_OTHER;
    if (rk && !store_resident_put(&rec)) {
        memset(priv, 0, sizeof(priv));
        return CTAP2_ERR_KEY_STORE_FULL;
    }

    uint8_t ad[256];
    size_t ad_len = auth_data(ad, rec.rp_id_hash, flags, store_next_counter());
    memcpy(ad + ad_len, AAGUID, 16);
    ad_len += 16;
    ad[ad_len++] = 0;
    ad[ad_len++] = CRED_ID_LEN;
    memcpy(ad + ad_len, rec.cred_id, CRED_ID_LEN);
    ad_len += CRED_ID_LEN;
    cbor_writer_t kw;
    cbor_writer_init(&kw, ad + ad_len, sizeof(ad) - ad_len);
    put_cose_key(&kw, pub, COSE_ES256);
    ad_len += kw.len;

    uint8_t sig[80];
    size_t sig_len;
    bool ok = sign_with(priv, ad, ad_len, cdh, sig, &sig_len);
    memset(priv, 0, sizeof(priv));
    if (!ok) return CTAP1_ERR_OTHER;

    cbor_put_map(w, 3);
    cbor_put_int(w, 1);
    cbor_put_text(w, "packed");
    cbor_put_int(w, 2);
    cbor_put_bytes(w, ad, ad_len);
    cbor_put_int(w, 3);
    cbor_put_map(w, 2);
    cbor_put_text(w, "alg");
    cbor_put_int(w, COSE_ES256);
    cbor_put_text(w, "sig");
    cbor_put_bytes(w, sig, sig_len);
    return CTAP2_OK;
}

static int write_assertion(cbor_writer_t *w, const uint8_t cred_id[CRED_ID_LEN], const uint8_t rp_id_hash[32],
                           const uint8_t cdh[32], uint8_t flags, const resident_t *user, int total) {
    uint8_t priv[32];
    if (!cred_private_key(cred_id, rp_id_hash, priv)) return CTAP1_ERR_OTHER;
    uint8_t ad[37], sig[80];
    size_t sig_len;
    auth_data(ad, rp_id_hash, flags, store_next_counter());
    bool ok = sign_with(priv, ad, sizeof(ad), cdh, sig, &sig_len);
    memset(priv, 0, sizeof(priv));
    if (!ok) return CTAP1_ERR_OTHER;

    size_t fields = 3 + (user ? 1 : 0) + (total > 1 ? 1 : 0);
    cbor_put_map(w, fields);
    cbor_put_int(w, 1);
    cbor_put_map(w, 2);
    cbor_put_text(w, "id");
    cbor_put_bytes(w, cred_id, CRED_ID_LEN);
    cbor_put_text(w, "type");
    cbor_put_text(w, "public-key");
    cbor_put_int(w, 2);
    cbor_put_bytes(w, ad, sizeof(ad));
    cbor_put_int(w, 3);
    cbor_put_bytes(w, sig, sig_len);
    if (user) {
        bool names = (flags & FLAG_UV) && total > 1;
        size_t n = 1 + (names && user->user_name[0] ? 1 : 0) + (names && user->display_name[0] ? 1 : 0);
        cbor_put_int(w, 4);
        cbor_put_map(w, n);
        cbor_put_text(w, "id");
        cbor_put_bytes(w, user->user_id, user->user_id_len);
        if (names && user->user_name[0]) {
            cbor_put_text(w, "name");
            cbor_put_text(w, user->user_name);
        }
        if (names && user->display_name[0]) {
            cbor_put_text(w, "displayName");
            cbor_put_text(w, user->display_name);
        }
    }
    if (total > 1) {
        cbor_put_int(w, 5);
        cbor_put_uint(w, total);
    }
    return CTAP2_OK;
}

static int get_assertion(cbor_reader_t *r, cbor_writer_t *w) {
    size_t pairs;
    if (!cbor_get_map(r, &pairs)) return CTAP2_ERR_INVALID_CBOR;
    const uint8_t *cdh = NULL, *pin_auth = NULL;
    size_t cdh_len = 0, pin_auth_len = 0;
    uint8_t rp_id_hash[32];
    bool have_rp = false, up = true, uv = false, have_pin_auth = false, have_allow = false;
    int64_t pin_protocol = 0;
    cbor_reader_t allow = {0};

    for (size_t i = 0; i < pairs; i++) {
        int64_t k;
        if (!cbor_get_int(r, &k)) return CTAP2_ERR_INVALID_CBOR;
        if (k == 1) {
            const char *rp;
            size_t n;
            if (!cbor_get_text(r, &rp, &n) || n == 0) return CTAP2_ERR_INVALID_CBOR;
            sha256(rp, n, rp_id_hash);
            have_rp = true;
        } else if (k == 2) {
            if (!cbor_get_bytes(r, &cdh, &cdh_len) || cdh_len != 32) return CTAP2_ERR_INVALID_CBOR;
        } else if (k == 3) {
            if (!cbor_get_item(r, &allow)) return CTAP2_ERR_INVALID_CBOR;
            have_allow = true;
        } else if (k == 5) {
            size_t n;
            if (!cbor_get_map(r, &n)) return CTAP2_ERR_INVALID_CBOR;
            for (size_t j = 0; j < n; j++) {
                const char *key;
                size_t kl;
                bool v;
                if (!cbor_get_text(r, &key, &kl) || !cbor_get_bool(r, &v)) return CTAP2_ERR_INVALID_CBOR;
                if (cbor_text_eq(key, kl, "up")) up = v;
                else if (cbor_text_eq(key, kl, "uv")) uv = v;
                else if (cbor_text_eq(key, kl, "rk")) return CTAP2_ERR_INVALID_OPTION;
            }
        } else if (k == 6) {
            if (!cbor_get_bytes(r, &pin_auth, &pin_auth_len)) return CTAP2_ERR_INVALID_CBOR;
            have_pin_auth = true;
        } else if (k == 7) {
            if (!cbor_get_int(r, &pin_protocol)) return CTAP2_ERR_INVALID_CBOR;
        } else if (!cbor_skip(r)) {
            return CTAP2_ERR_INVALID_CBOR;
        }
    }

    if (have_pin_auth && pin_auth_len == 0) return touch_probe();
    if (!have_rp || !cdh) return CTAP2_ERR_MISSING_PARAMETER;
    uint8_t flags = 0;
    if (have_pin_auth) {
        if (pin_protocol != 1) return CTAP2_ERR_PIN_AUTH_INVALID;
        if (!store_pin_set()) return CTAP2_ERR_PIN_NOT_SET;
        if (!pin_auth_ok(pin_auth, pin_auth_len, cdh)) return CTAP2_ERR_PIN_AUTH_INVALID;
        flags |= FLAG_UV;
    } else if (uv) {
        return CTAP2_ERR_UNSUPPORTED_OPTION;
    }

    memset(&next_state, 0, sizeof(next_state));
    const uint8_t *chosen = NULL;
    resident_t found;
    bool chosen_resident = false;
    int total = 0;

    if (have_allow) {
        size_t n;
        if (!cbor_get_array(&allow, &n)) return CTAP2_ERR_INVALID_CBOR;
        for (size_t j = 0; j < n; j++) {
            size_t m;
            if (!cbor_get_map(&allow, &m)) return CTAP2_ERR_INVALID_CBOR;
            for (size_t q = 0; q < m; q++) {
                const char *key;
                size_t kl;
                const uint8_t *id;
                size_t idl;
                if (!cbor_get_text(&allow, &key, &kl)) return CTAP2_ERR_INVALID_CBOR;
                if (cbor_text_eq(key, kl, "id")) {
                    if (!cbor_get_bytes(&allow, &id, &idl)) return CTAP2_ERR_INVALID_CBOR;
                    if (!chosen && cred_id_valid(id, idl, rp_id_hash)) chosen = id;
                } else if (!cbor_skip(&allow)) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
            }
        }
        if (!chosen) return CTAP2_ERR_NO_CREDENTIALS;
        total = 1;
    } else {
        resident_t r2;
        for (int s = 0; s < MAX_RESIDENT; s++) {
            if (store_resident_get(s, &r2) && !memcmp(r2.rp_id_hash, rp_id_hash, 32)) {
                int at = next_state.count++;
                next_state.slots[at] = s;
                while (at > 0) {
                    resident_t a;
                    store_resident_get(next_state.slots[at - 1], &a);
                    if (a.created >= r2.created) break;
                    int t = next_state.slots[at - 1];
                    next_state.slots[at - 1] = next_state.slots[at];
                    next_state.slots[at] = t;
                    at--;
                }
            }
        }
        total = next_state.count;
        if (total == 0) return CTAP2_ERR_NO_CREDENTIALS;
        store_resident_get(next_state.slots[0], &found);
        chosen = found.cred_id;
        chosen_resident = true;
    }

    if (up) {
        int st = ctap_wait_presence();
        if (st != CTAP2_OK) {
            memset(&next_state, 0, sizeof(next_state));
            return st;
        }
        flags |= FLAG_UP;
    }
    if (!chosen_resident && store_resident_find(chosen, NULL, &found)) chosen_resident = true;

    if (!have_allow && total > 1) {
        next_state.active = true;
        next_state.next = 1;
        memcpy(next_state.rp_id_hash, rp_id_hash, 32);
        memcpy(next_state.client_data_hash, cdh, 32);
        next_state.flags = flags;
        next_state.at = esp_timer_get_time();
    }
    uint8_t id_copy[CRED_ID_LEN];
    memcpy(id_copy, chosen, CRED_ID_LEN);
    return write_assertion(w, id_copy, rp_id_hash, cdh, flags, chosen_resident ? &found : NULL, have_allow ? 1 : total);
}

static int get_next_assertion(cbor_writer_t *w) {
    if (!next_state.active || next_state.next >= next_state.count ||
        esp_timer_get_time() - next_state.at > 30 * 1000000LL) {
        memset(&next_state, 0, sizeof(next_state));
        return CTAP2_ERR_NOT_ALLOWED;
    }
    resident_t rec;
    if (!store_resident_get(next_state.slots[next_state.next++], &rec)) return CTAP1_ERR_OTHER;
    next_state.at = esp_timer_get_time();
    int st = write_assertion(w, rec.cred_id, next_state.rp_id_hash, next_state.client_data_hash, next_state.flags, &rec, 1);
    if (next_state.next >= next_state.count) memset(&next_state, 0, sizeof(next_state));
    return st;
}

static int reset(void) {
    if (esp_timer_get_time() > 10 * 1000000LL) return CTAP2_ERR_NOT_ALLOWED;
    int st = ctap_wait_presence();
    if (st != CTAP2_OK) return st;
    if (!store_wipe()) return CTAP1_ERR_OTHER;
    pin_fails_since_boot = 0;
    ctap2_forget_session();
    new_key_agreement();
    return CTAP2_OK;
}

size_t ctap2_handle(const uint8_t *req, size_t len, uint8_t *resp, size_t cap) {
    if (len < 1 || cap < 1) return 0;
    cbor_reader_t r;
    cbor_reader_init(&r, req + 1, len - 1);
    cbor_writer_t w;
    cbor_writer_init(&w, resp + 1, cap - 1);
    int st;
    switch (req[0]) {
    case CMD_GET_INFO: st = get_info(&w); break;
    case CMD_MAKE_CREDENTIAL: st = make_credential(&r, &w); break;
    case CMD_GET_ASSERTION: st = get_assertion(&r, &w); break;
    case CMD_GET_NEXT_ASSERTION: st = get_next_assertion(&w); break;
    case CMD_CLIENT_PIN: st = client_pin(&r, &w); break;
    case CMD_RESET: st = reset(); break;
    case CMD_SELECTION: st = ctap_wait_presence(); break;
    default: st = CTAP1_ERR_INVALID_COMMAND;
    }
    if (st == CTAP2_OK && w.overflow) st = CTAP2_ERR_REQUEST_TOO_LARGE;
    resp[0] = (uint8_t)st;
    return st == CTAP2_OK ? 1 + w.len : 1;
}
