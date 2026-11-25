#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/base64.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "radio.h"

enum { ST_HELLO, ST_FIN, ST_READY, ST_DEAD };

struct rsess {
    int origin;
    int state;
    rsess_write_t write;
    void *ctx;
    uint8_t th[32], conf[32];
    mbedtls_gcm_context tx, rx;
    uint64_t tx_seq, rx_seq;
};

static void wipe(void *p, size_t n) {
    volatile uint8_t *v = p;
    while (n--) *v++ = 0;
}

static int rng(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    esp_fill_random(out, len);
    return 0;
}

static void hmac(const uint8_t *key, size_t kl, const uint8_t *a, size_t al, const uint8_t *b, size_t bl,
                 const uint8_t *c, size_t cl, uint8_t out[32]) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t m;
    mbedtls_md_init(&m);
    mbedtls_md_setup(&m, md, 1);
    mbedtls_md_hmac_starts(&m, key, kl);
    if (al) mbedtls_md_hmac_update(&m, a, al);
    if (bl) mbedtls_md_hmac_update(&m, b, bl);
    if (cl) mbedtls_md_hmac_update(&m, c, cl);
    mbedtls_md_hmac_finish(&m, out);
    mbedtls_md_free(&m);
}

static void hkdf96(const uint8_t salt[32], const uint8_t ikm[32], const uint8_t th[32], uint8_t out[96]) {
    uint8_t prk[32], info[40], t[32];
    memcpy(info, "VS1 keys", 8);
    memcpy(info + 8, th, 32);
    hmac(salt, 32, ikm, 32, NULL, 0, NULL, 0, prk);
    for (uint8_t i = 1; i <= 3; i++) {
        hmac(prk, 32, i > 1 ? t : NULL, i > 1 ? 32 : 0, info, sizeof(info), &i, 1, t);
        memcpy(out + 32 * (i - 1), t, 32);
    }
    wipe(prk, sizeof(prk));
    wipe(t, sizeof(t));
}

static void th_part(mbedtls_sha256_context *h, const void *p, size_t n) {
    uint8_t l[2] = {(uint8_t)(n >> 8), (uint8_t)n};
    mbedtls_sha256_update(h, l, 2);
    mbedtls_sha256_update(h, p, n);
}

static bool unb64(const char *s, uint8_t *out, size_t want) {
    size_t got = 0;
    return s && mbedtls_base64_decode(out, want, &got, (const uint8_t *)s, strlen(s)) == 0 && got == want;
}

static char *enb64(const uint8_t *p, size_t n) {
    size_t cap = 4 * ((n + 2) / 3) + 1, got = 0;
    char *o = malloc(cap);
    if (o && mbedtls_base64_encode((uint8_t *)o, cap, &got, p, n) != 0) {
        free(o);
        return NULL;
    }
    if (o) o[got] = 0;
    return o;
}

static void send_json(rsess_t *s, cJSON *o) {
    char *line = cJSON_PrintUnformatted(o);
    if (line) {
        s->write(s->ctx, line, strlen(line));
        free(line);
    }
    cJSON_Delete(o);
}

static void send_err(rsess_t *s, const char *why) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "hs", "err");
    cJSON_AddStringToObject(o, "error", why);
    send_json(s, o);
}

static void nonce(uint8_t n[12], const char *dir, uint64_t seq) {
    memcpy(n, dir, 4);
    for (int i = 0; i < 8; i++) n[4 + i] = (uint8_t)(seq >> (56 - 8 * i));
}

rsess_t *rsess_new(int origin, rsess_write_t write, void *ctx) {
    rsess_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->origin = origin;
    s->write = write;
    s->ctx = ctx;
    mbedtls_gcm_init(&s->tx);
    mbedtls_gcm_init(&s->rx);
    return s;
}

void rsess_free(rsess_t *s) {
    if (!s) return;
    mbedtls_gcm_free(&s->tx);
    mbedtls_gcm_free(&s->rx);
    wipe(s, sizeof(*s));
    free(s);
}

bool rsess_ready(const rsess_t *s) { return s && s->state == ST_READY; }

static bool hex8(const char *h, uint8_t out[8]) {
    if (!h || strlen(h) != 16) return false;
    for (int i = 0; i < 16; i++) {
        char c = h[i];
        int v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        if (v < 0) return false;
        out[i / 2] = (uint8_t)((i % 2) ? (out[i / 2] | v) : (v << 4));
    }
    return true;
}

static bool hello(rsess_t *s, cJSON *m) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(m, "v");
    const char *kidh = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(m, "kid"));
    uint8_t kid[8], key[32], epkC[32], nC[16], epkD[32], nD[16], shared[32], okm[96];
    if (!cJSON_IsNumber(v) || v->valueint != 1 || !hex8(kidh, kid) ||
        !unb64(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(m, "epk")), epkC, 32) ||
        !unb64(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(m, "n")), nC, 16)) {
        send_err(s, "bad hello");
        return false;
    }
    if (!radio_client_key(kid, key)) {
        vTaskDelay(pdMS_TO_TICKS(500));
        send_err(s, "unknown client");
        return false;
    }
    mbedtls_ecp_group grp;
    mbedtls_mpi d, z;
    mbedtls_ecp_point Q, P;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_point_init(&P);
    size_t olen = 0;
    bool ok = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) == 0 &&
              mbedtls_ecp_gen_keypair(&grp, &d, &Q, rng, NULL) == 0 &&
              mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, epkD, 32) == 0 && olen == 32 &&
              mbedtls_ecp_point_read_binary(&grp, &P, epkC, 32) == 0 &&
              mbedtls_ecdh_compute_shared(&grp, &z, &P, &d, rng, NULL) == 0 &&
              mbedtls_mpi_write_binary_le(&z, shared, 32) == 0;
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&z);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_point_free(&P);
    mbedtls_ecp_group_free(&grp);
    if (!ok) {
        wipe(key, sizeof(key));
        send_err(s, "key exchange failed");
        return false;
    }
    esp_fill_random(nD, sizeof(nD));
    const char *id = vault_device_id();
    mbedtls_sha256_context h;
    mbedtls_sha256_init(&h);
    mbedtls_sha256_starts(&h, 0);
    mbedtls_sha256_update(&h, (const uint8_t *)"VS1", 3);
    th_part(&h, kid, 8);
    th_part(&h, epkC, 32);
    th_part(&h, nC, 16);
    th_part(&h, epkD, 32);
    th_part(&h, nD, 16);
    th_part(&h, id, strlen(id));
    mbedtls_sha256_finish(&h, s->th);
    mbedtls_sha256_free(&h);
    hkdf96(key, shared, s->th, okm);
    mbedtls_gcm_setkey(&s->rx, MBEDTLS_CIPHER_ID_AES, okm, 256);
    mbedtls_gcm_setkey(&s->tx, MBEDTLS_CIPHER_ID_AES, okm + 32, 256);
    memcpy(s->conf, okm + 64, 32);
    uint8_t mac[32];
    hmac(s->conf, 32, (const uint8_t *)"D", 1, s->th, 32, NULL, 0, mac);
    wipe(key, sizeof(key));
    wipe(shared, sizeof(shared));
    wipe(okm, sizeof(okm));
    char *e = enb64(epkD, 32), *n = enb64(nD, 16), *mm = enb64(mac, 32);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "hs", "ok");
    cJSON_AddStringToObject(o, "epk", e ? e : "");
    cJSON_AddStringToObject(o, "n", n ? n : "");
    cJSON_AddStringToObject(o, "id", id);
    cJSON_AddStringToObject(o, "mac", mm ? mm : "");
    free(e);
    free(n);
    free(mm);
    send_json(s, o);
    s->state = ST_FIN;
    return true;
}

static bool fin(rsess_t *s, cJSON *m) {
    uint8_t got[32], want[32];
    hmac(s->conf, 32, (const uint8_t *)"C", 1, s->th, 32, NULL, 0, want);
    bool ok = unb64(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(m, "mac")), got, 32);
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= got[i] ^ want[i];
    wipe(s->conf, sizeof(s->conf));
    if (!ok || diff) {
        send_err(s, "authentication failed");
        return false;
    }
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "hs", "ready");
    send_json(s, o);
    s->state = ST_READY;
    return true;
}

static void sink(void *ctx, const char *line, size_t len) {
    rsess_t *s = ctx;
    if (s->state != ST_READY) return;
    uint8_t *buf = malloc(len + 16);
    if (!buf) return;
    uint8_t n[12];
    nonce(n, "D2C\0", s->tx_seq++);
    if (mbedtls_gcm_crypt_and_tag(&s->tx, MBEDTLS_GCM_ENCRYPT, len, n, 12, NULL, 0, (const uint8_t *)line, buf,
                                  16, buf + len) == 0) {
        char *b = enb64(buf, len + 16);
        if (b) {
            size_t bl = strlen(b);
            char *out = malloc(bl + 9);
            if (out) {
                memcpy(out, "{\"e\":\"", 6);
                memcpy(out + 6, b, bl);
                memcpy(out + 6 + bl, "\"}", 3);
                s->write(s->ctx, out, bl + 8);
                free(out);
            }
            free(b);
        }
    }
    wipe(buf, len + 16);
    free(buf);
}

static bool frame(rsess_t *s, cJSON *m) {
    const char *e = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(m, "e"));
    if (!e) return false;
    size_t el = strlen(e), cap = el / 4 * 3 + 3, n = 0;
    uint8_t *ct = malloc(cap), *pt = NULL;
    bool ok = ct && mbedtls_base64_decode(ct, cap, &n, (const uint8_t *)e, el) == 0 && n > 16;
    if (ok) {
        size_t len = n - 16;
        pt = malloc(len + 1);
        uint8_t iv[12];
        nonce(iv, "C2D\0", s->rx_seq);
        ok = pt && mbedtls_gcm_auth_decrypt(&s->rx, len, iv, 12, NULL, 0, ct + len, 16, ct, pt) == 0;
        if (ok) {
            s->rx_seq++;
            pt[len] = 0;
            vault_handle_line((const char *)pt, s->origin, sink, s);
            wipe(pt, len);
        }
    }
    free(ct);
    free(pt);
    return ok;
}

bool rsess_input(rsess_t *s, const char *line) {
    if (!s || s->state == ST_DEAD) return false;
    cJSON *m = cJSON_Parse(line);
    if (!m) {
        s->state = ST_DEAD;
        return false;
    }
    bool keep = false;
    const char *hs = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(m, "hs"));
    if (s->state == ST_HELLO && hs && strcmp(hs, "hello") == 0) keep = hello(s, m);
    else if (s->state == ST_FIN && hs && strcmp(hs, "fin") == 0) keep = fin(s, m);
    else if (s->state == ST_READY && !hs) keep = frame(s, m);
    cJSON_Delete(m);
    if (!keep) s->state = ST_DEAD;
    return keep;
}
