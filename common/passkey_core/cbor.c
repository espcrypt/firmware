#include "cbor.h"

#include <string.h>

#define CBOR_MAX_DEPTH 8

void cbor_writer_init(cbor_writer_t *w, uint8_t *buf, size_t cap) {
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->overflow = false;
}

static void put(cbor_writer_t *w, const void *data, size_t n) {
    if (w->overflow || w->len + n > w->cap) {
        w->overflow = true;
        return;
    }
    memcpy(w->buf + w->len, data, n);
    w->len += n;
}

static void put_head(cbor_writer_t *w, uint8_t major, uint64_t v) {
    uint8_t h[9];
    size_t n;
    major <<= 5;
    if (v < 24) {
        h[0] = major | (uint8_t)v;
        n = 1;
    } else if (v <= 0xFF) {
        h[0] = major | 24;
        h[1] = (uint8_t)v;
        n = 2;
    } else if (v <= 0xFFFF) {
        h[0] = major | 25;
        h[1] = (uint8_t)(v >> 8);
        h[2] = (uint8_t)v;
        n = 3;
    } else if (v <= 0xFFFFFFFFu) {
        h[0] = major | 26;
        for (int i = 0; i < 4; i++) h[1 + i] = (uint8_t)(v >> (24 - 8 * i));
        n = 5;
    } else {
        h[0] = major | 27;
        for (int i = 0; i < 8; i++) h[1 + i] = (uint8_t)(v >> (56 - 8 * i));
        n = 9;
    }
    put(w, h, n);
}

void cbor_put_uint(cbor_writer_t *w, uint64_t v) { put_head(w, CBOR_UINT, v); }

void cbor_put_int(cbor_writer_t *w, int64_t v) {
    if (v >= 0) put_head(w, CBOR_UINT, (uint64_t)v);
    else put_head(w, CBOR_NEGINT, (uint64_t)(-1 - v));
}

void cbor_put_bytes(cbor_writer_t *w, const uint8_t *data, size_t len) {
    put_head(w, CBOR_BYTES, len);
    put(w, data, len);
}

void cbor_put_text(cbor_writer_t *w, const char *s) {
    size_t len = strlen(s);
    put_head(w, CBOR_TEXT, len);
    put(w, s, len);
}

void cbor_put_bool(cbor_writer_t *w, bool v) {
    uint8_t b = v ? 0xF5 : 0xF4;
    put(w, &b, 1);
}

void cbor_put_map(cbor_writer_t *w, size_t pairs) { put_head(w, CBOR_MAP, pairs); }
void cbor_put_array(cbor_writer_t *w, size_t items) { put_head(w, CBOR_ARRAY, items); }

void cbor_reader_init(cbor_reader_t *r, const uint8_t *buf, size_t len) {
    r->p = buf;
    r->end = buf + len;
}

int cbor_peek_type(const cbor_reader_t *r) { return r->p < r->end ? (r->p[0] >> 5) : -1; }

static bool get_head(cbor_reader_t *r, uint8_t *major, uint64_t *arg) {
    if (r->p >= r->end) return false;
    uint8_t ib = *r->p++;
    *major = ib >> 5;
    uint8_t ai = ib & 0x1F;
    if (ai < 24) {
        *arg = ai;
        return true;
    }
    size_t n = ai == 24 ? 1 : ai == 25 ? 2 : ai == 26 ? 4 : ai == 27 ? 8 : 0;
    if (!n || (size_t)(r->end - r->p) < n) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) v = (v << 8) | *r->p++;
    *arg = v;
    return true;
}

bool cbor_get_int(cbor_reader_t *r, int64_t *v) {
    const uint8_t *save = r->p;
    uint8_t major;
    uint64_t arg;
    if (!get_head(r, &major, &arg) || arg > INT64_MAX || (major != CBOR_UINT && major != CBOR_NEGINT)) {
        r->p = save;
        return false;
    }
    *v = major == CBOR_UINT ? (int64_t)arg : -1 - (int64_t)arg;
    return true;
}

static bool get_string(cbor_reader_t *r, uint8_t want, const uint8_t **data, size_t *len) {
    const uint8_t *save = r->p;
    uint8_t major;
    uint64_t arg;
    if (!get_head(r, &major, &arg) || major != want || arg > (uint64_t)(r->end - r->p)) {
        r->p = save;
        return false;
    }
    *data = r->p;
    *len = (size_t)arg;
    r->p += arg;
    return true;
}

bool cbor_get_bytes(cbor_reader_t *r, const uint8_t **data, size_t *len) { return get_string(r, CBOR_BYTES, data, len); }

bool cbor_get_text(cbor_reader_t *r, const char **s, size_t *len) {
    return get_string(r, CBOR_TEXT, (const uint8_t **)s, len);
}

bool cbor_get_bool(cbor_reader_t *r, bool *v) {
    if (r->p >= r->end || (*r->p != 0xF4 && *r->p != 0xF5)) return false;
    *v = *r->p++ == 0xF5;
    return true;
}

static bool get_container(cbor_reader_t *r, uint8_t want, size_t *n) {
    const uint8_t *save = r->p;
    uint8_t major;
    uint64_t arg;
    if (!get_head(r, &major, &arg) || major != want || arg > 4096) {
        r->p = save;
        return false;
    }
    *n = (size_t)arg;
    return true;
}

bool cbor_get_map(cbor_reader_t *r, size_t *pairs) { return get_container(r, CBOR_MAP, pairs); }
bool cbor_get_array(cbor_reader_t *r, size_t *items) { return get_container(r, CBOR_ARRAY, items); }

static bool skip_depth(cbor_reader_t *r, int depth) {
    if (depth > CBOR_MAX_DEPTH) return false;
    uint8_t major;
    uint64_t arg;
    if (!get_head(r, &major, &arg)) return false;
    switch (major) {
    case CBOR_UINT:
    case CBOR_NEGINT:
    case CBOR_SIMPLE:
        return true;
    case CBOR_BYTES:
    case CBOR_TEXT:
        if (arg > (uint64_t)(r->end - r->p)) return false;
        r->p += arg;
        return true;
    case CBOR_ARRAY:
    case CBOR_MAP: {
        if (arg > 4096) return false;
        uint64_t items = major == CBOR_MAP ? arg * 2 : arg;
        for (uint64_t i = 0; i < items; i++)
            if (!skip_depth(r, depth + 1)) return false;
        return true;
    }
    case CBOR_TAG:
        return skip_depth(r, depth + 1);
    }
    return false;
}

bool cbor_skip(cbor_reader_t *r) {
    const uint8_t *save = r->p;
    if (!skip_depth(r, 0)) {
        r->p = save;
        return false;
    }
    return true;
}

bool cbor_get_item(cbor_reader_t *r, cbor_reader_t *item) {
    const uint8_t *start = r->p;
    if (!cbor_skip(r)) return false;
    item->p = start;
    item->end = r->p;
    return true;
}

bool cbor_text_eq(const char *s, size_t len, const char *want) {
    return strlen(want) == len && memcmp(s, want, len) == 0;
}
