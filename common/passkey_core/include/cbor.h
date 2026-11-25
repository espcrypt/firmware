#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
    bool overflow;
} cbor_writer_t;

void cbor_writer_init(cbor_writer_t *w, uint8_t *buf, size_t cap);
void cbor_put_uint(cbor_writer_t *w, uint64_t v);
void cbor_put_int(cbor_writer_t *w, int64_t v);
void cbor_put_bytes(cbor_writer_t *w, const uint8_t *data, size_t len);
void cbor_put_text(cbor_writer_t *w, const char *s);
void cbor_put_bool(cbor_writer_t *w, bool v);
void cbor_put_map(cbor_writer_t *w, size_t pairs);
void cbor_put_array(cbor_writer_t *w, size_t items);

typedef struct {
    const uint8_t *p;
    const uint8_t *end;
} cbor_reader_t;

enum { CBOR_UINT = 0, CBOR_NEGINT = 1, CBOR_BYTES = 2, CBOR_TEXT = 3, CBOR_ARRAY = 4, CBOR_MAP = 5, CBOR_TAG = 6, CBOR_SIMPLE = 7 };

void cbor_reader_init(cbor_reader_t *r, const uint8_t *buf, size_t len);
int cbor_peek_type(const cbor_reader_t *r);
bool cbor_get_int(cbor_reader_t *r, int64_t *v);
bool cbor_get_bytes(cbor_reader_t *r, const uint8_t **data, size_t *len);
bool cbor_get_text(cbor_reader_t *r, const char **s, size_t *len);
bool cbor_get_bool(cbor_reader_t *r, bool *v);
bool cbor_get_map(cbor_reader_t *r, size_t *pairs);
bool cbor_get_array(cbor_reader_t *r, size_t *items);
bool cbor_skip(cbor_reader_t *r);
bool cbor_get_item(cbor_reader_t *r, cbor_reader_t *item);
bool cbor_text_eq(const char *s, size_t len, const char *want);
