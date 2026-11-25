#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CRED_ID_LEN 33
#define MAX_RESIDENT 50
#define MAX_RP_ID 128
#define MAX_USER_ID 64
#define MAX_USER_NAME 64

typedef struct {
    uint8_t cred_id[CRED_ID_LEN];
    uint8_t rp_id_hash[32];
    char rp_id[MAX_RP_ID + 1];
    uint8_t user_id[MAX_USER_ID];
    uint8_t user_id_len;
    char user_name[MAX_USER_NAME + 1];
    char display_name[MAX_USER_NAME + 1];
    uint32_t created;
} resident_t;

typedef enum { TOUCH_BUTTON = 0, TOUCH_AUTO = 1 } touch_mode_t;

bool store_init(void);
const uint8_t *store_master_key(void);

bool store_pin_set(void);
bool store_pin_hash(uint8_t out[16]);
bool store_set_pin_hash(const uint8_t hash[16]);
uint8_t store_pin_retries(void);
void store_set_pin_retries(uint8_t retries);

uint32_t store_next_counter(void);

touch_mode_t store_touch_mode(void);
void store_set_touch_mode(touch_mode_t mode);

int store_resident_count(void);
bool store_resident_get(int slot, resident_t *out);
bool store_resident_find(const uint8_t cred_id[CRED_ID_LEN], int *slot, resident_t *out);
bool store_resident_put(resident_t *rec);
bool store_resident_delete(const uint8_t cred_id[CRED_ID_LEN]);

bool store_wipe(void);

uint32_t store_rev(void);
void store_bump_rev(void);

size_t store_state_max_size(void);
bool store_export(uint8_t *buf, size_t cap, size_t *len);
bool store_import(const uint8_t *buf, size_t len);
