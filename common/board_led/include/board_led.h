#pragma once
#include <stdbool.h>
#include <stdint.h>

void board_led_init(void);
bool board_led_is_rgb(void);
void board_led_set(bool on);
void board_led_rgb(uint8_t r, uint8_t g, uint8_t b);
