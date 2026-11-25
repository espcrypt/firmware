#include "board_led.h"

#include "driver/gpio.h"
#include "sdkconfig.h"

#if CONFIG_IDF_TARGET_ESP32S3
#include "driver/rmt_tx.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#endif

#if CONFIG_IDF_TARGET_ESP32C3
#define LED_GPIO GPIO_NUM_8
#elif CONFIG_IDF_TARGET_ESP32C6
#define LED_GPIO GPIO_NUM_15
#else
#define LED_GPIO GPIO_NUM_21
#endif

static bool rgb;
static bool ready;
static uint8_t last[3] = {1, 1, 1};

#if CONFIG_IDF_TARGET_ESP32S3
static rmt_channel_handle_t chan;
static rmt_encoder_handle_t enc;

static bool rgb_init(void) {
    uint8_t flash_cap = 0;
    if (esp_efuse_read_field_blob(ESP_EFUSE_FLASH_CAP, &flash_cap, ESP_EFUSE_FLASH_CAP[0]->bit_count) != ESP_OK || !flash_cap)
        return false;
    rmt_tx_channel_config_t cfg = {
        .gpio_num = LED_GPIO,
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 10 * 1000 * 1000,
        .mem_block_symbols = 64,
        .trans_queue_depth = 2,
    };
    if (rmt_new_tx_channel(&cfg, &chan) != ESP_OK) return false;
    rmt_bytes_encoder_config_t bytes = {
        .bit0 = {.level0 = 1, .duration0 = 3, .level1 = 0, .duration1 = 9},
        .bit1 = {.level0 = 1, .duration0 = 9, .level1 = 0, .duration1 = 3},
        .flags.msb_first = 1,
    };
    if (rmt_new_bytes_encoder(&bytes, &enc) != ESP_OK || rmt_enable(chan) != ESP_OK) return false;
    return true;
}
#endif

void board_led_init(void) {
#if CONFIG_IDF_TARGET_ESP32S3
    rgb = rgb_init();
#endif
    if (!rgb) {
        gpio_config_t cfg = {.pin_bit_mask = 1ULL << LED_GPIO, .mode = GPIO_MODE_OUTPUT};
        gpio_config(&cfg);
    }
    ready = true;
    board_led_rgb(0, 0, 0);
}

bool board_led_is_rgb(void) { return rgb; }

#define RGB_BRIGHTNESS 4

static uint8_t bright(uint8_t v) {
    unsigned s = (unsigned)v * RGB_BRIGHTNESS;
    return s > 255 ? 255 : (uint8_t)s;
}

void board_led_rgb(uint8_t r, uint8_t g, uint8_t b) {
    r = bright(r);
    g = bright(g);
    b = bright(b);
    if (!ready || (last[0] == r && last[1] == g && last[2] == b)) return;
    last[0] = r;
    last[1] = g;
    last[2] = b;
#if CONFIG_IDF_TARGET_ESP32S3
    if (rgb) {
        uint8_t grb[3] = {g, r, b};
        rmt_transmit_config_t tx = {.loop_count = 0};
        rmt_transmit(chan, enc, grb, sizeof(grb), &tx);
        rmt_tx_wait_all_done(chan, 20);
        return;
    }
#endif
    gpio_set_level(LED_GPIO, (r | g | b) ? 0 : 1);
}

void board_led_set(bool on) {
    if (on) board_led_rgb(24, 0, 40);
    else board_led_rgb(0, 0, 0);
}
