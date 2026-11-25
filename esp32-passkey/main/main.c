#include <string.h>

#include "board_led.h"
#include "cJSON.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "passkey_core.h"
#include "soc/rtc_cntl_reg.h"

#define FIRMWARE_VERSION "1.1.0"

static volatile passkey_led_t led_mode = PASSKEY_LED_IDLE;
static volatile int64_t led_until;

void passkey_led(passkey_led_t mode, int ms) {
    led_mode = mode;
    led_until = ms ? esp_timer_get_time() + ms * 1000LL : 0;
}

static void led_task(void *arg) {
    (void)arg;
    for (uint32_t tick = 0;; tick++) {
        if (led_until && esp_timer_get_time() > led_until) {
            led_mode = PASSKEY_LED_IDLE;
            led_until = 0;
        }
        switch (led_mode) {
        case PASSKEY_LED_TOUCH:
            if ((tick / 6) % 2) board_led_rgb(40, 40, 40);
            else board_led_rgb(0, 0, 0);
            break;
        case PASSKEY_LED_OK:
            board_led_rgb(0, 40, 0);
            break;
        case PASSKEY_LED_WINK:
            if ((tick / 4) % 2) board_led_rgb(0, 30, 60);
            else board_led_rgb(0, 0, 0);
            break;
        default:
            if (board_led_is_rgb()) board_led_rgb(0, 0, 10);
            else board_led_set((tick % 150) < 3);
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

static void reply(double id, bool ok, const char *error, cJSON *result) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "id", id);
    cJSON_AddBoolToObject(root, "ok", ok);
    if (!ok) cJSON_AddStringToObject(root, "error", error ? error : "operation failed");
    if (result) cJSON_AddItemToObject(root, "result", result);
    char *s = cJSON_PrintUnformatted(root);
    if (s) {
        passkey_cdc_write(s, strlen(s));
        passkey_cdc_write("\n", 1);
        cJSON_free(s);
    }
    cJSON_Delete(root);
}

static void handle(cJSON *q) {
    double id = cJSON_GetNumberValue(cJSON_GetObjectItem(q, "id"));
    const char *cmd = cJSON_GetStringValue(cJSON_GetObjectItem(q, "command"));
    if (!cmd) {
        reply(id, false, "missing command", NULL);
        return;
    }
    if (!strcmp(cmd, "download")) {
        reply(id, true, NULL, NULL);
        vTaskDelay(pdMS_TO_TICKS(200));
        REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
        esp_restart();
    }
    if (!strcmp(cmd, "restart")) {
        reply(id, true, NULL, NULL);
        vTaskDelay(pdMS_TO_TICKS(200));
        esp_restart();
    }
    cJSON *result = NULL;
    bool ok;
    const char *error;
    if (!passkey_mgmt_handle(cmd, q, &result, &ok, &error)) {
        reply(id, false, "unknown command", NULL);
        return;
    }
    if (ok && result && (!strcmp(cmd, "status") || !strcmp(cmd, "passkey_status"))) {
        cJSON_AddStringToObject(result, "firmware", "passkey");
        cJSON_AddStringToObject(result, "version", FIRMWARE_VERSION);
        cJSON_AddStringToObject(result, "chip", "ESP32-S3");
        cJSON_AddBoolToObject(result, "rgbLed", board_led_is_rgb());
    }
    reply(id, ok, error, result);
}

void app_main(void) {
    board_led_init();
    xTaskCreate(led_task, "led", 2048, NULL, 1, NULL);
    const passkey_usb_config_t usb = {.pid = 0x4AF1, .product = "ESP32 Passkey"};
    if (!passkey_core_start(&usb)) {
        for (;;) {
            board_led_rgb(40, 0, 0);
            vTaskDelay(pdMS_TO_TICKS(300));
            board_led_rgb(0, 0, 0);
            vTaskDelay(pdMS_TO_TICKS(300));
        }
    }
    static char line[1024];
    size_t used = 0;
    uint8_t buf[256];
    for (;;) {
        size_t n = passkey_cdc_read(buf, sizeof(buf), portMAX_DELAY);
        for (size_t i = 0; i < n; i++) {
            char ch = (char)buf[i];
            if (ch == '\r') continue;
            if (ch == '\n') {
                line[used] = 0;
                if (used) {
                    cJSON *q = cJSON_Parse(line);
                    if (q) {
                        handle(q);
                        cJSON_Delete(q);
                    } else {
                        reply(0, false, "invalid JSON request", NULL);
                    }
                }
                memset(line, 0, used);
                used = 0;
            } else if (used + 1 < sizeof(line)) {
                line[used++] = ch;
            } else {
                used = 0;
                reply(0, false, "request too large", NULL);
            }
        }
    }
}
