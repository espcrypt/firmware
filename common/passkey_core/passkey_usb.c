#include <stdio.h>
#include <string.h>

#include "class/hid/hid_device.h"
#include "ctap2.h"
#include "driver/gpio.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "passkey_core.h"
#include "store.h"
#include "tinyusb.h"
#include "tusb_cdc_acm.h"

#define BUTTON_GPIO GPIO_NUM_0

__attribute__((weak)) void passkey_led(passkey_led_t mode, int ms) {
    (void)mode;
    (void)ms;
}

enum { ITF_CDC = 0, ITF_CDC_DATA, ITF_HID, ITF_TOTAL };
#define EP_CDC_NOTIF 0x81
#define EP_CDC_OUT 0x02
#define EP_CDC_IN 0x82
#define EP_HID_OUT 0x03
#define EP_HID_IN 0x83
#define HID_PACKET 64

static const uint8_t hid_report_desc[] = {TUD_HID_REPORT_DESC_FIDO_U2F(HID_PACKET)};

#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN + TUD_HID_INOUT_DESC_LEN)
static const uint8_t config_desc[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_TOTAL, 0, CONFIG_TOTAL_LEN, 0, 100),
    TUD_CDC_DESCRIPTOR(ITF_CDC, 4, EP_CDC_NOTIF, 8, EP_CDC_OUT, EP_CDC_IN, 64),
    TUD_HID_INOUT_DESCRIPTOR(ITF_HID, 5, HID_ITF_PROTOCOL_NONE, sizeof(hid_report_desc), EP_HID_OUT, EP_HID_IN, HID_PACKET, 5),
};

static tusb_desc_device_t device_desc = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = TUSB_CLASS_MISC,
    .bDeviceSubClass = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = 0x303A,
    .idProduct = 0x4AF1,
    .bcdDevice = 0x0100,
    .iManufacturer = 1,
    .iProduct = 2,
    .iSerialNumber = 3,
    .bNumConfigurations = 1,
};

static char device_id[13];
static const char *string_desc[] = {
    (const char[]){0x09, 0x04},
    "ESP Crypt",
    "ESP32 Passkey",
    device_id,
    "Management",
    "FIDO2",
};

const char *passkey_device_id(void) { return device_id; }

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance) {
    (void)instance;
    return hid_report_desc;
}

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t *buffer,
                               uint16_t reqlen) {
    (void)instance;
    (void)report_id;
    (void)report_type;
    (void)buffer;
    (void)reqlen;
    return 0;
}

static QueueHandle_t hid_rx;

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t const *buffer,
                           uint16_t bufsize) {
    (void)instance;
    (void)report_type;
    uint8_t pkt[HID_PACKET] = {0};
    if (bufsize == HID_PACKET + 1 && report_id == 0 && buffer[0] == 0) {
        buffer++;
        bufsize--;
    }
    memcpy(pkt, buffer, bufsize < HID_PACKET ? bufsize : HID_PACKET);
    xQueueSend(hid_rx, pkt, 0);
}

static SemaphoreHandle_t cdc_rx_ready;
static SemaphoreHandle_t cdc_tx_lock;

static void cdc_rx_cb(int itf, cdcacm_event_t *event) {
    (void)itf;
    (void)event;
    xSemaphoreGive(cdc_rx_ready);
}

size_t passkey_cdc_read(uint8_t *buf, size_t len, TickType_t wait) {
    TickType_t start = xTaskGetTickCount();
    for (;;) {
        size_t n = 0;
        if (tinyusb_cdcacm_read(TINYUSB_CDC_ACM_0, buf, len, &n) == ESP_OK && n) return n;
        TickType_t waited = xTaskGetTickCount() - start;
        if (wait != portMAX_DELAY && waited >= wait) return 0;
        xSemaphoreTake(cdc_rx_ready, wait == portMAX_DELAY ? pdMS_TO_TICKS(100) : wait - waited);
    }
}

void passkey_cdc_write(const char *data, size_t len) {
    xSemaphoreTake(cdc_tx_lock, portMAX_DELAY);
    int64_t deadline = esp_timer_get_time() + 2 * 1000000LL;
    while (len && esp_timer_get_time() < deadline) {
        size_t n = tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_0, (const uint8_t *)data, len);
        tinyusb_cdcacm_write_flush(TINYUSB_CDC_ACM_0, pdMS_TO_TICKS(50));
        data += n;
        len -= n;
        if (!n) vTaskDelay(1);
    }
    xSemaphoreGive(cdc_tx_lock);
}

#define CTAPHID_PING 0x81
#define CTAPHID_INIT 0x86
#define CTAPHID_WINK 0x88
#define CTAPHID_CBOR 0x90
#define CTAPHID_CANCEL 0x91
#define CTAPHID_KEEPALIVE 0xBB
#define CTAPHID_ERROR 0xBF

#define ERR_INVALID_CMD 0x01
#define ERR_INVALID_LEN 0x03
#define ERR_INVALID_SEQ 0x04
#define ERR_MSG_TIMEOUT 0x05
#define ERR_CHANNEL_BUSY 0x06
#define ERR_INVALID_CHANNEL 0x0B
#define ERR_OTHER 0x7F

#define BROADCAST_CID 0xFFFFFFFFu

static uint32_t next_cid = 1;
static uint32_t current_cid;
static uint8_t msg_buf[CTAP2_MAX_MSG + 64];
static uint8_t resp_buf[CTAP2_MAX_MSG + 64];

static bool store_ok;
static SemaphoreHandle_t ctap_mutex;

void ctap_lock(void) { xSemaphoreTake(ctap_mutex, portMAX_DELAY); }
void ctap_unlock(void) { xSemaphoreGive(ctap_mutex); }

static uint32_t get_cid(const uint8_t *p) { return (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }

static void put_cid(uint8_t *p, uint32_t cid) {
    p[0] = cid >> 24;
    p[1] = cid >> 16;
    p[2] = cid >> 8;
    p[3] = cid;
}

static void hid_write(const uint8_t pkt[HID_PACKET]) {
    for (int i = 0; i < 200 && !tud_hid_ready(); i++) vTaskDelay(1);
    if (tud_hid_ready()) tud_hid_report(0, pkt, HID_PACKET);
}

static void hid_send(uint32_t cid, uint8_t cmd, const uint8_t *data, size_t len) {
    uint8_t pkt[HID_PACKET];
    memset(pkt, 0, sizeof(pkt));
    put_cid(pkt, cid);
    pkt[4] = cmd;
    pkt[5] = len >> 8;
    pkt[6] = len;
    size_t n = len < HID_PACKET - 7 ? len : HID_PACKET - 7;
    if (n) memcpy(pkt + 7, data, n);
    hid_write(pkt);
    size_t off = n;
    for (uint8_t seq = 0; off < len && seq < 0x80; seq++) {
        memset(pkt, 0, sizeof(pkt));
        put_cid(pkt, cid);
        pkt[4] = seq;
        n = len - off < HID_PACKET - 5 ? len - off : HID_PACKET - 5;
        memcpy(pkt + 5, data + off, n);
        hid_write(pkt);
        off += n;
    }
}

static void hid_error(uint32_t cid, uint8_t code) { hid_send(cid, CTAPHID_ERROR, &code, 1); }

static bool button_down(void) { return gpio_get_level(BUTTON_GPIO) == 0; }

int ctap_wait_presence(void) {
    if (store_touch_mode() == TOUCH_AUTO) {
        passkey_led(PASSKEY_LED_OK, 300);
        return CTAP2_OK;
    }
    passkey_led(PASSKEY_LED_TOUCH, 0);
    int64_t deadline = esp_timer_get_time() + 30 * 1000000LL;
    int64_t next_keepalive = 0;
    bool released = !button_down();
    int result = CTAP2_ERR_USER_ACTION_TIMEOUT;
    while (esp_timer_get_time() < deadline) {
        if (!button_down()) released = true;
        else if (released) {
            result = CTAP2_OK;
            break;
        }
        int64_t now = esp_timer_get_time();
        if (now >= next_keepalive) {
            uint8_t status = 2;
            if (current_cid) hid_send(current_cid, CTAPHID_KEEPALIVE, &status, 1);
            next_keepalive = now + 100 * 1000;
        }
        uint8_t pkt[HID_PACKET];
        if (xQueueReceive(hid_rx, pkt, pdMS_TO_TICKS(20)) == pdTRUE) {
            uint32_t cid = get_cid(pkt);
            if (cid == current_cid && pkt[4] == CTAPHID_CANCEL) {
                result = CTAP2_ERR_KEEPALIVE_CANCEL;
                break;
            }
            if (cid != current_cid && (pkt[4] & 0x80)) hid_error(cid, ERR_CHANNEL_BUSY);
        }
    }
    passkey_led(result == CTAP2_OK ? PASSKEY_LED_OK : PASSKEY_LED_IDLE, result == CTAP2_OK ? 400 : 0);
    return result;
}

static void handle_message(uint32_t cid, uint8_t cmd, const uint8_t *data, size_t len) {
    current_cid = cid;
    switch (cmd) {
    case CTAPHID_INIT: {
        if (len != 8) {
            hid_error(cid, ERR_INVALID_LEN);
            break;
        }
        uint8_t r[17];
        memcpy(r, data, 8);
        uint32_t new_cid = cid;
        if (cid == BROADCAST_CID) {
            new_cid = next_cid++;
            if (next_cid == BROADCAST_CID || next_cid == 0) next_cid = 1;
        }
        put_cid(r + 8, new_cid);
        r[12] = 2;
        r[13] = 1;
        r[14] = 0;
        r[15] = 0;
        r[16] = 0x01 | 0x04 | 0x08;
        hid_send(cid, CTAPHID_INIT, r, sizeof(r));
        break;
    }
    case CTAPHID_PING:
        hid_send(cid, CTAPHID_PING, data, len);
        break;
    case CTAPHID_WINK:
        passkey_led(PASSKEY_LED_WINK, 1500);
        hid_send(cid, CTAPHID_WINK, NULL, 0);
        break;
    case CTAPHID_CBOR: {
        ctap_lock();
        size_t n = ctap2_handle(data, len, resp_buf, sizeof(resp_buf));
        ctap_unlock();
        hid_send(cid, CTAPHID_CBOR, resp_buf, n);
        break;
    }
    case CTAPHID_CANCEL:
        break;
    default:
        hid_error(cid, ERR_INVALID_CMD);
    }
    current_cid = 0;
}

static void ctaphid_task(void *arg) {
    (void)arg;
    uint8_t pkt[HID_PACKET];
    for (;;) {
        if (xQueueReceive(hid_rx, pkt, portMAX_DELAY) != pdTRUE) continue;
        uint32_t cid = get_cid(pkt);
        uint8_t cmd = pkt[4];
        if (!(cmd & 0x80)) continue;
        if (cid == 0 || (cid == BROADCAST_CID && cmd != CTAPHID_INIT)) {
            hid_error(cid, ERR_INVALID_CHANNEL);
            continue;
        }
        if (!store_ok && cmd != CTAPHID_INIT) {
            hid_error(cid, ERR_OTHER);
            continue;
        }
        size_t len = (size_t)pkt[5] << 8 | pkt[6];
        if (len > CTAP2_MAX_MSG + 7) {
            hid_error(cid, ERR_INVALID_LEN);
            continue;
        }
        size_t got = len < HID_PACKET - 7 ? len : HID_PACKET - 7;
        memcpy(msg_buf, pkt + 7, got);
        uint8_t seq = 0;
        bool failed = false;
        while (got < len) {
            if (xQueueReceive(hid_rx, pkt, pdMS_TO_TICKS(750)) != pdTRUE) {
                hid_error(cid, ERR_MSG_TIMEOUT);
                failed = true;
                break;
            }
            uint32_t c = get_cid(pkt);
            if (c != cid) {
                if (pkt[4] & 0x80) hid_error(c, ERR_CHANNEL_BUSY);
                continue;
            }
            if (pkt[4] & 0x80) {
                if (pkt[4] == CTAPHID_INIT) xQueueSendToFront(hid_rx, pkt, 0);
                else hid_error(cid, ERR_INVALID_SEQ);
                failed = true;
                break;
            }
            if (pkt[4] != seq++) {
                hid_error(cid, ERR_INVALID_SEQ);
                failed = true;
                break;
            }
            size_t n = len - got < HID_PACKET - 5 ? len - got : HID_PACKET - 5;
            memcpy(msg_buf + got, pkt + 5, n);
            got += n;
        }
        if (!failed) handle_message(cid, cmd, msg_buf, len);
    }
}

bool passkey_core_start(const passkey_usb_config_t *cfg) {
    gpio_config_t btn = {.pin_bit_mask = 1ULL << BUTTON_GPIO, .mode = GPIO_MODE_INPUT, .pull_up_en = GPIO_PULLUP_ENABLE};
    gpio_config(&btn);
    ctap_mutex = xSemaphoreCreateMutex();
    store_ok = store_init();
    if (store_ok) ctap2_init();

    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(device_id, sizeof(device_id), "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    if (cfg) {
        device_desc.idProduct = cfg->pid;
        if (cfg->product) string_desc[2] = cfg->product;
    }

    hid_rx = xQueueCreate(16, HID_PACKET);
    cdc_rx_ready = xSemaphoreCreateBinary();
    cdc_tx_lock = xSemaphoreCreateMutex();
    xTaskCreate(ctaphid_task, "ctaphid", 12288, NULL, 5, NULL);

    const tinyusb_config_t tusb_cfg = {
        .device_descriptor = &device_desc,
        .string_descriptor = string_desc,
        .string_descriptor_count = sizeof(string_desc) / sizeof(string_desc[0]),
        .external_phy = false,
        .configuration_descriptor = config_desc,
    };
    if (tinyusb_driver_install(&tusb_cfg) != ESP_OK) return false;
    const tinyusb_config_cdcacm_t acm_cfg = {
        .usb_dev = TINYUSB_USBDEV_0,
        .cdc_port = TINYUSB_CDC_ACM_0,
        .rx_unread_buf_sz = 512,
        .callback_rx = cdc_rx_cb,
    };
    return tusb_cdc_acm_init(&acm_cfg) == ESP_OK;
}
