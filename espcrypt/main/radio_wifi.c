#include <stdio.h>
#include <string.h>

#include "cJSON.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "radio.h"

#define LINE_CAP (40 * 1024)
#define IDLE_SECONDS 300

static volatile bool started, connected;
static char ip_str[16];

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        connected = false;
        ip_str[0] = 0;
        vTaskDelay(pdMS_TO_TICKS(2000));
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = data;
        snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&e->ip_info.ip));
        connected = true;
    }
}

bool radio_wifi_status(char ip[16]) {
    if (!started) return false;
    if (ip) strcpy(ip, ip_str);
    return connected;
}

static void tcp_write(void *ctx, const char *line, size_t len) {
    int fd = *(int *)ctx;
    while (len) {
        int n = send(fd, line, len, 0);
        if (n <= 0) return;
        line += n;
        len -= (size_t)n;
    }
    send(fd, "\n", 1, 0);
}

#define MAX_CLIENTS 3
#define BUF_START (4 * 1024)

typedef struct {
    int fd;
    rsess_t *s;
    char *buf;
    size_t used, cap;
    bool ready;
    int64_t last;
} client_t;

static client_t clients[MAX_CLIENTS];

static void drop(client_t *c) {
    if (c->fd < 0) return;
    shutdown(c->fd, SHUT_RDWR);
    close(c->fd);
    rsess_free(c->s);
    if (c->buf) {
        memset(c->buf, 0, c->cap);
        free(c->buf);
    }
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

static void accept_one(int ls) {
    struct sockaddr_in peer;
    socklen_t pl = sizeof(peer);
    int fd = accept(ls, (struct sockaddr *)&peer, &pl);
    if (fd < 0) return;
    client_t *slot = NULL, *oldest = NULL;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].fd < 0 && !slot) slot = &clients[i];
        if (clients[i].fd >= 0 && (!oldest || clients[i].last < oldest->last)) oldest = &clients[i];
    }
    if (!slot) {
        drop(oldest);
        slot = oldest;
    }
    int one = 1, idle = 30, intvl = 10, cnt = 3;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
    slot->fd = fd;
    slot->s = rsess_new(ORIGIN_WIFI, tcp_write, &slot->fd);
    slot->cap = BUF_START;
    slot->buf = malloc(slot->cap);
    slot->used = 0;
    slot->ready = false;
    slot->last = esp_timer_get_time();
    if (!slot->s || !slot->buf) drop(slot);
}

static bool read_client(client_t *c) {
    if (c->used >= c->cap - 1) {
        size_t ncap = c->cap * 2 > LINE_CAP ? LINE_CAP : c->cap * 2;
        if (ncap <= c->cap) return false;
        char *nb = realloc(c->buf, ncap);
        if (!nb) return false;
        c->buf = nb;
        c->cap = ncap;
    }
    int n = recv(c->fd, c->buf + c->used, c->cap - 1 - c->used, 0);
    if (n <= 0) return false;
    c->used += (size_t)n;
    c->last = esp_timer_get_time();
    char *start = c->buf, *nl;
    while ((nl = memchr(start, '\n', c->used - (size_t)(start - c->buf)))) {
        *nl = 0;
        if (nl > start && nl[-1] == '\r') nl[-1] = 0;
        if (*start && !rsess_input(c->s, start)) return false;
        start = nl + 1;
    }
    c->used -= (size_t)(start - c->buf);
    memmove(c->buf, start, c->used);
    if (!c->ready && rsess_ready(c->s)) c->ready = true;
    if (c->used == 0 && c->cap > BUF_START) {
        char *nb = realloc(c->buf, BUF_START);
        if (nb) {
            c->buf = nb;
            c->cap = BUF_START;
        }
    }
    return true;
}

static void tcp_task(void *arg) {
    (void)arg;
    for (int i = 0; i < MAX_CLIENTS; i++) clients[i].fd = -1;
    for (;;) {
        int ls = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (ls < 0) {
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        int one = 1;
        setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(RADIO_TCP_PORT), .sin_addr.s_addr = htonl(INADDR_ANY)};
        if (bind(ls, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(ls, 4) != 0) {
            close(ls);
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        for (;;) {
            fd_set rd;
            FD_ZERO(&rd);
            FD_SET(ls, &rd);
            int maxfd = ls;
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].fd < 0) continue;
                FD_SET(clients[i].fd, &rd);
                if (clients[i].fd > maxfd) maxfd = clients[i].fd;
            }
            struct timeval tv = {.tv_sec = 1};
            int r = select(maxfd + 1, &rd, NULL, NULL, &tv);
            if (r < 0) break;
            int64_t now = esp_timer_get_time();
            for (int i = 0; i < MAX_CLIENTS; i++) {
                client_t *c = &clients[i];
                if (c->fd < 0) continue;
                if (FD_ISSET(c->fd, &rd)) {
                    if (!read_client(c)) drop(c);
                } else if ((!c->ready && now - c->last > 10 * 1000000LL) ||
                           now - c->last > (int64_t)IDLE_SECONDS * 1000000LL) {
                    drop(c);
                }
            }
            if (FD_ISSET(ls, &rd)) accept_one(ls);
        }
        for (int i = 0; i < MAX_CLIENTS; i++) drop(&clients[i]);
        close(ls);
    }
}

static void udp_task(void *arg) {
    (void)arg;
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(RADIO_TCP_PORT), .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
        vTaskDelete(NULL);
        return;
    }
    char in[32];
    for (;;) {
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        int n = recvfrom(s, in, sizeof(in) - 1, 0, (struct sockaddr *)&from, &fl);
        if (n < 9 || (memcmp(in, "ESPCRYPT?", 9) != 0 && memcmp(in, "ESPVAULT?", 9) != 0)) continue;
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "v", 1);
        cJSON_AddStringToObject(o, "name", radio_name());
        cJSON_AddStringToObject(o, "id", vault_device_id());
        cJSON_AddStringToObject(o, "chip", vault_chip_name());
        cJSON_AddNumberToObject(o, "port", RADIO_TCP_PORT);
        char *line = cJSON_PrintUnformatted(o);
        cJSON_Delete(o);
        if (line) {
            sendto(s, line, strlen(line), 0, (struct sockaddr *)&from, fl);
            free(line);
        }
    }
}

void radio_wifi_start(const char *ssid, const char *password, const char *hostname) {
    if (started) return;
    if (esp_netif_init() != ESP_OK) return;
    esp_err_t e = esp_event_loop_create_default();
    if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) return;
    esp_netif_t *netif = esp_netif_create_default_wifi_sta();
    if (netif) esp_netif_set_hostname(netif, hostname);
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    cfg.nvs_enable = 0;
    if (esp_wifi_init(&cfg) != ESP_OK) return;
    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_event, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_event, NULL);
    wifi_config_t wc = {0};
    strncpy((char *)wc.sta.ssid, ssid, sizeof(wc.sta.ssid));
    strncpy((char *)wc.sta.password, password, sizeof(wc.sta.password));
    wc.sta.threshold.authmode = password[0] ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    wc.sta.pmf_cfg.capable = true;
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &wc);
    memset(&wc, 0, sizeof(wc));
    if (esp_wifi_start() != ESP_OK) return;
    esp_wifi_set_ps(WIFI_PS_NONE);
    started = true;
    xTaskCreate(tcp_task, "vault_tcp", 10240, NULL, 4, NULL);
    xTaskCreate(udp_task, "vault_udp", 3072, NULL, 3, NULL);
}
