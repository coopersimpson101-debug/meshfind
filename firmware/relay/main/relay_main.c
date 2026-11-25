/*
 * meshfind relay / gateway firmware (ESP32, ESP-IDF v5.2+, NimBLE + ESP-NOW).
 *
 * Relay:   passive BLE scan -> decode meshfind adverts -> aggregate RSSI per
 *          key for CONFIG_MESHFIND_AGGREGATE_MS -> seal an ECIES report with
 *          this node's configured position -> originate into the mesh.
 * Mesh:    ESP-NOW broadcast frames handled by the portable core (mf_mesh.c):
 *          gradient routing, dedup, TTL, retries/passive acks, token bucket,
 *          store-and-forward, beacon time sync.
 * Gateway: additionally prints every delivered report as
 *          "MFRPT <216 hex chars>" on the console UART and accepts
 *          "MFTIME <unix seconds>" lines from the host (python -m meshfind
 *          gateway --serial ...) to learn wall-clock time.
 *
 * The relay never learns which tag it saw (keys rotate, it only holds the
 * public key for the aggregation window) and cannot read reports it forwards.
 *
 * STATUS: compiles in CI; NOT yet run on hardware.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "driver/uart.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_now.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "host/ble_hs.h"
#include "mf_crypto.h"
#include "mf_mesh.h"
#include "mf_proto.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#ifdef CONFIG_MESHFIND_IS_GATEWAY
#define IS_GW 1
#else
#define IS_GW 0
#endif
#ifdef CONFIG_MESHFIND_POS_LOCAL_FRAME
#define POS_LOCAL 1
#else
#define POS_LOCAL 0
#endif

static const char *TAG = "mf_relay";
static const uint8_t BCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#define AGG_SLOTS 16
#define AGG_SAMPLES 16

typedef struct {
    uint8_t pub[32];
    uint8_t status;
    int8_t rssi;
} sighting_msg_t;

typedef struct {
    uint8_t len;
    uint8_t data[MF_MESH_MAX_FRAME];
} rx_msg_t;

typedef struct {
    bool used;
    uint8_t pub[32];
    uint8_t status;
    uint32_t first_ms;
    uint8_t n;
    int8_t rssi[AGG_SAMPLES];
} agg_t;

static QueueHandle_t g_sight_q, g_rx_q;
static mf_mesh_node_t g_node;
static agg_t g_agg[AGG_SLOTS];
static uint32_t g_node_id;
static bool g_gw_time_valid;
static int64_t g_gw_offset_ms;

static uint32_t now_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }
static uint32_t rnd(void *ctx) { (void)ctx; return esp_random(); }

/* ------------------------------------------------------------------- BLE */

static int gap_cb(struct ble_gap_event *ev, void *arg)
{
    (void)arg;
    if (ev->type != BLE_GAP_EVENT_DISC) return 0;
    if (ev->disc.addr.type != BLE_ADDR_RANDOM || ev->disc.length_data != MF_ADV_LEN) return 0;
    uint8_t addr_msb[6];
    mf_adv_t a;
    for (int i = 0; i < 6; i++) addr_msb[i] = ev->disc.addr.val[5 - i]; /* NimBLE is LSB first */
    if (mf_adv_decode(addr_msb, ev->disc.data, ev->disc.length_data, &a) != MF_OK) return 0;
    sighting_msg_t m;
    memcpy(m.pub, a.pub, 32);
    m.status = mf_adv_status_bits(&a);
    m.rssi = ev->disc.rssi;
    xQueueSend(g_sight_q, &m, 0); /* drop if the worker is behind */
    return 0;
}

static void start_scan(void)
{
    struct ble_gap_disc_params p = {0};
    p.passive = 1;            /* never transmit scan requests */
    p.filter_duplicates = 0;  /* we want every advert for RSSI averaging */
    p.itvl = 160;             /* 100 ms */
    p.window = 80;            /* 50 ms: leave airtime for Wi-Fi/ESP-NOW coexistence */
    int rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &p, gap_cb, NULL);
    if (rc) ESP_LOGE(TAG, "ble_gap_disc failed: %d", rc);
}

static void on_sync(void) { start_scan(); }

static void host_task(void *arg)
{
    (void)arg;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

/* --------------------------------------------------------------- ESP-NOW */

static void espnow_rx(const esp_now_recv_info_t *info, const uint8_t *data, int len)
{
    (void)info; /* sender MAC is deliberately ignored: routing is address-free */
    rx_msg_t m;
    if (len <= 0 || len > MF_MESH_MAX_FRAME) return;
    m.len = (uint8_t)len;
    memcpy(m.data, data, (size_t)len);
    xQueueSend(g_rx_q, &m, 0);
}

static void wifi_espnow_init(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_channel(CONFIG_MESHFIND_ESPNOW_CHANNEL, WIFI_SECOND_CHAN_NONE));
    ESP_ERROR_CHECK(esp_now_init());
    ESP_ERROR_CHECK(esp_now_register_recv_cb(espnow_rx));
    esp_now_peer_info_t peer = {0};
    memcpy(peer.peer_addr, BCAST, 6);
    peer.channel = 0;
    peer.ifidx = WIFI_IF_STA;
    peer.encrypt = false;
    ESP_ERROR_CHECK(esp_now_add_peer(&peer));
}

/* --------------------------------------------------------------- gateway */

static void gw_deliver(void *ctx, const uint8_t env[MF_ENVELOPE_LEN])
{
    (void)ctx;
    static const char HEX[] = "0123456789abcdef";
    static const char PREFIX[] = "MFRPT ";
    char line[sizeof PREFIX - 1 + 2 * MF_ENVELOPE_LEN + 1];
    _Static_assert(sizeof line == sizeof PREFIX + 2 * MF_ENVELOPE_LEN, "gateway line buffer size");
    memcpy(line, PREFIX, sizeof PREFIX - 1);
    char *o = line + sizeof PREFIX - 1;
    for (size_t i = 0; i < MF_ENVELOPE_LEN; i++) {
        *o++ = HEX[env[i] >> 4];
        *o++ = HEX[env[i] & 0x0f];
    }
    *o = '\0';
    puts(line);
    fflush(stdout);
}

static bool unix_time(uint32_t *t)
{
    if (IS_GW) {
        if (!g_gw_time_valid) return false;
        *t = (uint32_t)(((int64_t)now_ms() + g_gw_offset_ms) / 1000);
        return true;
    }
    return mf_mesh_unix_time(&g_node, now_ms(), t);
}

static void gw_poll_uart(void)
{
    static char line[48];
    static size_t n;
    uint8_t ch;
    while (uart_read_bytes(UART_NUM_0, &ch, 1, 0) == 1) {
        if (ch == '\n' || ch == '\r') {
            line[n] = 0;
            if (n > 7 && strncmp(line, "MFTIME ", 7) == 0) {
                long long t = atoll(line + 7);
                if (t > 1600000000LL) {
                    g_gw_offset_ms = t * 1000 - (int64_t)now_ms();
                    g_gw_time_valid = true;
                }
            }
            n = 0;
        } else if (n + 1 < sizeof line) {
            line[n++] = (char)ch;
        } else {
            n = 0;
        }
    }
}

/* ---------------------------------------------------------- report path */

static int cmp_i8(const void *a, const void *b) { return *(const int8_t *)a - *(const int8_t *)b; }

static void seal_and_send(agg_t *a)
{
    mf_sighting_t s = {0};
    uint8_t eph[32], env[MF_ENVELOPE_LEN];
    uint32_t t;
    qsort(a->rssi, a->n, 1, cmp_i8);
    s.version = 1;
    s.flags = POS_LOCAL ? MF_PT_FLAG_LOCAL_FRAME : 0;
    if (unix_time(&t)) {
        s.flags |= MF_PT_FLAG_TIME_SYNCED;
        s.seen_ts = t;
    } else {
        s.seen_ts = now_ms() / 1000; /* uptime; owner treats unsynced times as unknown */
    }
    s.node_id = g_node_id;
    s.x = CONFIG_MESHFIND_NODE_X;
    s.y = CONFIG_MESHFIND_NODE_Y;
    s.z = CONFIG_MESHFIND_NODE_Z;
    s.accuracy_cm = CONFIG_MESHFIND_NODE_ACCURACY_CM;
    s.rssi = a->rssi[a->n / 2]; /* median */
    s.tag_status = a->status;
    esp_fill_random(eph, sizeof eph);
    if (mf_report_seal(a->pub, &s, eph, env) == MF_OK) {
        if (!mf_mesh_originate(&g_node, env, now_ms())) ESP_LOGD(TAG, "origination rate-limited");
    }
    mf_wipe(eph, sizeof eph);
    mf_wipe(a, sizeof *a); /* forget the key: nothing links this tag later */
}

static void on_sighting(const sighting_msg_t *m)
{
    agg_t *free_slot = NULL;
    for (int i = 0; i < AGG_SLOTS; i++) {
        agg_t *a = &g_agg[i];
        if (a->used && memcmp(a->pub, m->pub, 32) == 0) {
            if (a->n < AGG_SAMPLES) a->rssi[a->n++] = m->rssi;
            return;
        }
        if (!a->used && !free_slot) free_slot = a;
    }
    if (!free_slot) return; /* table full: busy area, drop */
    free_slot->used = true;
    memcpy(free_slot->pub, m->pub, 32);
    free_slot->status = m->status;
    free_slot->first_ms = now_ms();
    free_slot->n = 1;
    free_slot->rssi[0] = m->rssi;
}

static void mesh_task(void *arg)
{
    (void)arg;
    uint32_t next_beacon = 0;
    for (;;) {
        rx_msg_t rx;
        sighting_msg_t sm;
        uint8_t out[MF_MESH_MAX_FRAME];
        size_t len;
        uint32_t t = now_ms();

        while (xQueueReceive(g_rx_q, &rx, 0) == pdTRUE) mf_mesh_on_rx(&g_node, rx.data, rx.len, now_ms());
        while (xQueueReceive(g_sight_q, &sm, 0) == pdTRUE) on_sighting(&sm);
        for (int i = 0; i < AGG_SLOTS; i++)
            if (g_agg[i].used && (uint32_t)(t - g_agg[i].first_ms) >= (uint32_t)CONFIG_MESHFIND_AGGREGATE_MS)
                seal_and_send(&g_agg[i]);
        if (IS_GW) {
            gw_poll_uart();
            if ((int32_t)(t - next_beacon) >= 0) {
                uint32_t ut = 0;
                unix_time(&ut);
                mf_mesh_emit_beacon(&g_node, ut, t);
                next_beacon = t + 10000;
            }
        }
        while ((len = mf_mesh_poll(&g_node, now_ms(), out, sizeof out)) > 0) {
            esp_err_t err = esp_now_send(BCAST, out, len);
            if (err != ESP_OK) ESP_LOGD(TAG, "esp_now_send: %s", esp_err_to_name(err));
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    g_node_id = CONFIG_MESHFIND_NODE_ID;
    if (g_node_id == 0) {
        uint8_t mac[6];
        esp_read_mac(mac, ESP_MAC_WIFI_STA);
        g_node_id = (uint32_t)mac[2] << 24 | (uint32_t)mac[3] << 16 | (uint32_t)mac[4] << 8 | mac[5];
    }
    g_sight_q = xQueueCreate(32, sizeof(sighting_msg_t));
    g_rx_q = xQueueCreate(16, sizeof(rx_msg_t));
    if (IS_GW) uart_driver_install(UART_NUM_0, 512, 0, 0, NULL, 0);
    mf_mesh_init(&g_node, g_node_id, IS_GW, NULL, rnd, NULL,
                 IS_GW ? gw_deliver : NULL, NULL);
    wifi_espnow_init();
    ESP_ERROR_CHECK(nimble_port_init());
    ble_hs_cfg.sync_cb = on_sync;
    nimble_port_freertos_init(host_task);
    xTaskCreate(mesh_task, "mf_mesh", 10240, NULL, 5, NULL);
    ESP_LOGI(TAG, "meshfind %s node %08lx up", IS_GW ? "gateway" : "relay",
             (unsigned long)g_node_id);
}
