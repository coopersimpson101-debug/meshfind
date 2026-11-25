/*
 * meshfind tag firmware (ESP32-C3, ESP-IDF v5.2+, NimBLE).
 *
 *  - Holds the ratchet state in NVS (only the current chain values; the old
 *    ones are overwritten on every rotation).
 *  - Every epoch: derive P_i, set the BLE static random address from P_i and
 *    advertise the remaining key bytes, non-connectable (docs/PROTOCOL.md §2).
 *  - Periodically scans briefly for the owner-presence beacon; a valid
 *    token both proves the owner is near (stay in near-owner mode) and
 *    re-synchronises the tag clock to the token's epoch.
 *  - Without the owner for CONFIG_MESHFIND_TAG_SEPARATED_AFTER_MIN, switch to
 *    separated mode: daily key + flag bit (anti-stalking, THREAT_MODEL.md).
 *  - Battery-aware advertising interval (mf_adv_interval_ms).
 *  - Power: automatic light sleep between advertising events (esp_pm +
 *    tickless idle + BT modem sleep), and duty-cycled presence scans that
 *    pause advertising for a short window only.
 *
 * STATUS: compiles in CI; NOT yet run on hardware. Fill the README current-
 * draw table with PPK2 measurements once you have a board — never from the
 * analytical model in mf_adv_avg_current_ua / adv.adv_avg_current_ua.
 */
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "esp_adc/adc_oneshot.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_pm.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "host/ble_hs.h"
#include "mf_crypto.h"
#include "mf_proto.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

static const char *TAG = "mf_tag";

#define NVS_NS "meshfind"
#define PRESENCE_WINDOW_EPOCHS 4

typedef struct {
    uint32_t magic;
    mf_tag_state_t st;
    uint32_t last_owner_seen; /* unix seconds */
    uint32_t last_time;       /* last known wall clock, for power-loss recovery */
} persisted_t;

static persisted_t g_p;
static SemaphoreHandle_t g_sync_sem;
static volatile bool g_owner_seen_flag;
static volatile uint32_t g_owner_epoch;

/* Cached advertising parameters so presence scans can pause/resume cleanly. */
static uint8_t g_adv_pub[32];
static uint8_t g_adv_batt;
static bool g_adv_sep;
static uint32_t g_adv_interval_ms;
static bool g_adv_armed;

/* --------------------------------------------------------------- helpers */

static int hex_decode(const char *hex, uint8_t *out, size_t n)
{
    if (strlen(hex) != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static uint32_t now_unix(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint32_t)tv.tv_sec;
}

static void set_unix(uint32_t t)
{
    struct timeval tv = {.tv_sec = t, .tv_usec = 0};
    settimeofday(&tv, NULL);
}

static void persist(void)
{
    nvs_handle_t h;
    g_p.last_time = now_unix();
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_blob(h, "state", &g_p, sizeof g_p);
    nvs_commit(h);
    nvs_close(h);
}

static bool load_or_provision(void)
{
    nvs_handle_t h;
    size_t len = sizeof g_p;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        esp_err_t err = nvs_get_blob(h, "state", &g_p, &len);
        nvs_close(h);
        if (err == ESP_OK && len == sizeof g_p && g_p.magic == 0x4D460001) {
            /* RTC lost (power cycle)? resume from the last saved time. */
            if (now_unix() < g_p.last_time) set_unix(g_p.last_time);
            return true;
        }
    }
    uint8_t sk0[32], sep0[32], pk[32];
    if (hex_decode(CONFIG_MESHFIND_TAG_SK0, sk0, 32) || hex_decode(CONFIG_MESHFIND_TAG_SEP_SK0, sep0, 32) ||
        hex_decode(CONFIG_MESHFIND_TAG_PRESENCE_KEY, pk, 32) || CONFIG_MESHFIND_TAG_EPOCH0 <= 0) {
        ESP_LOGE(TAG, "not provisioned: run `python -m meshfind tag provision` and set menuconfig values");
        return false;
    }
    memset(&g_p, 0, sizeof g_p);
    g_p.magic = 0x4D460001;
    mf_tag_init(&g_p.st, sk0, sep0, pk, (uint32_t)CONFIG_MESHFIND_TAG_EPOCH0,
                (uint32_t)CONFIG_MESHFIND_TAG_EPOCH_SECONDS);
    mf_wipe(sk0, 32);
    mf_wipe(sep0, 32);
    set_unix((uint32_t)CONFIG_MESHFIND_TAG_EPOCH0);
    g_p.last_owner_seen = (uint32_t)CONFIG_MESHFIND_TAG_EPOCH0;
    persist();
    ESP_LOGW(TAG, "provisioned from sdkconfig; the seeds remain in this firmware image -- "
                  "reflash a build without them (or enable flash encryption), see THREAT_MODEL.md");
    return true;
}

static int battery_percent(void)
{
#if CONFIG_MESHFIND_TAG_BATTERY_ADC_CHANNEL >= 0
    static adc_oneshot_unit_handle_t adc;
    int raw = 0;
    if (!adc) {
        adc_oneshot_unit_init_cfg_t ucfg = {.unit_id = ADC_UNIT_1};
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 2, 0)
        adc_oneshot_chan_cfg_t ccfg = {.bitwidth = ADC_BITWIDTH_DEFAULT, .atten = ADC_ATTEN_DB_12};
#else
        adc_oneshot_chan_cfg_t ccfg = {.bitwidth = ADC_BITWIDTH_DEFAULT, .atten = ADC_ATTEN_DB_11};
#endif
        if (adc_oneshot_new_unit(&ucfg, &adc) != ESP_OK) return 100;
        adc_oneshot_config_channel(adc, (adc_channel_t)CONFIG_MESHFIND_TAG_BATTERY_ADC_CHANNEL, &ccfg);
    }
    if (adc_oneshot_read(adc, (adc_channel_t)CONFIG_MESHFIND_TAG_BATTERY_ADC_CHANNEL, &raw) != ESP_OK) return 100;
    /* uncalibrated estimate: ~0..3.3 V full scale at 12 dB attenuation */
    int mv = raw * 3300 / 4095 * CONFIG_MESHFIND_TAG_BATTERY_DIVIDER_X10 / 10;
    int pct = (mv - CONFIG_MESHFIND_TAG_BATTERY_MV_EMPTY) * 100 /
              (CONFIG_MESHFIND_TAG_BATTERY_MV_FULL - CONFIG_MESHFIND_TAG_BATTERY_MV_EMPTY);
    return pct < 0 ? 0 : pct > 100 ? 100 : pct;
#else
    return 100; /* no battery sensing wired */
#endif
}

/* ------------------------------------------------------------------- BLE */

static int presence_cb(struct ble_gap_event *ev, void *arg)
{
    (void)arg;
    uint32_t cur, e;
    if (ev->type != BLE_GAP_EVENT_DISC) return 0;
    if (mf_epoch_index(now_unix(), g_p.st.epoch0, g_p.st.epoch_seconds, &cur) != MF_OK) cur = 0;
    if (mf_presence_find(g_p.st.presence_key, ev->disc.data, ev->disc.length_data, cur, PRESENCE_WINDOW_EPOCHS,
                         &e) == MF_OK) {
        g_owner_epoch = e;
        g_owner_seen_flag = true;
    }
    return 0;
}

static void advertise(const uint8_t pub[32], uint8_t battery, bool separated, uint32_t interval_ms)
{
    mf_adv_t a;
    uint8_t addr_msb[6], addr_le[6], payload[MF_ADV_LEN];
    struct ble_gap_adv_params params = {0};
    memcpy(a.pub, pub, 32);
    a.battery = battery;
    a.separated = separated;
    mf_adv_encode(&a, addr_msb, payload);
    for (int i = 0; i < 6; i++) addr_le[i] = addr_msb[5 - i]; /* NimBLE stores LSB first */

    ble_gap_adv_stop();
    int rc = ble_hs_id_set_rnd(addr_le);
    if (rc == 0) rc = ble_gap_adv_set_data(payload, sizeof payload);
    params.conn_mode = BLE_GAP_CONN_MODE_NON;
    params.disc_mode = BLE_GAP_DISC_MODE_NON;
    params.itvl_min = params.itvl_max = (uint16_t)(interval_ms * 8 / 5); /* 0.625 ms units */
    if (rc == 0) rc = ble_gap_adv_start(BLE_OWN_ADDR_RANDOM, NULL, BLE_HS_FOREVER, &params, NULL, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "advertising setup failed: %d", rc);
        g_adv_armed = false;
        return;
    }
    memcpy(g_adv_pub, pub, 32);
    g_adv_batt = battery;
    g_adv_sep = separated;
    g_adv_interval_ms = interval_ms;
    g_adv_armed = true;
    ESP_LOGI(TAG, "adv %02X:%02X:%02X:%02X:%02X:%02X itvl %u ms batt %u sep %d sleep %u ms", addr_msb[0],
             addr_msb[1], addr_msb[2], addr_msb[3], addr_msb[4], addr_msb[5], (unsigned)interval_ms, battery,
             separated, (unsigned)mf_adv_sleep_ms(interval_ms, 1));
}

static void presence_scan(uint32_t ms)
{
    struct ble_gap_disc_params p = {0};
    bool resume = g_adv_armed;
    p.passive = 1;
    p.itvl = 0x10;   /* 10 ms */
    p.window = 0x10; /* continuous while the short scan is active */
    p.filter_duplicates = 0;

    /* Duty-cycle: pause advertising so the radio is not TX+RX at once. */
    ble_gap_adv_stop();
    /* Passive scan: transmits nothing, so the public address never goes on air */
    if (ble_gap_disc(BLE_OWN_ADDR_PUBLIC, (int32_t)ms, &p, presence_cb, NULL) == 0)
        vTaskDelay(pdMS_TO_TICKS(ms + 20));
    else
        ESP_LOGW(TAG, "presence scan start failed");
    ble_gap_disc_cancel();
    if (resume) advertise(g_adv_pub, g_adv_batt, g_adv_sep, g_adv_interval_ms);
}

static void on_sync(void) { xSemaphoreGive(g_sync_sem); }

static void host_task(void *arg)
{
    (void)arg;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

static void power_init(void)
{
#if CONFIG_PM_ENABLE
    esp_pm_config_t pm = {
        .max_freq_mhz = CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ,
        .min_freq_mhz = 40,
#if CONFIG_FREERTOS_USE_TICKLESS_IDLE
        .light_sleep_enable = true,
#endif
    };
    esp_err_t err = esp_pm_configure(&pm);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "esp_pm_configure: %s (continuing without automatic light sleep)", esp_err_to_name(err));
    } else {
        ESP_LOGI(TAG, "automatic light sleep between advertising events enabled");
    }
#else
    ESP_LOGW(TAG, "CONFIG_PM_ENABLE is off; tag will not light-sleep between ADV events");
#endif
}

/* ------------------------------------------------------------- main loop */

static void tag_task(void *arg)
{
    (void)arg;
    uint8_t pub[32] = {0}, last_pub[32] = {0};
    uint8_t last_batt = 0xFF;
    bool last_sep = false;
    uint32_t last_scan = 0;
    xSemaphoreTake(g_sync_sem, portMAX_DELAY);

    for (;;) {
        uint32_t now = now_unix();
        if (CONFIG_MESHFIND_TAG_PRESENCE_SCAN_PERIOD_S > 0 &&
            now - last_scan >= (uint32_t)CONFIG_MESHFIND_TAG_PRESENCE_SCAN_PERIOD_S) {
            presence_scan((uint32_t)CONFIG_MESHFIND_TAG_PRESENCE_SCAN_MS);
            last_scan = now = now_unix();
            if (g_owner_seen_flag) {
                g_owner_seen_flag = false;
                uint32_t idx;
                /* authenticated clock resync: snap to the token's epoch if we drifted out of it */
                if (mf_epoch_index(now, g_p.st.epoch0, g_p.st.epoch_seconds, &idx) == MF_OK && idx != g_owner_epoch &&
                    g_owner_epoch >= g_p.st.index) {
                    now = g_p.st.epoch0 + g_owner_epoch * g_p.st.epoch_seconds + g_p.st.epoch_seconds / 2;
                    set_unix(now);
                    ESP_LOGW(TAG, "clock resynchronised from owner presence token (epoch %u)", (unsigned)g_owner_epoch);
                }
                g_p.last_owner_seen = now;
            }
        }
        bool separated = now - g_p.last_owner_seen > (uint32_t)CONFIG_MESHFIND_TAG_SEPARATED_AFTER_MIN * 60u;
        int pct = battery_percent();
        uint8_t batt = mf_battery_level(pct);
        if (mf_tag_current_public(&g_p.st, now, separated, pub) != MF_OK) {
            ESP_LOGE(TAG, "key derivation failed (clock before epoch0?)");
            vTaskDelay(pdMS_TO_TICKS(10000));
            continue;
        }
        if (memcmp(pub, last_pub, 32) != 0 || batt != last_batt || separated != last_sep) {
            advertise(pub, batt, separated, mf_adv_interval_ms(pct, separated));
            if (memcmp(pub, last_pub, 32) != 0) persist(); /* overwrites (erases) the old chain value */
            memcpy(last_pub, pub, 32);
            last_batt = batt;
            last_sep = separated;
        }
        /* wake at the next epoch boundary, the next presence scan, or in 60 s.
         * With tickless idle + light sleep this is a timed light sleep, not a
         * busy wait: the BLE controller still wakes for each ADV event. */
        uint32_t period = separated ? MF_DAY_SECONDS : g_p.st.epoch_seconds;
        uint32_t into = (now - g_p.st.epoch0) % period;
        uint32_t sleep_s = period - into;
        if (sleep_s > 60) sleep_s = 60;
        if (CONFIG_MESHFIND_TAG_PRESENCE_SCAN_PERIOD_S > 0 && last_scan != 0 && now >= last_scan) {
            uint32_t since = now - last_scan;
            uint32_t scan_period = (uint32_t)CONFIG_MESHFIND_TAG_PRESENCE_SCAN_PERIOD_S;
            if (since < scan_period) {
                uint32_t until_scan = scan_period - since;
                if (until_scan < sleep_s) sleep_s = until_scan;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(sleep_s * 1000u));
    }
}

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    if (!load_or_provision()) return;
    power_init();
    g_sync_sem = xSemaphoreCreateBinary();
    ESP_ERROR_CHECK(nimble_port_init());
    ble_hs_cfg.sync_cb = on_sync;
    nimble_port_freertos_init(host_task);
    xTaskCreate(tag_task, "mf_tag", 8192, NULL, 5, NULL);
}
