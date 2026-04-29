#include <esp_netif.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <nvs_flash.h>

#include "wg_task.h"
#include "wg_netif.h"
#include "wifi_station.h"

static const char *TAG = "main";

void app_main(void)
{

    /**
     * ESP32 Wi-Fi is stateful and stores persistent data across boot
     * PHY calibration data
     * Country / regulatory domain
     * STA/AP configuration
     * Power-saving state
     * Fast reconnect / roaming info
     * ect ...
     */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // If you only want to open more logs in the wifi module, you need to make
    // the max level greater than the default level, and call
    // esp_log_level_set() before esp_wifi_init() to improve the log level of
    // the wifi module.
    esp_log_level_set("wifi", ESP_LOG_DEBUG);

    wifi_init_sta();

    ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");

    // WG subsystem: queues, packet pools, session mutex, Ada init
    if (!wg_task_init()) {
        ESP_LOGE(TAG, "WG init failed");
        return;
    }

    if (!wg_task_start()) {
        ESP_LOGE(TAG, "WG protocol task failed to start");
        return;
    }

    if (!wg_netif_init()) {
        ESP_LOGE(TAG, "WG netif init failed");
        return;
    }

    if (!wg_netif_start()) {
        ESP_LOGE(TAG, "WG netif start failed");
        return;
    }

    ESP_LOGI(TAG, "All tasks started");

    // app_main() returns here -- FreeRTOS deletes the main task.
    // Both tasks continue running independently.
}
