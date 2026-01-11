#include <esp_netif.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <nvs_flash.h>

#include "udp_server.h"
#include "wifi_station.h"

static const char *TAG = "main";

int app_main(void)
{
    /*
     * TODO: Implement ESP-IDF application entry point
     *
     * 1. Initialize hardware (WiFi, DMA, timers)
     * 2. Call Ada initialization (if needed)
     * 3. Enter main loop:
     *    - Poll for RX packets, call wg_receive_bytes()
     *    - Check TX queue, call wg_prepare_tx()
     *    - Handle interrupts / timers
     */

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

    /* If you only want to open more logs in the wifi module, you need to make the max level greater than the default level,
     * and call esp_log_level_set() before esp_wifi_init() to improve the log level of the wifi module. */
    esp_log_level_set("wifi", ESP_LOG_DEBUG);

    wifi_init_sta();
    ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");

    xTaskCreate(udp_server_task, "udp_server", 4096, (void*)0, 5, NULL);
    ESP_LOGI(TAG, "UDP Server task started ...");

    return 0;
}
