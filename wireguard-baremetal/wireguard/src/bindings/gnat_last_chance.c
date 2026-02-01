/**
 * gnat_last_chance.c - Ada runtime exception handler for bare-metal
 *
 * This function is called by the GNAT Ada runtime when an unhandled
 * exception occurs. On embedded systems without a full runtime, we
 * must provide this ourselves.
 *
 * For SPARK code with proven absence of runtime errors, this should
 * never be called. But the linker still needs the symbol.
 */

#include <esp_log.h>
#include <esp_system.h>

static const char *TAG = "ada_runtime";

/**
 * Called by Ada runtime for unhandled exceptions.
 *
 * @param source_location String describing where the exception occurred
 * @param line            Line number in source file
 */
void __gnat_last_chance_handler(const char *source_location, int line)
{
    ESP_LOGE(TAG, "Ada exception at %s:%d", source_location, line);
    ESP_LOGE(TAG, "Halting system - this should not happen with SPARK-proven code!");

    // On ESP-IDF, restart the system after logging
    esp_restart();

    // Should never reach here, but satisfy the compiler
    while (1) {
        // Infinite loop as fallback
    }
}
