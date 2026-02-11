/**
 * gnat_last_chance.c - Ada runtime exception handler for bare-metal
 *
 * This function is called by the GNAT Ada runtime when an unhandled
 * exception occurs. On embedded systems without a full runtime, we
 * must provide this ourselves.
 *
 * For SPARK code with proven absence of runtime errors, this should
 * never be called. But the linker still needs the symbol.
 *
 * With -gnata (contracts enabled), assertion failures call
 * system__assertions__raise_assert_failure instead of
 * __gnat_last_chance_handler directly. We provide that symbol here
 * so it routes through the same restart path.
 */

#include <stdlib.h>
#include <stdint.h>
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

    abort();  // Triggers panic handler → GDB backtrace / core dump
}

/**
 * Called by GNAT when a Pre/Post/Type_Invariant/Assert fails at runtime
 * (enabled by -gnata / Contracts => Yes).
 *
 * GNAT passes an Ada fat-string (pointer + bounds), but the ABI for
 * bare-metal RISC-V lays it out as (pointer, first, last). We only
 * need the pointer to log something useful.
 *
 * This is the missing symbol: system.assertions.raise_assert_failure
 */
void system__assertions__raise_assert_failure(const char *msg,
                                              int32_t first,
                                              int32_t last)
{
    int len = last - first + 1;
    ESP_LOGE(TAG, "Assertion failed: %.*s", len, msg);

    abort();  // Triggers panic handler → GDB backtrace / core dump
}
