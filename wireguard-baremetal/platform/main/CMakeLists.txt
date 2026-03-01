idf_component_register(
    SRCS main.c wg_netif.c wg_task.c wg_commands.c wg_clock.c wifi_station.c wg_keys.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../wireguard/src/bindings/Ada_Export/gnat_last_chance.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../wireguard/src/bindings/Ada_Export/packet_pool.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../wireguard/src/bindings/C_Import/wg_mutex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../wireguard/src/bindings/Ada_Export/wg_sessions.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/BLAKE2/ref/blake2s-ref.c
    INCLUDE_DIRS "."
    PRIV_REQUIRES esp_wifi nvs_flash esp_netif libsodium esp_timer
)

# ============================================================================
# Ada/SPARK Bindings - Include paths for C headers
# ============================================================================

set(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")

# Add Ada bindings headers to include path
target_include_directories(${COMPONENT_LIB} PRIVATE
    "${PROJECT_ROOT}/wireguard/src/bindings/Ada_Export"
    "${PROJECT_ROOT}/wireguard/src/bindings/C_Import"
    "${PROJECT_ROOT}/third_party/BLAKE2/ref"
)

# ============================================================================
# Link Ada Static Libraries
# ============================================================================
#
# These libraries are built by Alire (alr build) in the wireguard crate.
# Run build.py --alr before idf.py build.

# Ada library paths (built by Alire in wireguard/lib/)
set(ADA_LIBS
    "${PROJECT_ROOT}/wireguard/lib/libWireguard.a"
    "${PROJECT_ROOT}/wireguard/lib/libWgHandshake.a"
    "${PROJECT_ROOT}/wireguard/lib/libWgCrypto.a"
    "${PROJECT_ROOT}/wireguard/lib/libWgMessages.a"
    "${PROJECT_ROOT}/wireguard/lib/libWgTransport.a"
    "${PROJECT_ROOT}/wireguard/lib/libWgNet.a"
    "${PROJECT_ROOT}/wireguard/lib/libWgUtils.a"
    "${PROJECT_ROOT}/wireguard/lib/libWgThreads.a"
    "${PROJECT_ROOT}/wireguard/lib/libWgSession.a"
    "${PROJECT_ROOT}/wireguard/lib/libWgTimer.a"
)

foreach(ada_lib ${ADA_LIBS})
    if(EXISTS ${ada_lib})
        message(STATUS "Linking Ada library: ${ada_lib}")
    else()
        message(WARNING "Ada library not found (run 'alr build' first): ${ada_lib}")
    endif()
endforeach()

# ── Linker group for Ada + dependencies ──────────────────────────────
#
# ESP-IDF places PRIVATE link deps at the END of the link line, after
# all component archives have been scanned.  Ada libraries have:
#
#   1. Inter-crate references  (libWgHandshake → libWgCrypto)
#   2. Calls into libsodium    (crypto_scalarmult, crypto_box_keypair)
#   3. Calls into wg_keys.c    (wg_get_static_private_key)
#
# --whole-archive   → include ALL Ada objects (resolves inter-Ada deps)
# --start-group     → multiple passes   (resolves Ada ↔ C ↔ libsodium)
#
# libsodium and libmain.a are re-listed inside the group so the linker
# can satisfy Ada's undefined references in a second pass.
target_link_libraries(${COMPONENT_LIB} PRIVATE
    "-Wl,--start-group"
    "-Wl,--whole-archive"
    ${ADA_LIBS}
    "-Wl,--no-whole-archive"
    "${CMAKE_BINARY_DIR}/esp-idf/espressif__libsodium/libespressif__libsodium.a"
    "${CMAKE_BINARY_DIR}/esp-idf/main/libmain.a"
    "-Wl,--end-group"
)

# Force linker to include Ada runtime symbols
target_link_libraries(${COMPONENT_LIB} PRIVATE "-Wl,-u,__gnat_last_chance_handler")
target_link_libraries(${COMPONENT_LIB} PRIVATE "-Wl,-u,system__assertions__raise_assert_failure")
