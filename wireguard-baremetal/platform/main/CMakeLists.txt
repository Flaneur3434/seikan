idf_component_register(
    SRCS main.c udp_server.c wifi_station.c wg_keys.c
         ${CMAKE_CURRENT_SOURCE_DIR}/../../wireguard/src/bindings/gnat_last_chance.c
    INCLUDE_DIRS "."
    PRIV_REQUIRES esp_wifi nvs_flash esp_netif
)

# ============================================================================
# Ada/SPARK Bindings - Include paths for C headers
# ============================================================================

set(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")

# Add Ada bindings headers to include path
target_include_directories(${COMPONENT_LIB} PRIVATE
    "${PROJECT_ROOT}/wireguard/src/bindings"
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
    "${PROJECT_ROOT}/wireguard/lib/libWgCrypto.a"
    "${PROJECT_ROOT}/wireguard/lib/libWgNet.a"
    "${PROJECT_ROOT}/wireguard/lib/libWgTransport.a"
    "${PROJECT_ROOT}/wireguard/lib/libWgUtils.a"
)

# Link Ada libraries to this component
foreach(ada_lib ${ADA_LIBS})
    if(EXISTS ${ada_lib})
        target_link_libraries(${COMPONENT_LIB} PRIVATE ${ada_lib})
        message(STATUS "Linking Ada library: ${ada_lib}")
    else()
        message(WARNING "Ada library not found (run 'alr build' first): ${ada_lib}")
    endif()
endforeach()

# Force linker to include Ada runtime symbols from this component
# (needed because Ada libs are linked after libmain.a is processed)
target_link_libraries(${COMPONENT_LIB} PRIVATE "-Wl,-u,__gnat_last_chance_handler")

# Ada runtime library (GNAT RTS - may need adjustment for target)
# target_link_libraries(${COMPONENT_LIB} PRIVATE gnat)
