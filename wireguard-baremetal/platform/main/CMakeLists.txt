idf_component_register(
    SRCS main.c udp_server.c wifi_station.c
    INCLUDE_DIRS "."
    PRIV_REQUIRES esp_wifi nvs_flash esp_netif
)

# ============================================================================
# Link Ada Static Libraries
# ============================================================================
# 
# These libraries are built by Alire (alr build) in each crate directory.
# Run build_ada.sh before idf.py build.

set(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")

# Ada library paths (built by Alire)
set(ADA_LIBS
    "${PROJECT_ROOT}/bindings/lib/libBindings.a"
    "${PROJECT_ROOT}/wireguard/lib/libWireguard.a"
    "${PROJECT_ROOT}/crypto/lib/libCrypto.a"
    "${PROJECT_ROOT}/net/lib/libNet.a"
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

# Ada runtime library (GNAT RTS - may need adjustment for target)
# target_link_libraries(${COMPONENT_LIB} PRIVATE gnat)
