cmake_minimum_required(VERSION 3.16)

project(VeriGuard)

# ============================================================================
# Configuration
# ============================================================================

set(WIREGUARD_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(ESP_IDF_COMPONENTS_DIR ${WIREGUARD_ROOT}/platform)
set(ADA_CRATES_DIR ${WIREGUARD_ROOT})

# ============================================================================
# Build Ada/SPARK Crates
# ============================================================================

# Uses Alire to build Ada libraries
# Output: lib/crypto/lib/libCrypto.a, lib/wireguard/lib/libWireguard.a, etc.

add_custom_target(build_ada_crates
    COMMAND bash -c "
        cd '${ADA_CRATES_DIR}/crypto' && alr build
        cd '${ADA_CRATES_DIR}/wireguard' && alr build
        cd '${ADA_CRATES_DIR}/net' && alr build
        cd '${ADA_CRATES_DIR}/bindings' && alr build
    "
    COMMENT "Building Ada/SPARK crates with Alire"
    VERBATIM
)

# ============================================================================
# ESP-IDF Project Setup
# ============================================================================

# Include ESP-IDF CMake functionality
include($ENV{IDF_PATH}/tools/cmake/idf.cmake)

# Include components
set(EXTRA_COMPONENT_DIRS ${ESP_IDF_COMPONENTS_DIR})

# ============================================================================
# Project Definition
# ============================================================================

idf_project_init(
    PROJECT_NAME VeriGuard
    PROJECT_VERSION "0.1.0-dev"
)

# ============================================================================
# Ada Library Paths
# ============================================================================

# After Alire builds, collect Ada library paths
# These will be linked into the final firmware

set(ADA_LIB_DIRS
    ${ADA_CRATES_DIR}/crypto/lib
    ${ADA_CRATES_DIR}/wireguard/lib
    ${ADA_CRATES_DIR}/net/lib
    ${ADA_CRATES_DIR}/bindings/lib
)

set(ADA_LIBS
    Crypto
    Wireguard
    Net
    Bindings
)

# ============================================================================
# Add Projects
# ============================================================================

idf_build_process(
    TARGET esp32c6
    SDKCONFIG ${WIREGUARD_ROOT}/sdkconfig
    BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}
    PROJECT_DIR ${WIREGUARD_ROOT}
)

# ============================================================================
# Link Ada Libraries
# ============================================================================

# After ESP-IDF components are defined, link Ada libraries to main component
idf_component_get_property(main_lib main COMPONENT_LIB)

foreach(lib_dir ${ADA_LIB_DIRS})
    link_directories(${lib_dir})
endforeach()

foreach(lib_name ${ADA_LIBS})
    target_link_libraries(${main_lib} PUBLIC ${lib_name})
endforeach()

# ============================================================================
# Build Order
# ============================================================================

# Ensure Ada crates are built before linking
idf_build_set_property(DEPENDENCIES build_ada_crates)

# ============================================================================
# Install / Distribution
# ============================================================================

# Output firmware to known location
set(FINAL_FIRMWARE ${CMAKE_CURRENT_BINARY_DIR}/VeriGuard.elf)

add_custom_command(
    TARGET app POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "VeriGuard firmware: ${FINAL_FIRMWARE}"
    COMMENT "VeriGuard build complete"
)
