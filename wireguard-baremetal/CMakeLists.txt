# VeriGuard - ESP-IDF Project
#
# Standard ESP-IDF CMakeLists.txt format.
# See: https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/build-system.html

cmake_minimum_required(VERSION 3.16)

# ============================================================================
# Ada/SPARK Crates - Build before ESP-IDF
# ============================================================================
# 
# Ada crates must be built separately using Alire before running idf.py build.
# Run: ./build_ada.sh (or manually: cd crypto && alr build, etc.)
#
# The Ada static libraries (.a) are then linked into the ESP-IDF build.

# ============================================================================
# ESP-IDF Project Setup
# ============================================================================

# Components directories (platform/main, platform/common, platform/cortex_m)
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/platform")

# Include ESP-IDF build system
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Define the project
project(VeriGuard)

# ============================================================================
# Ada Library Linking (after project() call)
# ============================================================================
#
# Link Ada static libraries into the main component.
# These paths assume `alr build` was run in each crate directory.

# Note: Ada library linking is done in platform/main/CMakeLists.txt
# because component libraries need to be linked at component level.
