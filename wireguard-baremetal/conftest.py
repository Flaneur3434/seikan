# SPDX-FileCopyrightText: 2026 VeriGuard Project
# SPDX-License-Identifier: MIT
"""
pytest configuration for VeriGuard integration tests.
"""
import pytest


@pytest.fixture(autouse=True)
def reset_device_before_test(dut):
    """Reset the ESP32 before each test to ensure clean state."""
    # Hard reset the device via RTS pin
    dut.serial.hard_reset()
    yield
