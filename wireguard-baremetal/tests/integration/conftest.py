# SPDX-FileCopyrightText: 2026 VeriGuard Project
# SPDX-License-Identifier: MIT
"""
pytest configuration for VeriGuard integration tests.

Software-only tests (handshake self-tests, KDF vectors) run without
any fixtures.  Hardware tests (marked ``esp32c6``) use the ``dut``
fixture provided by pytest-embedded-idf.
"""
import pytest


@pytest.fixture
def reset_dut(dut):
    """Reset the ESP32 before a test.  Use explicitly in hardware tests."""
    dut.serial.hard_reset()
    yield dut
