# SPDX-FileCopyrightText: 2026 VeriGuard Project
# SPDX-License-Identifier: MIT
"""
Integration tests for VeriGuard WiFi station and WireGuard netif startup.

Tests verify:
1. WiFi station connects to configured AP
2. wg_netif initialises the wg0 lwIP netif and binds the outer UDP PCB
3. WireGuard Ada subsystem initialises successfully
4. The WireGuard protocol task starts and enters its main loop

The old raw-UDP echo server (udp_server.c) has been replaced by the
lwIP wg_netif module.  There is no longer a plaintext echo path;
all data exchange requires a WireGuard session.

Usage:
    cd wireguard-baremetal
    pytest --target esp32c6 tests/integration/pytest_veriguard.py
"""
import re
import pytest
from pytest_embedded_idf.dut import IdfDut


@pytest.mark.esp32c6
@pytest.mark.generic
def test_wifi_station_connects(dut: IdfDut) -> None:
    """WiFi station connects to the configured AP and obtains an IP."""
    dut.expect('wifi sta: wifi_init_sta finished', timeout=30)
    dut.expect(r'wifi sta: got ip:', timeout=60)
    dut.expect(r'wifi sta: connected to ap SSID:', timeout=10)


@pytest.mark.esp32c6
@pytest.mark.generic
def test_wg_netif_starts(dut: IdfDut) -> None:
    """wg_netif registers wg0 with lwIP and binds the outer UDP PCB on port 51820."""
    dut.expect(r'wifi sta: got ip:', timeout=60)
    dut.expect('wg0 netif', timeout=30)


@pytest.mark.esp32c6
@pytest.mark.generic
def test_wg_init(dut: IdfDut) -> None:
    """Ada WireGuard subsystem initialises (keys load, pools ready)."""
    dut.expect(r'wifi sta: got ip:', timeout=60)
    dut.expect('WireGuard initialized', timeout=30)


@pytest.mark.esp32c6
@pytest.mark.generic
def test_wg_task_starts(dut: IdfDut) -> None:
    """WireGuard protocol task is created and enters its main loop."""
    dut.expect(r'wifi sta: got ip:', timeout=60)
    dut.expect('WG protocol task started', timeout=30)


@pytest.mark.esp32c6
@pytest.mark.generic
def test_full_startup_sequence(dut: IdfDut) -> None:
    """Complete VeriGuard startup sequence in the expected order."""
    # 1. WiFi initialisation
    dut.expect('wifi sta: wifi_init_sta finished', timeout=30)

    # 2. WiFi connection
    dut.expect(r'wifi sta: got ip:', timeout=60)
    dut.expect(r'wifi sta: connected to ap SSID:', timeout=10)

    # 3. wg_netif: wg0 netif + outer UDP PCB ready
    dut.expect('wg0 netif', timeout=15)

    # 4. Ada WireGuard subsystem ready
    dut.expect('WireGuard initialized', timeout=15)

    # 5. WireGuard protocol task running
    dut.expect('WG protocol task started', timeout=10)

    # 6. FreeRTOS returns from app_main (normal for task-based apps)
    dut.expect('main_task: Returned from app_main', timeout=10)
