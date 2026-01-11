# SPDX-FileCopyrightText: 2026 VeriGuard Project
# SPDX-License-Identifier: MIT
"""
Integration tests for VeriGuard WiFi station and UDP echo server.

Tests verify:
1. WiFi station connects to configured AP
2. UDP server binds to WireGuard port (51820)
3. UDP echo server correctly echoes packets

Usage (after building):
    cd /path/to/wireguard-baremetal
    idf.py build
    pytest --target esp32c6

Or run specific test:
    pytest --target esp32c6 -k test_udp_echo
"""
import socket
import time
import pytest
from pytest_embedded_idf.dut import IdfDut


@pytest.mark.esp32c6
@pytest.mark.generic
def test_wifi_station_connects(dut: IdfDut) -> None:
    """Test that WiFi station successfully connects to the configured AP."""
    
    # Wait for WiFi initialization
    dut.expect('wifi sta: wifi_init_sta finished', timeout=30)
    
    # Wait for successful connection (got IP)
    dut.expect(r'wifi sta: got ip:', timeout=60)
    dut.expect(r'wifi sta: connected to ap SSID:', timeout=10)


@pytest.mark.esp32c6
@pytest.mark.generic
def test_udp_server_starts(dut: IdfDut) -> None:
    """Test that UDP server creates and binds socket on port 51820."""
    
    # Wait for system initialization
    dut.expect('ESP_WIFI_MODE_STA', timeout=30)
    
    # Wait for WiFi to connect first (UDP server starts after WiFi)
    dut.expect(r'wifi sta: got ip:', timeout=60)
    
    # UDP server should create socket
    dut.expect('udp srv: Socket created', timeout=30)
    
    # Socket should bind successfully
    dut.expect('udp srv: Socket bound, port 51820', timeout=10)
    
    # Server should enter receive loop
    dut.expect('udp srv: Waiting for data', timeout=10)


@pytest.mark.esp32c6
@pytest.mark.generic
def test_full_startup_sequence(dut: IdfDut) -> None:
    """Test complete VeriGuard startup sequence."""
    
    # 1. WiFi initialization
    dut.expect('wifi sta: wifi_init_sta finished', timeout=30)
    
    # 2. WiFi connection (with retries allowed)
    dut.expect(r'wifi sta: got ip:', timeout=60)
    dut.expect(r'wifi sta: connected to ap SSID:', timeout=10)
    
    # 3. Main app starts
    dut.expect('ESP_WIFI_MODE_STA', timeout=10)
    
    # 4. UDP server initializes
    dut.expect('udp srv: Socket created', timeout=10)
    dut.expect('udp srv: Socket bound, port 51820', timeout=10)
    dut.expect('udp srv: Waiting for data', timeout=10)
    
    # 5. FreeRTOS returns from app_main (normal for task-based apps)
    dut.expect('main_task: Returned from app_main', timeout=10)


@pytest.mark.esp32c6
@pytest.mark.generic
def test_udp_echo_server(dut: IdfDut) -> None:
    """Test UDP echo server by sending packets every 2 seconds for 10 seconds.
    
    Verifies:
    1. ESP32 receives each packet (visible in serial log)
    2. ESP32 echoes the packet back
    3. Test host receives the echoed packet with matching content
    """
    UDP_PORT = 51820
    TEST_DURATION = 10  # seconds
    PACKET_INTERVAL = 2  # seconds
    
    # Wait for WiFi connection and get the ESP32's IP address
    dut.expect('wifi sta: wifi_init_sta finished', timeout=30)
    match = dut.expect(r'wifi sta: got ip:(\d+\.\d+\.\d+\.\d+)', timeout=60)
    esp32_ip = match.group(1)
    print(f'[TEST] ESP32 IP address: {esp32_ip}')
    
    # Wait for UDP server to be ready
    dut.expect('udp srv: Socket bound, port 51820', timeout=10)
    dut.expect('udp srv: Waiting for data', timeout=10)
    
    # Create UDP socket on test host
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)  # 3 second timeout for responses
    
    try:
        packets_sent = 0
        packets_echoed = 0
        start_time = time.time()
        
        while time.time() - start_time < TEST_DURATION:
            # Send test packet
            packets_sent += 1
            test_message = f'VeriGuard test packet #{packets_sent}'
            
            print(f'[TEST] Sending: {test_message}')
            sock.sendto(test_message.encode(), (esp32_ip, UDP_PORT))
            
            # Verify ESP32 received it (check serial log)
            try:
                dut.expect(f'Received {len(test_message)} bytes from', timeout=3)
                dut.expect_exact(test_message, timeout=1)
            except Exception as e:
                print(f'[TEST] Warning: Did not see packet in ESP32 log: {e}')
            
            # Wait for echo response
            try:
                response, addr = sock.recvfrom(1024)
                response_str = response.decode()
                
                if response_str == test_message:
                    packets_echoed += 1
                    print(f'[TEST] Echo received: {response_str}')
                else:
                    print(f'[TEST] Mismatch! Sent: {test_message}, Got: {response_str}')
            except socket.timeout:
                print(f'[TEST] Timeout waiting for echo of packet #{packets_sent}')
            
            # Wait before next packet
            time.sleep(PACKET_INTERVAL)
        
        elapsed = time.time() - start_time
        print(f'[TEST] Results: {packets_echoed}/{packets_sent} packets echoed in {elapsed:.1f}s')
        
        # Verify at least 80% of packets were echoed
        success_rate = packets_echoed / packets_sent if packets_sent > 0 else 0
        assert success_rate >= 0.8, \
            f'Echo success rate {success_rate:.0%} below 80% threshold ({packets_echoed}/{packets_sent})'
        
    finally:
        sock.close()
