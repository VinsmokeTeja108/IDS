"""Test script for BruteForceDetector"""

from datetime import datetime
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from ids.detectors.brute_force_detector import BruteForceDetector
from ids.models.data_models import ThreatType


def create_rst_packet(src_ip: str, dst_ip: str, dst_port: int) -> Packet:
    """Create a TCP RST packet for testing"""
    packet = IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, flags="R")
    return packet


def test_brute_force_detection():
    """Test brute force detection with multiple RST packets"""
    print("Testing BruteForceDetector...")
    
    detector = BruteForceDetector(threshold=5, time_window=60)
    
    source_ip = "192.168.1.100"
    target_ip = "10.0.0.5"
    
    print(f"\n1. Sending 4 RST packets to SSH port (below threshold)...")
    for i in range(4):
        packet = create_rst_packet(source_ip, target_ip, 22)
        result = detector.detect(packet)
        assert result is None, f"Should not detect threat yet (attempt {i+1}/4)"
    print("   ✓ No threat detected (as expected)")
    
    print(f"\n2. Sending 5th RST packet (should trigger alert)...")
    packet = create_rst_packet(source_ip, target_ip, 22)
    result = detector.detect(packet)
    
    assert result is not None, "Should detect brute force attack"
    assert result.threat_type == ThreatType.BRUTE_FORCE
    assert result.source_ip == source_ip
    assert result.protocol == "TCP"
    assert result.raw_data["attempt_count"] == 5
    assert 22 in result.raw_data["targeted_ports"]
    assert "SSH" in result.raw_data["services"]
    
    print("   ✓ Brute force attack detected!")
    print(f"   - Source IP: {result.source_ip}")
    print(f"   - Attempt count: {result.raw_data['attempt_count']}")
    print(f"   - Targeted ports: {result.raw_data['targeted_ports']}")
    print(f"   - Services: {result.raw_data['services']}")
    
    print(f"\n3. Testing with RDP port (3389)...")
    detector2 = BruteForceDetector(threshold=3, time_window=60)
    
    for i in range(3):
        packet = create_rst_packet("10.0.0.50", "192.168.1.10", 3389)
        result = detector2.detect(packet)
    
    assert result is not None
    assert 3389 in result.raw_data["targeted_ports"]
    assert "RDP" in result.raw_data["services"]
    print("   ✓ RDP brute force detected!")
    
    print(f"\n4. Testing with FTP port (21)...")
    detector3 = BruteForceDetector(threshold=3, time_window=60)
    
    for i in range(3):
        packet = create_rst_packet("172.16.0.100", "192.168.1.20", 21)
        result = detector3.detect(packet)
    
    assert result is not None
    assert 21 in result.raw_data["targeted_ports"]
    assert "FTP" in result.raw_data["services"]
    print("   ✓ FTP brute force detected!")
    
    print(f"\n5. Testing with non-auth port (should not trigger)...")
    detector4 = BruteForceDetector(threshold=3, time_window=60)
    
    for i in range(5):
        packet = create_rst_packet("192.168.1.200", "10.0.0.30", 80)  # HTTP port
        result = detector4.detect(packet)
        assert result is None
    
    print("   ✓ Non-auth port correctly ignored")
    
    print(f"\n6. Testing with SYN packets (should not trigger)...")
    detector5 = BruteForceDetector(threshold=3, time_window=60)
    
    for i in range(5):
        packet = IP(src="192.168.1.250", dst="10.0.0.40") / TCP(dport=22, flags="S")
        result = detector5.detect(packet)
        assert result is None
    
    print("   ✓ Non-RST packets correctly ignored")
    
    print(f"\n7. Testing multiple targets...")
    detector6 = BruteForceDetector(threshold=5, time_window=60)
    
    targets = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    for target in targets:
        packet = create_rst_packet("192.168.1.99", target, 22)
        detector6.detect(packet)
    
    packet = create_rst_packet("192.168.1.99", "10.0.0.4", 3389)
    detector6.detect(packet)
    
    packet = create_rst_packet("192.168.1.99", "10.0.0.5", 21)
    result = detector6.detect(packet)
    
    assert result is not None
    assert len(result.raw_data["targeted_hosts"]) == 5
    assert len(result.raw_data["services"]) == 3  # SSH, RDP, FTP
    print("   ✓ Multiple targets and services detected!")
    print(f"   - Targeted hosts: {len(result.raw_data['targeted_hosts'])}")
    print(f"   - Services: {result.raw_data['services']}")
    
    print("\n" + "="*60)
    print("All tests passed! ✓")
    print("="*60)


if __name__ == "__main__":
    test_brute_force_detection()
