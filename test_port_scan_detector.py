"""Test script for PortScanDetector"""

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from ids.detectors.port_scan_detector import PortScanDetector
from ids.models.data_models import ThreatType


def create_syn_packet(src_ip: str, dst_ip: str, dst_port: int):
    """Create a SYN packet for testing"""
    return IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, flags='S')


def create_ack_packet(src_ip: str, dst_ip: str, dst_port: int):
    """Create an ACK packet for testing"""
    return IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, flags='A')


def test_port_scan_detection():
    """Test basic port scan detection"""
    print("Testing PortScanDetector...")
    
    # Create detector with low threshold for testing
    detector = PortScanDetector(threshold=5, time_window=60)
    
    attacker_ip = "192.168.1.100"
    target_ip = "10.0.0.5"
    
    # Simulate scanning 5 ports (should trigger alert)
    print(f"\nSimulating port scan from {attacker_ip} to {target_ip}...")
    
    for port in range(80, 85):
        packet = create_syn_packet(attacker_ip, target_ip, port)
        result = detector.detect(packet)
        
        if result:
            print(f"\n✓ Port scan detected!")
            print(f"  Threat Type: {result.threat_type.value}")
            print(f"  Source IP: {result.source_ip}")
            print(f"  Destination IP: {result.destination_ip}")
            print(f"  Protocol: {result.protocol}")
            print(f"  Scanned Ports: {result.raw_data['scanned_ports']}")
            print(f"  Port Count: {result.raw_data['port_count']}")
            print(f"  Scan Type: {result.raw_data['scan_type']}")
            
            assert result.threat_type == ThreatType.PORT_SCAN
            assert result.source_ip == attacker_ip
            assert result.protocol == "TCP"
            assert result.raw_data['port_count'] >= 5
            print("\n✓ All assertions passed!")
            return
    
    print("\n✗ Port scan was not detected (expected detection)")


def test_no_false_positive():
    """Test that normal traffic doesn't trigger false positives"""
    print("\n\nTesting false positive prevention...")
    
    detector = PortScanDetector(threshold=10, time_window=60)
    
    client_ip = "192.168.1.50"
    server_ip = "10.0.0.10"
    
    # Simulate normal connection (SYN followed by ACK)
    print(f"Simulating normal traffic from {client_ip} to {server_ip}...")
    
    for port in [80, 443, 8080]:
        syn_packet = create_syn_packet(client_ip, server_ip, port)
        result = detector.detect(syn_packet)
        
        if result:
            print(f"✗ False positive detected on port {port}")
            return
        
        # Simulate ACK response (successful connection)
        ack_packet = create_ack_packet(client_ip, server_ip, port)
        detector.detect(ack_packet)
    
    print("✓ No false positives - normal traffic not flagged")


def test_threshold_not_exceeded():
    """Test that scans below threshold don't trigger alerts"""
    print("\n\nTesting threshold enforcement...")
    
    detector = PortScanDetector(threshold=10, time_window=60)
    
    scanner_ip = "192.168.1.200"
    target_ip = "10.0.0.20"
    
    # Scan only 5 ports (below threshold of 10)
    print(f"Simulating scan of 5 ports (threshold is 10)...")
    
    for port in range(100, 105):
        packet = create_syn_packet(scanner_ip, target_ip, port)
        result = detector.detect(packet)
        
        if result:
            print(f"✗ Alert triggered below threshold")
            return
    
    print("✓ No alert triggered - threshold not exceeded")


if __name__ == "__main__":
    print("=" * 60)
    print("Port Scan Detector Test Suite")
    print("=" * 60)
    
    test_port_scan_detection()
    test_no_false_positive()
    test_threshold_not_exceeded()
    
    print("\n" + "=" * 60)
    print("All tests completed!")
    print("=" * 60)
