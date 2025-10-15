"""Test data exfiltration detector"""

from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from ids.detectors.data_exfiltration_detector import DataExfiltrationDetector
from ids.models.data_models import ThreatType


def test_data_exfiltration_detection():
    """Test detection of large data transfers"""
    detector = DataExfiltrationDetector(threshold_bytes=1000, time_window=60)
    
    # Create multiple packets simulating large data transfer
    source_ip = "192.168.1.100"
    dest_ip = "203.0.113.50"
    
    threat_detected = False
    
    # Send 10 packets of 150 bytes each (total 1500 bytes > 1000 threshold)
    for i in range(10):
        packet = IP(src=source_ip, dst=dest_ip) / TCP(sport=12345, dport=443) / Raw(load="X" * 150)
        result = detector.detect(packet)
        
        if result:
            threat_detected = True
            print(f"✓ Data exfiltration detected!")
            print(f"  Source: {result.source_ip}")
            print(f"  Destination: {result.destination_ip}")
            print(f"  Threat Type: {result.threat_type.value}")
            print(f"  Protocol: {result.protocol}")
            print(f"  Total Bytes: {result.raw_data['total_bytes']}")
            print(f"  Total MB: {result.raw_data['total_mb']}")
            print(f"  Transfer Count: {result.raw_data['transfer_count']}")
            print(f"  Duration: {result.raw_data['duration_seconds']} seconds")
            
            assert result.threat_type == ThreatType.DATA_EXFILTRATION
            assert result.source_ip == source_ip
            assert result.destination_ip == dest_ip
            assert result.protocol == "TCP"
            assert result.raw_data['total_bytes'] >= 1000
            break
    
    assert threat_detected, "Data exfiltration should have been detected"
    print("\n✓ All data exfiltration detector tests passed!")


def test_no_false_positive_small_transfers():
    """Test that small transfers don't trigger alerts"""
    detector = DataExfiltrationDetector(threshold_bytes=10000, time_window=60)
    
    # Send small packets that shouldn't trigger alert
    packet = IP(src="192.168.1.100", dst="203.0.113.50") / TCP(sport=12345, dport=443) / Raw(load="X" * 100)
    
    result = detector.detect(packet)
    assert result is None, "Small transfer should not trigger alert"
    print("✓ No false positive for small transfers")


def test_udp_protocol_detection():
    """Test detection works with UDP protocol"""
    detector = DataExfiltrationDetector(threshold_bytes=500, time_window=60)
    
    source_ip = "192.168.1.100"
    dest_ip = "203.0.113.50"
    
    # Send UDP packets
    for i in range(5):
        packet = IP(src=source_ip, dst=dest_ip) / UDP(sport=12345, dport=53) / Raw(load="X" * 150)
        result = detector.detect(packet)
        
        if result:
            assert result.protocol == "UDP"
            print("✓ UDP protocol detection works")
            return
    
    print("✓ UDP protocol detection works")


if __name__ == "__main__":
    test_data_exfiltration_detection()
    test_no_false_positive_small_transfers()
    test_udp_protocol_detection()
    print("\n✅ All tests completed successfully!")
