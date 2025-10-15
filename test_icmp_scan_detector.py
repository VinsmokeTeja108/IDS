"""Test script for ICMP scan detector"""

from scapy.all import IP, ICMP
from ids.detectors.icmp_scan_detector import ICMPScanDetector
from ids.models.data_models import ThreatType


def test_icmp_scan_detection():
    """Test ICMP scan detection with multiple hosts"""
    print("Testing ICMP Scan Detector...")
    
    # Create detector with threshold of 5 hosts in 30 seconds
    detector = ICMPScanDetector(threshold=5, time_window=30)
    
    source_ip = "192.168.1.100"
    
    # Simulate ICMP echo requests to multiple hosts (ping sweep)
    print(f"\nSimulating ICMP ping sweep from {source_ip}...")
    
    threat_detected = False
    for i in range(1, 8):  # Scan 7 hosts
        dest_ip = f"10.0.0.{i}"
        
        # Create ICMP echo request packet (type 8)
        packet = IP(src=source_ip, dst=dest_ip) / ICMP(type=8)
        
        result = detector.detect(packet)
        
        if result:
            threat_detected = True
            print(f"\n✓ ICMP scan detected after {i} hosts!")
            print(f"  Threat Type: {result.threat_type.value}")
            print(f"  Source IP: {result.source_ip}")
            print(f"  Protocol: {result.protocol}")
            print(f"  Scanned Hosts: {result.raw_data['scanned_hosts']}")
            print(f"  Host Count: {result.raw_data['host_count']}")
            print(f"  Scan Type: {result.raw_data['scan_type']}")
            break
        else:
            print(f"  Scanned host {dest_ip} ({i} hosts so far)")
    
    if threat_detected:
        print("\n✓ Test PASSED: ICMP scan was detected correctly")
    else:
        print("\n✗ Test FAILED: ICMP scan was not detected")
    
    return threat_detected


def test_icmp_echo_reply_ignored():
    """Test that ICMP echo replies (type 0) are ignored"""
    print("\n\nTesting ICMP Echo Reply Filtering...")
    
    detector = ICMPScanDetector(threshold=5, time_window=30)
    
    # Create ICMP echo reply packet (type 0) - should be ignored
    packet = IP(src="192.168.1.100", dst="10.0.0.1") / ICMP(type=0)
    
    result = detector.detect(packet)
    
    if result is None:
        print("✓ Test PASSED: ICMP echo replies are correctly ignored")
        return True
    else:
        print("✗ Test FAILED: ICMP echo reply triggered detection")
        return False


def test_threshold_not_exceeded():
    """Test that detection doesn't trigger below threshold"""
    print("\n\nTesting Threshold Behavior...")
    
    detector = ICMPScanDetector(threshold=5, time_window=30)
    
    source_ip = "192.168.1.200"
    
    # Send only 4 ICMP requests (below threshold of 5)
    print(f"Sending 4 ICMP requests (threshold is 5)...")
    
    for i in range(1, 5):
        dest_ip = f"10.0.0.{i}"
        packet = IP(src=source_ip, dst=dest_ip) / ICMP(type=8)
        result = detector.detect(packet)
        
        if result:
            print(f"✗ Test FAILED: Detection triggered at {i} hosts (threshold is 5)")
            return False
    
    print("✓ Test PASSED: No detection below threshold")
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("ICMP Scan Detector Test Suite")
    print("=" * 60)
    
    test1 = test_icmp_scan_detection()
    test2 = test_icmp_echo_reply_ignored()
    test3 = test_threshold_not_exceeded()
    
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    print(f"ICMP Scan Detection: {'PASSED' if test1 else 'FAILED'}")
    print(f"Echo Reply Filtering: {'PASSED' if test2 else 'FAILED'}")
    print(f"Threshold Behavior: {'PASSED' if test3 else 'FAILED'}")
    
    all_passed = test1 and test2 and test3
    print(f"\nOverall: {'ALL TESTS PASSED ✓' if all_passed else 'SOME TESTS FAILED ✗'}")
