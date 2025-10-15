"""Simple test for ThreatDetectionEngine without pytest"""

from datetime import datetime
from scapy.layers.inet import IP, TCP, ICMP
from scapy.packet import Packet

from ids.services.threat_detection_engine import ThreatDetectionEngine
from ids.detectors.port_scan_detector import PortScanDetector
from ids.detectors.icmp_scan_detector import ICMPScanDetector
from ids.detectors.base_detector import ThreatDetector
from ids.models.data_models import ThreatEvent, ThreatType


class MockDetector(ThreatDetector):
    """Mock detector for testing"""
    
    def __init__(self, should_detect=False, threat_type=ThreatType.PORT_SCAN):
        self.should_detect = should_detect
        self.threat_type = threat_type
        self.call_count = 0
    
    def detect(self, packet: Packet):
        self.call_count += 1
        if self.should_detect:
            return ThreatEvent(
                timestamp=datetime.now(),
                threat_type=self.threat_type,
                source_ip="192.168.1.100",
                destination_ip="10.0.0.1",
                protocol="TCP",
                raw_data={"test": "data"}
            )
        return None


def test_engine_initialization():
    """Test that engine initializes correctly"""
    print("Testing engine initialization...")
    engine = ThreatDetectionEngine()
    
    stats = engine.get_statistics()
    assert stats["packets_analyzed"] == 0
    assert stats["threats_detected"] == 0
    assert stats["registered_detectors"] == 0
    assert stats["detector_types"] == []
    print("✓ Engine initialization test passed")


def test_register_detector():
    """Test registering detectors"""
    print("Testing detector registration...")
    engine = ThreatDetectionEngine()
    detector1 = MockDetector()
    detector2 = MockDetector()
    
    engine.register_detector(detector1)
    engine.register_detector(detector2)
    
    stats = engine.get_statistics()
    assert stats["registered_detectors"] == 2
    assert len(stats["detector_types"]) == 2
    print("✓ Detector registration test passed")


def test_register_invalid_detector():
    """Test that registering non-detector raises TypeError"""
    print("Testing invalid detector registration...")
    engine = ThreatDetectionEngine()
    
    try:
        engine.register_detector("not a detector")
        assert False, "Should have raised TypeError"
    except TypeError:
        print("✓ Invalid detector registration test passed")


def test_analyze_packet_no_threat():
    """Test analyzing packet when no threat is detected"""
    print("Testing packet analysis with no threat...")
    engine = ThreatDetectionEngine()
    detector = MockDetector(should_detect=False)
    engine.register_detector(detector)
    
    packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
    
    result = engine.analyze_packet(packet)
    
    assert result is None
    assert detector.call_count == 1
    
    stats = engine.get_statistics()
    assert stats["packets_analyzed"] == 1
    assert stats["threats_detected"] == 0
    print("✓ No threat detection test passed")


def test_analyze_packet_with_threat():
    """Test analyzing packet when threat is detected"""
    print("Testing packet analysis with threat...")
    engine = ThreatDetectionEngine()
    detector = MockDetector(should_detect=True)
    engine.register_detector(detector)
    
    packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
    
    result = engine.analyze_packet(packet)
    
    assert result is not None
    assert isinstance(result, ThreatEvent)
    assert result.threat_type == ThreatType.PORT_SCAN
    assert result.source_ip == "192.168.1.100"
    
    stats = engine.get_statistics()
    assert stats["packets_analyzed"] == 1
    assert stats["threats_detected"] == 1
    print("✓ Threat detection test passed")


def test_multiple_detectors():
    """Test that first detector to detect threat returns result"""
    print("Testing multiple detectors...")
    engine = ThreatDetectionEngine()
    
    detector1 = MockDetector(should_detect=True, threat_type=ThreatType.PORT_SCAN)
    detector2 = MockDetector(should_detect=True, threat_type=ThreatType.ICMP_SCAN)
    
    engine.register_detector(detector1)
    engine.register_detector(detector2)
    
    packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
    
    result = engine.analyze_packet(packet)
    
    # First detector should return its threat
    assert result.threat_type == ThreatType.PORT_SCAN
    
    # Second detector should not be called (short-circuit)
    assert detector1.call_count == 1
    assert detector2.call_count == 0
    print("✓ Multiple detectors test passed")


def test_statistics_tracking():
    """Test that statistics are tracked correctly"""
    print("Testing statistics tracking...")
    engine = ThreatDetectionEngine()
    detector = MockDetector(should_detect=True)
    engine.register_detector(detector)
    
    packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
    
    # Analyze multiple packets
    for _ in range(5):
        engine.analyze_packet(packet)
    
    stats = engine.get_statistics()
    assert stats["packets_analyzed"] == 5
    assert stats["threats_detected"] == 5
    print("✓ Statistics tracking test passed")


def test_reset_statistics():
    """Test resetting statistics"""
    print("Testing statistics reset...")
    engine = ThreatDetectionEngine()
    detector = MockDetector(should_detect=True)
    engine.register_detector(detector)
    
    packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
    
    engine.analyze_packet(packet)
    engine.analyze_packet(packet)
    
    stats = engine.get_statistics()
    assert stats["packets_analyzed"] == 2
    assert stats["threats_detected"] == 2
    
    engine.reset_statistics()
    
    stats = engine.get_statistics()
    assert stats["packets_analyzed"] == 0
    assert stats["threats_detected"] == 0
    assert stats["registered_detectors"] == 1  # Detectors remain registered
    print("✓ Statistics reset test passed")


def test_integration_with_real_detectors():
    """Test engine with real detector implementations"""
    print("Testing integration with real detectors...")
    engine = ThreatDetectionEngine()
    
    # Register real detectors
    port_scan_detector = PortScanDetector(threshold=3, time_window=60)
    icmp_scan_detector = ICMPScanDetector(threshold=3, time_window=30)
    
    engine.register_detector(port_scan_detector)
    engine.register_detector(icmp_scan_detector)
    
    stats = engine.get_statistics()
    assert stats["registered_detectors"] == 2
    assert "PortScanDetector" in stats["detector_types"]
    assert "ICMPScanDetector" in stats["detector_types"]
    
    # Create port scan packets
    threat_detected = False
    for port in range(80, 84):
        packet = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=port, flags="S")
        result = engine.analyze_packet(packet)
        
        if result:
            assert result.threat_type == ThreatType.PORT_SCAN
            threat_detected = True
            break
    
    assert threat_detected, "Port scan should have been detected"
    print("✓ Real detector integration test passed")


if __name__ == "__main__":
    print("\n=== Running ThreatDetectionEngine Tests ===\n")
    
    try:
        test_engine_initialization()
        test_register_detector()
        test_register_invalid_detector()
        test_analyze_packet_no_threat()
        test_analyze_packet_with_threat()
        test_multiple_detectors()
        test_statistics_tracking()
        test_reset_statistics()
        test_integration_with_real_detectors()
        
        print("\n=== All Tests Passed! ===\n")
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}\n")
        raise
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}\n")
        raise
