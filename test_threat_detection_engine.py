"""Tests for ThreatDetectionEngine"""

import pytest
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


class FailingDetector(ThreatDetector):
    """Detector that raises exceptions for testing error handling"""
    
    def detect(self, packet: Packet):
        raise RuntimeError("Detector failure")


def test_engine_initialization():
    """Test that engine initializes correctly"""
    engine = ThreatDetectionEngine()
    
    stats = engine.get_statistics()
    assert stats["packets_analyzed"] == 0
    assert stats["threats_detected"] == 0
    assert stats["registered_detectors"] == 0
    assert stats["detector_types"] == []


def test_register_detector():
    """Test registering detectors"""
    engine = ThreatDetectionEngine()
    detector1 = MockDetector()
    detector2 = MockDetector()
    
    engine.register_detector(detector1)
    engine.register_detector(detector2)
    
    stats = engine.get_statistics()
    assert stats["registered_detectors"] == 2
    assert len(stats["detector_types"]) == 2


def test_register_invalid_detector():
    """Test that registering non-detector raises TypeError"""
    engine = ThreatDetectionEngine()
    
    with pytest.raises(TypeError):
        engine.register_detector("not a detector")


def test_analyze_packet_no_threat():
    """Test analyzing packet when no threat is detected"""
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


def test_analyze_packet_with_threat():
    """Test analyzing packet when threat is detected"""
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


def test_multiple_detectors_first_detects():
    """Test that first detector to detect threat returns result"""
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


def test_multiple_detectors_second_detects():
    """Test that second detector can detect if first doesn't"""
    engine = ThreatDetectionEngine()
    
    detector1 = MockDetector(should_detect=False)
    detector2 = MockDetector(should_detect=True, threat_type=ThreatType.ICMP_SCAN)
    
    engine.register_detector(detector1)
    engine.register_detector(detector2)
    
    packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
    
    result = engine.analyze_packet(packet)
    
    # Second detector should return its threat
    assert result.threat_type == ThreatType.ICMP_SCAN
    
    # Both detectors should be called
    assert detector1.call_count == 1
    assert detector2.call_count == 1


def test_detector_error_handling():
    """Test that engine continues when a detector fails"""
    engine = ThreatDetectionEngine()
    
    failing_detector = FailingDetector()
    working_detector = MockDetector(should_detect=True)
    
    engine.register_detector(failing_detector)
    engine.register_detector(working_detector)
    
    packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
    
    # Should not raise exception, should continue to working detector
    result = engine.analyze_packet(packet)
    
    assert result is not None
    assert result.threat_type == ThreatType.PORT_SCAN


def test_statistics_tracking():
    """Test that statistics are tracked correctly"""
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


def test_reset_statistics():
    """Test resetting statistics"""
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


def test_integration_with_real_detectors():
    """Test engine with real detector implementations"""
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
    for port in range(80, 84):
        packet = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=port, flags="S")
        result = engine.analyze_packet(packet)
        
        if result:
            assert result.threat_type == ThreatType.PORT_SCAN
            break


def test_empty_engine():
    """Test engine with no registered detectors"""
    engine = ThreatDetectionEngine()
    
    packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
    
    result = engine.analyze_packet(packet)
    
    assert result is None
    
    stats = engine.get_statistics()
    assert stats["packets_analyzed"] == 1
    assert stats["threats_detected"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
