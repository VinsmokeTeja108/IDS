"""Test suite for AttackerIdentifier"""

import unittest
from datetime import datetime, timedelta
from ids.detectors.attacker_identifier import AttackerIdentifier
from ids.models.data_models import ThreatEvent, ThreatType


class TestAttackerIdentifier(unittest.TestCase):
    """Test cases for the AttackerIdentifier class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.identifier = AttackerIdentifier(threshold=2, time_window=300)
    
    def test_single_threat_type_no_alert(self):
        """Test that a single threat type doesn't trigger attacker identification"""
        threat_event = ThreatEvent(
            timestamp=datetime.now(),
            threat_type=ThreatType.PORT_SCAN,
            source_ip="192.168.1.100",
            destination_ip="10.0.0.5",
            protocol="TCP",
            raw_data={"scanned_ports": [80, 443, 22]}
        )
        
        result = self.identifier.record_threat_event(threat_event)
        self.assertIsNone(result)
    
    def test_multiple_threat_types_triggers_alert(self):
        """Test that multiple threat types from same IP triggers attacker identification"""
        source_ip = "192.168.1.100"
        
        # First threat: Port scan
        threat1 = ThreatEvent(
            timestamp=datetime.now(),
            threat_type=ThreatType.PORT_SCAN,
            source_ip=source_ip,
            destination_ip="10.0.0.5",
            protocol="TCP",
            raw_data={"scanned_ports": [80, 443, 22]}
        )
        
        result1 = self.identifier.record_threat_event(threat1)
        self.assertIsNone(result1)
        
        # Second threat: ICMP scan
        threat2 = ThreatEvent(
            timestamp=datetime.now(),
            threat_type=ThreatType.ICMP_SCAN,
            source_ip=source_ip,
            destination_ip=None,
            protocol="ICMP",
            raw_data={"scanned_hosts": ["10.0.0.1", "10.0.0.2"]}
        )
        
        result2 = self.identifier.record_threat_event(threat2)
        self.assertIsNotNone(result2)
        self.assertEqual(result2.threat_type, ThreatType.ATTACKER_IDENTIFIED)
        self.assertEqual(result2.source_ip, source_ip)
        self.assertEqual(len(result2.raw_data["threat_types"]), 2)
        self.assertIn("port_scan", result2.raw_data["threat_types"])
        self.assertIn("icmp_scan", result2.raw_data["threat_types"])
    
    def test_three_threat_types_triggers_alert(self):
        """Test that three different threat types triggers attacker identification"""
        source_ip = "192.168.1.200"
        
        threats = [
            ThreatEvent(
                timestamp=datetime.now(),
                threat_type=ThreatType.PORT_SCAN,
                source_ip=source_ip,
                destination_ip="10.0.0.5",
                protocol="TCP",
                raw_data={}
            ),
            ThreatEvent(
                timestamp=datetime.now(),
                threat_type=ThreatType.BRUTE_FORCE,
                source_ip=source_ip,
                destination_ip="10.0.0.5",
                protocol="TCP",
                raw_data={}
            ),
            ThreatEvent(
                timestamp=datetime.now(),
                threat_type=ThreatType.MALWARE,
                source_ip=source_ip,
                destination_ip="10.0.0.5",
                protocol="TCP",
                raw_data={}
            )
        ]
        
        result1 = self.identifier.record_threat_event(threats[0])
        self.assertIsNone(result1)
        
        result2 = self.identifier.record_threat_event(threats[1])
        self.assertIsNotNone(result2)
        self.assertEqual(result2.threat_type, ThreatType.ATTACKER_IDENTIFIED)
        self.assertEqual(len(result2.raw_data["threat_types"]), 2)
    
    def test_duplicate_threat_type_no_alert(self):
        """Test that duplicate threat types don't count as multiple indicators"""
        source_ip = "192.168.1.150"
        
        # Two port scans from same IP
        threat1 = ThreatEvent(
            timestamp=datetime.now(),
            threat_type=ThreatType.PORT_SCAN,
            source_ip=source_ip,
            destination_ip="10.0.0.5",
            protocol="TCP",
            raw_data={}
        )
        
        threat2 = ThreatEvent(
            timestamp=datetime.now(),
            threat_type=ThreatType.PORT_SCAN,
            source_ip=source_ip,
            destination_ip="10.0.0.6",
            protocol="TCP",
            raw_data={}
        )
        
        result1 = self.identifier.record_threat_event(threat1)
        self.assertIsNone(result1)
        
        result2 = self.identifier.record_threat_event(threat2)
        self.assertIsNone(result2)
    
    def test_no_duplicate_alerts_for_same_ip(self):
        """Test that once an IP is identified, no duplicate alerts are generated"""
        source_ip = "192.168.1.100"
        
        # First two threats trigger alert
        threat1 = ThreatEvent(
            timestamp=datetime.now(),
            threat_type=ThreatType.PORT_SCAN,
            source_ip=source_ip,
            destination_ip="10.0.0.5",
            protocol="TCP",
            raw_data={}
        )
        
        threat2 = ThreatEvent(
            timestamp=datetime.now(),
            threat_type=ThreatType.ICMP_SCAN,
            source_ip=source_ip,
            destination_ip=None,
            protocol="ICMP",
            raw_data={}
        )
        
        self.identifier.record_threat_event(threat1)
        result = self.identifier.record_threat_event(threat2)
        self.assertIsNotNone(result)
        
        # Third threat should not trigger another alert
        threat3 = ThreatEvent(
            timestamp=datetime.now(),
            threat_type=ThreatType.MALWARE,
            source_ip=source_ip,
            destination_ip="10.0.0.5",
            protocol="TCP",
            raw_data={}
        )
        
        result2 = self.identifier.record_threat_event(threat3)
        self.assertIsNone(result2)
    
    def test_different_ips_tracked_separately(self):
        """Test that different source IPs are tracked independently"""
        # IP 1 with one threat
        threat1 = ThreatEvent(
            timestamp=datetime.now(),
            threat_type=ThreatType.PORT_SCAN,
            source_ip="192.168.1.100",
            destination_ip="10.0.0.5",
            protocol="TCP",
            raw_data={}
        )
        
        # IP 2 with two threats
        threat2 = ThreatEvent(
            timestamp=datetime.now(),
            threat_type=ThreatType.PORT_SCAN,
            source_ip="192.168.1.200",
            destination_ip="10.0.0.5",
            protocol="TCP",
            raw_data={}
        )
        
        threat3 = ThreatEvent(
            timestamp=datetime.now(),
            threat_type=ThreatType.ICMP_SCAN,
            source_ip="192.168.1.200",
            destination_ip=None,
            protocol="ICMP",
            raw_data={}
        )
        
        result1 = self.identifier.record_threat_event(threat1)
        self.assertIsNone(result1)
        
        result2 = self.identifier.record_threat_event(threat2)
        self.assertIsNone(result2)
        
        result3 = self.identifier.record_threat_event(threat3)
        self.assertIsNotNone(result3)
        self.assertEqual(result3.source_ip, "192.168.1.200")
    
    def test_threat_summary_includes_counts(self):
        """Test that threat summary includes correct counts for each threat type"""
        source_ip = "192.168.1.100"
        
        # Multiple port scans and one ICMP scan
        for _ in range(3):
            threat = ThreatEvent(
                timestamp=datetime.now(),
                threat_type=ThreatType.PORT_SCAN,
                source_ip=source_ip,
                destination_ip="10.0.0.5",
                protocol="TCP",
                raw_data={}
            )
            self.identifier.record_threat_event(threat)
        
        threat_icmp = ThreatEvent(
            timestamp=datetime.now(),
            threat_type=ThreatType.ICMP_SCAN,
            source_ip=source_ip,
            destination_ip=None,
            protocol="ICMP",
            raw_data={}
        )
        
        result = self.identifier.record_threat_event(threat_icmp)
        self.assertIsNotNone(result)
        self.assertEqual(result.raw_data["threat_count"], 4)
        self.assertEqual(result.raw_data["threat_details"]["port_scan"], 3)
        self.assertEqual(result.raw_data["threat_details"]["icmp_scan"], 1)
    
    def test_attacker_identified_events_ignored(self):
        """Test that ATTACKER_IDENTIFIED events are not recorded"""
        source_ip = "192.168.1.100"
        
        threat = ThreatEvent(
            timestamp=datetime.now(),
            threat_type=ThreatType.ATTACKER_IDENTIFIED,
            source_ip=source_ip,
            destination_ip=None,
            protocol="Multiple",
            raw_data={}
        )
        
        result = self.identifier.record_threat_event(threat)
        self.assertIsNone(result)
        
        # Verify it wasn't recorded
        unique_threats = self.identifier._get_unique_threat_types(source_ip)
        self.assertEqual(len(unique_threats), 0)


if __name__ == '__main__':
    unittest.main()

