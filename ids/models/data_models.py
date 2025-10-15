"""Core data models for threat detection and analysis"""

from enum import Enum
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any, Optional


class ThreatType(Enum):
    """Enumeration of threat types that can be detected"""
    PORT_SCAN = "port_scan"
    ICMP_SCAN = "icmp_scan"
    MALWARE = "malware"
    BRUTE_FORCE = "brute_force"
    ATTACKER_IDENTIFIED = "attacker_identified"
    DATA_EXFILTRATION = "data_exfiltration"


class SeverityLevel(Enum):
    """Enumeration of threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatEvent:
    """Represents a detected threat event"""
    timestamp: datetime
    threat_type: ThreatType
    source_ip: str
    destination_ip: Optional[str]
    protocol: str
    raw_data: Dict[str, Any]


@dataclass
class ThreatAnalysis:
    """Represents the analysis of a threat event"""
    threat_event: ThreatEvent
    severity: SeverityLevel
    classification: str
    description: str
    recommendations: List[str]
    justification: str


@dataclass
class Config:
    """System configuration"""
    email_config: Dict[str, Any]
    detection_config: Dict[str, Any]
    logging_config: Dict[str, Any]
    notification_config: Dict[str, Any]
