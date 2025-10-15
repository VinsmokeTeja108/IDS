"""Attacker identifier implementation"""

from datetime import datetime, timedelta
from typing import Optional, Dict, List, Set
from collections import defaultdict
from scapy.packet import Packet

from ids.detectors.base_detector import ThreatDetector
from ids.models.data_models import ThreatEvent, ThreatType


class AttackerIdentifier(ThreatDetector):
    """
    Identifies potential attackers by aggregating threat events from the same source IP.
    
    Detection logic:
    - Aggregates threat events by source IP address
    - Identifies IPs with multiple threat indicators
    - Generates alert when multiple threat types are detected from same source
    """
    
    def __init__(self, threshold: int = 2, time_window: int = 300):
        """
        Initialize the attacker identifier.
        
        Args:
            threshold: Number of different threat types before identifying as attacker (default: 2)
            time_window: Time window in seconds for aggregating threats (default: 300 = 5 minutes)
        """
        self.threshold = threshold
        self.time_window = time_window
        
        # Track threat events by source IP: {source_ip: [(threat_type, timestamp)]}
        self.threat_history: Dict[str, List[tuple]] = defaultdict(list)
        
        # Track which IPs have already been identified as attackers to avoid duplicate alerts
        self.identified_attackers: Set[str] = set()
    
    def detect(self, packet: Packet) -> Optional[ThreatEvent]:
        """
        This detector doesn't analyze individual packets directly.
        Instead, it should be called with threat events from other detectors.
        
        Args:
            packet: The network packet (not used by this detector)
            
        Returns:
            None (use record_threat_event method instead)
        """
        return None
    
    def record_threat_event(self, threat_event: ThreatEvent) -> Optional[ThreatEvent]:
        """
        Record a threat event and check if the source IP should be identified as an attacker.
        
        Args:
            threat_event: A threat event detected by another detector
            
        Returns:
            ThreatEvent with ATTACKER_IDENTIFIED type if threshold is met, None otherwise
        """
        source_ip = threat_event.source_ip
        threat_type = threat_event.threat_type
        current_time = datetime.now()
        
        # Skip if this IP is already identified as an attacker
        if source_ip in self.identified_attackers:
            return None
        
        # Skip if this is already an attacker identification event
        if threat_type == ThreatType.ATTACKER_IDENTIFIED:
            return None
        
        # Record this threat event
        self.threat_history[source_ip].append((threat_type, current_time))
        
        # Clean up old entries outside the time window
        self._cleanup_old_entries(source_ip, current_time)
        
        # Get unique threat types within the time window
        unique_threats = self._get_unique_threat_types(source_ip)
        
        # Check if threshold is exceeded
        if len(unique_threats) >= self.threshold:
            # Attacker identified
            threat_details = self._get_threat_summary(source_ip)
            
            attacker_event = ThreatEvent(
                timestamp=current_time,
                threat_type=ThreatType.ATTACKER_IDENTIFIED,
                source_ip=source_ip,
                destination_ip=None,  # Multiple potential destinations
                protocol="Multiple",
                raw_data={
                    "threat_types": [t.value for t in unique_threats],
                    "threat_count": len(self.threat_history[source_ip]),
                    "unique_threat_types": len(unique_threats),
                    "time_window_seconds": self.time_window,
                    "threshold": self.threshold,
                    "threat_details": threat_details
                }
            )
            
            # Mark this IP as identified to avoid duplicate alerts
            self.identified_attackers.add(source_ip)
            
            return attacker_event
        
        return None
    
    def _cleanup_old_entries(self, source_ip: str, current_time: datetime) -> None:
        """
        Remove entries older than the time window.
        
        Args:
            source_ip: Source IP address to clean up
            current_time: Current timestamp
        """
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        
        if source_ip in self.threat_history:
            # Keep only recent threats
            self.threat_history[source_ip] = [
                (threat_type, timestamp)
                for threat_type, timestamp in self.threat_history[source_ip]
                if timestamp >= cutoff_time
            ]
            
            # Remove empty entries
            if not self.threat_history[source_ip]:
                del self.threat_history[source_ip]
                # Also remove from identified attackers if no recent activity
                self.identified_attackers.discard(source_ip)
    
    def _get_unique_threat_types(self, source_ip: str) -> Set[ThreatType]:
        """
        Get unique threat types for a source IP.
        
        Args:
            source_ip: Source IP address to check
            
        Returns:
            Set of unique ThreatType values
        """
        if source_ip not in self.threat_history:
            return set()
        
        return {threat_type for threat_type, _ in self.threat_history[source_ip]}
    
    def _get_threat_summary(self, source_ip: str) -> Dict[str, int]:
        """
        Get a summary of threat types and their counts for a source IP.
        
        Args:
            source_ip: Source IP address to summarize
            
        Returns:
            Dictionary mapping threat type names to counts
        """
        if source_ip not in self.threat_history:
            return {}
        
        summary = defaultdict(int)
        for threat_type, _ in self.threat_history[source_ip]:
            summary[threat_type.value] += 1
        
        return dict(summary)

