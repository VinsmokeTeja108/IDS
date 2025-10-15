"""Threat detection engine orchestrator"""

from typing import List, Optional
from scapy.packet import Packet

from ids.detectors.base_detector import ThreatDetector
from ids.models.data_models import ThreatEvent


class ThreatDetectionEngine:
    """
    Orchestrates multiple threat detectors to analyze network packets.
    
    The engine maintains a collection of detector modules and coordinates
    their execution on each packet. It manages detection state and returns
    threat events when threats are detected.
    """
    
    def __init__(self):
        """Initialize the threat detection engine."""
        self._detectors: List[ThreatDetector] = []
        self._packet_count = 0
        self._threat_count = 0
    
    def register_detector(self, detector: ThreatDetector) -> None:
        """
        Register a threat detector module.
        
        Args:
            detector: A ThreatDetector instance to add to the engine
        """
        if not isinstance(detector, ThreatDetector):
            raise TypeError(f"Detector must be an instance of ThreatDetector, got {type(detector)}")
        
        self._detectors.append(detector)
    
    def analyze_packet(self, packet: Packet) -> Optional[ThreatEvent]:
        """
        Analyze a packet using all registered detectors.
        
        Runs each detector on the packet and returns the first threat detected.
        If multiple threats are detected in a single packet, only the first
        is returned (detectors are run in registration order).
        
        Args:
            packet: The network packet to analyze
            
        Returns:
            ThreatEvent if a threat is detected by any detector, None otherwise
        """
        self._packet_count += 1
        
        # Run each detector on the packet
        for detector in self._detectors:
            try:
                threat_event = detector.detect(packet)
                
                if threat_event is not None:
                    self._threat_count += 1
                    return threat_event
                    
            except Exception as e:
                # Log error but continue with other detectors (graceful degradation)
                # In production, this should use proper logging
                print(f"Error in detector {detector.__class__.__name__}: {e}")
                continue
        
        return None
    
    def get_statistics(self) -> dict:
        """
        Get detection engine statistics.
        
        Returns:
            Dictionary containing packet count, threat count, and detector count
        """
        return {
            "packets_analyzed": self._packet_count,
            "threats_detected": self._threat_count,
            "registered_detectors": len(self._detectors),
            "detector_types": [detector.__class__.__name__ for detector in self._detectors]
        }
    
    def reset_statistics(self) -> None:
        """Reset packet and threat counters."""
        self._packet_count = 0
        self._threat_count = 0
