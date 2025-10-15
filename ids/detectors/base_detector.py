"""Abstract base class for threat detectors"""

from abc import ABC, abstractmethod
from typing import Optional
from scapy.packet import Packet
from ids.models.data_models import ThreatEvent


class ThreatDetector(ABC):
    """
    Abstract base class for all threat detectors.
    
    Each detector implementation must define the detect() method to analyze
    packets and identify specific threat patterns.
    """
    
    @abstractmethod
    def detect(self, packet: Packet) -> Optional[ThreatEvent]:
        """
        Analyze a packet and detect potential threats.
        
        Args:
            packet: The network packet to analyze
            
        Returns:
            ThreatEvent if a threat is detected, None otherwise
        """
        pass
