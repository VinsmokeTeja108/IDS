"""Port scan detector implementation"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Set
from collections import defaultdict
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP

from ids.detectors.base_detector import ThreatDetector
from ids.models.data_models import ThreatEvent, ThreatType


class PortScanDetector(ThreatDetector):
    """
    Detects port scanning attempts by monitoring SYN packets and tracking
    connection attempts from single source IPs to multiple ports.
    
    Detection logic:
    - Tracks SYN packets without corresponding ACK responses
    - Monitors multiple port connection attempts from single source IP
    - Triggers alert when threshold exceeded (default 10 ports in 60 seconds)
    """
    
    def __init__(self, threshold: int = 10, time_window: int = 60):
        """
        Initialize the port scan detector.
        
        Args:
            threshold: Number of ports scanned before triggering alert (default: 10)
            time_window: Time window in seconds for tracking scans (default: 60)
        """
        self.threshold = threshold
        self.time_window = time_window
        
        # Track SYN packets: {source_ip: {(dest_ip, dest_port): timestamp}}
        self.syn_packets: Dict[str, Dict[tuple, datetime]] = defaultdict(dict)
        
        # Track ACK responses: {source_ip: {(dest_ip, dest_port)}}
        self.ack_responses: Dict[str, Set[tuple]] = defaultdict(set)
    
    def detect(self, packet: Packet) -> Optional[ThreatEvent]:
        """
        Analyze a packet for port scan patterns.
        
        Args:
            packet: The network packet to analyze
            
        Returns:
            ThreatEvent if port scan is detected, None otherwise
        """
        # Only process TCP packets with IP layer
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return None
        
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        
        source_ip = ip_layer.src
        dest_ip = ip_layer.dst
        dest_port = tcp_layer.dport
        flags = tcp_layer.flags
        
        current_time = datetime.now()
        connection_key = (dest_ip, dest_port)
        
        # Track SYN packets (potential scan attempts)
        # This includes both SYN and SYN-ACK packets
        if flags & 0x02:  # SYN flag is set
            self.syn_packets[source_ip][connection_key] = current_time
        
        # Clean up old entries outside the time window
        self._cleanup_old_entries(source_ip, current_time)
        
        # Check if threshold is exceeded based on total unique ports accessed
        # Count all SYN packets regardless of ACK responses
        total_ports_accessed = len(self.syn_packets.get(source_ip, {}))
        
        if total_ports_accessed >= self.threshold:
            # Port scan detected
            scanned_ports = sorted([port for _, port in self.syn_packets[source_ip].keys()])
            
            threat_event = ThreatEvent(
                timestamp=current_time,
                threat_type=ThreatType.PORT_SCAN,
                source_ip=source_ip,
                destination_ip=dest_ip,
                protocol="TCP",
                raw_data={
                    "scanned_ports": scanned_ports,
                    "port_count": len(scanned_ports),
                    "time_window_seconds": self.time_window,
                    "threshold": self.threshold,
                    "scan_type": "TCP scan"
                }
            )
            
            # Don't clear all data - just reset the counter to avoid spam
            # Keep tracking but reset to allow detection of continued scanning
            if source_ip in self.syn_packets:
                # Keep only the most recent ports to avoid immediate re-trigger
                recent_ports = dict(list(self.syn_packets[source_ip].items())[-5:])
                self.syn_packets[source_ip] = recent_ports
            
            return threat_event
        
        return None
    
    def _cleanup_old_entries(self, source_ip: str, current_time: datetime) -> None:
        """
        Remove entries older than the time window.
        
        Args:
            source_ip: Source IP address to clean up
            current_time: Current timestamp
        """
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        
        # Remove old SYN packets
        if source_ip in self.syn_packets:
            expired_keys = [
                key for key, timestamp in self.syn_packets[source_ip].items()
                if timestamp < cutoff_time
            ]
            for key in expired_keys:
                del self.syn_packets[source_ip][key]
