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
        if flags & 0x02:  # SYN flag is set
            self.syn_packets[source_ip][connection_key] = current_time
        
        # Track ACK responses (successful connections)
        if flags & 0x10:  # ACK flag is set
            self.ack_responses[source_ip].add(connection_key)
        
        # Clean up old entries outside the time window
        self._cleanup_old_entries(source_ip, current_time)
        
        # Check if threshold is exceeded
        unanswered_syns = self._get_unanswered_syns(source_ip)
        
        if len(unanswered_syns) >= self.threshold:
            # Port scan detected
            scanned_ports = sorted([port for _, port in unanswered_syns])
            
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
                    "scan_type": "SYN scan"
                }
            )
            
            # Clear tracked data for this source to avoid duplicate alerts
            self._clear_source_data(source_ip)
            
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
    
    def _get_unanswered_syns(self, source_ip: str) -> Set[tuple]:
        """
        Get SYN packets without corresponding ACK responses.
        
        Args:
            source_ip: Source IP address to check
            
        Returns:
            Set of (dest_ip, dest_port) tuples for unanswered SYNs
        """
        if source_ip not in self.syn_packets:
            return set()
        
        all_syns = set(self.syn_packets[source_ip].keys())
        acks = self.ack_responses.get(source_ip, set())
        
        # Return SYNs that don't have corresponding ACKs
        return all_syns - acks
    
    def _clear_source_data(self, source_ip: str) -> None:
        """
        Clear all tracked data for a source IP after alert is triggered.
        
        Args:
            source_ip: Source IP address to clear
        """
        if source_ip in self.syn_packets:
            del self.syn_packets[source_ip]
        if source_ip in self.ack_responses:
            del self.ack_responses[source_ip]
