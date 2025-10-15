"""ICMP scan detector implementation"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Set
from collections import defaultdict
from scapy.packet import Packet
from scapy.layers.inet import IP, ICMP

from ids.detectors.base_detector import ThreatDetector
from ids.models.data_models import ThreatEvent, ThreatType


class ICMPScanDetector(ThreatDetector):
    """
    Detects ICMP scan/ping sweep attempts by monitoring ICMP echo request packets
    and tracking requests to multiple destination hosts from a single source.
    
    Detection logic:
    - Monitors ICMP echo request packets (type 8)
    - Tracks ICMP requests to multiple destination hosts from single source IP
    - Triggers alert when threshold exceeded (default 5 hosts in 30 seconds)
    """
    
    def __init__(self, threshold: int = 5, time_window: int = 30):
        """
        Initialize the ICMP scan detector.
        
        Args:
            threshold: Number of hosts scanned before triggering alert (default: 5)
            time_window: Time window in seconds for tracking scans (default: 30)
        """
        self.threshold = threshold
        self.time_window = time_window
        
        # Track ICMP echo requests: {source_ip: {dest_ip: timestamp}}
        self.icmp_requests: Dict[str, Dict[str, datetime]] = defaultdict(dict)
    
    def detect(self, packet: Packet) -> Optional[ThreatEvent]:
        """
        Analyze a packet for ICMP scan patterns.
        
        Args:
            packet: The network packet to analyze
            
        Returns:
            ThreatEvent if ICMP scan is detected, None otherwise
        """
        # Only process ICMP packets with IP layer
        if not packet.haslayer(ICMP) or not packet.haslayer(IP):
            return None
        
        ip_layer = packet[IP]
        icmp_layer = packet[ICMP]
        
        # Only track ICMP echo requests (type 8)
        if icmp_layer.type != 8:
            return None
        
        source_ip = ip_layer.src
        dest_ip = ip_layer.dst
        current_time = datetime.now()
        
        # Track this ICMP request
        self.icmp_requests[source_ip][dest_ip] = current_time
        
        # Clean up old entries outside the time window
        self._cleanup_old_entries(source_ip, current_time)
        
        # Check if threshold is exceeded
        scanned_hosts = set(self.icmp_requests[source_ip].keys())
        
        if len(scanned_hosts) >= self.threshold:
            # ICMP scan detected
            threat_event = ThreatEvent(
                timestamp=current_time,
                threat_type=ThreatType.ICMP_SCAN,
                source_ip=source_ip,
                destination_ip=None,  # Multiple destinations
                protocol="ICMP",
                raw_data={
                    "scanned_hosts": sorted(list(scanned_hosts)),
                    "host_count": len(scanned_hosts),
                    "time_window_seconds": self.time_window,
                    "threshold": self.threshold,
                    "scan_type": "ICMP ping sweep"
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
        
        # Remove old ICMP requests
        if source_ip in self.icmp_requests:
            expired_hosts = [
                dest_ip for dest_ip, timestamp in self.icmp_requests[source_ip].items()
                if timestamp < cutoff_time
            ]
            for dest_ip in expired_hosts:
                del self.icmp_requests[source_ip][dest_ip]
    
    def _clear_source_data(self, source_ip: str) -> None:
        """
        Clear all tracked data for a source IP after alert is triggered.
        
        Args:
            source_ip: Source IP address to clear
        """
        if source_ip in self.icmp_requests:
            del self.icmp_requests[source_ip]
