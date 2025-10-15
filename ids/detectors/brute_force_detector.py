"""Brute force attack detector implementation"""

from datetime import datetime, timedelta
from typing import Optional, Dict, List
from collections import defaultdict
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP

from ids.detectors.base_detector import ThreatDetector
from ids.models.data_models import ThreatEvent, ThreatType


class BruteForceDetector(ThreatDetector):
    """
    Detects brute force authentication attempts by monitoring TCP RST packets
    on common authentication ports (SSH, RDP, FTP).
    
    Detection logic:
    - Monitors TCP RST packets on common auth ports: 22 (SSH), 3389 (RDP), 21 (FTP)
    - Tracks failed authentication attempts per source IP
    - Triggers alert when threshold exceeded (default 5 attempts in 60 seconds)
    """
    
    # Common authentication ports to monitor
    AUTH_PORTS = {22, 3389, 21}  # SSH, RDP, FTP
    
    def __init__(self, threshold: int = 5, time_window: int = 60):
        """
        Initialize the brute force detector.
        
        Args:
            threshold: Number of failed attempts before triggering alert (default: 5)
            time_window: Time window in seconds for tracking attempts (default: 60)
        """
        self.threshold = threshold
        self.time_window = time_window
        
        # Track failed attempts: {source_ip: [(timestamp, dest_ip, dest_port)]}
        self.failed_attempts: Dict[str, List[tuple]] = defaultdict(list)
    
    def detect(self, packet: Packet) -> Optional[ThreatEvent]:
        """
        Analyze a packet for brute force attack patterns.
        
        Args:
            packet: The network packet to analyze
            
        Returns:
            ThreatEvent if brute force attack is detected, None otherwise
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
        
        # Only track RST packets on authentication ports
        # RST flag indicates connection reset (failed authentication)
        if not (flags & 0x04) or dest_port not in self.AUTH_PORTS:  # RST flag
            return None
        
        current_time = datetime.now()
        
        # Track this failed attempt
        self.failed_attempts[source_ip].append((current_time, dest_ip, dest_port))
        
        # Clean up old entries outside the time window
        self._cleanup_old_entries(source_ip, current_time)
        
        # Check if threshold is exceeded
        attempt_count = len(self.failed_attempts[source_ip])
        
        if attempt_count >= self.threshold:
            # Brute force attack detected
            attempts = self.failed_attempts[source_ip]
            
            # Gather details about the attempts
            targeted_ports = sorted(set(port for _, _, port in attempts))
            targeted_hosts = sorted(set(host for _, host, _ in attempts))
            
            # Determine service type based on ports
            services = []
            if 22 in targeted_ports:
                services.append("SSH")
            if 3389 in targeted_ports:
                services.append("RDP")
            if 21 in targeted_ports:
                services.append("FTP")
            
            threat_event = ThreatEvent(
                timestamp=current_time,
                threat_type=ThreatType.BRUTE_FORCE,
                source_ip=source_ip,
                destination_ip=targeted_hosts[0] if len(targeted_hosts) == 1 else None,
                protocol="TCP",
                raw_data={
                    "attempt_count": attempt_count,
                    "targeted_ports": targeted_ports,
                    "targeted_hosts": targeted_hosts,
                    "services": services,
                    "time_window_seconds": self.time_window,
                    "threshold": self.threshold,
                    "attack_type": "Brute force authentication"
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
        
        # Remove old failed attempts
        if source_ip in self.failed_attempts:
            self.failed_attempts[source_ip] = [
                attempt for attempt in self.failed_attempts[source_ip]
                if attempt[0] >= cutoff_time
            ]
    
    def _clear_source_data(self, source_ip: str) -> None:
        """
        Clear all tracked data for a source IP after alert is triggered.
        
        Args:
            source_ip: Source IP address to clear
        """
        if source_ip in self.failed_attempts:
            del self.failed_attempts[source_ip]
