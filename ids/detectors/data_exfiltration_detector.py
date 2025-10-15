"""Data exfiltration detector implementation"""

from datetime import datetime, timedelta
from typing import Optional, Dict, List
from collections import defaultdict
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP

from ids.detectors.base_detector import ThreatDetector
from ids.models.data_models import ThreatEvent, ThreatType


class DataExfiltrationDetector(ThreatDetector):
    """
    Detects data exfiltration attempts by monitoring outbound traffic volume
    and identifying unusual large data transfers.
    
    Detection logic:
    - Monitors outbound traffic volume per destination
    - Tracks data transfer sizes over time windows
    - Triggers alert for suspicious outbound patterns exceeding thresholds
    """
    
    def __init__(self, threshold_bytes: int = 10485760, time_window: int = 60):
        """
        Initialize the data exfiltration detector.
        
        Args:
            threshold_bytes: Data volume threshold in bytes (default: 10MB)
            time_window: Time window in seconds for tracking transfers (default: 60)
        """
        self.threshold_bytes = threshold_bytes
        self.time_window = time_window
        
        # Track outbound data: {source_ip: {dest_ip: [(timestamp, bytes)]}}
        self.outbound_data: Dict[str, Dict[str, List[tuple]]] = defaultdict(lambda: defaultdict(list))
    
    def detect(self, packet: Packet) -> Optional[ThreatEvent]:
        """
        Analyze a packet for data exfiltration patterns.
        
        Args:
            packet: The network packet to analyze
            
        Returns:
            ThreatEvent if data exfiltration is detected, None otherwise
        """
        # Only process packets with IP layer
        if not packet.haslayer(IP):
            return None
        
        ip_layer = packet[IP]
        source_ip = ip_layer.src
        dest_ip = ip_layer.dst
        
        # Calculate packet size (payload size)
        packet_size = len(packet)
        
        current_time = datetime.now()
        
        # Track outbound data transfer
        self.outbound_data[source_ip][dest_ip].append((current_time, packet_size))
        
        # Clean up old entries outside the time window
        self._cleanup_old_entries(source_ip, dest_ip, current_time)
        
        # Calculate total bytes transferred to this destination
        total_bytes = sum(size for _, size in self.outbound_data[source_ip][dest_ip])
        
        # Check if threshold is exceeded
        if total_bytes >= self.threshold_bytes:
            # Data exfiltration detected
            transfer_count = len(self.outbound_data[source_ip][dest_ip])
            duration = self._calculate_duration(source_ip, dest_ip)
            
            # Determine protocol
            protocol = "Unknown"
            if packet.haslayer(TCP):
                protocol = "TCP"
            elif packet.haslayer(UDP):
                protocol = "UDP"
            
            threat_event = ThreatEvent(
                timestamp=current_time,
                threat_type=ThreatType.DATA_EXFILTRATION,
                source_ip=source_ip,
                destination_ip=dest_ip,
                protocol=protocol,
                raw_data={
                    "total_bytes": total_bytes,
                    "total_mb": round(total_bytes / (1024 * 1024), 2),
                    "transfer_count": transfer_count,
                    "duration_seconds": duration,
                    "time_window_seconds": self.time_window,
                    "threshold_bytes": self.threshold_bytes,
                    "threshold_mb": round(self.threshold_bytes / (1024 * 1024), 2),
                    "transfer_type": "Unusual large outbound data transfer"
                }
            )
            
            # Clear tracked data for this source-destination pair to avoid duplicate alerts
            self._clear_destination_data(source_ip, dest_ip)
            
            return threat_event
        
        return None
    
    def _cleanup_old_entries(self, source_ip: str, dest_ip: str, current_time: datetime) -> None:
        """
        Remove entries older than the time window.
        
        Args:
            source_ip: Source IP address to clean up
            dest_ip: Destination IP address to clean up
            current_time: Current timestamp
        """
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        
        # Remove old transfer records
        if source_ip in self.outbound_data and dest_ip in self.outbound_data[source_ip]:
            self.outbound_data[source_ip][dest_ip] = [
                (timestamp, size) for timestamp, size in self.outbound_data[source_ip][dest_ip]
                if timestamp >= cutoff_time
            ]
    
    def _calculate_duration(self, source_ip: str, dest_ip: str) -> float:
        """
        Calculate the duration of the data transfer in seconds.
        
        Args:
            source_ip: Source IP address
            dest_ip: Destination IP address
            
        Returns:
            Duration in seconds
        """
        if source_ip not in self.outbound_data or dest_ip not in self.outbound_data[source_ip]:
            return 0.0
        
        transfers = self.outbound_data[source_ip][dest_ip]
        if not transfers:
            return 0.0
        
        timestamps = [timestamp for timestamp, _ in transfers]
        duration = (max(timestamps) - min(timestamps)).total_seconds()
        return round(duration, 2)
    
    def _clear_destination_data(self, source_ip: str, dest_ip: str) -> None:
        """
        Clear tracked data for a source-destination pair after alert is triggered.
        
        Args:
            source_ip: Source IP address to clear
            dest_ip: Destination IP address to clear
        """
        if source_ip in self.outbound_data and dest_ip in self.outbound_data[source_ip]:
            del self.outbound_data[source_ip][dest_ip]
