"""ICMP scan detector — only detects inbound pings directed at THIS machine."""

import socket
import time
from datetime import datetime, timedelta
from typing import Optional, Dict
from collections import defaultdict
from scapy.packet import Packet
from scapy.layers.inet import IP, ICMP

from ids.detectors.base_detector import ThreatDetector
from ids.models.data_models import ThreatEvent, ThreatType


_LOCAL_IPS_CACHE = set()
_LOCAL_IPS_LAST_UPDATE = 0

def _get_current_local_ips() -> set:
    global _LOCAL_IPS_CACHE, _LOCAL_IPS_LAST_UPDATE
    current_time = time.time()
    if current_time - _LOCAL_IPS_LAST_UPDATE < 60 and _LOCAL_IPS_CACHE:
        return _LOCAL_IPS_CACHE
        
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if ':' not in addr:
                ips.add(addr)
    except Exception:
        pass
    ips.add('127.0.0.1')
    
    _LOCAL_IPS_CACHE = ips
    _LOCAL_IPS_LAST_UPDATE = current_time
    return ips


class ICMPScanDetector(ThreatDetector):
    """
    Detects ICMP ping sweeps directed AT this machine.
    
    An ICMP scan = same source sending many ICMP echo requests to OUR IP
    in a short time window (e.g. repeated pings to check if we're reachable).
    Outgoing pings FROM this machine are ignored.
    """

    def __init__(self, threshold: int = 10, time_window: int = 30):
        """
        Args:
            threshold: ICMP echo requests from same source before alert (default 10).
            time_window: Seconds for tracking window (default 30).
        """
        self.threshold = threshold
        self.time_window = time_window
        # {source_ip: [timestamps]}
        self.icmp_requests: Dict[str, list] = defaultdict(list)

    def detect(self, packet: Packet) -> Optional[ThreatEvent]:
        if not packet.haslayer(ICMP) or not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        icmp_layer = packet[ICMP]

        # Only echo requests (type 8)
        if icmp_layer.type != 8:
            return None

        source_ip = ip_layer.src
        dest_ip = ip_layer.dst
        current_time = datetime.now()

        # Only count pings TO our machine from external sources
        local_ips = _get_current_local_ips()
        if dest_ip not in local_ips:
            return None
        if source_ip in local_ips:
            return None

        # Track this request
        self.icmp_requests[source_ip].append(current_time)

        # Clean up old entries
        self._cleanup_old_entries(source_ip, current_time)

        count = len(self.icmp_requests[source_ip])

        if count >= self.threshold:
            threat_event = ThreatEvent(
                timestamp=current_time,
                threat_type=ThreatType.ICMP_SCAN,
                source_ip=source_ip,
                destination_ip=dest_ip,
                protocol="ICMP",
                raw_data={
                    "request_count": count,
                    "time_window_seconds": self.time_window,
                    "threshold": self.threshold,
                    "scan_type": "ICMP ping flood / sweep"
                }
            )
            # Reset to avoid immediate re-alert
            self.icmp_requests[source_ip] = []
            return threat_event

        return None

    def _cleanup_old_entries(self, source_ip: str, current_time: datetime) -> None:
        cutoff = current_time - timedelta(seconds=self.time_window)
        if source_ip in self.icmp_requests:
            self.icmp_requests[source_ip] = [
                ts for ts in self.icmp_requests[source_ip] if ts >= cutoff
            ]
