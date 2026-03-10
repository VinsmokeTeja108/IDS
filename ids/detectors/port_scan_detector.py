"""Port scan detector implementation - Enhanced for all nmap scan types.

Only detects INBOUND scans directed at THIS machine.
Outgoing connections from our machine are NOT counted as attacks.
"""

import socket
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Set, List
from collections import defaultdict
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP

from ids.detectors.base_detector import ThreatDetector
from ids.models.data_models import ThreatEvent, ThreatType


_LOCAL_IPS_CACHE = set()
_LOCAL_IPS_LAST_UPDATE = 0

def _get_current_local_ips() -> set:
    """Return set of all IP addresses belonging to this machine, cached for 60s."""
    global _LOCAL_IPS_CACHE, _LOCAL_IPS_LAST_UPDATE
    current_time = time.time()
    if current_time - _LOCAL_IPS_LAST_UPDATE < 60 and _LOCAL_IPS_CACHE:
        return _LOCAL_IPS_CACHE
        
    ips = set()
    try:
        # Primary outbound IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        # All IPs this hostname resolves to
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if ':' not in addr:  # IPv4 only
                ips.add(addr)
    except Exception:
        pass
    ips.add('127.0.0.1')
    
    _LOCAL_IPS_CACHE = ips
    _LOCAL_IPS_LAST_UPDATE = current_time
    return ips


class PortScanDetector(ThreatDetector):
    """
    Enhanced port scan detector that identifies various nmap scan techniques.

    Only triggers on packets arriving AT THIS MACHINE (destination = our IP).
    Normal outgoing connections from our machine are ignored entirely.

    Detection logic:
    - TCP SYN, FIN, NULL, XMAS, ACK scans
    - UDP scans
    - Multiple different ports from the same source → alert
    - Triggers when threshold exceeded (default 10 unique ports in 60 seconds)
    """

    def __init__(self, threshold: int = 10, time_window: int = 60):
        """
        Args:
            threshold: Unique destination ports before triggering (default 10).
            time_window: Seconds for tracking window (default 60).
        """
        self.threshold = threshold
        self.time_window = time_window

        # {source_ip: {dest_port: (timestamp, scan_type)}} — only for inbound
        self.connection_attempts: Dict[str, Dict[int, tuple]] = defaultdict(dict)
        self.scan_patterns: Dict[str, List[str]] = defaultdict(list)

    def detect(self, packet: Packet) -> Optional[ThreatEvent]:
        """Analyse a packet for port scan patterns. Only inbound traffic counted."""
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        source_ip = ip_layer.src
        dest_ip = ip_layer.dst
        current_time = datetime.now()

        # ── KEY FILTER ──────────────────────────────────────────────────────
        # Only track packets coming INTO our machine.
        # Ignore: our own outgoing traffic AND loopback AND packets not for us.
        local_ips = _get_current_local_ips()
        
        # --- DEBUG LOGGING ---
        try:
            with open(r"d:\IDS\scan_debug.log", "a") as f:
                if dest_ip not in local_ips:
                    f.write(f"[{current_time}] DROP NOT_FOR_US: src={source_ip} dst={dest_ip} (local_ips={local_ips})\n")
                    return None
                if source_ip in local_ips:
                    f.write(f"[{current_time}] DROP OUTGOING/LOCAL: src={source_ip} dst={dest_ip}\n")
                    return None
        except Exception:
            pass
        # ---------------------

        if dest_ip not in local_ips:
            return None
        if source_ip in local_ips:
            return None   # Loopback / local traffic
        # ────────────────────────────────────────────────────────────────────

        scan_type = None
        dest_port = None
        protocol = None

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            dest_port = tcp_layer.dport
            flags = int(tcp_layer.flags)
            protocol = "TCP"

            if flags & 0x02 and not (flags & 0x10):  # SYN only
                scan_type = "TCP SYN scan"
            elif flags & 0x01 and not (flags & 0x02):  # FIN only
                scan_type = "TCP FIN scan (stealth)"
            elif flags == 0:  # NULL scan
                scan_type = "TCP NULL scan (stealth)"
            elif (flags & 0x29) == 0x29:  # FIN+PSH+URG
                scan_type = "TCP XMAS scan (stealth)"
            elif flags & 0x10 and not (flags & 0x02):  # ACK only
                scan_type = "TCP ACK scan"
            else:
                scan_type = "TCP scan"

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            dest_port = udp_layer.dport
            protocol = "UDP"
            scan_type = "UDP scan"

        if scan_type is None or dest_port is None:
            return None

        # Track this attempt
        self.connection_attempts[source_ip][dest_port] = (current_time, scan_type)
        self.scan_patterns[source_ip].append(scan_type)

        # Remove stale entries
        self._cleanup_old_entries(source_ip, current_time)

        total_ports = len(self.connection_attempts.get(source_ip, {}))

        if total_ports >= self.threshold:
            attempts = self.connection_attempts[source_ip]
            scanned_ports = sorted(attempts.keys())
            protocols_used = {protocol}
            scan_types_used = list(set(self.scan_patterns.get(source_ip, [])))

            primary_scan_type = (
                max(set(scan_types_used), key=scan_types_used.count)
                if scan_types_used else "Unknown scan"
            )
            is_stealth = any("stealth" in st.lower() for st in scan_types_used)

            threat_event = ThreatEvent(
                timestamp=current_time,
                threat_type=ThreatType.PORT_SCAN,
                source_ip=source_ip,      # Attacker
                destination_ip=dest_ip,  # Our machine (victim)
                protocol=protocol,
                raw_data={
                    "scanned_ports": scanned_ports,
                    "port_count": len(scanned_ports),
                    "total_attempts": total_ports,
                    "protocols": list(protocols_used),
                    "scan_types": scan_types_used,
                    "primary_scan_type": primary_scan_type,
                    "is_stealth_scan": is_stealth,
                    "time_window_seconds": self.time_window,
                    "threshold": self.threshold,
                    "scan_type": primary_scan_type
                }
            )

            # Keep only last few entries to avoid re-alerting immediately
            if source_ip in self.connection_attempts:
                self.connection_attempts[source_ip] = dict(
                    list(self.connection_attempts[source_ip].items())[-3:]
                )
            if source_ip in self.scan_patterns:
                self.scan_patterns[source_ip] = self.scan_patterns[source_ip][-3:]

            return threat_event

        return None

    def _cleanup_old_entries(self, source_ip: str, current_time: datetime) -> None:
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        if source_ip in self.connection_attempts:
            expired = [
                port for port, (ts, _) in self.connection_attempts[source_ip].items()
                if ts < cutoff_time
            ]
            for port in expired:
                del self.connection_attempts[source_ip][port]
