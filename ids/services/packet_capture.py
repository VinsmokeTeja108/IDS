"""Packet capture engine for network traffic monitoring.

Windows-compatible: uses Scapy's L3RawSocket (native Windows raw socket)
when wpcap.dll is not available, so it works with or without Npcap in PATH.
"""

import threading
import queue
import socket
import struct
import sys
import os
import logging
from typing import Iterator, Optional
from ids.models.exceptions import CaptureException

logger = logging.getLogger(__name__)


def _resolve_scapy_interface(interface_name: str):
    """
    Resolve a friendly interface name (e.g. 'Wi-Fi', 'Ethernet') to
    the correct Scapy interface object.

    On Windows, Scapy uses NPF device paths internally but also supports
    matching by name from the IFACES registry.

    Returns:
        The resolved Scapy interface object or None to use default.
    """
    try:
        from scapy.all import IFACES, conf
        if not interface_name or interface_name.lower() in ('', 'auto', 'default'):
            return None

        # First: exact NPF path match
        if interface_name in IFACES:
            return IFACES[interface_name]

        # Second: match by friendly name (case-insensitive)
        for iface_id, iface_obj in IFACES.items():
            name = getattr(iface_obj, 'name', '') or ''
            if name.lower() == interface_name.lower():
                logger.info(f"Resolved '{interface_name}' → {iface_id}")
                return iface_obj

        # Third: match by description substring
        for iface_id, iface_obj in IFACES.items():
            desc = getattr(iface_obj, 'description', '') or ''
            if interface_name.lower() in desc.lower():
                logger.info(f"Resolved '{interface_name}' by description → {iface_id}")
                return iface_obj

        # Not found — use default
        logger.warning(f"Interface '{interface_name}' not found, using default: {conf.iface}")
        return None
    except Exception as e:
        logger.warning(f"Interface resolution error: {e}")
        return None


class PacketCaptureEngine:
    """
    Engine for capturing network packets using Scapy.
    
    Uses L3RawSocket on Windows when wpcap.dll is unavailable,
    falling back gracefully so the IDS always starts.
    """

    def __init__(self):
        """Initialize the packet capture engine"""
        self._capture_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._packet_queue: queue.Queue = queue.Queue(maxsize=2000)
        self._interface: Optional[str] = None
        self._is_capturing = False
        self._capture_error: Optional[Exception] = None

    def start_capture(self, interface: str, packet_filter: Optional[str] = None) -> None:
        """
        Begin packet sniffing on the specified network interface.

        Args:
            interface: Network interface friendly name (e.g. 'Wi-Fi', 'Ethernet')
                       or NPF device path on Windows.
            packet_filter: Optional BPF filter string (used only with wpcap/Npcap).
        """
        if self._is_capturing:
            raise CaptureException("Packet capture is already running")

        self._interface = interface
        self._stop_event.clear()
        self._capture_error = None

        self._capture_thread = threading.Thread(
            target=self._capture_worker,
            args=(interface, packet_filter),
            daemon=True,
            name="PacketCapture"
        )
        self._capture_thread.start()
        self._is_capturing = True

    def stop_capture(self) -> None:
        """Stop packet capture and clean up resources."""
        if not self._is_capturing:
            raise CaptureException("No packet capture is currently running")

        self._stop_event.set()

        if self._capture_thread:
            self._capture_thread.join(timeout=5.0)
            self._capture_thread = None

        self._is_capturing = False

        if self._capture_error:
            error = self._capture_error
            self._capture_error = None
            raise error

    def get_packet_stream(self) -> Iterator:
        """
        Yield captured packets from the queue.

        Yields:
            Packet: Captured Scapy packets
        """
        if not self._is_capturing:
            raise CaptureException("Packet capture is not running")

        while self._is_capturing or not self._packet_queue.empty():
            try:
                if self._capture_error:
                    raise self._capture_error

                packet = self._packet_queue.get(timeout=0.5)
                yield packet
            except queue.Empty:
                yield None

    def _capture_worker(self, interface: str, packet_filter: Optional[str]) -> None:
        """Worker thread: tries L2 sniff first, falls back to L3 raw socket."""
        try:
            # Resolve Scapy interface object for this friendly name
            scapy_iface = _resolve_scapy_interface(interface)

            # Try L2 (requires wpcap/Npcap in PATH)
            if self._try_l2_capture(scapy_iface, packet_filter):
                return  # L2 capture completed (or stopped)

            # L2 failed — fall back to L3 raw socket capture
            logger.info("L2 capture not available, falling back to L3 raw socket capture")
            self._try_l3_capture(scapy_iface)

        except Exception as e:
            logger.exception("Unexpected error in capture worker")
            self._capture_error = CaptureException(f"Packet capture failed: {e}")
            self._is_capturing = False

    def _try_l2_capture(self, scapy_iface, packet_filter: Optional[str]) -> bool:
        """
        Attempt Layer 2 packet capture using Scapy's sniff().
        Returns True if capture ran successfully, False if L2 is unavailable.
        """
        try:
            from scapy.all import sniff, conf

            # Quick probe: check if L2socket is available
            L2sock = conf.L2socket
            if 'NotAvailable' in type(L2sock).__name__ or 'NotAvailable' in str(L2sock):
                logger.info("L2 socket not available (wpcap.dll missing)")
                return False

            def packet_handler(packet):
                if not self._stop_event.is_set():
                    try:
                        self._packet_queue.put_nowait(packet)
                    except queue.Full:
                        pass

            logger.info(f"Starting L2 capture on interface: {scapy_iface or 'default'}")
            sniff(
                iface=scapy_iface,
                prn=packet_handler,
                store=False,
                filter=packet_filter,
                stop_filter=lambda _: self._stop_event.is_set()
            )
            return True

        except Exception as e:
            err_str = str(e).lower()
            if 'winpcap' in err_str or 'wpcap' in err_str or 'pcap' in err_str or 'layer 2' in err_str:
                logger.info(f"L2 capture failed (expected on Windows without wpcap): {e}")
                return False
            logger.warning(f"L2 capture error: {e}")
            return False

    def _try_l3_capture(self, scapy_iface) -> None:
        """
        Layer 3 raw socket capture — works on Windows without wpcap.
        Uses native Windows raw socket to capture IPv4 packets, then
        wraps them as Scapy IP packets for the detection pipeline.
        """
        try:
            from scapy.layers.inet import IP as ScapyIP

            iface_ip = None
            if scapy_iface:
                iface_ip = getattr(scapy_iface, 'ip', None)

            if not iface_ip or iface_ip.startswith('169.254') or iface_ip == '0.0.0.0':
                iface_ip = self._get_primary_ip()

            logger.info(f"Starting L3 raw socket capture, binding to IP: {iface_ip}")

            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            raw_sock.bind((iface_ip, 0))
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            if sys.platform == 'win32':
                try:
                    import ctypes
                    SIO_RCVALL = 0x98000001
                    raw_sock.ioctl(SIO_RCVALL, socket.RCVALL_ON)
                except Exception as e:
                    logger.warning(f"Could not enable promiscuous mode (SIO_RCVALL): {e}")
                    # Continue without promiscuous mode, we still get packets destined to us

            raw_sock.settimeout(0.5)
            logger.info("L3 raw socket capture started successfully")

            try:
                while not self._stop_event.is_set():
                    try:
                        raw_data = raw_sock.recv(65535)
                        if raw_data and not self._stop_event.is_set():
                            try:
                                pkt = ScapyIP(raw_data)
                                try:
                                    self._packet_queue.put_nowait(pkt)
                                except queue.Full:
                                    pass
                            except Exception:
                                pass
                    except socket.timeout:
                        continue
                    except OSError as e:
                        if self._stop_event.is_set():
                            break
                        logger.warning(f"Raw socket recv error: {e}")
                        break
            finally:
                try:
                    if sys.platform == 'win32':
                        SIO_RCVALL = 0x98000001
                        raw_sock.ioctl(SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
                raw_sock.close()

        except PermissionError:
            self._capture_error = CaptureException(
                "Permission denied: Run as Administrator to capture packets."
            )
            self._is_capturing = False
        except OSError as e:
            # Handle Windows specific socket errors gracefully
            if getattr(e, 'winerror', None) == 10013:
                self._capture_error = CaptureException(
                    "Permission denied (WinError 10013): Run as Administrator to capture packets."
                )
            elif getattr(e, 'winerror', None) == 10022:
                self._capture_error = CaptureException(
                    "Socket format error (WinError 10022): Native raw sockets restricted on this Windows version."
                )
            else:
                self._capture_error = CaptureException(
                    f"Socket error during packet capture: {e}"
                )
            self._is_capturing = False
        except Exception as e:
            self._capture_error = CaptureException(f"L3 capture failed: {e}")
            self._is_capturing = False


    def _get_primary_ip(self) -> str:
        """Return the primary outbound IP address of this machine."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "0.0.0.0"

    @property
    def is_capturing(self) -> bool:
        """Check if packet capture is currently active"""
        return self._is_capturing

    @property
    def interface(self) -> Optional[str]:
        """Get the current capture interface"""
        return self._interface
