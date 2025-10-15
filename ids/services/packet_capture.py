"""Packet capture engine for network traffic monitoring"""

import threading
import queue
from typing import Iterator, Optional, Callable
from scapy.all import sniff, Packet
from ids.models.exceptions import CaptureException


class PacketCaptureEngine:
    """
    Engine for capturing network packets using Scapy.
    Runs packet capture in a separate thread to avoid blocking the main application.
    """
    
    def __init__(self):
        """Initialize the packet capture engine"""
        self._capture_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._packet_queue: queue.Queue = queue.Queue(maxsize=1000)
        self._interface: Optional[str] = None
        self._is_capturing = False
        self._capture_error: Optional[Exception] = None
    
    def start_capture(self, interface: str, packet_filter: Optional[str] = None) -> None:
        """
        Begin packet sniffing on the specified network interface.
        
        Args:
            interface: Network interface name (e.g., 'eth0', 'wlan0')
            packet_filter: Optional BPF filter string for packet filtering
            
        Raises:
            CaptureException: If capture is already running or interface is invalid
        """
        if self._is_capturing:
            raise CaptureException("Packet capture is already running")
        
        self._interface = interface
        self._stop_event.clear()
        self._capture_error = None
        
        # Start capture in separate thread
        self._capture_thread = threading.Thread(
            target=self._capture_worker,
            args=(interface, packet_filter),
            daemon=True
        )
        self._capture_thread.start()
        self._is_capturing = True
    
    def stop_capture(self) -> None:
        """
        Stop packet capture and clean up resources.
        
        Raises:
            CaptureException: If no capture is currently running
        """
        if not self._is_capturing:
            raise CaptureException("No packet capture is currently running")
        
        # Signal the capture thread to stop
        self._stop_event.set()
        
        # Wait for thread to finish (with timeout)
        if self._capture_thread:
            self._capture_thread.join(timeout=5.0)
            self._capture_thread = None
        
        self._is_capturing = False
        
        # Check if there was an error during capture
        if self._capture_error:
            error = self._capture_error
            self._capture_error = None
            raise error
    
    def get_packet_stream(self) -> Iterator[Packet]:
        """
        Yield captured packets from the queue.
        
        Yields:
            Packet: Captured network packets
            
        Raises:
            CaptureException: If capture is not running or an error occurred
        """
        if not self._is_capturing:
            raise CaptureException("Packet capture is not running")
        
        while self._is_capturing or not self._packet_queue.empty():
            try:
                # Check for capture errors
                if self._capture_error:
                    raise self._capture_error
                
                # Get packet with timeout to allow checking stop condition
                packet = self._packet_queue.get(timeout=0.5)
                yield packet
            except queue.Empty:
                # No packet available, continue loop
                continue
    
    def _capture_worker(self, interface: str, packet_filter: Optional[str]) -> None:
        """
        Worker function that runs in separate thread to capture packets.
        
        Args:
            interface: Network interface to capture from
            packet_filter: Optional BPF filter string
        """
        try:
            # Callback function to handle each captured packet
            def packet_handler(packet: Packet) -> None:
                if not self._stop_event.is_set():
                    try:
                        self._packet_queue.put(packet, timeout=1.0)
                    except queue.Full:
                        # Queue is full, drop packet (prevents memory issues)
                        pass
            
            # Start sniffing packets
            sniff(
                iface=interface,
                prn=packet_handler,
                store=False,  # Don't store packets in memory
                stop_filter=lambda _: self._stop_event.is_set(),
                filter=packet_filter
            )
            
        except PermissionError as e:
            self._capture_error = CaptureException(
                f"Permission denied: Packet capture requires administrator/root privileges. {str(e)}"
            )
            self._is_capturing = False
            
        except OSError as e:
            # Handle interface not found and other OS errors
            if "No such device" in str(e) or "not found" in str(e).lower():
                self._capture_error = CaptureException(
                    f"Network interface '{interface}' not found. Please check the interface name."
                )
            else:
                self._capture_error = CaptureException(
                    f"OS error during packet capture: {str(e)}"
                )
            self._is_capturing = False
            
        except Exception as e:
            # Catch any other unexpected errors
            self._capture_error = CaptureException(
                f"Unexpected error during packet capture: {str(e)}"
            )
            self._is_capturing = False
    
    @property
    def is_capturing(self) -> bool:
        """Check if packet capture is currently active"""
        return self._is_capturing
    
    @property
    def interface(self) -> Optional[str]:
        """Get the current capture interface"""
        return self._interface
