"""Main IDS Application orchestrator"""

import signal
import sys
import threading
from typing import Optional
from datetime import datetime

from ids.utils.config_manager import ConfigurationManager
from ids.utils.logger import IDSLogger
from ids.services.packet_capture import PacketCaptureEngine
from ids.services.threat_detection_engine import ThreatDetectionEngine
from ids.services.threat_analyzer import ThreatAnalyzer
from ids.services.severity_classifier import SeverityClassifier
from ids.services.email_service import EmailService
from ids.services.notification_service import NotificationService
from ids.detectors.port_scan_detector import PortScanDetector
from ids.detectors.icmp_scan_detector import ICMPScanDetector
from ids.detectors.brute_force_detector import BruteForceDetector
from ids.detectors.malware_detector import MalwareDetector
from ids.detectors.data_exfiltration_detector import DataExfiltrationDetector
from ids.detectors.attacker_identifier import AttackerIdentifier
from ids.models.exceptions import IDSException, CaptureException, ConfigurationException


class IDSApplication:
    """
    Main Intrusion Detection System application.
    
    Orchestrates all IDS components including packet capture, threat detection,
    analysis, and notification. Manages the main detection loop and graceful shutdown.
    """
    
    def __init__(self, config_path: str, event_bus=None, threat_store=None):
        """
        Initialize the IDS application.
        
        Args:
            config_path: Path to the configuration file
            event_bus: Optional EventBus for real-time event broadcasting
            threat_store: Optional ThreatStore for in-memory threat storage
        """
        self.config_path = config_path
        self.config_manager: Optional[ConfigurationManager] = None
        self.logger: Optional[IDSLogger] = None
        self.packet_capture: Optional[PacketCaptureEngine] = None
        self.detection_engine: Optional[ThreatDetectionEngine] = None
        self.threat_analyzer: Optional[ThreatAnalyzer] = None
        self.notification_service: Optional[NotificationService] = None
        self.attacker_identifier: Optional[AttackerIdentifier] = None
        
        # Web UI integration
        self.event_bus = event_bus
        self.threat_store = threat_store
        
        self._running = False
        self._shutdown_requested = False
        self._start_time: Optional[datetime] = None
        self._monitoring_thread: Optional[threading.Thread] = None
        
        # Store detector instances for management
        self._detectors = {}
        
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def initialize(self) -> None:
        """
        Initialize all IDS components.
        
        Loads configuration, sets up logging, and initializes all detection
        and notification components.
        
        Raises:
            ConfigurationException: If configuration cannot be loaded
            IDSException: If component initialization fails
        """
        try:
            # Load configuration
            print("Loading configuration...")
            self.config_manager = ConfigurationManager()
            config = self.config_manager.load_config(self.config_path)
            
            # Set up logging
            print("Initializing logging system...")
            logging_config = config.logging_config
            self.logger = IDSLogger(
                log_file=logging_config['log_file'],
                log_level=logging_config['log_level'],
                max_log_size_mb=logging_config['max_log_size_mb'],
                backup_count=logging_config['backup_count']
            )
            
            self.logger.log_system_event("IDS Application starting", level="INFO")
            
            # Initialize email service
            print("Initializing email service...")
            email_config = config.email_config
            email_service = EmailService(
                smtp_host=email_config['smtp_host'],
                smtp_port=email_config['smtp_port'],
                username=email_config['username'],
                password=email_config['password'],
                use_tls=email_config['use_tls'],
                retry_attempts=config.notification_config['retry_attempts'],
                retry_delay=config.notification_config['retry_delay_seconds']
            )
            
            # Initialize notification service
            print("Initializing notification service...")
            self.notification_service = NotificationService(
                email_service=email_service,
                logger=self.logger,
                recipients=email_config['recipients'],
                batch_window_seconds=config.notification_config['batch_window_seconds'],
                batch_threshold=config.notification_config['batch_threshold']
            )
            
            # Initialize severity classifier and threat analyzer
            print("Initializing threat analysis components...")
            severity_classifier = SeverityClassifier()
            self.threat_analyzer = ThreatAnalyzer(severity_classifier)
            
            # Initialize packet capture engine
            print("Initializing packet capture engine...")
            self.packet_capture = PacketCaptureEngine()
            
            # Initialize threat detection engine
            print("Initializing threat detection engine...")
            self.detection_engine = ThreatDetectionEngine()
            
            # Register all detectors
            print("Registering threat detectors...")
            detection_config = config.detection_config
            
            # Port scan detector
            port_scan_detector = PortScanDetector(
                threshold=detection_config['port_scan_threshold'],
                time_window=60
            )
            self.detection_engine.register_detector(port_scan_detector)
            self._detectors['port_scan'] = port_scan_detector
            
            # ICMP scan detector
            icmp_scan_detector = ICMPScanDetector(
                threshold=detection_config['icmp_scan_threshold'],
                time_window=30
            )
            self.detection_engine.register_detector(icmp_scan_detector)
            self._detectors['icmp_scan'] = icmp_scan_detector
            
            # Brute force detector
            brute_force_detector = BruteForceDetector(
                threshold=detection_config['brute_force_threshold'],
                time_window=60
            )
            self.detection_engine.register_detector(brute_force_detector)
            self._detectors['brute_force'] = brute_force_detector
            
            # Malware detector
            malware_detector = MalwareDetector()
            self.detection_engine.register_detector(malware_detector)
            self._detectors['malware'] = malware_detector
            
            # Data exfiltration detector
            data_exfiltration_detector = DataExfiltrationDetector(
                threshold_bytes=10485760,  # 10MB
                time_window=60
            )
            self.detection_engine.register_detector(data_exfiltration_detector)
            self._detectors['data_exfiltration'] = data_exfiltration_detector
            
            # Attacker identifier (not registered with detection engine)
            self.attacker_identifier = AttackerIdentifier(
                threshold=2,
                time_window=300
            )
            self._detectors['attacker_identifier'] = self.attacker_identifier
            
            self.logger.log_system_event(
                "IDS initialization complete",
                level="INFO",
                details=self.detection_engine.get_statistics()
            )
            
            print("IDS initialization complete!")
            
        except ConfigurationException as e:
            print(f"Configuration error: {e}")
            raise
        except Exception as e:
            print(f"Initialization error: {e}")
            if self.logger:
                self.logger.log_system_event(
                    "IDS initialization failed",
                    level="ERROR",
                    details={"error": str(e)}
                )
            raise IDSException(f"Failed to initialize IDS: {e}")
    
    def run(self) -> None:
        """
        Start the main IDS detection loop.
        
        Captures packets, detects threats, analyzes them, and sends notifications.
        Runs until shutdown is requested.
        
        Raises:
            CaptureException: If packet capture fails
            IDSException: If a critical error occurs during operation
        """
        if not self._is_initialized():
            raise IDSException("IDS not initialized. Call initialize() first.")
        
        try:
            # Get network interface from configuration
            interface = self.config_manager.get('detection.network_interface')
            
            self.logger.log_system_event(
                "Starting packet capture",
                level="INFO",
                details={"interface": interface}
            )
            
            print(f"\nStarting IDS on interface: {interface}")
            print("Press Ctrl+C to stop...\n")
            
            # Start packet capture
            self.packet_capture.start_capture(interface)
            self._running = True
            self._start_time = datetime.now()
            
            # Emit status change event
            if self.event_bus:
                self.event_bus.publish('status_changed', {
                    'status': 'running',
                    'interface': interface,
                    'timestamp': self._start_time.isoformat()
                })
            
            # Main detection loop
            packet_count = 0
            for packet in self.packet_capture.get_packet_stream():
                # Check if shutdown was requested
                if self._shutdown_requested:
                    break
                
                packet_count += 1
                
                # Analyze packet for threats
                threat_event = self.detection_engine.analyze_packet(packet)
                
                if threat_event:
                    # Threat detected - analyze it
                    threat_analysis = self.threat_analyzer.analyze(threat_event)
                    
                    # Log the threat
                    self.logger.log_threat(threat_analysis)
                    
                    # Send notification
                    self.notification_service.notify(threat_analysis)
                    
                    # Store threat and emit event for web UI
                    if self.threat_store:
                        self.threat_store.add_threat(threat_analysis)
                    if self.event_bus:
                        self.event_bus.publish('threat_detected', threat_analysis)
                    
                    # Check if this indicates an attacker
                    attacker_event = self.attacker_identifier.record_threat_event(threat_event)
                    if attacker_event:
                        # Attacker identified - analyze and notify
                        attacker_analysis = self.threat_analyzer.analyze(attacker_event)
                        self.logger.log_threat(attacker_analysis)
                        self.notification_service.notify(attacker_analysis)
                        
                        # Store and emit attacker event
                        if self.threat_store:
                            self.threat_store.add_threat(attacker_analysis)
                        if self.event_bus:
                            self.event_bus.publish('threat_detected', attacker_analysis)
                
                # Periodic status update (every 1000 packets)
                if packet_count % 1000 == 0:
                    stats = self.detection_engine.get_statistics()
                    self.logger.log_system_event(
                        "Periodic status update",
                        level="INFO",
                        details=stats
                    )
                    
                    # Emit stats update event
                    if self.event_bus:
                        self.event_bus.publish('stats_updated', stats)
            
        except CaptureException as e:
            self.logger.log_system_event(
                "Packet capture error",
                level="ERROR",
                details={"error": str(e)}
            )
            print(f"\nPacket capture error: {e}")
            raise
        except KeyboardInterrupt:
            # Handled by signal handler
            pass
        except Exception as e:
            self.logger.log_system_event(
                "Unexpected error in main loop",
                level="ERROR",
                details={"error": str(e)}
            )
            print(f"\nUnexpected error: {e}")
            raise IDSException(f"Error during IDS operation: {e}")
        finally:
            self._running = False
    
    def shutdown(self) -> None:
        """
        Gracefully shutdown the IDS application.
        
        Stops packet capture, sends any remaining notifications, and cleans up resources.
        """
        if self._shutdown_requested:
            return
        
        self._shutdown_requested = True
        
        print("\nShutting down IDS...")
        
        if self.logger:
            self.logger.log_system_event("IDS shutdown initiated", level="INFO")
        
        # Stop packet capture
        if self.packet_capture and self.packet_capture.is_capturing:
            try:
                print("Stopping packet capture...")
                self.packet_capture.stop_capture()
            except Exception as e:
                print(f"Error stopping packet capture: {e}")
        
        # Shutdown notification service (sends remaining queued notifications)
        if self.notification_service:
            try:
                print("Sending remaining notifications...")
                self.notification_service.shutdown()
            except Exception as e:
                print(f"Error during notification service shutdown: {e}")
        
        # Log final statistics
        if self.detection_engine and self.logger:
            stats = self.detection_engine.get_statistics()
            self.logger.log_system_event(
                "IDS shutdown complete",
                level="INFO",
                details=stats
            )
            print(f"\nFinal statistics:")
            print(f"  Packets analyzed: {stats['packets_analyzed']}")
            print(f"  Threats detected: {stats['threats_detected']}")
        
        # Emit status change event
        if self.event_bus:
            self.event_bus.publish('status_changed', {
                'status': 'stopped',
                'timestamp': datetime.now().isoformat()
            })
        
        print("IDS shutdown complete.")
    
    def _is_initialized(self) -> bool:
        """
        Check if all required components are initialized.
        
        Returns:
            True if initialized, False otherwise
        """
        return all([
            self.config_manager,
            self.logger,
            self.packet_capture,
            self.detection_engine,
            self.threat_analyzer,
            self.notification_service,
            self.attacker_identifier
        ])
    
    def _signal_handler(self, signum, frame):
        """
        Handle shutdown signals (SIGINT, SIGTERM).
        
        Args:
            signum: Signal number
            frame: Current stack frame
        """
        print(f"\nReceived signal {signum}, initiating shutdown...")
        self.shutdown()
        sys.exit(0)
    
    def get_current_status(self) -> dict:
        """
        Get current IDS status for web UI.
        
        Returns:
            Dictionary containing current status information including:
            - running: Whether IDS is currently running
            - interface: Network interface being monitored
            - uptime: Seconds since monitoring started
            - packet_count: Number of packets analyzed
            - threat_count: Number of threats detected
        """
        status = {
            'running': self._running,
            'interface': None,
            'uptime': 0,
            'packet_count': 0,
            'threat_count': 0
        }
        
        if self.config_manager:
            status['interface'] = self.config_manager.get('detection.network_interface')
        
        if self._running and self._start_time:
            uptime_delta = datetime.now() - self._start_time
            status['uptime'] = int(uptime_delta.total_seconds())
        
        if self.detection_engine:
            stats = self.detection_engine.get_statistics()
            status['packet_count'] = stats.get('packets_analyzed', 0)
            status['threat_count'] = stats.get('threats_detected', 0)
        
        return status
    
    def get_detector_status(self) -> list:
        """
        Get status of all detectors.
        
        Returns:
            List of dictionaries containing detector information:
            - name: Detector name
            - enabled: Whether detector is enabled
            - description: Detector description
            - type: Detector type
        """
        detector_info = []
        
        detector_descriptions = {
            'port_scan': {
                'description': 'Detects port scanning attempts by monitoring connection patterns',
                'type': 'port_scan'
            },
            'icmp_scan': {
                'description': 'Detects ICMP scanning and ping sweeps',
                'type': 'icmp_scan'
            },
            'brute_force': {
                'description': 'Detects brute force authentication attempts',
                'type': 'brute_force'
            },
            'malware': {
                'description': 'Detects known malware signatures and suspicious patterns',
                'type': 'malware'
            },
            'data_exfiltration': {
                'description': 'Detects large data transfers that may indicate data exfiltration',
                'type': 'data_exfiltration'
            },
            'attacker_identifier': {
                'description': 'Identifies repeat attackers based on threat patterns',
                'type': 'attacker_identified'
            }
        }
        
        for name, detector in self._detectors.items():
            info = {
                'name': name,
                'enabled': detector.enabled if hasattr(detector, 'enabled') else True,
                'description': detector_descriptions.get(name, {}).get('description', 'No description available'),
                'type': detector_descriptions.get(name, {}).get('type', name)
            }
            detector_info.append(info)
        
        return detector_info
    
    def start_monitoring_async(self) -> None:
        """
        Start monitoring in a background thread.
        
        This allows the IDS to run without blocking the main thread,
        which is useful for web UI integration.
        
        Raises:
            IDSException: If IDS is already running or not initialized
        """
        if self._running:
            raise IDSException("IDS is already running")
        
        if not self._is_initialized():
            raise IDSException("IDS not initialized. Call initialize() first.")
        
        # Create and start monitoring thread
        self._monitoring_thread = threading.Thread(target=self.run, daemon=True)
        self._monitoring_thread.start()
    
    @property
    def is_running(self) -> bool:
        """Check if the IDS is currently running."""
        return self._running
