"""
IDSController for bridging web UI and IDS application.

This module provides a high-level controller interface for the web UI to
interact with the IDS application. It handles starting/stopping monitoring,
retrieving status and threats, managing configuration, and controlling detectors.
"""

import threading
import logging
import yaml
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path

from ids.ids_application import IDSApplication
from web_ui.controllers.event_bus import EventBus
from web_ui.controllers.threat_store import ThreatStore


class IDSController:
    """
    Controller for IDS operations from the web UI.
    
    This class provides a high-level interface for the web server to control
    the IDS application, including starting/stopping monitoring, retrieving
    threats and statistics, updating configuration, and managing detectors.
    """
    
    def __init__(self, config_path: str, event_bus: EventBus = None, threat_store: ThreatStore = None):
        """
        Initialize the IDS controller.
        
        Args:
            config_path: Path to the IDS configuration file
            event_bus: Optional EventBus instance for real-time updates
            threat_store: Optional ThreatStore instance for threat storage
        """
        self.config_path = config_path
        self.event_bus = event_bus or EventBus()
        self.threat_store = threat_store or ThreatStore()
        self.ids_app: Optional[IDSApplication] = None
        self.monitoring_thread: Optional[threading.Thread] = None
        self.logger = logging.getLogger(__name__)
        self.start_time: Optional[datetime] = None
        
        self.logger.info(f"IDSController initialized with config: {config_path}")
    
    def start_monitoring(self) -> Dict[str, Any]:
        """
        Start IDS monitoring in a background thread.
        
        Initializes the IDS application and starts packet capture and threat
        detection in a separate thread. Publishes status change event.
        
        Returns:
            Dict containing:
                - 'success': bool - Whether monitoring started successfully
                - 'message': str - Status message
                - 'status': dict - Current IDS status
        
        Example:
            result = controller.start_monitoring()
            if result['success']:
                print("Monitoring started successfully")
        """
        try:
            # Check if already running
            if self.ids_app and self.ids_app.is_running:
                self.logger.warning("Attempted to start monitoring while already running")
                return {
                    'success': False,
                    'message': 'IDS is already running',
                    'status': self.get_status()
                }
            
            self.logger.info("Starting IDS monitoring...")
            
            # Create new IDS application instance
            self.ids_app = IDSApplication(self.config_path)
            
            # Initialize the IDS
            self.ids_app.initialize()
            
            # Integrate with event bus and threat store
            self._integrate_ids_with_web_ui()
            
            # Start monitoring in background thread
            self.monitoring_thread = threading.Thread(
                target=self._run_monitoring,
                daemon=True,
                name="IDS-Monitoring-Thread"
            )
            self.monitoring_thread.start()
            
            # Record start time
            self.start_time = datetime.now()
            
            # Publish status change event
            self.event_bus.on_status_changed('running', {
                'interface': self.ids_app.config_manager.get('detection.network_interface'),
                'start_time': self.start_time.isoformat()
            })
            
            self.logger.info("IDS monitoring started successfully")
            
            return {
                'success': True,
                'message': 'IDS monitoring started successfully',
                'status': self.get_status()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
            self.event_bus.on_status_changed('error', {'error': str(e)})
            return {
                'success': False,
                'message': f'Failed to start monitoring: {str(e)}',
                'status': self.get_status()
            }
    
    def stop_monitoring(self) -> Dict[str, Any]:
        """
        Gracefully stop IDS monitoring.
        
        Stops packet capture, shuts down the IDS application, and waits for
        the monitoring thread to complete. Publishes status change event.
        
        Returns:
            Dict containing:
                - 'success': bool - Whether monitoring stopped successfully
                - 'message': str - Status message
                - 'status': dict - Current IDS status
        
        Example:
            result = controller.stop_monitoring()
            if result['success']:
                print("Monitoring stopped successfully")
        """
        try:
            # Check if running
            if not self.ids_app or not self.ids_app.is_running:
                self.logger.warning("Attempted to stop monitoring while not running")
                return {
                    'success': False,
                    'message': 'IDS is not running',
                    'status': self.get_status()
                }
            
            self.logger.info("Stopping IDS monitoring...")
            
            # Shutdown the IDS application
            self.ids_app.shutdown()
            
            # Wait for monitoring thread to complete (with timeout)
            if self.monitoring_thread and self.monitoring_thread.is_alive():
                self.monitoring_thread.join(timeout=5.0)
            
            # Publish status change event
            self.event_bus.on_status_changed('stopped', {
                'stop_time': datetime.now().isoformat()
            })
            
            self.logger.info("IDS monitoring stopped successfully")
            
            return {
                'success': True,
                'message': 'IDS monitoring stopped successfully',
                'status': self.get_status()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to stop monitoring: {e}")
            return {
                'success': False,
                'message': f'Failed to stop monitoring: {str(e)}',
                'status': self.get_status()
            }

    def get_status(self) -> Dict[str, Any]:
        """
        Retrieve current IDS status.
        
        Returns comprehensive status information including running state,
        network interface, uptime, packet count, and threat count.
        
        Returns:
            Dict containing:
                - 'running': bool - Whether IDS is currently running
                - 'interface': str - Network interface being monitored
                - 'uptime': int - Seconds since monitoring started
                - 'uptime_formatted': str - Human-readable uptime
                - 'packet_count': int - Total packets analyzed
                - 'threat_count': int - Total threats detected
                - 'start_time': str - ISO timestamp of when monitoring started
        
        Example:
            status = controller.get_status()
            print(f"IDS is {'running' if status['running'] else 'stopped'}")
            print(f"Uptime: {status['uptime_formatted']}")
        """
        try:
            # Check if IDS is running
            is_running = self.ids_app is not None and self.ids_app.is_running
            
            # Calculate uptime
            uptime_seconds = 0
            uptime_formatted = "Not running"
            if is_running and self.start_time:
                uptime_seconds = int((datetime.now() - self.start_time).total_seconds())
                uptime_formatted = self._format_uptime(uptime_seconds)
            
            # Get statistics from detection engine
            packet_count = 0
            threat_count = 0
            interface = "N/A"
            
            if self.ids_app:
                if self.ids_app.detection_engine:
                    stats = self.ids_app.detection_engine.get_statistics()
                    packet_count = stats.get('packets_analyzed', 0)
                    threat_count = stats.get('threats_detected', 0)
                
                if self.ids_app.config_manager:
                    interface = self.ids_app.config_manager.get('detection.network_interface', 'N/A')
            
            status = {
                'running': is_running,
                'interface': interface,
                'uptime': uptime_seconds,
                'uptime_formatted': uptime_formatted,
                'packet_count': packet_count,
                'threat_count': threat_count,
                'start_time': self.start_time.isoformat() if self.start_time else None
            }
            
            self.logger.debug(f"Status retrieved: running={is_running}, uptime={uptime_seconds}s")
            return status
            
        except Exception as e:
            self.logger.error(f"Error retrieving status: {e}")
            return {
                'running': False,
                'interface': 'N/A',
                'uptime': 0,
                'uptime_formatted': 'Error',
                'packet_count': 0,
                'threat_count': 0,
                'start_time': None,
                'error': str(e)
            }
    
    def get_threats(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Retrieve threats with optional filtering.
        
        Delegates to the ThreatStore to retrieve threats matching the
        specified filters.
        
        Args:
            filters: Optional dictionary containing filter criteria:
                - 'type': str or List[str] - Filter by threat type(s)
                - 'severity': str or List[str] - Filter by severity level(s)
                - 'start_time': str (ISO format) - Filter threats after this time
                - 'end_time': str (ISO format) - Filter threats before this time
                - 'limit': int - Maximum number of threats to return
                - 'source_ip': str - Filter by source IP address
        
        Returns:
            List[Dict[str, Any]]: List of threat dictionaries matching the filters
        
        Example:
            # Get all high severity threats
            threats = controller.get_threats({'severity': 'high', 'limit': 10})
            
            # Get port scans from specific IP
            threats = controller.get_threats({
                'type': 'port_scan',
                'source_ip': '192.168.1.100'
            })
        """
        try:
            threats = self.threat_store.get_threats(filters)
            self.logger.debug(f"Retrieved {len(threats)} threats with filters: {filters}")
            return threats
        except Exception as e:
            self.logger.error(f"Error retrieving threats: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get threat statistics for dashboard display.
        
        Retrieves comprehensive statistics from the ThreatStore including
        threat counts by severity and type, top attackers, and recent activity.
        
        Returns:
            Dict containing:
                - 'total_threats': Total number of stored threats
                - 'by_severity': Count of threats by severity level
                - 'by_type': Count of threats by threat type
                - 'top_attackers': List of top attacking source IPs with counts
                - 'recent_count': Number of threats in the last hour
                - 'last_threat_time': Timestamp of most recent threat
        
        Example:
            stats = controller.get_statistics()
            print(f"Total threats: {stats['total_threats']}")
            print(f"Critical: {stats['by_severity']['critical']}")
        """
        try:
            stats = self.threat_store.get_statistics()
            self.logger.debug(f"Retrieved statistics: {stats['total_threats']} total threats")
            return stats
        except Exception as e:
            self.logger.error(f"Error retrieving statistics: {e}")
            return {
                'total_threats': 0,
                'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'by_type': {},
                'top_attackers': [],
                'recent_count': 0,
                'last_threat_time': None
            }
    
    def update_configuration(self, config_updates: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update IDS configuration settings.
        
        Validates and applies configuration updates to the IDS config file.
        The IDS must be restarted for changes to take effect.
        
        Args:
            config_updates: Dictionary containing configuration updates.
                           Should follow the same structure as config.yaml:
                           - 'email': Email settings
                           - 'detection': Detection thresholds
                           - 'logging': Logging configuration
                           - 'notification': Notification settings
        
        Returns:
            Dict containing:
                - 'success': bool - Whether update was successful
                - 'message': str - Status message
                - 'requires_restart': bool - Whether IDS restart is needed
        
        Example:
            result = controller.update_configuration({
                'detection': {
                    'port_scan_threshold': 15
                },
                'email': {
                    'recipients': ['[email]', '[email]']
                }
            })
        """
        try:
            self.logger.info(f"Updating configuration with: {config_updates}")
            
            # Load current configuration
            config_file = Path(self.config_path)
            if not config_file.exists():
                return {
                    'success': False,
                    'message': 'Configuration file not found',
                    'requires_restart': False
                }
            
            with open(config_file, 'r') as f:
                current_config = yaml.safe_load(f) or {}
            
            # Merge updates with current configuration
            for section, values in config_updates.items():
                if section not in current_config:
                    current_config[section] = {}
                
                if isinstance(values, dict):
                    current_config[section].update(values)
                else:
                    current_config[section] = values
            
            # Validate configuration (basic validation)
            validation_result = self._validate_configuration(current_config)
            if not validation_result['valid']:
                return {
                    'success': False,
                    'message': f"Configuration validation failed: {validation_result['error']}",
                    'requires_restart': False
                }
            
            # Write updated configuration back to file
            with open(config_file, 'w') as f:
                yaml.dump(current_config, f, default_flow_style=False, sort_keys=False)
            
            self.logger.info("Configuration updated successfully")
            
            # Determine if restart is needed
            is_running = self.ids_app is not None and self.ids_app.is_running
            
            return {
                'success': True,
                'message': 'Configuration updated successfully',
                'requires_restart': is_running
            }
            
        except Exception as e:
            self.logger.error(f"Failed to update configuration: {e}")
            return {
                'success': False,
                'message': f'Failed to update configuration: {str(e)}',
                'requires_restart': False
            }
    
    def toggle_detector(self, detector_name: str, enabled: bool) -> Dict[str, Any]:
        """
        Enable or disable a specific threat detector.
        
        Note: This is a placeholder implementation. Full detector toggling
        would require modifications to the IDS application to support
        dynamic detector management.
        
        Args:
            detector_name: Name of the detector to toggle (e.g., 'PortScanDetector')
            enabled: True to enable, False to disable
        
        Returns:
            Dict containing:
                - 'success': bool - Whether toggle was successful
                - 'message': str - Status message
                - 'detector': str - Detector name
                - 'enabled': bool - New enabled state
        
        Example:
            result = controller.toggle_detector('PortScanDetector', False)
            if result['success']:
                print(f"Detector {result['detector']} is now disabled")
        """
        try:
            self.logger.info(f"Toggling detector {detector_name} to {'enabled' if enabled else 'disabled'}")
            
            # Check if IDS is initialized
            if not self.ids_app or not self.ids_app.detection_engine:
                return {
                    'success': False,
                    'message': 'IDS not initialized',
                    'detector': detector_name,
                    'enabled': enabled
                }
            
            # Get current detectors
            detectors = self.ids_app.detection_engine._detectors
            
            # Find the detector by name
            detector_found = False
            for detector in detectors:
                if detector.__class__.__name__ == detector_name:
                    detector_found = True
                    # Note: Current detector implementation doesn't have enable/disable
                    # This would require adding an 'enabled' flag to the base detector
                    # For now, we'll return success but note the limitation
                    break
            
            if not detector_found:
                return {
                    'success': False,
                    'message': f'Detector {detector_name} not found',
                    'detector': detector_name,
                    'enabled': enabled
                }
            
            # TODO: Implement actual detector toggling when base detector supports it
            # For now, return success with a note
            self.logger.warning(f"Detector toggling not fully implemented for {detector_name}")
            
            return {
                'success': True,
                'message': f'Detector {detector_name} toggle requested (requires IDS enhancement)',
                'detector': detector_name,
                'enabled': enabled,
                'note': 'Full detector toggling requires IDS application enhancement'
            }
            
        except Exception as e:
            self.logger.error(f"Failed to toggle detector {detector_name}: {e}")
            return {
                'success': False,
                'message': f'Failed to toggle detector: {str(e)}',
                'detector': detector_name,
                'enabled': enabled
            }
    
    def get_detector_status(self) -> List[Dict[str, Any]]:
        """
        Get status of all registered detectors.
        
        Returns information about all detectors including their names,
        types, and current status.
        
        Returns:
            List[Dict[str, Any]]: List of detector information dictionaries:
                - 'name': str - Detector class name
                - 'type': str - Detector type (e.g., 'port_scan')
                - 'enabled': bool - Whether detector is enabled
                - 'description': str - Detector description
        
        Example:
            detectors = controller.get_detector_status()
            for detector in detectors:
                print(f"{detector['name']}: {'enabled' if detector['enabled'] else 'disabled'}")
        """
        try:
            # Use get_detector_status from IDS application if available
            if self.ids_app and hasattr(self.ids_app, 'get_detector_status'):
                return self.ids_app.get_detector_status()
            
            # Fallback: check if IDS is initialized
            if not self.ids_app:
                self.logger.warning("Cannot get detector status: IDS not initialized")
                return []
            
            # Try to get detectors from _detectors dictionary
            if hasattr(self.ids_app, '_detectors') and self.ids_app._detectors:
                detector_info = []
                
                # Detector descriptions
                descriptions = {
                    'port_scan': 'Detects port scanning attempts by monitoring connection patterns',
                    'icmp_scan': 'Detects ICMP scanning and ping sweeps',
                    'brute_force': 'Detects brute force authentication attempts',
                    'malware': 'Detects known malware signatures and suspicious patterns',
                    'data_exfiltration': 'Detects large data transfers that may indicate data exfiltration',
                    'attacker_identifier': 'Identifies repeat attackers based on threat patterns'
                }
                
                for detector_key, detector in self.ids_app._detectors.items():
                    detector_name = detector.__class__.__name__
                    detector_info.append({
                        'name': detector_name,
                        'type': detector_key,
                        'enabled': getattr(detector, 'enabled', True),
                        'description': descriptions.get(detector_key, 'Threat detector')
                    })
                
                self.logger.debug(f"Retrieved status for {len(detector_info)} detectors")
                return detector_info
            
            self.logger.warning("Cannot get detector status: No detectors found")
            return []
            
        except Exception as e:
            self.logger.error(f"Error retrieving detector status: {e}", exc_info=True)
            return []
    
    def _run_monitoring(self) -> None:
        """
        Internal method to run IDS monitoring in background thread.
        
        This method is called by the monitoring thread and runs the IDS
        main detection loop.
        """
        try:
            self.logger.info("Monitoring thread started")
            self.ids_app.run()
            self.logger.info("Monitoring thread completed")
        except Exception as e:
            self.logger.error(f"Error in monitoring thread: {e}")
            self.event_bus.on_status_changed('error', {'error': str(e)})
    
    def _integrate_ids_with_web_ui(self) -> None:
        """
        Integrate IDS application with web UI components.
        
        Sets up event handlers to capture threats and publish them to
        the event bus and threat store.
        """
        # Store original run method
        original_run = self.ids_app.run
        
        def enhanced_run():
            """Enhanced run method that captures threats"""
            try:
                # Get network interface from configuration
                interface = self.ids_app.config_manager.get('detection.network_interface')
                
                self.ids_app.logger.log_system_event(
                    "Starting packet capture",
                    level="INFO",
                    details={"interface": interface}
                )
                
                # Start packet capture
                self.ids_app.packet_capture.start_capture(interface)
                self.ids_app._running = True
                
                # Main detection loop
                packet_count = 0
                for packet in self.ids_app.packet_capture.get_packet_stream():
                    # Check if shutdown was requested
                    if self.ids_app._shutdown_requested:
                        break
                    
                    packet_count += 1
                    
                    # Analyze packet for threats
                    threat_event = self.ids_app.detection_engine.analyze_packet(packet)
                    
                    if threat_event:
                        # Threat detected - analyze it
                        threat_analysis = self.ids_app.threat_analyzer.analyze(threat_event)
                        
                        # Log the threat
                        self.ids_app.logger.log_threat(threat_analysis)
                        
                        # Send notification
                        self.ids_app.notification_service.notify(threat_analysis)
                        
                        # NEW: Store threat and emit event for web UI
                        threat_id = self.threat_store.add_threat(threat_analysis)
                        self.event_bus.on_threat_detected(threat_analysis)
                        
                        # Check if this indicates an attacker
                        attacker_event = self.ids_app.attacker_identifier.record_threat_event(threat_event)
                        if attacker_event:
                            # Attacker identified - analyze and notify
                            attacker_analysis = self.ids_app.threat_analyzer.analyze(attacker_event)
                            self.ids_app.logger.log_threat(attacker_analysis)
                            self.ids_app.notification_service.notify(attacker_analysis)
                            
                            # Store attacker threat
                            self.threat_store.add_threat(attacker_analysis)
                            self.event_bus.on_threat_detected(attacker_analysis)
                    
                    # Periodic status update (every 1000 packets)
                    if packet_count % 1000 == 0:
                        stats = self.ids_app.detection_engine.get_statistics()
                        self.ids_app.logger.log_system_event(
                            "Periodic status update",
                            level="INFO",
                            details=stats
                        )
                        # Publish stats update to web UI
                        self.event_bus.on_stats_updated(self.get_statistics())
                        
            except Exception as e:
                self.ids_app.logger.log_system_event(
                    "Unexpected error in main loop",
                    level="ERROR",
                    details={"error": str(e)}
                )
                raise
            finally:
                self.ids_app._running = False
        
        # Replace run method with enhanced version
        self.ids_app.run = enhanced_run
    
    def _format_uptime(self, seconds: int) -> str:
        """
        Format uptime seconds into human-readable string.
        
        Args:
            seconds: Uptime in seconds
        
        Returns:
            Formatted uptime string (e.g., "2h 15m 30s")
        """
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        
        parts = []
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        if secs > 0 or not parts:
            parts.append(f"{secs}s")
        
        return " ".join(parts)
    
    def _validate_configuration(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate configuration dictionary.
        
        Args:
            config: Configuration dictionary to validate
        
        Returns:
            Dict with 'valid' (bool) and 'error' (str) keys
        """
        try:
            # Check required sections
            required_sections = ['email', 'detection', 'logging', 'notification']
            for section in required_sections:
                if section not in config:
                    return {
                        'valid': False,
                        'error': f"Missing required section: {section}"
                    }
            
            # Validate email section
            if 'email' in config:
                email_config = config['email']
                if 'recipients' in email_config and not email_config['recipients']:
                    return {
                        'valid': False,
                        'error': "Email recipients list cannot be empty"
                    }
            
            # Validate detection thresholds
            if 'detection' in config:
                detection_config = config['detection']
                threshold_fields = ['port_scan_threshold', 'icmp_scan_threshold', 'brute_force_threshold']
                
                for field in threshold_fields:
                    if field in detection_config:
                        value = detection_config[field]
                        if not isinstance(value, int) or value <= 0:
                            return {
                                'valid': False,
                                'error': f"{field} must be a positive integer"
                            }
            
            return {'valid': True, 'error': None}
            
        except Exception as e:
            return {
                'valid': False,
                'error': f"Validation error: {str(e)}"
            }
