"""Logging system for IDS with JSON formatting and rotation"""

import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from ids.models.data_models import ThreatAnalysis, SeverityLevel


class IDSLogger:
    """Logger class for IDS with JSON formatting and log rotation"""
    
    def __init__(
        self,
        log_file: str = "ids.log",
        log_level: str = "INFO",
        max_log_size_mb: int = 100,
        backup_count: int = 5
    ):
        """
        Initialize the IDS logger with JSON formatting and rotation.
        
        Args:
            log_file: Path to the log file
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            max_log_size_mb: Maximum log file size in MB before rotation
            backup_count: Number of backup log files to keep
        """
        self.log_file = log_file
        self.logger = logging.getLogger("IDS")
        self.logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        
        # Remove existing handlers to avoid duplicates
        self.logger.handlers.clear()
        
        # Create log directory if it doesn't exist
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Set up rotating file handler
        max_bytes = max_log_size_mb * 1024 * 1024  # Convert MB to bytes
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        
        # Use basic formatter since we'll format as JSON in our methods
        file_handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(file_handler)
        
        # Also add console handler for immediate visibility
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(console_handler)
    
    def _log_json(self, level: int, data: Dict[str, Any]) -> None:
        """
        Log data as JSON with timestamp.
        
        Args:
            level: Logging level
            data: Dictionary to log as JSON
        """
        # Ensure timestamp is present
        if 'timestamp' not in data:
            data['timestamp'] = datetime.now().isoformat()
        
        # Convert to JSON string
        json_str = json.dumps(data, default=str, ensure_ascii=False)
        self.logger.log(level, json_str)
    
    def log_threat(self, threat_analysis: ThreatAnalysis) -> None:
        """
        Log a detected threat event.
        
        Args:
            threat_analysis: ThreatAnalysis object containing threat details
        """
        threat_event = threat_analysis.threat_event
        
        log_data = {
            "event_type": "threat_detected",
            "timestamp": threat_event.timestamp.isoformat(),
            "threat_type": threat_event.threat_type.value,
            "severity": threat_analysis.severity.value,
            "source_ip": threat_event.source_ip,
            "destination_ip": threat_event.destination_ip,
            "protocol": threat_event.protocol,
            "classification": threat_analysis.classification,
            "description": threat_analysis.description,
            "justification": threat_analysis.justification,
            "recommendations": threat_analysis.recommendations,
            "details": threat_event.raw_data
        }
        
        # Use appropriate log level based on severity
        log_level = self._get_log_level_from_severity(threat_analysis.severity)
        self._log_json(log_level, log_data)
    
    def log_notification(
        self,
        status: str,
        recipient: str,
        threat_type: Optional[str] = None,
        severity: Optional[str] = None,
        error: Optional[str] = None
    ) -> None:
        """
        Log an email notification event.
        
        Args:
            status: Status of notification (sent, failed, retrying)
            recipient: Email recipient address
            threat_type: Type of threat (optional)
            severity: Severity level (optional)
            error: Error message if notification failed (optional)
        """
        log_data = {
            "event_type": "notification",
            "status": status,
            "recipient": recipient
        }
        
        if threat_type:
            log_data["threat_type"] = threat_type
        if severity:
            log_data["severity"] = severity
        if error:
            log_data["error"] = error
        
        # Use WARNING level for failures, INFO for success
        log_level = logging.WARNING if status == "failed" else logging.INFO
        self._log_json(log_level, log_data)
    
    def log_system_event(
        self,
        event: str,
        level: str = "INFO",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log a system event.
        
        Args:
            event: Description of the system event
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            details: Additional details about the event (optional)
        """
        log_data = {
            "event_type": "system_event",
            "event": event
        }
        
        if details:
            log_data["details"] = details
        
        log_level = getattr(logging, level.upper(), logging.INFO)
        self._log_json(log_level, log_data)
    
    def set_level(self, level: str) -> None:
        """
        Set the logging level dynamically.
        
        Args:
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        log_level = getattr(logging, level.upper(), logging.INFO)
        self.logger.setLevel(log_level)
        self.log_system_event(
            f"Logging level changed to {level.upper()}",
            level="INFO"
        )
    
    def _get_log_level_from_severity(self, severity: SeverityLevel) -> int:
        """
        Map threat severity to logging level.
        
        Args:
            severity: Threat severity level
            
        Returns:
            Logging level constant
        """
        severity_map = {
            SeverityLevel.LOW: logging.INFO,
            SeverityLevel.MEDIUM: logging.WARNING,
            SeverityLevel.HIGH: logging.ERROR,
            SeverityLevel.CRITICAL: logging.CRITICAL
        }
        return severity_map.get(severity, logging.INFO)
