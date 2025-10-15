"""Notification service for managing threat alerts with batching logic"""

import threading
import time
from datetime import datetime, timedelta
from typing import List, Optional
from collections import deque

from ids.models.data_models import ThreatAnalysis, SeverityLevel
from ids.services.email_service import EmailService
from ids.utils.logger import IDSLogger
from ids.models.exceptions import NotificationException


class NotificationService:
    """
    Manages threat notifications with batching logic and immediate alerts for critical threats.
    
    Collects threats within a configurable time window and sends batched notifications
    to avoid email flooding. Critical severity threats are sent immediately.
    """
    
    def __init__(
        self,
        email_service: EmailService,
        logger: IDSLogger,
        recipients: List[str],
        batch_window_seconds: int = 300,
        batch_threshold: int = 3
    ):
        """
        Initialize the notification service.
        
        Args:
            email_service: EmailService instance for sending emails
            logger: IDSLogger instance for logging notifications
            recipients: List of email addresses to send notifications to
            batch_window_seconds: Time window in seconds for batching (default: 300 = 5 minutes)
            batch_threshold: Minimum number of threats to trigger batching (default: 3)
        """
        self.email_service = email_service
        self.logger = logger
        self.recipients = recipients
        self.batch_window_seconds = batch_window_seconds
        self.batch_threshold = batch_threshold
        
        # Thread-safe queue for batching
        self._batch_queue: deque = deque()
        self._batch_lock = threading.Lock()
        self._batch_timer: Optional[threading.Timer] = None
    
    def notify(self, threat_analysis: ThreatAnalysis) -> bool:
        """
        Send notification for a single threat.
        
        For Critical severity threats, sends immediately.
        For other severities, adds to batch queue for potential batching.
        
        Args:
            threat_analysis: ThreatAnalysis object containing threat details
            
        Returns:
            True if notification was sent/queued successfully, False otherwise
        """
        try:
            # Critical threats are sent immediately
            if threat_analysis.severity == SeverityLevel.CRITICAL:
                self.logger.log_system_event(
                    "Sending immediate notification for critical threat",
                    level="INFO",
                    details={
                        "threat_type": threat_analysis.threat_event.threat_type.value,
                        "source_ip": threat_analysis.threat_event.source_ip
                    }
                )
                return self._send_single_notification(threat_analysis)
            
            # Non-critical threats are added to batch queue
            with self._batch_lock:
                self._batch_queue.append(threat_analysis)
                
                # Start batch timer if not already running
                if self._batch_timer is None:
                    self._start_batch_timer()
                
                # If we've reached the batch threshold, send immediately
                if len(self._batch_queue) >= self.batch_threshold:
                    self._send_batch_now()
            
            return True
            
        except Exception as e:
            self.logger.log_system_event(
                "Failed to process notification",
                level="ERROR",
                details={"error": str(e)}
            )
            return False
    
    def batch_notifications(self, analyses: List[ThreatAnalysis]) -> bool:
        """
        Send a batched notification for multiple threats.
        
        Args:
            analyses: List of ThreatAnalysis objects to include in batch
            
        Returns:
            True if batch notification was sent successfully, False otherwise
        """
        if not analyses:
            return True
        
        try:
            # Format batched email
            subject = f"[IDS ALERT - BATCH] {len(analyses)} Threats Detected"
            body = self._format_batch_email(analyses)
            
            # Send to all recipients
            success = True
            for recipient in self.recipients:
                try:
                    self.email_service.send_email(recipient, subject, body)
                    self.logger.log_notification(
                        status="sent",
                        recipient=recipient,
                        threat_type="batch",
                        severity=f"{len(analyses)} threats"
                    )
                except NotificationException as e:
                    self.logger.log_notification(
                        status="failed",
                        recipient=recipient,
                        threat_type="batch",
                        error=str(e)
                    )
                    success = False
            
            return success
            
        except Exception as e:
            self.logger.log_system_event(
                "Failed to send batch notification",
                level="ERROR",
                details={"error": str(e), "threat_count": len(analyses)}
            )
            return False
    
    def _send_single_notification(self, threat_analysis: ThreatAnalysis) -> bool:
        """
        Send notification for a single threat to all recipients.
        
        Args:
            threat_analysis: ThreatAnalysis object
            
        Returns:
            True if sent to at least one recipient successfully
        """
        subject, body = self.email_service.format_threat_email(threat_analysis)
        
        success = True
        for recipient in self.recipients:
            try:
                self.email_service.send_email(recipient, subject, body)
                self.logger.log_notification(
                    status="sent",
                    recipient=recipient,
                    threat_type=threat_analysis.threat_event.threat_type.value,
                    severity=threat_analysis.severity.value
                )
            except NotificationException as e:
                self.logger.log_notification(
                    status="failed",
                    recipient=recipient,
                    threat_type=threat_analysis.threat_event.threat_type.value,
                    severity=threat_analysis.severity.value,
                    error=str(e)
                )
                success = False
        
        return success
    
    def _start_batch_timer(self) -> None:
        """Start the batch timer to send queued notifications after the batch window."""
        self._batch_timer = threading.Timer(
            self.batch_window_seconds,
            self._on_batch_timer_expired
        )
        self._batch_timer.daemon = True
        self._batch_timer.start()
    
    def _on_batch_timer_expired(self) -> None:
        """Called when the batch timer expires. Sends all queued notifications."""
        with self._batch_lock:
            self._send_batch_now()
    
    def _send_batch_now(self) -> None:
        """
        Send all queued notifications immediately.
        Must be called while holding _batch_lock.
        """
        if not self._batch_queue:
            self._batch_timer = None
            return
        
        # Cancel existing timer
        if self._batch_timer is not None:
            self._batch_timer.cancel()
            self._batch_timer = None
        
        # Get all queued threats
        threats = list(self._batch_queue)
        self._batch_queue.clear()
        
        # Send batch notification
        self.logger.log_system_event(
            "Sending batch notification",
            level="INFO",
            details={"threat_count": len(threats)}
        )
        self.batch_notifications(threats)
    
    def _format_batch_email(self, analyses: List[ThreatAnalysis]) -> str:
        """
        Format a batched email body with multiple threats.
        
        Args:
            analyses: List of ThreatAnalysis objects
            
        Returns:
            Formatted email body string
        """
        body = f"""=== BATCH THREAT ALERT ===
Total Threats Detected: {len(analyses)}
Time Window: {self.batch_window_seconds} seconds

"""
        
        # Group by severity
        severity_counts = {}
        for analysis in analyses:
            severity = analysis.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        body += "=== SEVERITY SUMMARY ===\n"
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in severity_counts:
                body += f"{severity.upper()}: {severity_counts[severity]}\n"
        
        body += "\n=== INDIVIDUAL THREATS ===\n\n"
        
        # List each threat
        for i, analysis in enumerate(analyses, 1):
            threat_event = analysis.threat_event
            body += f"--- Threat {i} ---\n"
            body += f"Type: {threat_event.threat_type.value.replace('_', ' ').title()}\n"
            body += f"Severity: {analysis.severity.value.upper()}\n"
            body += f"Timestamp: {threat_event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            body += f"Source: {threat_event.source_ip}\n"
            body += f"Destination: {threat_event.destination_ip or 'N/A'}\n"
            body += f"Description: {analysis.description}\n"
            body += "\n"
        
        body += """---
This is an automated batch alert from your Intrusion Detection System.
Multiple threats were detected within a short time window.
"""
        
        return body
    
    def shutdown(self) -> None:
        """
        Gracefully shutdown the notification service.
        Sends any remaining queued notifications.
        """
        with self._batch_lock:
            if self._batch_timer is not None:
                self._batch_timer.cancel()
            
            if self._batch_queue:
                self.logger.log_system_event(
                    "Sending remaining queued notifications on shutdown",
                    level="INFO",
                    details={"threat_count": len(self._batch_queue)}
                )
                self._send_batch_now()
