"""Email service for sending threat notifications via SMTP"""

import smtplib
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Tuple, Optional
from ids.models.data_models import ThreatAnalysis
from ids.models.exceptions import NotificationException


class EmailService:
    """Handles email sending with SMTP support, retry logic, and threat email formatting"""
    
    def __init__(self, smtp_host: str, smtp_port: int, username: str, password: str, 
                 use_tls: bool = True, retry_attempts: int = 3, retry_delay: int = 10):
        """
        Initialize the email service
        
        Args:
            smtp_host: SMTP server hostname
            smtp_port: SMTP server port
            username: SMTP authentication username
            password: SMTP authentication password
            use_tls: Whether to use TLS encryption (default: True)
            retry_attempts: Number of retry attempts for failed sends (default: 3)
            retry_delay: Base delay in seconds between retries (default: 10)
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay
    
    def send_email(self, recipient: str, subject: str, body: str) -> bool:
        """
        Send an email with SMTP connection, TLS support, and retry logic
        
        Args:
            recipient: Email address of the recipient
            subject: Email subject line
            body: Email body content
            
        Returns:
            True if email was sent successfully, False otherwise
            
        Raises:
            NotificationException: If all retry attempts fail
        """
        last_exception = None
        
        for attempt in range(1, self.retry_attempts + 1):
            try:
                # Create message
                msg = MIMEMultipart()
                msg['From'] = self.username
                msg['To'] = recipient
                msg['Subject'] = subject
                msg.attach(MIMEText(body, 'plain'))
                
                # Connect to SMTP server
                if self.use_tls:
                    server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30)
                    server.starttls()
                else:
                    server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30)
                
                # Authenticate
                if self.username and self.password:
                    server.login(self.username, self.password)
                
                # Send email
                server.send_message(msg)
                server.quit()
                
                return True
                
            except smtplib.SMTPAuthenticationError as e:
                last_exception = e
                raise NotificationException(f"SMTP authentication failed: {e}")
                
            except smtplib.SMTPConnectError as e:
                last_exception = e
                if attempt < self.retry_attempts:
                    # Exponential backoff
                    delay = self.retry_delay * (2 ** (attempt - 1))
                    time.sleep(delay)
                    continue
                    
            except smtplib.SMTPException as e:
                last_exception = e
                if attempt < self.retry_attempts:
                    # Exponential backoff
                    delay = self.retry_delay * (2 ** (attempt - 1))
                    time.sleep(delay)
                    continue
                    
            except Exception as e:
                last_exception = e
                if attempt < self.retry_attempts:
                    # Exponential backoff
                    delay = self.retry_delay * (2 ** (attempt - 1))
                    time.sleep(delay)
                    continue
        
        # All retries failed
        raise NotificationException(
            f"Failed to send email after {self.retry_attempts} attempts. Last error: {last_exception}"
        )
    
    def format_threat_email(self, analysis: ThreatAnalysis) -> Tuple[str, str]:
        """
        Generate email subject and body from ThreatAnalysis
        
        Args:
            analysis: ThreatAnalysis object containing threat details
            
        Returns:
            Tuple of (subject, body) strings
        """
        threat_event = analysis.threat_event
        
        # Format subject with severity and threat type
        subject = f"[IDS ALERT - {analysis.severity.value.upper()}] {threat_event.threat_type.value.replace('_', ' ').title()} Detected"
        
        # Format body with all threat details
        body = f"""=== THREAT DETECTED ===
Type: {threat_event.threat_type.value.replace('_', ' ').title()}
Severity: {analysis.severity.value.upper()}
Timestamp: {threat_event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
Source: {threat_event.source_ip}
Destination: {threat_event.destination_ip or 'N/A'}
Protocol: {threat_event.protocol}

=== ANALYSIS ===
{analysis.description}

=== SEVERITY JUSTIFICATION ===
{analysis.justification}

=== RECOMMENDED ACTIONS ===
"""
        
        # Add numbered recommendations
        for i, recommendation in enumerate(analysis.recommendations, 1):
            body += f"{i}. {recommendation}\n"
        
        # Add technical details
        body += f"""
=== TECHNICAL DETAILS ===
"""
        for key, value in threat_event.raw_data.items():
            body += f"{key}: {value}\n"
        
        body += """
---
This is an automated alert from your Intrusion Detection System.
"""
        
        return subject, body
