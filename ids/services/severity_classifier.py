"""Severity classification for detected threats"""

from typing import Dict, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from ids.models.data_models import ThreatEvent, ThreatType, SeverityLevel


class ThreatContext:
    """Context information for threat severity classification"""
    
    def __init__(self):
        # Track threat frequency by source IP
        self._threat_history: Dict[str, list] = defaultdict(list)
        # Track known malicious IPs (simple reputation system)
        self._malicious_ips: set = set()
        # Time window for frequency analysis (in seconds)
        self._frequency_window = 3600  # 1 hour
    
    def add_threat(self, source_ip: str, threat_type: ThreatType, timestamp: datetime):
        """Record a threat event for context tracking"""
        self._threat_history[source_ip].append({
            'type': threat_type,
            'timestamp': timestamp
        })
        
        # Clean old entries outside the frequency window
        cutoff_time = timestamp - timedelta(seconds=self._frequency_window)
        self._threat_history[source_ip] = [
            t for t in self._threat_history[source_ip]
            if t['timestamp'] > cutoff_time
        ]
        
        # Mark IP as malicious if multiple threat types detected
        if len(self._threat_history[source_ip]) >= 3:
            self._malicious_ips.add(source_ip)
    
    def get_threat_count(self, source_ip: str) -> int:
        """Get the number of threats from a source IP in the time window"""
        return len(self._threat_history.get(source_ip, []))
    
    def is_known_malicious(self, source_ip: str) -> bool:
        """Check if an IP is known to be malicious"""
        return source_ip in self._malicious_ips
    
    def get_threat_types(self, source_ip: str) -> set:
        """Get unique threat types from a source IP"""
        threats = self._threat_history.get(source_ip, [])
        return {t['type'] for t in threats}


class SeverityClassifier:
    """Classifies threat severity based on threat type, frequency, and context"""
    
    # Base severity levels for each threat type
    BASE_SEVERITY = {
        ThreatType.PORT_SCAN: SeverityLevel.MEDIUM,
        ThreatType.ICMP_SCAN: SeverityLevel.MEDIUM,
        ThreatType.MALWARE: SeverityLevel.CRITICAL,
        ThreatType.BRUTE_FORCE: SeverityLevel.MEDIUM,
        ThreatType.ATTACKER_IDENTIFIED: SeverityLevel.HIGH,
        ThreatType.DATA_EXFILTRATION: SeverityLevel.CRITICAL,
    }
    
    # Severity level ordering for escalation
    SEVERITY_ORDER = [
        SeverityLevel.LOW,
        SeverityLevel.MEDIUM,
        SeverityLevel.HIGH,
        SeverityLevel.CRITICAL
    ]
    
    def __init__(self, context: Optional[ThreatContext] = None):
        """Initialize the severity classifier
        
        Args:
            context: Optional ThreatContext for tracking threat history
        """
        self.context = context or ThreatContext()
    
    def classify(self, threat_event: ThreatEvent) -> tuple[SeverityLevel, str]:
        """Classify the severity of a threat event
        
        Args:
            threat_event: The threat event to classify
            
        Returns:
            Tuple of (severity_level, justification)
        """
        # Get base severity for the threat type
        base_severity = self.BASE_SEVERITY.get(
            threat_event.threat_type,
            SeverityLevel.MEDIUM
        )
        
        # Update context with this threat
        self.context.add_threat(
            threat_event.source_ip,
            threat_event.threat_type,
            threat_event.timestamp
        )
        
        # Check for escalation conditions
        final_severity = base_severity
        escalation_reasons = []
        
        # Escalate based on frequency
        threat_count = self.context.get_threat_count(threat_event.source_ip)
        if threat_count >= 5:
            final_severity = self._escalate_severity(final_severity)
            escalation_reasons.append(
                f"multiple threats detected from source ({threat_count} in last hour)"
            )
        
        # Escalate based on source reputation
        if self.context.is_known_malicious(threat_event.source_ip):
            final_severity = self._escalate_severity(final_severity)
            escalation_reasons.append("source IP has known malicious activity")
        
        # Escalate if multiple threat types from same source
        threat_types = self.context.get_threat_types(threat_event.source_ip)
        if len(threat_types) >= 3:
            final_severity = self._escalate_severity(final_severity)
            escalation_reasons.append(
                f"multiple attack vectors from same source ({len(threat_types)} types)"
            )
        
        # Generate justification
        justification = self._generate_justification(
            threat_event,
            base_severity,
            final_severity,
            escalation_reasons
        )
        
        return final_severity, justification
    
    def _escalate_severity(self, current_severity: SeverityLevel) -> SeverityLevel:
        """Escalate severity to the next level
        
        Args:
            current_severity: Current severity level
            
        Returns:
            Escalated severity level (or same if already at maximum)
        """
        try:
            current_index = self.SEVERITY_ORDER.index(current_severity)
            if current_index < len(self.SEVERITY_ORDER) - 1:
                return self.SEVERITY_ORDER[current_index + 1]
        except ValueError:
            pass
        
        return current_severity
    
    def _generate_justification(
        self,
        threat_event: ThreatEvent,
        base_severity: SeverityLevel,
        final_severity: SeverityLevel,
        escalation_reasons: list
    ) -> str:
        """Generate a human-readable justification for the severity rating
        
        Args:
            threat_event: The threat event
            base_severity: Base severity before escalation
            final_severity: Final severity after escalation
            escalation_reasons: List of reasons for escalation
            
        Returns:
            Justification string
        """
        threat_type_name = threat_event.threat_type.value.replace('_', ' ').title()
        
        justification_parts = [
            f"Threat type '{threat_type_name}' has base severity: {base_severity.value.upper()}"
        ]
        
        if escalation_reasons:
            justification_parts.append(
                f"Severity escalated to {final_severity.value.upper()} due to:"
            )
            for reason in escalation_reasons:
                justification_parts.append(f"  - {reason}")
        else:
            justification_parts.append(
                f"No escalation factors detected. Final severity: {final_severity.value.upper()}"
            )
        
        return "\n".join(justification_parts)
