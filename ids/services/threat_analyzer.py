"""Threat analysis and recommendation generation"""

from typing import List, Dict
from ids.models.data_models import ThreatEvent, ThreatAnalysis, ThreatType, SeverityLevel


class ThreatAnalyzer:
    """Analyzes detected threats and generates detailed analysis with recommendations"""
    
    def __init__(self, severity_classifier=None):
        """Initialize the threat analyzer
        
        Args:
            severity_classifier: Optional SeverityClassifier instance. If not provided,
                                a new one will be created.
        """
        # Import here to avoid circular imports
        if severity_classifier is None:
            from ids.services.severity_classifier import SeverityClassifier
            severity_classifier = SeverityClassifier()
        self.severity_classifier = severity_classifier
        
        # Recommendation templates for each threat type
        self.RECOMMENDATIONS = {
            ThreatType.PORT_SCAN: [
                "Immediately block the source IP address ({source_ip}) using firewall rules",
                "Review and close unnecessary open ports on the target system",
                "Enable port knocking or implement network segmentation to limit exposure",
                "Monitor for follow-up attacks from the same source or related IPs",
                "Consider implementing rate limiting on connection attempts",
                "Review firewall logs for other suspicious activity from this source"
            ],
            ThreatType.ICMP_SCAN: [
                "Block ICMP echo requests from the source IP ({source_ip}) at the firewall",
                "Disable ICMP responses on critical systems to prevent reconnaissance",
                "Implement network segmentation to limit scan visibility",
                "Monitor for subsequent attacks following the reconnaissance phase",
                "Review network topology to identify exposed systems",
                "Consider implementing IDS/IPS rules to detect and block scan patterns"
            ],
            ThreatType.MALWARE: [
                "URGENT: Immediately isolate the affected system from the network",
                "Quarantine the suspicious file or process identified in the threat details",
                "Run a full system antivirus/antimalware scan with updated signatures",
                "Review system logs for signs of data exfiltration or lateral movement",
                "Change all passwords and credentials that may have been compromised",
                "Restore from a known clean backup if system integrity is compromised",
                "Update all security software and apply latest security patches",
                "Conduct forensic analysis to determine the infection vector"
            ],
            ThreatType.BRUTE_FORCE: [
                "Immediately block the source IP ({source_ip}) using firewall or fail2ban",
                "Review authentication logs for any successful login attempts",
                "Enforce strong password policies and multi-factor authentication (MFA)",
                "Implement account lockout policies after failed login attempts",
                "Change passwords for any accounts that may have been targeted",
                "Consider implementing CAPTCHA or rate limiting on authentication endpoints",
                "Monitor for distributed brute force attacks from multiple IPs",
                "Review and restrict remote access to essential personnel only"
            ],
            ThreatType.ATTACKER_IDENTIFIED: [
                "Block the identified attacker IP ({source_ip}) across all network perimeters",
                "Review all logs for activity from this IP to assess the scope of compromise",
                "Check for any successful breaches or data access from this source",
                "Implement enhanced monitoring for related IP ranges or attack patterns",
                "Report the IP to threat intelligence platforms and abuse contacts",
                "Conduct a security audit of systems that were targeted",
                "Review and update security policies based on attack vectors used",
                "Consider implementing geo-blocking if attacks originate from unexpected regions"
            ],
            ThreatType.DATA_EXFILTRATION: [
                "CRITICAL: Immediately block outbound connections to the destination ({destination_ip})",
                "Isolate the source system ({source_ip}) to prevent further data loss",
                "Identify what data was transmitted and assess the impact",
                "Review system for malware or unauthorized access that enabled exfiltration",
                "Implement Data Loss Prevention (DLP) solutions to monitor sensitive data",
                "Enable egress filtering to control outbound traffic",
                "Conduct forensic analysis to determine the exfiltration method",
                "Notify relevant stakeholders and comply with breach notification requirements",
                "Review and strengthen access controls on sensitive data",
                "Monitor for additional exfiltration attempts to different destinations"
            ]
        }

        # Description templates for each threat type
        self.DESCRIPTIONS = {
            ThreatType.PORT_SCAN: (
                "A port scanning attack has been detected from {source_ip}. "
                "The attacker is probing the network to identify open ports and services, "
                "which is typically the reconnaissance phase before a targeted attack. "
                "This activity indicates an attempt to map your network infrastructure and "
                "identify potential vulnerabilities."
            ),
            ThreatType.ICMP_SCAN: (
                "An ICMP scanning activity (ping sweep) has been detected from {source_ip}. "
                "The attacker is attempting to discover active hosts on the network by sending "
                "ICMP echo requests to multiple targets. This is a reconnaissance technique used "
                "to map the network topology before launching more sophisticated attacks."
            ),
            ThreatType.MALWARE: (
                "Malware has been detected in network traffic or system activity. "
                "The malicious payload matches known malware signatures and poses an immediate "
                "threat to system integrity and data security. Source: {source_ip}. "
                "This could indicate a successful compromise or an attempted infection that must "
                "be addressed immediately to prevent further damage."
            ),
            ThreatType.BRUTE_FORCE: (
                "A brute force attack has been detected from {source_ip}. "
                "Multiple failed authentication attempts indicate an attacker is systematically "
                "trying to guess credentials to gain unauthorized access. This type of attack "
                "can lead to account compromise if weak passwords are in use."
            ),
            ThreatType.ATTACKER_IDENTIFIED: (
                "A persistent attacker has been identified at {source_ip}. "
                "This IP address has exhibited multiple types of malicious behavior, indicating "
                "a coordinated attack effort. The attacker has demonstrated intent and capability "
                "to compromise your systems through various attack vectors."
            ),
            ThreatType.DATA_EXFILTRATION: (
                "Potential data exfiltration has been detected from {source_ip} to {destination_ip}. "
                "Unusual outbound data transfer patterns suggest that sensitive information may be "
                "leaving your network without authorization. This could indicate a successful breach "
                "where an attacker is stealing data, or malware is transmitting information to a "
                "command and control server."
            )
        }

    def analyze(self, threat_event: ThreatEvent) -> ThreatAnalysis:
        """Generate a comprehensive analysis of a threat event
        
        Args:
            threat_event: The threat event to analyze
            
        Returns:
            ThreatAnalysis object containing severity, classification, description,
            recommendations, and justification
        """
        # Get severity and justification from the classifier
        severity, justification = self.severity_classifier.classify(threat_event)
        
        # Generate classification string
        classification = self._generate_classification(threat_event, severity)
        
        # Generate description
        description = self._generate_description(threat_event)
        
        # Get recommendations
        recommendations = self.get_recommendations(threat_event)
        
        # Create and return the analysis
        return ThreatAnalysis(
            threat_event=threat_event,
            severity=severity,
            classification=classification,
            description=description,
            recommendations=recommendations,
            justification=justification
        )
    
    def get_recommendations(self, threat_event: ThreatEvent) -> List[str]:
        """Get threat-specific remediation recommendations
        
        Args:
            threat_event: The threat event to get recommendations for
            
        Returns:
            List of actionable remediation steps
        """
        # Get the recommendation template for this threat type
        template_recommendations = self.RECOMMENDATIONS.get(
            threat_event.threat_type,
            [
                "Block the source IP address ({source_ip})",
                "Review system logs for additional suspicious activity",
                "Update security policies and monitoring rules",
                "Conduct a security assessment of affected systems"
            ]
        )
        
        # Format recommendations with actual threat data
        formatted_recommendations = []
        for recommendation in template_recommendations:
            formatted_rec = recommendation.format(
                source_ip=threat_event.source_ip,
                destination_ip=threat_event.destination_ip or "unknown"
            )
            formatted_recommendations.append(formatted_rec)
        
        return formatted_recommendations

    def _generate_classification(self, threat_event: ThreatEvent, severity: SeverityLevel) -> str:
        """Generate a classification string for the threat
        
        Args:
            threat_event: The threat event
            severity: The assigned severity level
            
        Returns:
            Classification string
        """
        threat_name = threat_event.threat_type.value.replace('_', ' ').title()
        return f"{severity.value.upper()} - {threat_name}"
    
    def _generate_description(self, threat_event: ThreatEvent) -> str:
        """Generate a detailed description of the threat
        
        Args:
            threat_event: The threat event
            
        Returns:
            Description string
        """
        # Get the description template for this threat type
        template = self.DESCRIPTIONS.get(
            threat_event.threat_type,
            (
                "A security threat has been detected from {source_ip}. "
                "Please review the technical details and take appropriate action."
            )
        )
        
        # Format the description with actual threat data
        description = template.format(
            source_ip=threat_event.source_ip,
            destination_ip=threat_event.destination_ip or "unknown"
        )
        
        # Add protocol and timestamp information
        description += f"\n\nProtocol: {threat_event.protocol}"
        description += f"\nDetection Time: {threat_event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}"
        
        # Add additional context from raw_data if available
        if threat_event.raw_data:
            description += "\n\nAdditional Details:"
            for key, value in threat_event.raw_data.items():
                description += f"\n  - {key}: {value}"
        
        return description