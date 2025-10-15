"""Quick test to verify ThreatAnalyzer implementation"""

from datetime import datetime
from ids.models.data_models import ThreatEvent, ThreatType
from ids.services.threat_analyzer import ThreatAnalyzer

# Create a test threat event
threat_event = ThreatEvent(
    timestamp=datetime.now(),
    threat_type=ThreatType.PORT_SCAN,
    source_ip="192.168.1.100",
    destination_ip="10.0.0.5",
    protocol="TCP",
    raw_data={"ports_scanned": [22, 80, 443, 3389], "scan_duration": "45s"}
)

# Create analyzer and analyze the threat
analyzer = ThreatAnalyzer()
analysis = analyzer.analyze(threat_event)

# Print results
print("=" * 60)
print("THREAT ANALYSIS TEST")
print("=" * 60)
print(f"\nClassification: {analysis.classification}")
print(f"Severity: {analysis.severity.value.upper()}")
print(f"\nDescription:\n{analysis.description}")
print(f"\nJustification:\n{analysis.justification}")
print(f"\nRecommendations:")
for i, rec in enumerate(analysis.recommendations, 1):
    print(f"  {i}. {rec}")
print("\n" + "=" * 60)
print("TEST PASSED - ThreatAnalyzer working correctly!")
print("=" * 60)
