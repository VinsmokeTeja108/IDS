import sys
sys.path.insert(0, '.')

# Direct import
from ids.services import threat_analyzer
print("Module imported:", threat_analyzer)
print("Module contents:", dir(threat_analyzer))
print("Has ThreatAnalyzer:", hasattr(threat_analyzer, 'ThreatAnalyzer'))

if hasattr(threat_analyzer, 'ThreatAnalyzer'):
    print("SUCCESS: ThreatAnalyzer class found!")
else:
    print("ERROR: ThreatAnalyzer class not found")
