import traceback

try:
    from ids.services.threat_analyzer import ThreatAnalyzer
    print("ThreatAnalyzer imported successfully")
    print(f"ThreatAnalyzer: {ThreatAnalyzer}")
except Exception as e:
    print(f"Failed to import ThreatAnalyzer: {e}")
    traceback.print_exc()

try:
    from ids.cli import main
    print("CLI imported successfully")
except Exception as e:
    print(f"Failed to import CLI: {e}")
    traceback.print_exc()
