import traceback

try:
    print("Testing imports...")
    from typing import List, Dict
    print("✓ typing imports OK")
    
    from ids.models.data_models import ThreatEvent, ThreatAnalysis, ThreatType, SeverityLevel
    print("✓ data_models imports OK")
    
    from ids.services.severity_classifier import SeverityClassifier, ThreatContext
    print("✓ severity_classifier imports OK")
    
    print("\nNow trying to load the file directly...")
    with open('ids/services/threat_analyzer.py', 'r') as f:
        code = f.read()
        exec(compile(code, 'ids/services/threat_analyzer.py', 'exec'))
    
    print("✓ File executed successfully")
    print(f"ThreatAnalyzer defined: {'ThreatAnalyzer' in dir()}")
    
except Exception as e:
    print(f"Error: {e}")
    traceback.print_exc()
