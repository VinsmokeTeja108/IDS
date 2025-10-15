import traceback

try:
    print("Attempting to import threat_analyzer module...")
    import ids.services.threat_analyzer as ta
    print(f"Module loaded from: {ta.__file__}")
    print(f"Module attributes: {dir(ta)}")
    
    print("\nAttempting to import ThreatAnalyzer class...")
    from ids.services.threat_analyzer import ThreatAnalyzer
    print("Success!")
    
except Exception as e:
    print(f"Error: {e}")
    traceback.print_exc()
