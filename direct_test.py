import sys
sys.path.insert(0, '.')

# Try to load the module directly
import ids.services.threat_analyzer as ta_module
print("Module loaded successfully")
print("Module attributes:", [x for x in dir(ta_module) if not x.startswith('_')])
