with open('ids/services/threat_analyzer.py', 'rb') as f:
    content = f.read()
    print(f'File size: {len(content)} bytes')
    print(f'First 100 bytes: {content[:100]}')
    
# Try to exec the file
try:
    with open('ids/services/threat_analyzer.py', 'r') as f:
        code = f.read()
    compile(code, 'ids/services/threat_analyzer.py', 'exec')
    print("File compiles successfully")
except SyntaxError as e:
    print(f"Syntax error: {e}")
