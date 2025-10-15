"""Demonstration of IDSApplication usage"""

from ids.ids_application import IDSApplication

# This script demonstrates how to use the IDSApplication class
# Note: Actual execution requires proper configuration and root/admin privileges

def main():
    """Main demonstration function"""
    
    print("=" * 60)
    print("IDS Application Demonstration")
    print("=" * 60)
    
    # Create IDS application instance with config file path
    print("\n1. Creating IDS Application...")
    ids_app = IDSApplication('config.yaml')
    
    # Initialize all components
    print("2. Initializing components...")
    try:
        ids_app.initialize()
        print("   ✓ Configuration loaded")
        print("   ✓ Logger initialized")
        print("   ✓ Email service configured")
        print("   ✓ Notification service ready")
        print("   ✓ Threat analyzer initialized")
        print("   ✓ Packet capture engine ready")
        print("   ✓ Detection engine with 5 detectors registered")
        print("   ✓ Attacker identifier initialized")
    except Exception as e:
        print(f"   ✗ Initialization failed: {e}")
        return
    
    # In a real scenario, you would call ids_app.run() here
    # This starts the main detection loop
    print("\n3. Ready to start detection loop")
    print("   To run: ids_app.run()")
    print("   This will:")
    print("   - Start packet capture on configured interface")
    print("   - Analyze each packet for threats")
    print("   - Generate threat analysis for detected threats")
    print("   - Send email notifications")
    print("   - Log all events")
    
    # Graceful shutdown
    print("\n4. Shutting down...")
    ids_app.shutdown()
    print("   ✓ Shutdown complete")
    
    print("\n" + "=" * 60)
    print("Demonstration complete!")
    print("=" * 60)


if __name__ == '__main__':
    main()
