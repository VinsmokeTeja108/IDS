#!/usr/bin/env python3
"""
Network Interface Checker for Windows

This script helps you find the correct network interface name to use
in your IDS configuration on Windows systems.
"""

import sys

try:
    from scapy.all import get_if_list, get_working_ifaces, conf
    print("=" * 70)
    print("  Network Interface Checker for IDS")
    print("=" * 70)
    print()
    
    print("Available Network Interfaces:")
    print("-" * 70)
    
    # Get all interfaces
    interfaces = get_if_list()
    
    if not interfaces:
        print("ERROR: No network interfaces found!")
        print("Make sure Npcap is installed correctly.")
        sys.exit(1)
    
    for i, iface in enumerate(interfaces, 1):
        print(f"{i}. {iface}")
    
    print()
    print("=" * 70)
    print("Working Interfaces (recommended):")
    print("-" * 70)
    
    # Get working interfaces
    working_ifaces = get_working_ifaces()
    
    if not working_ifaces:
        print("WARNING: No working interfaces detected!")
        print("This might indicate a problem with Npcap installation.")
        print()
        print("Try using one of the interfaces listed above.")
    else:
        for iface in working_ifaces:
            print(f"  - {iface.name}")
            if hasattr(iface, 'description'):
                print(f"    Description: {iface.description}")
            if hasattr(iface, 'ip'):
                print(f"    IP: {iface.ip}")
            print()
    
    print("=" * 70)
    print("Current Default Interface:")
    print(f"  {conf.iface}")
    print("=" * 70)
    print()
    print("INSTRUCTIONS:")
    print("1. Copy one of the interface names above")
    print("2. Update your config.yaml file:")
    print("   detection:")
    print("     network_interface: <paste_interface_name_here>")
    print()
    print("TIP: Use the 'Working Interfaces' if available, or try the")
    print("     interface that matches your active network connection.")
    print("=" * 70)

except ImportError as e:
    print("ERROR: Scapy is not installed or cannot be imported")
    print(f"Details: {e}")
    print()
    print("Please install Scapy:")
    print("  pip install scapy")
    sys.exit(1)

except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
