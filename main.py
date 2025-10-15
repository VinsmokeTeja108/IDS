#!/usr/bin/env python3
"""
Simple entry point for the Intrusion Detection System (IDS).

This is a simplified entry point that delegates to the main IDS entry script.
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the main IDS entry point
from ids_main import main

if __name__ == '__main__':
    sys.exit(main())