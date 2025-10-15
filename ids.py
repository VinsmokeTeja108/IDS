#!/usr/bin/env python3
"""
IDS entry point script.

Alternative entry point for the Intrusion Detection System.
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the main IDS entry point
from ids_main import main

if __name__ == '__main__':
    sys.exit(main())