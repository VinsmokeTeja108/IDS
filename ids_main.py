#!/usr/bin/env python3
"""
Entry point script for the Intrusion Detection System (IDS).

This script provides a convenient way to run the IDS application
with command-line argument parsing and privilege checking.
"""

from ids.cli import main

if __name__ == '__main__':
    exit(main())
