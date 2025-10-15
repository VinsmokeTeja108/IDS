#!/usr/bin/env python3
"""
Main entry point for the Intrusion Detection System (IDS).

This script serves as the primary entry point for the IDS application,
providing privilege checking, signal handling, and graceful shutdown capabilities.
"""

import sys
import os
import signal
import platform
from typing import NoReturn

# Add the current directory to Python path to ensure imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ids.cli import main as cli_main


def check_privileges() -> bool:
    """
    Check if the application is running with sufficient privileges for packet capture.
    
    Returns:
        True if running with sufficient privileges, False otherwise
    """
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        # Unix-like systems (Linux, macOS, etc.)
        return os.geteuid() == 0


def require_privileges() -> None:
    """
    Check for required privileges and exit if insufficient.
    
    Raises:
        SystemExit: If insufficient privileges are detected
    """
    if not check_privileges():
        print("❌ ERROR: Insufficient privileges detected!", file=sys.stderr)
        print("", file=sys.stderr)
        
        if platform.system() == "Windows":
            print("This application requires Administrator privileges for packet capture.", file=sys.stderr)
            print("Please run this script as Administrator:", file=sys.stderr)
            print("  1. Right-click on Command Prompt or PowerShell", file=sys.stderr)
            print("  2. Select 'Run as administrator'", file=sys.stderr)
            print("  3. Navigate to the IDS directory and run the script again", file=sys.stderr)
        else:
            print("This application requires root privileges for packet capture.", file=sys.stderr)
            print("Please run this script with sudo:", file=sys.stderr)
            print(f"  sudo python3 {sys.argv[0]} {' '.join(sys.argv[1:])}", file=sys.stderr)
        
        print("", file=sys.stderr)
        print("Note: Root/Administrator privileges are required to:", file=sys.stderr)
        print("  - Capture network packets from network interfaces", file=sys.stderr)
        print("  - Access low-level network operations", file=sys.stderr)
        print("  - Monitor system network traffic", file=sys.stderr)
        
        sys.exit(1)


def setup_signal_handlers() -> None:
    """
    Set up signal handlers for graceful shutdown.
    
    Handles SIGINT (Ctrl+C) and SIGTERM (termination request) signals
    to ensure the application shuts down gracefully.
    """
    def signal_handler(signum: int, frame) -> NoReturn:
        """
        Handle shutdown signals.
        
        Args:
            signum: Signal number received
            frame: Current stack frame (unused)
        """
        signal_names = {
            signal.SIGINT: "SIGINT (Ctrl+C)",
            signal.SIGTERM: "SIGTERM (Termination)"
        }
        
        signal_name = signal_names.get(signum, f"Signal {signum}")
        print(f"\n🛑 Received {signal_name}, initiating graceful shutdown...", file=sys.stderr)
        
        # The actual shutdown logic is handled by the IDSApplication class
        # This handler just ensures we exit cleanly
        sys.exit(0)
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # On Windows, also handle SIGBREAK (Ctrl+Break)
    if platform.system() == "Windows":
        try:
            signal.signal(signal.SIGBREAK, signal_handler)
        except AttributeError:
            # SIGBREAK might not be available on all Windows versions
            pass


def print_startup_info() -> None:
    """Print startup information and privilege status."""
    print("🔒 Privilege Check:")
    if check_privileges():
        if platform.system() == "Windows":
            print("  ✅ Running with Administrator privileges")
        else:
            print("  ✅ Running with root privileges")
    else:
        print("  ⚠️  Running without elevated privileges")
        print("     Packet capture may fail!")
    print()


def main() -> int:
    """
    Main entry point for the IDS application.
    
    Performs privilege checking, sets up signal handlers, and delegates
    to the CLI main function.
    
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    try:
        # Set up signal handlers for graceful shutdown
        setup_signal_handlers()
        
        # Check for required privileges
        # Note: We require privileges but don't exit immediately to allow
        # for help/version commands that don't need packet capture
        has_privileges = check_privileges()
        
        # Check if this is a help or version request (doesn't need privileges)
        help_args = {'-h', '--help', '--version'}
        if not any(arg in help_args for arg in sys.argv[1:]):
            # Not a help request, check privileges
            if not has_privileges:
                require_privileges()
        
        # Print startup information
        if not any(arg in {'--no-banner', '-h', '--help', '--version'} for arg in sys.argv[1:]):
            print_startup_info()
        
        # Delegate to the CLI main function
        return cli_main()
        
    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user", file=sys.stderr)
        return 0
    except SystemExit as e:
        # Re-raise SystemExit to preserve exit codes
        raise
    except Exception as e:
        print(f"\n❌ Fatal error: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    # Ensure we're running with Python 3.8+
    if sys.version_info < (3, 8):
        print("❌ ERROR: Python 3.8 or higher is required", file=sys.stderr)
        print(f"Current version: {sys.version}", file=sys.stderr)
        sys.exit(1)
    
    # Run the main function and exit with its return code
    sys.exit(main())