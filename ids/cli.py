"""Command-line interface for the IDS application"""

import argparse
import sys
import platform
import os
from datetime import datetime
from typing import Optional

from ids.ids_application import IDSApplication
from ids.models.exceptions import IDSException, ConfigurationException


def print_banner() -> None:
    """Print the IDS startup banner with system information."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   Intrusion Detection System (IDS)                           ║
║   Network Threat Monitoring & Analysis                       ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)
    
    # System information
    print("System Information:")
    print(f"  Platform: {platform.system()} {platform.release()}")
    print(f"  Architecture: {platform.machine()}")
    print(f"  Python Version: {platform.python_version()}")
    print(f"  Hostname: {platform.node()}")
    print(f"  Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()


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
        except:
            return False
    else:
        # Unix-like systems
        return os.geteuid() == 0


def create_parser() -> argparse.ArgumentParser:
    """
    Create and configure the argument parser.
    
    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog='ids',
        description='Intrusion Detection System - Network threat monitoring and analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -c config.yaml -i eth0
  %(prog)s --config config.yaml --interface wlan0 --verbose
  %(prog)s -c config.yaml -i eth0 --dry-run
  
Note: This application requires root/administrator privileges for packet capture.
        """
    )
    
    # Required arguments
    parser.add_argument(
        '-c', '--config',
        type=str,
        default='config.yaml',
        metavar='FILE',
        help='Path to configuration file (default: config.yaml)'
    )
    
    parser.add_argument(
        '-i', '--interface',
        type=str,
        metavar='INTERFACE',
        help='Network interface to monitor (overrides config file)'
    )
    
    # Optional arguments
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging output'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Run in dry-run mode (no emails sent, logging only)'
    )
    
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Suppress startup banner'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )
    
    return parser


def validate_arguments(args: argparse.Namespace) -> bool:
    """
    Validate command-line arguments.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        True if arguments are valid, False otherwise
    """
    # Check if config file exists
    if not os.path.isfile(args.config):
        print(f"Error: Configuration file not found: {args.config}", file=sys.stderr)
        return False
    
    return True


def main() -> int:
    """
    Main entry point for the IDS CLI.
    
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    # Parse command-line arguments
    parser = create_parser()
    args = parser.parse_args()
    
    # Print banner unless suppressed
    if not args.no_banner:
        print_banner()
    
    # Validate arguments
    if not validate_arguments(args):
        return 1
    
    # Check privileges
    if not check_privileges():
        print("WARNING: Not running with administrator/root privileges.", file=sys.stderr)
        print("Packet capture may fail without sufficient privileges.", file=sys.stderr)
        print()
    
    # Display configuration
    print("Configuration:")
    print(f"  Config File: {args.config}")
    if args.interface:
        print(f"  Network Interface: {args.interface} (override)")
    print(f"  Verbose Mode: {'Enabled' if args.verbose else 'Disabled'}")
    print(f"  Dry-Run Mode: {'Enabled' if args.dry_run else 'Disabled'}")
    print()
    
    if args.dry_run:
        print("⚠ DRY-RUN MODE: No email notifications will be sent")
        print()
    
    try:
        # Initialize IDS application
        ids_app = IDSApplication(args.config)
        
        # Apply CLI overrides
        if args.verbose:
            print("Verbose logging enabled")
        
        if args.dry_run:
            print("Dry-run mode enabled - notifications disabled")
        
        # Initialize components
        ids_app.initialize()
        
        # Override interface if specified
        if args.interface:
            ids_app.config_manager.config.detection_config['network_interface'] = args.interface
            print(f"Network interface overridden to: {args.interface}")
        
        # Apply dry-run mode if enabled
        if args.dry_run:
            # Disable email notifications in dry-run mode
            if ids_app.notification_service:
                ids_app.notification_service._dry_run = True
        
        # Apply verbose mode if enabled
        if args.verbose:
            if ids_app.logger:
                ids_app.logger.set_level('DEBUG')
        
        # Run the IDS
        ids_app.run()
        
        return 0
        
    except ConfigurationException as e:
        print(f"\n❌ Configuration Error: {e}", file=sys.stderr)
        return 2
    except IDSException as e:
        print(f"\n❌ IDS Error: {e}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        return 0
    except Exception as e:
        print(f"\n❌ Unexpected Error: {e}", file=sys.stderr)
        import traceback
        if args.verbose:
            traceback.print_exc()
        return 4


if __name__ == '__main__':
    sys.exit(main())
