#!/usr/bin/env python3
"""
Integrated IDS + Web UI Startup Script

This script starts both the IDS monitoring system and the web UI in an
integrated manner. The IDS runs in a background thread while the Flask
web server runs in the main thread, allowing real-time monitoring and
control through the web interface.

Usage:
    python run_ids_with_ui.py [options]

Examples:
    # Start with default settings
    python run_ids_with_ui.py
    
    # Start on specific host and port
    python run_ids_with_ui.py --host 0.0.0.0 --port 8080
    
    # Start with custom config file
    python run_ids_with_ui.py --config /path/to/config.yaml
    
    # Start with IDS monitoring enabled by default
    python run_ids_with_ui.py --auto-start
"""

import sys
import signal
import argparse
import logging
from pathlib import Path

from flask_socketio import SocketIO
from web_ui.app import app, init_app
from web_ui.controllers.ids_controller import IDSController
from web_ui.controllers.event_bus import EventBus
from web_ui.controllers.threat_store import ThreatStore

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global references for graceful shutdown
ids_controller = None
socketio = None


def parse_arguments():
    """
    Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed command-line arguments
    """
    parser = argparse.ArgumentParser(
        description='Integrated IDS + Web UI - Start IDS monitoring with web interface',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start with default settings (IDS not started automatically)
  python run_ids_with_ui.py
  
  # Start with IDS monitoring enabled
  python run_ids_with_ui.py --auto-start
  
  # Start on specific host and port
  python run_ids_with_ui.py --host 0.0.0.0 --port 8080
  
  # Start with custom config file
  python run_ids_with_ui.py --config /path/to/config.yaml
  
  # Start in debug mode
  python run_ids_with_ui.py --debug

Note:
  The IDS monitoring can be started/stopped through the web interface
  even if --auto-start is not specified.
        """
    )
    
    parser.add_argument(
        '--host',
        type=str,
        default='0.0.0.0',
        help='Host to bind the web server to (default: 0.0.0.0)'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Port to bind the web server to (default: 5000)'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        default='config.yaml',
        help='Path to IDS configuration file (default: config.yaml)'
    )
    
    parser.add_argument(
        '--auto-start',
        action='store_true',
        help='Automatically start IDS monitoring on startup'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Run in debug mode (not recommended for production)'
    )
    
    parser.add_argument(
        '--log-level',
        type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Logging level (default: INFO)'
    )
    
    return parser.parse_args()


def signal_handler(signum, frame):
    """
    Handle shutdown signals (SIGINT, SIGTERM) for graceful shutdown.
    
    Args:
        signum: Signal number
        frame: Current stack frame
    """
    logger.info(f"\nReceived signal {signum}, initiating graceful shutdown...")
    
    # Stop IDS monitoring if running
    if ids_controller and ids_controller.ids_app and ids_controller.ids_app.is_running:
        logger.info("Stopping IDS monitoring...")
        try:
            ids_controller.stop_monitoring()
            logger.info("IDS monitoring stopped successfully")
        except Exception as e:
            logger.error(f"Error stopping IDS monitoring: {e}")
    
    logger.info("Shutdown complete")
    sys.exit(0)


def main():
    """
    Main entry point for the integrated IDS + Web UI application.
    
    This function:
    1. Parses command-line arguments
    2. Validates configuration
    3. Initializes EventBus and ThreatStore
    4. Creates IDSController
    5. Initializes Flask application
    6. Optionally starts IDS monitoring
    7. Starts Flask web server in main thread
    8. Handles graceful shutdown
    """
    global ids_controller, socketio
    
    # Parse command-line arguments
    args = parse_arguments()
    
    # Configure logging level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Validate configuration file
    config_path = Path(args.config)
    if not config_path.exists():
        logger.error(f"Configuration file not found: {config_path}")
        logger.error("Please create a configuration file or specify a valid path with --config")
        logger.error("You can copy config.yaml.example to config.yaml and modify it")
        sys.exit(1)
    
    # Print startup banner
    logger.info("=" * 70)
    logger.info("  IDS + Web UI - Integrated Intrusion Detection System")
    logger.info("=" * 70)
    logger.info(f"Configuration file: {config_path.absolute()}")
    logger.info(f"Web server host:    {args.host}")
    logger.info(f"Web server port:    {args.port}")
    logger.info(f"Auto-start IDS:     {args.auto_start}")
    logger.info(f"Debug mode:         {args.debug}")
    logger.info(f"Log level:          {args.log_level}")
    logger.info("=" * 70)
    
    try:
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Initialize EventBus for real-time event broadcasting
        logger.info("Initializing EventBus...")
        event_bus = EventBus()
        
        # Initialize ThreatStore for in-memory threat storage
        logger.info("Initializing ThreatStore...")
        threat_store = ThreatStore(max_threats=1000)
        
        # Initialize IDS controller
        logger.info("Initializing IDS controller...")
        ids_controller = IDSController(
            config_path=str(config_path.absolute()),
            event_bus=event_bus,
            threat_store=threat_store
        )
        
        # Initialize Flask app with controller
        logger.info("Initializing Flask application...")
        init_app(ids_controller)
        
        # Get SocketIO instance from app module
        from web_ui.app import socketio as app_socketio
        socketio = app_socketio
        
        # Auto-start IDS monitoring if requested
        if args.auto_start:
            logger.info("Auto-starting IDS monitoring...")
            result = ids_controller.start_monitoring()
            if result['success']:
                logger.info("IDS monitoring started successfully")
            else:
                logger.warning(f"Failed to auto-start IDS monitoring: {result['message']}")
                logger.info("You can start monitoring through the web interface")
        else:
            logger.info("IDS monitoring not started automatically")
            logger.info("Use the web interface to start monitoring")
        
        logger.info("=" * 70)
        logger.info(f"Web UI is now available at: http://{args.host}:{args.port}")
        logger.info("=" * 70)
        logger.info("Features:")
        logger.info("  - Real-time threat monitoring")
        logger.info("  - System control (start/stop/restart)")
        logger.info("  - Threat analytics and statistics")
        logger.info("  - Configuration management")
        logger.info("  - System logs viewer")
        logger.info("  - Detector management")
        logger.info("=" * 70)
        logger.info("Press Ctrl+C to stop the server")
        logger.info("=" * 70)
        
        # Start Flask-SocketIO server in main thread
        socketio.run(
            app,
            host=args.host,
            port=args.port,
            debug=args.debug,
            use_reloader=False,  # Disable reloader to prevent duplicate threads
            log_output=True
        )
    
    except KeyboardInterrupt:
        # This should be caught by signal_handler, but just in case
        logger.info("\nShutting down...")
        signal_handler(signal.SIGINT, None)
    
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        
        # Attempt to stop IDS monitoring on error
        if ids_controller and ids_controller.ids_app and ids_controller.ids_app.is_running:
            logger.info("Attempting to stop IDS monitoring...")
            try:
                ids_controller.stop_monitoring()
            except Exception as stop_error:
                logger.error(f"Error stopping IDS monitoring: {stop_error}")
        
        sys.exit(1)


if __name__ == '__main__':
    main()
