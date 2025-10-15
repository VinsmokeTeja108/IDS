"""
Flask application entry point for IDS Web UI.

This module initializes the Flask application, configures routes,
and sets up WebSocket communication for real-time updates.
"""

import os
import sys
import argparse
import logging
from pathlib import Path
from flask import Flask, render_template
from flask_socketio import SocketIO
from flask_cors import CORS

from web_ui.controllers.ids_controller import IDSController
from web_ui.controllers.event_bus import EventBus
from web_ui.controllers.threat_store import ThreatStore

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'ids-web-ui-secret-key-change-in-production')

# Enable CORS for API endpoints
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Initialize SocketIO for WebSocket support
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global reference to IDS controller (will be set during initialization)
ids_controller = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def init_app(controller):
    """
    Initialize the Flask app with IDS controller.
    
    Args:
        controller: IDSController instance for managing IDS operations
    """
    global ids_controller
    ids_controller = controller
    
    # Register API routes
    from web_ui.api import routes
    routes.register_routes(app, ids_controller)
    
    # Register WebSocket events
    from web_ui.api import websocket_events
    websocket_events.register_events(socketio, ids_controller)
    
    logger.info("Flask application initialized successfully")


@app.route('/')
def index():
    """Redirect to dashboard"""
    return render_template('dashboard.html')


@app.route('/dashboard')
def dashboard():
    """Dashboard page"""
    return render_template('dashboard.html')


@app.route('/threats')
def threats():
    """Threats page"""
    return render_template('threats.html')


@app.route('/analytics')
def analytics():
    """Analytics page"""
    return render_template('analytics.html')


@app.route('/config')
def config():
    """Configuration page"""
    return render_template('config.html')


@app.route('/logs')
def logs():
    """Logs page"""
    return render_template('logs.html')


def parse_arguments():
    """
    Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed command-line arguments
    """
    parser = argparse.ArgumentParser(
        description='IDS Web UI - Web interface for Intrusion Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start with default settings
  python -m web_ui.app
  
  # Start on specific host and port
  python -m web_ui.app --host 0.0.0.0 --port 8080
  
  # Start with custom config file
  python -m web_ui.app --config /path/to/config.yaml
  
  # Start in debug mode
  python -m web_ui.app --debug
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


def main():
    """
    Main entry point for the Flask application.
    
    Parses command-line arguments, initializes the IDS controller,
    and starts the Flask web server with SocketIO support.
    """
    # Parse command-line arguments
    args = parse_arguments()
    
    # Configure logging level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Validate configuration file
    config_path = Path(args.config)
    if not config_path.exists():
        logger.error(f"Configuration file not found: {config_path}")
        logger.error("Please create a configuration file or specify a valid path with --config")
        sys.exit(1)
    
    logger.info("=" * 60)
    logger.info("IDS Web UI - Intrusion Detection System Web Interface")
    logger.info("=" * 60)
    logger.info(f"Configuration file: {config_path.absolute()}")
    logger.info(f"Host: {args.host}")
    logger.info(f"Port: {args.port}")
    logger.info(f"Debug mode: {args.debug}")
    logger.info(f"Log level: {args.log_level}")
    logger.info("=" * 60)
    
    try:
        # Initialize EventBus and ThreatStore
        event_bus = EventBus()
        threat_store = ThreatStore()
        
        # Initialize IDS controller
        controller = IDSController(
            config_path=str(config_path.absolute()),
            event_bus=event_bus,
            threat_store=threat_store
        )
        
        # Initialize Flask app with controller
        init_app(controller)
        
        logger.info("Starting Flask web server...")
        logger.info(f"Access the web UI at: http://{args.host}:{args.port}")
        logger.info("Press Ctrl+C to stop the server")
        logger.info("=" * 60)
        
        # Start Flask-SocketIO server
        socketio.run(
            app,
            host=args.host,
            port=args.port,
            debug=args.debug,
            use_reloader=False  # Disable reloader to prevent duplicate threads
        )
    
    except KeyboardInterrupt:
        logger.info("\nShutting down web server...")
        if ids_controller and ids_controller.ids_app and ids_controller.ids_app.is_running:
            logger.info("Stopping IDS monitoring...")
            ids_controller.stop_monitoring()
        logger.info("Web server stopped")
        sys.exit(0)
    
    except Exception as e:
        logger.error(f"Failed to start web server: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
