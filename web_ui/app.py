"""
Flask application entry point for IDS Web UI.

This module initializes the Flask application, configures routes,
and sets up WebSocket communication for real-time updates.
"""

import os
from flask import Flask, render_template
from flask_socketio import SocketIO
from flask_cors import CORS

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'ids-web-ui-secret-key-change-in-production')

# Enable CORS for API endpoints
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Initialize SocketIO for WebSocket support
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global reference to IDS controller (will be set during initialization)
ids_controller = None


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


if __name__ == '__main__':
    # Development server (not for production)
    print("Starting IDS Web UI in development mode...")
    print("Access the UI at: http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
