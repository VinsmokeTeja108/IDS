"""
WebSocket event handlers for real-time communication.

This module implements WebSocket connection handlers and event emitters
for real-time updates to the web UI.
"""

from flask_socketio import emit, disconnect
from flask import request
import logging

logger = logging.getLogger(__name__)

# Global reference to SocketIO instance
socketio_instance = None
ids_controller_instance = None


def register_events(socketio, ids_controller):
    """
    Register WebSocket event handlers.
    
    Args:
        socketio: SocketIO instance
        ids_controller: IDSController instance for managing IDS operations
    """
    global socketio_instance, ids_controller_instance
    socketio_instance = socketio
    ids_controller_instance = ids_controller
    
    # Connect EventBus to WebSocket emitters
    if ids_controller and hasattr(ids_controller, 'event_bus'):
        _connect_event_bus_to_websocket(ids_controller.event_bus)
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        client_id = request.sid
        logger.info(f"Client connected: {client_id}")
        
        # Send initial connection acknowledgment
        emit('connection_established', {
            'status': 'connected',
            'message': 'Successfully connected to IDS Web UI'
        })
        
        # Send current IDS status to newly connected client
        try:
            if ids_controller_instance:
                status = ids_controller_instance.get_status()
                emit('status_changed', status)
        except Exception as e:
            logger.error(f"Error sending initial status to client {client_id}: {e}")
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection"""
        client_id = request.sid
        logger.info(f"Client disconnected: {client_id}")
    
    @socketio.on('error')
    def handle_error(error):
        """Handle WebSocket errors"""
        client_id = request.sid
        logger.error(f"WebSocket error from client {client_id}: {error}")
    
    @socketio.on('ping')
    def handle_ping(data=None):
        """Handle ping from client for connection health check"""
        timestamp = data.get('timestamp', '') if data else ''
        emit('pong', {'timestamp': timestamp})


def emit_threat_detected(threat_data):
    """
    Emit threat_detected event to all connected clients.
    
    Args:
        threat_data: Dictionary containing threat information
    """
    if socketio_instance:
        socketio_instance.emit('threat_detected', threat_data)
        logger.debug(f"Emitted threat_detected event: {threat_data.get('type', 'unknown')}")


def emit_status_changed(status_data):
    """
    Emit status_changed event to all connected clients.
    
    Args:
        status_data: Dictionary containing IDS status information
    """
    if socketio_instance:
        socketio_instance.emit('status_changed', status_data)
        logger.debug(f"Emitted status_changed event: {status_data.get('running', 'unknown')}")


def emit_stats_updated(stats_data):
    """
    Emit stats_updated event to all connected clients.
    
    Args:
        stats_data: Dictionary containing statistics information
    """
    if socketio_instance:
        socketio_instance.emit('stats_updated', stats_data)
        logger.debug("Emitted stats_updated event")


def emit_notification_sent(notification_data):
    """
    Emit notification_sent event to all connected clients.
    
    Args:
        notification_data: Dictionary containing notification information
    """
    if socketio_instance:
        socketio_instance.emit('notification_sent', notification_data)
        logger.debug("Emitted notification_sent event")


def _connect_event_bus_to_websocket(event_bus):
    """
    Connect EventBus to WebSocket emitters.
    
    This function subscribes to the EventBus and routes events to the
    appropriate WebSocket emitter functions.
    
    Args:
        event_bus: EventBus instance to subscribe to
    """
    def event_handler(event_type, data):
        """
        Handle events from EventBus and emit them via WebSocket.
        
        Args:
            event_type: Type of event (threat_detected, status_changed, etc.)
            data: Event data dictionary
        """
        try:
            if event_type == 'threat_detected':
                emit_threat_detected(data)
            elif event_type == 'status_changed':
                emit_status_changed(data)
            elif event_type == 'stats_updated':
                emit_stats_updated(data)
            elif event_type == 'notification_sent':
                emit_notification_sent(data)
            else:
                logger.warning(f"Unknown event type received: {event_type}")
        except Exception as e:
            logger.error(f"Error handling event {event_type}: {e}")
    
    # Subscribe to EventBus
    event_bus.subscribe(event_handler)
    logger.info("EventBus connected to WebSocket emitters")
