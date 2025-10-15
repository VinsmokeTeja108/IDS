"""
EventBus for real-time event broadcasting.

This module provides an event bus implementation for broadcasting IDS events
to WebSocket clients in real-time. It supports subscribing to events and
publishing events to all registered subscribers.
"""

from typing import Callable, List, Dict, Any
from datetime import datetime
import logging


class EventBus:
    """
    Event bus for broadcasting IDS events to WebSocket clients.
    
    The EventBus allows components to subscribe to events and publishes
    events to all registered subscribers. It handles threat detection,
    status changes, and statistics updates.
    """
    
    def __init__(self):
        """Initialize the event bus with an empty subscriber list."""
        self.subscribers: List[Callable] = []
        self.logger = logging.getLogger(__name__)
        self.logger.info("EventBus initialized")
    
    def subscribe(self, callback: Callable[[str, Dict[str, Any]], None]) -> None:
        """
        Register an event listener to receive events.
        
        Args:
            callback: A callable that accepts event_type (str) and data (dict)
                     as parameters. This callback will be invoked when events
                     are published.
        
        Example:
            def my_handler(event_type, data):
                print(f"Received {event_type}: {data}")
            
            event_bus.subscribe(my_handler)
        """
        if callback not in self.subscribers:
            self.subscribers.append(callback)
            self.logger.debug(f"Subscriber registered: {callback.__name__}")
        else:
            self.logger.warning(f"Subscriber already registered: {callback.__name__}")
    
    def unsubscribe(self, callback: Callable[[str, Dict[str, Any]], None]) -> None:
        """
        Unregister an event listener.
        
        Args:
            callback: The callback function to remove from subscribers
        """
        if callback in self.subscribers:
            self.subscribers.remove(callback)
            self.logger.debug(f"Subscriber unregistered: {callback.__name__}")
        else:
            self.logger.warning(f"Subscriber not found: {callback.__name__}")
    
    def publish(self, event_type: str, data: Dict[str, Any]) -> None:
        """
        Broadcast an event to all registered subscribers.
        
        Args:
            event_type: The type of event being published (e.g., 'threat_detected',
                       'status_changed', 'stats_updated')
            data: Dictionary containing event data to be sent to subscribers
        
        Example:
            event_bus.publish('threat_detected', {
                'threat_id': '123',
                'severity': 'high',
                'type': 'port_scan'
            })
        """
        self.logger.debug(f"Publishing event: {event_type} to {len(self.subscribers)} subscribers")
        
        # Add timestamp to event data if not present
        if 'timestamp' not in data:
            data['timestamp'] = datetime.utcnow().isoformat()
        
        # Notify all subscribers
        for subscriber in self.subscribers:
            try:
                subscriber(event_type, data)
            except Exception as e:
                self.logger.error(f"Error notifying subscriber {subscriber.__name__}: {e}")
    
    def on_threat_detected(self, threat_analysis) -> None:
        """
        Event handler for threat detection events.
        
        This method is called when the IDS detects a threat. It formats
        the threat data and publishes it to all subscribers.
        
        Args:
            threat_analysis: ThreatAnalysis object containing threat details
        """
        try:
            # Format threat data for transmission
            threat_data = {
                'id': str(id(threat_analysis)),  # Generate unique ID
                'timestamp': threat_analysis.timestamp.isoformat() if hasattr(threat_analysis.timestamp, 'isoformat') else str(threat_analysis.timestamp),
                'type': threat_analysis.threat_type,
                'severity': threat_analysis.severity,
                'source_ip': threat_analysis.source_ip,
                'destination_ip': getattr(threat_analysis, 'destination_ip', None),
                'protocol': getattr(threat_analysis, 'protocol', 'Unknown'),
                'description': threat_analysis.description,
                'recommendations': threat_analysis.recommendations,
                'justification': threat_analysis.justification
            }
            
            self.logger.info(f"Threat detected: {threat_data['type']} from {threat_data['source_ip']}")
            self.publish('threat_detected', threat_data)
            
        except Exception as e:
            self.logger.error(f"Error handling threat detection event: {e}")
    
    def on_status_changed(self, status: str, details: Dict[str, Any] = None) -> None:
        """
        Event handler for IDS status change events.
        
        This method is called when the IDS status changes (e.g., started,
        stopped, error). It publishes the status change to all subscribers.
        
        Args:
            status: The new status (e.g., 'running', 'stopped', 'error')
            details: Optional dictionary with additional status details
        """
        try:
            status_data = {
                'status': status,
                'details': details or {}
            }
            
            self.logger.info(f"Status changed: {status}")
            self.publish('status_changed', status_data)
            
        except Exception as e:
            self.logger.error(f"Error handling status change event: {e}")
    
    def on_stats_updated(self, statistics: Dict[str, Any]) -> None:
        """
        Event handler for statistics update events.
        
        This method is called when threat statistics are updated. It publishes
        the updated statistics to all subscribers for dashboard updates.
        
        Args:
            statistics: Dictionary containing updated statistics (threat counts,
                       severity distribution, etc.)
        """
        try:
            stats_data = {
                'statistics': statistics
            }
            
            self.logger.debug(f"Statistics updated: {statistics}")
            self.publish('stats_updated', stats_data)
            
        except Exception as e:
            self.logger.error(f"Error handling statistics update event: {e}")
    
    def on_notification_sent(self, notification_info: Dict[str, Any]) -> None:
        """
        Event handler for notification sent events.
        
        This method is called when an email notification is sent. It publishes
        the notification information to all subscribers.
        
        Args:
            notification_info: Dictionary containing notification details
                             (recipients, status, timestamp, etc.)
        """
        try:
            notification_data = {
                'notification': notification_info
            }
            
            self.logger.info(f"Notification sent: {notification_info.get('status', 'unknown')}")
            self.publish('notification_sent', notification_data)
            
        except Exception as e:
            self.logger.error(f"Error handling notification sent event: {e}")
    
    def get_subscriber_count(self) -> int:
        """
        Get the number of registered subscribers.
        
        Returns:
            int: Number of active subscribers
        """
        return len(self.subscribers)
    
    def clear_subscribers(self) -> None:
        """
        Remove all registered subscribers.
        
        This is useful for cleanup or testing purposes.
        """
        count = len(self.subscribers)
        self.subscribers.clear()
        self.logger.info(f"Cleared {count} subscribers")
