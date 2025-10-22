"""
Flask API routes for IDS Web UI.

This module defines all REST API endpoints for controlling the IDS,
retrieving threats, managing configuration, and accessing logs.
"""

from flask import Blueprint, jsonify, request
from typing import Optional
import logging

# Logger for API routes
logger = logging.getLogger(__name__)

# Global reference to IDS controller (set during initialization)
ids_controller = None


def register_routes(app, controller):
    """
    Register all API routes with the Flask application.
    
    Args:
        app: Flask application instance
        controller: IDSController instance for managing IDS operations
    """
    global ids_controller
    ids_controller = controller
    
    # System control endpoints
    app.add_url_rule('/api/status', 'get_status', get_status, methods=['GET'])
    app.add_url_rule('/api/start', 'start_monitoring', start_monitoring, methods=['POST'])
    app.add_url_rule('/api/stop', 'stop_monitoring', stop_monitoring, methods=['POST'])
    app.add_url_rule('/api/restart', 'restart_monitoring', restart_monitoring, methods=['POST'])
    
    # Threats endpoints
    app.add_url_rule('/api/threats', 'get_threats', get_threats, methods=['GET'])
    app.add_url_rule('/api/threats/<threat_id>', 'get_threat_by_id', get_threat_by_id, methods=['GET'])
    app.add_url_rule('/api/threats/<threat_id>', 'delete_threat', delete_threat, methods=['DELETE'])
    app.add_url_rule('/api/threats', 'clear_all_threats', clear_all_threats, methods=['DELETE'])
    app.add_url_rule('/api/threats/stats', 'get_threat_stats', get_threat_stats, methods=['GET'])
    
    # Configuration endpoints
    app.add_url_rule('/api/config', 'get_config', get_config, methods=['GET'])
    app.add_url_rule('/api/config', 'update_config', update_config, methods=['PUT'])
    app.add_url_rule('/api/config/test-email', 'test_email', test_email, methods=['POST'])
    
    # Detector management endpoints
    app.add_url_rule('/api/detectors', 'get_detectors', get_detectors, methods=['GET'])
    app.add_url_rule('/api/detectors/<detector_name>', 'toggle_detector', toggle_detector_endpoint, methods=['PUT'])
    
    # Logs endpoints
    app.add_url_rule('/api/logs', 'get_logs', get_logs, methods=['GET'])
    app.add_url_rule('/api/logs/search', 'search_logs', search_logs, methods=['GET'])
    
    # Notifications endpoints
    app.add_url_rule('/api/notifications', 'get_notifications', get_notifications, methods=['GET'])
    app.add_url_rule('/api/notifications/settings', 'update_notification_settings', update_notification_settings, methods=['PUT'])
    
    # Analytics endpoints
    app.add_url_rule('/api/analytics/summary', 'get_analytics_summary', get_analytics_summary, methods=['GET'])
    app.add_url_rule('/api/analytics/timeline', 'get_analytics_timeline', get_analytics_timeline, methods=['GET'])
    
    # Diagnostic endpoint
    app.add_url_rule('/api/diagnostic', 'get_diagnostic', get_diagnostic, methods=['GET'])
    
    logger.info("API routes registered successfully")


# ============================================================================
# System Control API Endpoints
# ============================================================================

def get_status():
    """
    GET /api/status
    
    Retrieve current IDS status including running state, network interface,
    uptime, packet count, and threat count.
    
    Returns:
        JSON response with status information:
        {
            "running": bool,
            "interface": str,
            "uptime": int,
            "uptime_formatted": str,
            "packet_count": int,
            "threat_count": int,
            "start_time": str
        }
    
    Status Codes:
        200: Success
        500: Internal server error
    """
    try:
        status = ids_controller.get_status()
        logger.debug(f"Status retrieved: running={status['running']}")
        return jsonify(status), 200
    
    except Exception as e:
        logger.error(f"Error retrieving status: {e}")
        return jsonify({
            'error': 'Failed to retrieve status',
            'message': str(e)
        }), 500


def start_monitoring():
    """
    POST /api/start
    
    Start IDS monitoring. Initializes the IDS application and begins
    packet capture and threat detection in a background thread.
    
    Returns:
        JSON response with operation result:
        {
            "success": bool,
            "message": str,
            "status": dict
        }
    
    Status Codes:
        200: Monitoring started successfully
        400: Monitoring already running
        500: Failed to start monitoring
    """
    try:
        result = ids_controller.start_monitoring()
        
        if result['success']:
            logger.info("Monitoring started successfully")
            return jsonify(result), 200
        else:
            logger.warning(f"Failed to start monitoring: {result['message']}")
            return jsonify(result), 400
    
    except Exception as e:
        logger.error(f"Error starting monitoring: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to start monitoring',
            'message': str(e)
        }), 500


def stop_monitoring():
    """
    POST /api/stop
    
    Stop IDS monitoring. Gracefully shuts down packet capture and
    the IDS application.
    
    Returns:
        JSON response with operation result:
        {
            "success": bool,
            "message": str,
            "status": dict
        }
    
    Status Codes:
        200: Monitoring stopped successfully
        400: Monitoring not running
        500: Failed to stop monitoring
    """
    try:
        result = ids_controller.stop_monitoring()
        
        if result['success']:
            logger.info("Monitoring stopped successfully")
            return jsonify(result), 200
        else:
            logger.warning(f"Failed to stop monitoring: {result['message']}")
            return jsonify(result), 400
    
    except Exception as e:
        logger.error(f"Error stopping monitoring: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to stop monitoring',
            'message': str(e)
        }), 500


def restart_monitoring():
    """
    POST /api/restart
    
    Restart IDS monitoring. Stops the current monitoring session and
    starts a new one, reloading configuration.
    
    Returns:
        JSON response with operation result:
        {
            "success": bool,
            "message": str,
            "status": dict
        }
    
    Status Codes:
        200: Monitoring restarted successfully
        500: Failed to restart monitoring
    """
    try:
        logger.info("Restarting monitoring...")
        
        # Stop monitoring if running
        if ids_controller.ids_app and ids_controller.ids_app.is_running:
            stop_result = ids_controller.stop_monitoring()
            if not stop_result['success']:
                return jsonify({
                    'success': False,
                    'message': f"Failed to stop monitoring: {stop_result['message']}",
                    'status': ids_controller.get_status()
                }), 500
        
        # Start monitoring
        start_result = ids_controller.start_monitoring()
        
        if start_result['success']:
            logger.info("Monitoring restarted successfully")
            return jsonify({
                'success': True,
                'message': 'IDS monitoring restarted successfully',
                'status': start_result['status']
            }), 200
        else:
            logger.error(f"Failed to restart monitoring: {start_result['message']}")
            return jsonify({
                'success': False,
                'message': f"Failed to restart monitoring: {start_result['message']}",
                'status': start_result['status']
            }), 500
    
    except Exception as e:
        logger.error(f"Error restarting monitoring: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to restart monitoring',
            'message': str(e)
        }), 500



# ============================================================================
# Threats API Endpoints
# ============================================================================

def get_threats():
    """
    GET /api/threats
    
    Retrieve detected threats with optional filtering by type, severity,
    time range, and limit.
    
    Query Parameters:
        type: str or comma-separated list - Filter by threat type(s)
        severity: str or comma-separated list - Filter by severity level(s)
        start_time: str (ISO format) - Filter threats after this time
        end_time: str (ISO format) - Filter threats before this time
        limit: int - Maximum number of threats to return
        source_ip: str - Filter by source IP address
    
    Returns:
        JSON response with list of threats:
        {
            "threats": [
                {
                    "id": str,
                    "timestamp": str,
                    "type": str,
                    "severity": str,
                    "source_ip": str,
                    "destination_ip": str,
                    "protocol": str,
                    "description": str,
                    "recommendations": list,
                    "justification": str
                },
                ...
            ],
            "count": int
        }
    
    Status Codes:
        200: Success
        400: Invalid query parameters
        500: Internal server error
    
    Example:
        GET /api/threats?severity=high&limit=10
        GET /api/threats?type=port_scan,icmp_scan&source_ip=192.168.1.100
    """
    try:
        # Parse query parameters
        filters = {}
        
        # Type filter
        if 'type' in request.args:
            type_param = request.args.get('type')
            filters['type'] = type_param.split(',') if ',' in type_param else type_param
        
        # Severity filter
        if 'severity' in request.args:
            severity_param = request.args.get('severity')
            filters['severity'] = severity_param.split(',') if ',' in severity_param else severity_param
        
        # Time range filters
        if 'start_time' in request.args:
            filters['start_time'] = request.args.get('start_time')
        
        if 'end_time' in request.args:
            filters['end_time'] = request.args.get('end_time')
        
        # Limit filter
        if 'limit' in request.args:
            try:
                filters['limit'] = int(request.args.get('limit'))
            except ValueError:
                return jsonify({
                    'error': 'Invalid limit parameter',
                    'message': 'Limit must be an integer'
                }), 400
        
        # Source IP filter
        if 'source_ip' in request.args:
            filters['source_ip'] = request.args.get('source_ip')
        
        # Retrieve threats with filters
        threats = ids_controller.get_threats(filters)
        
        logger.debug(f"Retrieved {len(threats)} threats with filters: {filters}")
        
        return jsonify({
            'threats': threats,
            'count': len(threats)
        }), 200
    
    except Exception as e:
        logger.error(f"Error retrieving threats: {e}")
        return jsonify({
            'error': 'Failed to retrieve threats',
            'message': str(e)
        }), 500


def get_threat_by_id(threat_id: str):
    """
    GET /api/threats/<id>
    
    Retrieve detailed information for a specific threat by ID.
    
    Args:
        threat_id: Unique identifier of the threat
    
    Returns:
        JSON response with threat details:
        {
            "id": str,
            "timestamp": str,
            "type": str,
            "severity": str,
            "source_ip": str,
            "destination_ip": str,
            "protocol": str,
            "classification": str,
            "description": str,
            "recommendations": list,
            "justification": str,
            "raw_data": dict
        }
    
    Status Codes:
        200: Success
        404: Threat not found
        500: Internal server error
    
    Example:
        GET /api/threats/123e4567-e89b-12d3-a456-426614174000
    """
    try:
        threat = ids_controller.threat_store.get_threat_by_id(threat_id)
        
        if threat:
            logger.debug(f"Retrieved threat by ID: {threat_id}")
            return jsonify(threat), 200
        else:
            logger.warning(f"Threat not found: {threat_id}")
            return jsonify({
                'error': 'Threat not found',
                'message': f'No threat found with ID: {threat_id}'
            }), 404
    
    except Exception as e:
        logger.error(f"Error retrieving threat {threat_id}: {e}")
        return jsonify({
            'error': 'Failed to retrieve threat',
            'message': str(e)
        }), 500


def delete_threat(threat_id: str):
    """
    DELETE /api/threats/<id>
    
    Delete a specific threat by ID.
    
    Args:
        threat_id: Unique identifier of the threat to delete
    
    Returns:
        JSON response with operation result
    
    Status Codes:
        200: Threat deleted successfully
        404: Threat not found
        500: Internal server error
    """
    try:
        success = ids_controller.threat_store.delete_threat(threat_id)
        
        if success:
            logger.info(f"Deleted threat: {threat_id}")
            return jsonify({
                'success': True,
                'message': 'Threat deleted successfully',
                'threat_id': threat_id
            }), 200
        else:
            logger.warning(f"Threat not found for deletion: {threat_id}")
            return jsonify({
                'success': False,
                'error': 'Threat not found',
                'message': f'No threat found with ID: {threat_id}'
            }), 404
    
    except Exception as e:
        logger.error(f"Error deleting threat {threat_id}: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to delete threat',
            'message': str(e)
        }), 500


def clear_all_threats():
    """
    DELETE /api/threats
    
    Clear all threats from the threat store.
    
    Returns:
        JSON response with operation result
    
    Status Codes:
        200: All threats cleared successfully
        500: Internal server error
    """
    try:
        count = ids_controller.threat_store.clear_all()
        
        logger.info(f"Cleared all threats: {count} threats removed")
        return jsonify({
            'success': True,
            'message': f'All threats cleared successfully',
            'count': count
        }), 200
    
    except Exception as e:
        logger.error(f"Error clearing all threats: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to clear threats',
            'message': str(e)
        }), 500


def get_threat_stats():
    """
    GET /api/threats/stats
    
    Retrieve threat statistics including counts by severity and type,
    top attackers, and recent activity.
    
    Returns:
        JSON response with statistics:
        {
            "total_threats": int,
            "by_severity": {
                "critical": int,
                "high": int,
                "medium": int,
                "low": int
            },
            "by_type": {
                "port_scan": int,
                "icmp_scan": int,
                ...
            },
            "top_attackers": [
                {"ip": str, "count": int},
                ...
            ],
            "recent_count": int,
            "last_threat_time": str
        }
    
    Status Codes:
        200: Success
        500: Internal server error
    
    Example:
        GET /api/threats/stats
    """
    try:
        stats = ids_controller.get_statistics()
        logger.debug(f"Retrieved threat statistics: {stats['total_threats']} total threats")
        return jsonify(stats), 200
    
    except Exception as e:
        logger.error(f"Error retrieving threat statistics: {e}")
        return jsonify({
            'error': 'Failed to retrieve threat statistics',
            'message': str(e)
        }), 500



# ============================================================================
# Configuration API Endpoints
# ============================================================================

def get_config():
    """
    GET /api/config
    
    Retrieve current IDS configuration with sensitive values masked.
    
    Returns:
        JSON response with configuration:
        {
            "email": {
                "smtp_host": str,
                "smtp_port": int,
                "username": str,
                "password": str (masked),
                "use_tls": bool,
                "recipients": list
            },
            "detection": {
                "network_interface": str,
                "port_scan_threshold": int,
                "icmp_scan_threshold": int,
                "brute_force_threshold": int,
                ...
            },
            "logging": {
                "log_file": str,
                "log_level": str,
                ...
            },
            "notification": {
                "batch_window": int,
                "batch_threshold": int,
                ...
            }
        }
    
    Status Codes:
        200: Success
        500: Internal server error
    """
    try:
        import yaml
        from pathlib import Path
        
        # Load configuration file
        config_file = Path(ids_controller.config_path)
        if not config_file.exists():
            return jsonify({
                'error': 'Configuration file not found',
                'message': f'Config file does not exist: {ids_controller.config_path}'
            }), 500
        
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f) or {}
        
        # Mask sensitive values
        if 'email' in config and 'password' in config['email']:
            config['email']['password'] = '********'
        
        logger.debug("Configuration retrieved successfully")
        return jsonify(config), 200
    
    except Exception as e:
        logger.error(f"Error retrieving configuration: {e}")
        return jsonify({
            'error': 'Failed to retrieve configuration',
            'message': str(e)
        }), 500


def update_config():
    """
    PUT /api/config
    
    Update IDS configuration settings with validation.
    
    Request Body:
        JSON object with configuration updates following the same
        structure as config.yaml. Can include partial updates.
        
        Example:
        {
            "detection": {
                "port_scan_threshold": 15
            },
            "email": {
                "recipients": ["[email]", "[email]"]
            }
        }
    
    Returns:
        JSON response with operation result:
        {
            "success": bool,
            "message": str,
            "requires_restart": bool
        }
    
    Status Codes:
        200: Configuration updated successfully
        400: Invalid configuration or validation failed
        500: Internal server error
    """
    try:
        # Get configuration updates from request body
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'Invalid request',
                'message': 'Request body must be JSON'
            }), 400
        
        config_updates = request.get_json()
        
        if not config_updates:
            return jsonify({
                'success': False,
                'error': 'Invalid request',
                'message': 'Request body cannot be empty'
            }), 400
        
        # Update configuration
        result = ids_controller.update_configuration(config_updates)
        
        if result['success']:
            logger.info(f"Configuration updated successfully: {config_updates}")
            return jsonify(result), 200
        else:
            logger.warning(f"Configuration update failed: {result['message']}")
            return jsonify(result), 400
    
    except Exception as e:
        logger.error(f"Error updating configuration: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to update configuration',
            'message': str(e)
        }), 500


def test_email():
    """
    POST /api/config/test-email
    
    Send a test email to verify email configuration settings.
    
    Request Body (optional):
        {
            "recipient": str  # Optional: specific recipient to test
        }
    
    Returns:
        JSON response with test result:
        {
            "success": bool,
            "message": str,
            "recipient": str
        }
    
    Status Codes:
        200: Test email sent successfully
        400: Invalid email configuration
        500: Failed to send test email
    """
    try:
        import yaml
        from pathlib import Path
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from datetime import datetime
        
        # Get optional recipient from request
        recipient = None
        if request.is_json:
            data = request.get_json()
            recipient = data.get('recipient')
        
        # Load email configuration
        config_file = Path(ids_controller.config_path)
        if not config_file.exists():
            return jsonify({
                'success': False,
                'error': 'Configuration file not found',
                'message': f'Config file does not exist: {ids_controller.config_path}'
            }), 500
        
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f) or {}
        
        if 'email' not in config:
            return jsonify({
                'success': False,
                'error': 'Email configuration not found',
                'message': 'Email section missing from configuration'
            }), 400
        
        email_config = config['email']
        
        # Validate required email settings
        required_fields = ['smtp_host', 'smtp_port', 'username', 'password']
        for field in required_fields:
            if field not in email_config:
                return jsonify({
                    'success': False,
                    'error': 'Invalid email configuration',
                    'message': f'Missing required field: {field}'
                }), 400
        
        # Determine recipient
        if not recipient:
            if 'recipients' in email_config and email_config['recipients']:
                recipient = email_config['recipients'][0]
            else:
                return jsonify({
                    'success': False,
                    'error': 'No recipient specified',
                    'message': 'No recipient in request or configuration'
                }), 400
        
        # Create test email
        msg = MIMEMultipart()
        msg['From'] = email_config['username']
        msg['To'] = recipient
        msg['Subject'] = 'IDS Web UI - Test Email'
        
        body = f"""
        This is a test email from the IDS Web UI.
        
        If you received this email, your email configuration is working correctly.
        
        Timestamp: {datetime.now().isoformat()}
        SMTP Host: {email_config['smtp_host']}
        SMTP Port: {email_config['smtp_port']}
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        try:
            if email_config.get('use_tls', True):
                server = smtplib.SMTP(email_config['smtp_host'], email_config['smtp_port'])
                server.starttls()
            else:
                server = smtplib.SMTP(email_config['smtp_host'], email_config['smtp_port'])
            
            server.login(email_config['username'], email_config['password'])
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Test email sent successfully to {recipient}")
            return jsonify({
                'success': True,
                'message': 'Test email sent successfully',
                'recipient': recipient
            }), 200
        
        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP authentication failed")
            return jsonify({
                'success': False,
                'error': 'Authentication failed',
                'message': 'Invalid username or password'
            }), 400
        
        except smtplib.SMTPException as smtp_error:
            logger.error(f"SMTP error: {smtp_error}")
            return jsonify({
                'success': False,
                'error': 'SMTP error',
                'message': str(smtp_error)
            }), 500
    
    except Exception as e:
        logger.error(f"Error sending test email: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to send test email',
            'message': str(e)
        }), 500



# ============================================================================
# Detector Management API Endpoints
# ============================================================================

def get_detectors():
    """
    GET /api/detectors
    
    Retrieve list of all threat detectors with their current status.
    
    Returns:
        JSON response with detector information:
        {
            "detectors": [
                {
                    "name": str,
                    "type": str,
                    "enabled": bool,
                    "description": str
                },
                ...
            ],
            "count": int
        }
    
    Status Codes:
        200: Success
        503: IDS not initialized
        500: Internal server error
    
    Example:
        GET /api/detectors
    """
    try:
        detectors = ids_controller.get_detector_status()
        
        # If IDS not initialized, return default detector list
        if not detectors and (not ids_controller.ids_app or not ids_controller.ids_app.detection_engine):
            logger.info("IDS not initialized, returning default detector list")
            # Return default detector information
            default_detectors = [
                {
                    'name': 'PortScanDetector',
                    'type': 'port_scan',
                    'enabled': True,
                    'description': 'Detects port scanning attempts by monitoring connection patterns'
                },
                {
                    'name': 'ICMPScanDetector',
                    'type': 'icmp_scan',
                    'enabled': True,
                    'description': 'Detects ICMP scanning and ping sweeps'
                },
                {
                    'name': 'BruteForceDetector',
                    'type': 'brute_force',
                    'enabled': True,
                    'description': 'Detects brute force authentication attempts'
                },
                {
                    'name': 'MalwareDetector',
                    'type': 'malware',
                    'enabled': True,
                    'description': 'Detects known malware signatures and suspicious patterns'
                },
                {
                    'name': 'DataExfiltrationDetector',
                    'type': 'data_exfiltration',
                    'enabled': True,
                    'description': 'Detects large data transfers that may indicate data exfiltration'
                }
            ]
            return jsonify({
                'detectors': default_detectors,
                'count': len(default_detectors),
                'note': 'IDS not started - showing default detector configuration'
            }), 200
        
        logger.debug(f"Retrieved {len(detectors)} detectors")
        return jsonify({
            'detectors': detectors,
            'count': len(detectors)
        }), 200
    
    except Exception as e:
        logger.error(f"Error retrieving detectors: {e}")
        return jsonify({
            'error': 'Failed to retrieve detectors',
            'message': str(e)
        }), 500


def toggle_detector_endpoint(detector_name: str):
    """
    PUT /api/detectors/<name>
    
    Enable or disable a specific threat detector.
    
    Args:
        detector_name: Name of the detector to toggle (e.g., 'PortScanDetector')
    
    Request Body:
        {
            "enabled": bool  # True to enable, False to disable
        }
    
    Returns:
        JSON response with operation result:
        {
            "success": bool,
            "message": str,
            "detector": str,
            "enabled": bool
        }
    
    Status Codes:
        200: Detector toggled successfully
        400: Invalid request or detector not found
        503: IDS not initialized
        500: Internal server error
    
    Example:
        PUT /api/detectors/PortScanDetector
        Body: {"enabled": false}
    """
    try:
        # Validate request body
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'Invalid request',
                'message': 'Request body must be JSON'
            }), 400
        
        data = request.get_json()
        
        if 'enabled' not in data:
            return jsonify({
                'success': False,
                'error': 'Invalid request',
                'message': 'Request body must include "enabled" field'
            }), 400
        
        enabled = data['enabled']
        
        if not isinstance(enabled, bool):
            return jsonify({
                'success': False,
                'error': 'Invalid request',
                'message': '"enabled" field must be a boolean'
            }), 400
        
        # Toggle detector
        result = ids_controller.toggle_detector(detector_name, enabled)
        
        if result['success']:
            logger.info(f"Detector {detector_name} toggled to {'enabled' if enabled else 'disabled'}")
            return jsonify(result), 200
        else:
            logger.warning(f"Failed to toggle detector {detector_name}: {result['message']}")
            
            # Check if it's a "not found" error
            if 'not found' in result['message'].lower():
                return jsonify(result), 400
            elif 'not initialized' in result['message'].lower():
                return jsonify(result), 503
            else:
                return jsonify(result), 400
    
    except Exception as e:
        logger.error(f"Error toggling detector {detector_name}: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to toggle detector',
            'message': str(e)
        }), 500



# ============================================================================
# Logs API Endpoints
# ============================================================================

def get_logs():
    """
    GET /api/logs
    
    Retrieve system logs with pagination and optional filtering by event type.
    
    Query Parameters:
        page: int - Page number (default: 1)
        limit: int - Number of logs per page (default: 50)
        event_type: str - Filter by event type (threat, notification, system)
    
    Returns:
        JSON response with logs:
        {
            "logs": [
                {
                    "timestamp": str,
                    "level": str,
                    "event_type": str,
                    "message": str,
                    "details": dict
                },
                ...
            ],
            "page": int,
            "limit": int,
            "total": int,
            "total_pages": int
        }
    
    Status Codes:
        200: Success
        400: Invalid query parameters
        500: Internal server error
    
    Example:
        GET /api/logs?page=1&limit=50&event_type=threat
    """
    try:
        import json
        from pathlib import Path
        
        # Parse query parameters
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 50))
        event_type_filter = request.args.get('event_type')
        
        if page < 1:
            return jsonify({
                'error': 'Invalid page parameter',
                'message': 'Page must be >= 1'
            }), 400
        
        if limit < 1 or limit > 1000:
            return jsonify({
                'error': 'Invalid limit parameter',
                'message': 'Limit must be between 1 and 1000'
            }), 400
        
        # Load configuration to get log file path
        import yaml
        config_file = Path(ids_controller.config_path)
        if not config_file.exists():
            return jsonify({
                'error': 'Configuration file not found',
                'message': 'Cannot determine log file location'
            }), 500
        
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f) or {}
        
        log_file_path = config.get('logging', {}).get('log_file', 'ids.log')
        log_file = Path(log_file_path)
        
        if not log_file.exists():
            logger.warning(f"Log file not found: {log_file_path}")
            return jsonify({
                'logs': [],
                'page': page,
                'limit': limit,
                'total': 0,
                'total_pages': 0
            }), 200
        
        # Read and parse log file
        logs = []
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    log_entry = json.loads(line)
                    
                    # Filter by event type if specified
                    if event_type_filter:
                        entry_type = log_entry.get('event_type', '').lower()
                        if entry_type != event_type_filter.lower():
                            continue
                    
                    logs.append(log_entry)
                
                except json.JSONDecodeError:
                    # Skip malformed log entries
                    continue
        
        # Reverse to show most recent first
        logs.reverse()
        
        # Calculate pagination
        total = len(logs)
        total_pages = (total + limit - 1) // limit  # Ceiling division
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        
        # Get page of logs
        page_logs = logs[start_idx:end_idx]
        
        logger.debug(f"Retrieved {len(page_logs)} logs (page {page}/{total_pages})")
        
        return jsonify({
            'logs': page_logs,
            'page': page,
            'limit': limit,
            'total': total,
            'total_pages': total_pages
        }), 200
    
    except ValueError as ve:
        return jsonify({
            'error': 'Invalid query parameters',
            'message': str(ve)
        }), 400
    
    except Exception as e:
        logger.error(f"Error retrieving logs: {e}")
        return jsonify({
            'error': 'Failed to retrieve logs',
            'message': str(e)
        }), 500


def search_logs():
    """
    GET /api/logs/search
    
    Search system logs by keyword or IP address.
    
    Query Parameters:
        query: str - Search keyword or IP address (required)
        event_type: str - Filter by event type (threat, notification, system)
        limit: int - Maximum number of results (default: 100)
    
    Returns:
        JSON response with matching logs:
        {
            "logs": [
                {
                    "timestamp": str,
                    "level": str,
                    "event_type": str,
                    "message": str,
                    "details": dict
                },
                ...
            ],
            "query": str,
            "count": int
        }
    
    Status Codes:
        200: Success
        400: Missing or invalid query parameter
        500: Internal server error
    
    Example:
        GET /api/logs/search?query=192.168.1.100
        GET /api/logs/search?query=port+scan&event_type=threat
    """
    try:
        import json
        from pathlib import Path
        
        # Get search query
        search_query = request.args.get('query')
        if not search_query:
            return jsonify({
                'error': 'Missing query parameter',
                'message': 'Search query is required'
            }), 400
        
        search_query = search_query.lower()
        
        # Parse optional parameters
        event_type_filter = request.args.get('event_type')
        limit = int(request.args.get('limit', 100))
        
        if limit < 1 or limit > 1000:
            return jsonify({
                'error': 'Invalid limit parameter',
                'message': 'Limit must be between 1 and 1000'
            }), 400
        
        # Load configuration to get log file path
        import yaml
        config_file = Path(ids_controller.config_path)
        if not config_file.exists():
            return jsonify({
                'error': 'Configuration file not found',
                'message': 'Cannot determine log file location'
            }), 500
        
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f) or {}
        
        log_file_path = config.get('logging', {}).get('log_file', 'ids.log')
        log_file = Path(log_file_path)
        
        if not log_file.exists():
            logger.warning(f"Log file not found: {log_file_path}")
            return jsonify({
                'logs': [],
                'query': search_query,
                'count': 0
            }), 200
        
        # Read and search log file
        matching_logs = []
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    log_entry = json.loads(line)
                    
                    # Filter by event type if specified
                    if event_type_filter:
                        entry_type = log_entry.get('event_type', '').lower()
                        if entry_type != event_type_filter.lower():
                            continue
                    
                    # Search in message and details
                    log_text = json.dumps(log_entry).lower()
                    if search_query in log_text:
                        matching_logs.append(log_entry)
                        
                        # Stop if we've reached the limit
                        if len(matching_logs) >= limit:
                            break
                
                except json.JSONDecodeError:
                    # Skip malformed log entries
                    continue
        
        # Reverse to show most recent first
        matching_logs.reverse()
        
        logger.debug(f"Found {len(matching_logs)} logs matching query: {search_query}")
        
        return jsonify({
            'logs': matching_logs,
            'query': search_query,
            'count': len(matching_logs)
        }), 200
    
    except ValueError as ve:
        return jsonify({
            'error': 'Invalid query parameters',
            'message': str(ve)
        }), 400
    
    except Exception as e:
        logger.error(f"Error searching logs: {e}")
        return jsonify({
            'error': 'Failed to search logs',
            'message': str(e)
        }), 500



# ============================================================================
# Notifications API Endpoints
# ============================================================================

def get_notifications():
    """
    GET /api/notifications
    
    Retrieve notification history including sent and failed notifications.
    
    Query Parameters:
        limit: int - Maximum number of notifications to return (default: 100)
        status: str - Filter by status (sent, failed)
    
    Returns:
        JSON response with notification history:
        {
            "notifications": [
                {
                    "timestamp": str,
                    "status": str,
                    "recipients": list,
                    "subject": str,
                    "threat_type": str,
                    "error": str (if failed)
                },
                ...
            ],
            "count": int
        }
    
    Status Codes:
        200: Success
        500: Internal server error
    
    Example:
        GET /api/notifications?limit=50&status=sent
    """
    try:
        import json
        from pathlib import Path
        
        # Parse query parameters
        limit = int(request.args.get('limit', 100))
        status_filter = request.args.get('status')
        
        if limit < 1 or limit > 1000:
            return jsonify({
                'error': 'Invalid limit parameter',
                'message': 'Limit must be between 1 and 1000'
            }), 400
        
        # Load configuration to get log file path
        import yaml
        config_file = Path(ids_controller.config_path)
        if not config_file.exists():
            return jsonify({
                'error': 'Configuration file not found',
                'message': 'Cannot determine log file location'
            }), 500
        
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f) or {}
        
        log_file_path = config.get('logging', {}).get('log_file', 'ids.log')
        log_file = Path(log_file_path)
        
        if not log_file.exists():
            logger.warning(f"Log file not found: {log_file_path}")
            return jsonify({
                'notifications': [],
                'count': 0
            }), 200
        
        # Read and parse log file for notification events
        notifications = []
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    log_entry = json.loads(line)
                    
                    # Look for notification events
                    event_type = log_entry.get('event_type', '').lower()
                    if event_type == 'notification':
                        # Extract notification details
                        details = log_entry.get('details', {})
                        notification_status = details.get('status', 'unknown')
                        
                        # Filter by status if specified
                        if status_filter and notification_status.lower() != status_filter.lower():
                            continue
                        
                        notification = {
                            'timestamp': log_entry.get('timestamp'),
                            'status': notification_status,
                            'recipients': details.get('recipients', []),
                            'subject': details.get('subject', ''),
                            'threat_type': details.get('threat_type', ''),
                            'error': details.get('error')
                        }
                        
                        notifications.append(notification)
                        
                        # Stop if we've reached the limit
                        if len(notifications) >= limit:
                            break
                
                except json.JSONDecodeError:
                    # Skip malformed log entries
                    continue
        
        # Reverse to show most recent first
        notifications.reverse()
        
        logger.debug(f"Retrieved {len(notifications)} notifications")
        
        return jsonify({
            'notifications': notifications,
            'count': len(notifications)
        }), 200
    
    except ValueError as ve:
        return jsonify({
            'error': 'Invalid query parameters',
            'message': str(ve)
        }), 400
    
    except Exception as e:
        logger.error(f"Error retrieving notifications: {e}")
        return jsonify({
            'error': 'Failed to retrieve notifications',
            'message': str(e)
        }), 500


def update_notification_settings():
    """
    PUT /api/notifications/settings
    
    Update email notification settings including recipients and batching configuration.
    
    Request Body:
        {
            "recipients": list,  # Optional: list of email addresses
            "batch_window": int,  # Optional: batch window in seconds
            "batch_threshold": int  # Optional: number of threats to trigger batch
        }
    
    Returns:
        JSON response with operation result:
        {
            "success": bool,
            "message": str,
            "requires_restart": bool
        }
    
    Status Codes:
        200: Settings updated successfully
        400: Invalid request or validation failed
        500: Internal server error
    
    Example:
        PUT /api/notifications/settings
        Body: {
            "recipients": ["[email]", "[email]"],
            "batch_window": 300,
            "batch_threshold": 5
        }
    """
    try:
        # Validate request body
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'Invalid request',
                'message': 'Request body must be JSON'
            }), 400
        
        settings = request.get_json()
        
        if not settings:
            return jsonify({
                'success': False,
                'error': 'Invalid request',
                'message': 'Request body cannot be empty'
            }), 400
        
        # Build configuration updates
        config_updates = {}
        
        # Update email recipients
        if 'recipients' in settings:
            recipients = settings['recipients']
            
            if not isinstance(recipients, list):
                return jsonify({
                    'success': False,
                    'error': 'Invalid recipients',
                    'message': 'Recipients must be a list'
                }), 400
            
            if not recipients:
                return jsonify({
                    'success': False,
                    'error': 'Invalid recipients',
                    'message': 'Recipients list cannot be empty'
                }), 400
            
            # Validate email addresses (basic validation)
            for email in recipients:
                if not isinstance(email, str) or '@' not in email:
                    return jsonify({
                        'success': False,
                        'error': 'Invalid email address',
                        'message': f'Invalid email format: {email}'
                    }), 400
            
            config_updates['email'] = {'recipients': recipients}
        
        # Update batching settings
        notification_updates = {}
        
        if 'batch_window' in settings:
            batch_window = settings['batch_window']
            
            if not isinstance(batch_window, int) or batch_window < 0:
                return jsonify({
                    'success': False,
                    'error': 'Invalid batch_window',
                    'message': 'batch_window must be a non-negative integer'
                }), 400
            
            notification_updates['batch_window'] = batch_window
        
        if 'batch_threshold' in settings:
            batch_threshold = settings['batch_threshold']
            
            if not isinstance(batch_threshold, int) or batch_threshold < 1:
                return jsonify({
                    'success': False,
                    'error': 'Invalid batch_threshold',
                    'message': 'batch_threshold must be a positive integer'
                }), 400
            
            notification_updates['batch_threshold'] = batch_threshold
        
        if notification_updates:
            config_updates['notification'] = notification_updates
        
        # Update configuration
        result = ids_controller.update_configuration(config_updates)
        
        if result['success']:
            logger.info(f"Notification settings updated: {settings}")
            return jsonify(result), 200
        else:
            logger.warning(f"Failed to update notification settings: {result['message']}")
            return jsonify(result), 400
    
    except Exception as e:
        logger.error(f"Error updating notification settings: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to update notification settings',
            'message': str(e)
        }), 500



# ============================================================================
# Analytics API Endpoints
# ============================================================================

def get_analytics_summary():
    """
    GET /api/analytics/summary
    
    Retrieve threat analytics summary including counts by severity and type,
    and top attacking IPs.
    
    Returns:
        JSON response with analytics summary:
        {
            "total_threats": int,
            "by_severity": {
                "critical": int,
                "high": int,
                "medium": int,
                "low": int
            },
            "by_type": {
                "port_scan": int,
                "icmp_scan": int,
                ...
            },
            "top_attackers": [
                {"ip": str, "count": int},
                ...
            ]
        }
    
    Status Codes:
        200: Success
        500: Internal server error
    
    Example:
        GET /api/analytics/summary
    """
    try:
        stats = ids_controller.get_statistics()
        
        # Format for analytics display
        summary = {
            'total_threats': stats['total_threats'],
            'by_severity': stats['by_severity'],
            'by_type': stats['by_type'],
            'top_attackers': stats['top_attackers']
        }
        
        logger.debug(f"Retrieved analytics summary: {summary['total_threats']} total threats")
        return jsonify(summary), 200
    
    except Exception as e:
        logger.error(f"Error retrieving analytics summary: {e}")
        return jsonify({
            'error': 'Failed to retrieve analytics summary',
            'message': str(e)
        }), 500


def get_analytics_timeline():
    """
    GET /api/analytics/timeline
    
    Retrieve threat timeline data for visualization with Chart.js.
    Groups threats by time intervals based on the specified time range.
    
    Query Parameters:
        range: str - Time range (1h, 24h, 7d, 30d) (default: 24h)
    
    Returns:
        JSON response with timeline data formatted for Chart.js:
        {
            "labels": list,  # Time labels for x-axis
            "datasets": [
                {
                    "label": str,
                    "data": list,  # Threat counts for each time interval
                    "by_severity": {
                        "critical": list,
                        "high": list,
                        "medium": list,
                        "low": list
                    },
                    "by_type": {
                        "port_scan": list,
                        "icmp_scan": list,
                        ...
                    }
                }
            ],
            "range": str,
            "total_threats": int
        }
    
    Status Codes:
        200: Success
        400: Invalid time range parameter
        500: Internal server error
    
    Example:
        GET /api/analytics/timeline?range=24h
        GET /api/analytics/timeline?range=7d
    """
    try:
        from datetime import datetime, timedelta
        from collections import defaultdict
        
        # Parse time range parameter
        time_range = request.args.get('range', '24h')
        
        # Define time range configurations
        range_configs = {
            '1h': {'hours': 1, 'interval_minutes': 5, 'label_format': '%H:%M'},
            '24h': {'hours': 24, 'interval_minutes': 60, 'label_format': '%H:%M'},
            '7d': {'days': 7, 'interval_minutes': 360, 'label_format': '%m/%d %H:%M'},
            '30d': {'days': 30, 'interval_minutes': 1440, 'label_format': '%m/%d'}
        }
        
        if time_range not in range_configs:
            return jsonify({
                'error': 'Invalid time range',
                'message': f'Time range must be one of: {", ".join(range_configs.keys())}'
            }), 400
        
        config = range_configs[time_range]
        
        # Calculate start time
        now = datetime.now()
        if 'hours' in config:
            start_time = now - timedelta(hours=config['hours'])
        else:
            start_time = now - timedelta(days=config['days'])
        
        # Get threats within time range
        threats = ids_controller.get_threats({
            'start_time': start_time.isoformat()
        })
        
        # Calculate number of intervals
        total_minutes = int((now - start_time).total_seconds() / 60)
        interval_minutes = config['interval_minutes']
        num_intervals = (total_minutes // interval_minutes) + 1
        
        # Initialize data structures
        labels = []
        total_counts = [0] * num_intervals
        severity_counts = {
            'critical': [0] * num_intervals,
            'high': [0] * num_intervals,
            'medium': [0] * num_intervals,
            'low': [0] * num_intervals
        }
        type_counts = defaultdict(lambda: [0] * num_intervals)
        
        # Generate time labels
        for i in range(num_intervals):
            interval_time = start_time + timedelta(minutes=i * interval_minutes)
            labels.append(interval_time.strftime(config['label_format']))
        
        # Group threats by time interval
        for threat in threats:
            try:
                threat_time = datetime.fromisoformat(threat['timestamp'].replace('Z', '+00:00'))
                
                # Calculate which interval this threat belongs to
                minutes_diff = int((threat_time - start_time).total_seconds() / 60)
                interval_idx = min(minutes_diff // interval_minutes, num_intervals - 1)
                
                if interval_idx >= 0:
                    # Increment total count
                    total_counts[interval_idx] += 1
                    
                    # Increment severity count
                    severity = threat.get('severity', 'low')
                    if severity in severity_counts:
                        severity_counts[severity][interval_idx] += 1
                    
                    # Increment type count
                    threat_type = threat.get('type', 'unknown')
                    type_counts[threat_type][interval_idx] += 1
            
            except Exception:
                # Skip threats with invalid timestamps
                continue
        
        # Convert type_counts defaultdict to regular dict
        type_counts_dict = {k: v for k, v in type_counts.items()}
        
        # Format response for Chart.js
        timeline_data = {
            'labels': labels,
            'datasets': [
                {
                    'label': 'Total Threats',
                    'data': total_counts,
                    'by_severity': severity_counts,
                    'by_type': type_counts_dict
                }
            ],
            'range': time_range,
            'total_threats': sum(total_counts)
        }
        
        logger.debug(f"Retrieved timeline data for range {time_range}: {sum(total_counts)} threats")
        return jsonify(timeline_data), 200
    
    except Exception as e:
        logger.error(f"Error retrieving analytics timeline: {e}")
        return jsonify({
            'error': 'Failed to retrieve analytics timeline',
            'message': str(e)
        }), 500



# ============================================================================
# Diagnostic API Endpoint
# ============================================================================

def get_diagnostic():
    """
    GET /api/diagnostic
    
    Diagnostic endpoint to check IDS controller state and help troubleshoot issues.
    
    Returns:
        JSON response with diagnostic information:
        {
            "ids_app_exists": bool,
            "ids_app_running": bool,
            "detection_engine_exists": bool,
            "detectors_count": int,
            "threat_store_count": int,
            "config_path": str,
            "error": str (if any)
        }
    
    Status Codes:
        200: Success
    """
    try:
        diagnostic_info = {
            "ids_app_exists": ids_controller.ids_app is not None,
            "ids_app_running": ids_controller.ids_app.is_running if ids_controller.ids_app else False,
            "detection_engine_exists": False,
            "detectors_dict_exists": False,
            "detectors_count": 0,
            "threat_store_count": len(ids_controller.threat_store.threats) if ids_controller.threat_store else 0,
            "config_path": ids_controller.config_path,
            "start_time": ids_controller.start_time.isoformat() if ids_controller.start_time else None
        }
        
        if ids_controller.ids_app:
            diagnostic_info["detection_engine_exists"] = ids_controller.ids_app.detection_engine is not None
            
            if hasattr(ids_controller.ids_app, '_detectors'):
                diagnostic_info["detectors_dict_exists"] = True
                diagnostic_info["detectors_count"] = len(ids_controller.ids_app._detectors)
                diagnostic_info["detector_keys"] = list(ids_controller.ids_app._detectors.keys())
        
        logger.info(f"Diagnostic info: {diagnostic_info}")
        return jsonify(diagnostic_info), 200
    
    except Exception as e:
        logger.error(f"Error in diagnostic endpoint: {e}", exc_info=True)
        return jsonify({
            "error": str(e),
            "error_type": type(e).__name__
        }), 500
