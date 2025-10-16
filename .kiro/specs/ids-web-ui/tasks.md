   # Implementation Plan

- [x] 1. Set up web UI project structure and dependencies



  - Create `web_ui/` directory with subdirectories: `static/`, `templates/`, `api/`, `controllers/`
  - Create `requirements.txt` with Flask, Flask-SocketIO, Flask-CORS dependencies
  - Create basic Flask application structure with `app.py` as entry point
  - _Requirements: 15.1_

- [x] 2. Implement IDS integration layer

  - [x] 2.1 Create EventBus class for real-time event broadcasting





    - Implement `subscribe()` method to register event listeners
    - Implement `publish()` method to broadcast events to subscribers
    - Implement event handlers for threat detection, status changes, and statistics updates
    - _Requirements: 15.2, 15.3_
  
  - [x] 2.2 Create ThreatStore class for in-memory threat storage





    - Implement `add_threat()` method to store detected threats
    - Implement `get_threats()` method with filtering support (by type, severity, time range)
    - Implement `get_threat_by_id()` method for detailed threat retrieval
    - Implement `get_statistics()` method for threat analytics
    - Implement automatic cleanup of old threats (keep last 1000)
    - _Requirements: 2.1, 2.2, 2.3, 2.4_
  
  - [x] 2.3 Create IDSController class to bridge web UI and IDS application





    - Implement `start_monitoring()` method to start IDS in background thread
    - Implement `stop_monitoring()` method to gracefully stop IDS
    - Implement `get_status()` method to retrieve current IDS status
    - Implement `get_threats()` method with filtering
    - Implement `get_statistics()` method for dashboard
    - Implement `update_configuration()` method to modify IDS config
    - Implement `toggle_detector()` method to enable/disable detectors
    - _Requirements: 13.1, 13.2, 13.3, 7.1, 7.2, 14.3_
  
  - [x] 2.4 Modify IDSApplication to integrate with web UI





    - Add `event_bus` parameter to constructor
    - Add `threat_store` instance variable
    - Modify threat detection loop to emit events via event bus
    - Implement `get_current_status()` method for web UI
    - Implement `get_detector_status()` method to list all detectors
    - Implement `start_monitoring_async()` to run in background thread
    - _Requirements: 15.1, 15.2, 9.1, 14.1, 14.2_

- [x] 3. Implement Flask backend API endpoints




  - [x] 3.1 Create system control API endpoints


    - Implement `GET /api/status` to return IDS status (running, interface, uptime, packet count)
    - Implement `POST /api/start` to start monitoring
    - Implement `POST /api/stop` to stop monitoring
    - Implement `POST /api/restart` to restart IDS
    - Add error handling for all endpoints
    - _Requirements: 13.1, 13.2, 13.3, 13.5, 9.1, 9.2_
  
  - [x] 3.2 Create threats API endpoints


    - Implement `GET /api/threats` with query parameters for filtering (type, severity, limit)
    - Implement `GET /api/threats/<id>` to get detailed threat information
    - Implement `GET /api/threats/stats` to return threat statistics
    - Return threats in JSON format with proper serialization
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 4.1, 4.2, 4.3, 4.4, 4.5_
  
  - [x] 3.3 Create configuration API endpoints


    - Implement `GET /api/config` to return current configuration (mask passwords)
    - Implement `PUT /api/config` to update configuration with validation
    - Implement `POST /api/config/test-email` to send test email
    - Add validation for email settings, detection thresholds, and logging config
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_
  
  - [x] 3.4 Create detector management API endpoints


    - Implement `GET /api/detectors` to list all detectors with status
    - Implement `PUT /api/detectors/<name>` to enable/disable specific detector
    - Return detector descriptions and current configuration
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5_
  
  - [x] 3.5 Create logs API endpoints


    - Implement `GET /api/logs` with pagination support (page, limit parameters)
    - Implement `GET /api/logs/search` with query parameter for keyword search
    - Add filtering by event type (threat, notification, system)
    - Parse JSON log files and return structured data
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6_
  
  - [x] 3.6 Create notifications API endpoints


    - Implement `GET /api/notifications` to return notification history
    - Implement `PUT /api/notifications/settings` to update email recipients and batching settings
    - Return notification status (sent, failed) with timestamps
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_
  
  - [x] 3.7 Create analytics API endpoints


    - Implement `GET /api/analytics/summary` to return threat counts by severity and type
    - Implement `GET /api/analytics/timeline` with time range parameter (1h, 24h, 7d, 30d)
    - Implement top attackers list (source IPs with threat counts)
    - Return data formatted for Chart.js visualization
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6_

- [x] 4. Implement WebSocket real-time communication

  - [x] 4.1 Set up Flask-SocketIO for WebSocket support





    - Initialize SocketIO with Flask app
    - Configure CORS for WebSocket connections
    - Implement connection and disconnection handlers
    - _Requirements: 15.2, 15.5_
  
  - [x] 4.2 Implement WebSocket event emitters





    - Implement `threat_detected` event emission when new threat is detected
    - Implement `status_changed` event emission when IDS status changes
    - Implement `stats_updated` event emission for periodic statistics updates
    - Implement `notification_sent` event emission when email is sent
    - Connect event bus to WebSocket emitters
    - _Requirements: 2.1, 13.5, 15.2, 15.6_

- [x] 5. Create frontend HTML templates





  - [x] 5.1 Create base template with navigation


    - Create `base.html` with Bootstrap layout
    - Add navigation menu (Dashboard, Threats, Analytics, Configuration, Logs)
    - Add header with system title and status indicator
    - Include CSS and JavaScript imports
    - _Requirements: 5.1, 5.2, 5.3, 5.4_
  

  - [x] 5.2 Create dashboard page template

    - Create `dashboard.html` extending base template
    - Add system status card (status, interface, uptime, packet count)
    - Add quick stats cards for severity counts (Critical, High, Medium, Low)
    - Add recent threats list (last 5 threats)
    - Add start/stop monitoring button
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 9.1, 9.2, 9.3, 9.4, 9.5, 9.6_
  
  - [x] 5.3 Create threats page template


    - Create `threats.html` extending base template
    - Add filter dropdowns (threat type, severity)
    - Add search input for IP address or keyword search
    - Add threats list with color-coded severity badges
    - Add "View Details" button for each threat
    - Add threat details modal with full information
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 4.1, 4.2, 4.3, 4.4, 4.5, 10.1, 10.2, 10.3, 10.4, 10.5_
  

  - [x] 5.4 Create analytics page template

    - Create `analytics.html` extending base template
    - Add time range selector dropdown
    - Add canvas elements for Chart.js charts (line, pie, bar)
    - Add top attackers table
    - Add summary statistics cards
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6_
  

  - [x] 5.5 Create configuration page template

    - Create `config.html` extending base template
    - Add tabbed interface for configuration sections (Email, Detection, Logging, Notifications)
    - Add email settings form with SMTP configuration
    - Add detection thresholds form
    - Add logging configuration form
    - Add notification batching settings form
    - Add "Test Email" and "Save Changes" buttons
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 8.1, 8.2, 8.5, 8.6_
  
  - [x] 5.6 Create logs page template


    - Create `logs.html` extending base template
    - Add event type filter dropdown
    - Add search input
    - Add logs table with timestamp, event type, and details columns
    - Add pagination controls
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6_
  

  - [x] 5.7 Create detector management section in configuration

    - Add detector list with enable/disable toggles
    - Add detector descriptions
    - Add warning message when all detectors are disabled
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.6_

- [x] 6. Implement frontend JavaScript functionality




  - [x] 6.1 Create WebSocket client connection handler


    - Initialize Socket.IO client connection
    - Implement connection status indicator
    - Implement auto-reconnection logic
    - Add connection error handling with user notification
    - _Requirements: 15.2, 15.5, 15.6_
  
  - [x] 6.2 Implement dashboard JavaScript


    - Fetch and display system status on page load
    - Implement real-time status updates via WebSocket
    - Implement start/stop monitoring button handlers
    - Update quick stats cards when new threats arrive
    - Update recent threats list in real-time
    - Add auto-refresh for uptime and packet count
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 9.1, 9.2, 9.3, 9.4, 9.5, 13.1, 13.2, 13.5_
  
  - [x] 6.3 Implement threats page JavaScript


    - Fetch and display threats on page load
    - Implement filter functionality (type, severity)
    - Implement search functionality
    - Add real-time threat updates via WebSocket (prepend new threats)
    - Implement threat details modal population
    - Add color-coded severity badges dynamically
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 4.1, 4.2, 4.3, 4.4, 4.5, 10.1, 10.2, 10.3, 10.4, 10.5_
  
  - [x] 6.4 Implement analytics page JavaScript


    - Fetch analytics data based on selected time range
    - Implement Chart.js line chart for threats over time
    - Implement Chart.js pie chart for threats by type
    - Implement Chart.js bar chart for threats by severity
    - Update top attackers table
    - Add time range selector change handler
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5_
  
  - [x] 6.5 Implement configuration page JavaScript


    - Fetch and populate current configuration on page load
    - Implement form validation for all configuration fields
    - Implement save configuration handler with API call
    - Implement test email button handler
    - Show success/error messages after save or test
    - Mask password fields appropriately
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 8.1, 8.2, 8.5_
  
  - [x] 6.6 Implement logs page JavaScript


    - Fetch and display logs with pagination
    - Implement event type filter
    - Implement search functionality
    - Implement pagination controls (previous, next)
    - Add auto-refresh option for real-time log viewing
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6_
  
  - [x] 6.7 Implement detector management JavaScript


    - Fetch and display detector status
    - Implement enable/disable toggle handlers
    - Show warning when all detectors are disabled
    - Update detector status in real-time
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.6_

- [x] 7. Create frontend CSS styling


  - [x] 7.1 Create custom CSS for severity color coding





    - Define CSS classes for severity badges (critical, high, medium, low)
    - Apply Bootstrap color scheme (red, orange, yellow, blue)
    - Add hover effects for interactive elements
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_
  
  - [x] 7.2 Create responsive layout styles





    - Ensure mobile-friendly layout for tablets
    - Add media queries for different screen sizes
    - Test responsive design on various devices
    - _Requirements: 5.4_
  
  - [x] 7.3 Create custom styles for dashboard and cards





    - Style status cards with appropriate spacing
    - Style quick stats cards with large numbers
    - Add loading indicators and animations
    - _Requirements: 5.1, 5.2, 5.3_

- [x] 8. Implement error handling and user feedback




  - [x] 8.1 Add toast notifications for user actions


    - Implement toast notification component (success, error, info)
    - Show notifications for save actions, errors, and status changes
    - Auto-dismiss notifications after 5 seconds
    - _Requirements: 1.5, 5.1, 5.2, 5.3_
  
  - [x] 8.2 Add loading indicators


    - Show spinner when fetching data from API
    - Disable buttons during API calls
    - Show loading state for charts and tables
    - _Requirements: 1.3, 5.1_
  
  - [x] 8.3 Add connection status indicator


    - Show WebSocket connection status in header
    - Display reconnection attempts
    - Show error message when backend is unavailable
    - _Requirements: 15.4, 15.5, 15.6_

- [x] 9. Create entry point and startup script




  - [x] 9.1 Create main Flask application entry point


    - Create `app.py` with Flask app initialization
    - Configure Flask-SocketIO
    - Initialize IDSController with IDS application
    - Register all API routes
    - Add command-line arguments for host, port, and config file
    - _Requirements: 15.1_
  

  - [x] 9.2 Create startup script for integrated IDS + Web UI

    - Create `run_ids_with_ui.py` script
    - Initialize IDS application with event bus
    - Start Flask web server in main thread
    - Run IDS monitoring in background thread
    - Add graceful shutdown handling
    - _Requirements: 13.1, 13.6, 15.1_

- [ ] 10. Create documentation and deployment files
  - [x] 10.1 Create README for web UI





    - Document installation steps
    - Document how to run the web UI
    - Document API endpoints
    - Include screenshots of UI
    - Add troubleshooting section
    - _Requirements: 5.1_
  
  - [x] 10.2 Update main IDS README with web UI instructions





    - Add section about web UI feature
    - Document how to access the web interface
    - Add configuration examples
    - _Requirements: 5.1_
  
  - [x] 10.3 Create deployment configuration examples





    - Create Nginx configuration example for reverse proxy
    - Create systemd service file for production deployment
    - Document HTTPS setup recommendations
    - _Requirements: 15.1_

- [ ]* 11. Create tests for web UI
  - Write unit tests for API endpoints
  - Write integration tests for IDSController
  - Test WebSocket event emission
  - Test frontend JavaScript functions
  - _Requirements: 15.1, 15.2_
