# IDS with Web UI - Technical Documentation

Complete technical documentation for the Intrusion Detection System with Web User Interface.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Core Components](#core-components)
3. [Web UI Components](#web-ui-components)
4. [Detection Mechanisms](#detection-mechanisms)
5. [API Reference](#api-reference)
6. [Configuration Reference](#configuration-reference)
7. [Database and Storage](#database-and-storage)
8. [Security Considerations](#security-considerations)
9. [Performance Optimization](#performance-optimization)
10. [Extending the System](#extending-the-system)

---

## Architecture Overview

### System Architecture

The IDS consists of two main components that work together:

1. **Core IDS Engine**: Packet capture, threat detection, and analysis
2. **Web UI**: Real-time monitoring interface with RESTful API

```
┌─────────────────────────────────────────────────────────────┐
│                     Web Browser (Client)                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │Dashboard │  │ Threats  │  │Analytics │  │  Config  │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP/WebSocket
┌────────────────────────┴────────────────────────────────────┐
│                    Flask Web Server                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  REST API    │  │  WebSocket   │  │   Templates  │     │
│  │   Routes     │  │   Events     │  │   (Jinja2)   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────────────┐
│                   IDS Controller Layer                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ IDS Control  │  │  Event Bus   │  │ Threat Store │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────────────┐
│                    Core IDS Engine                           │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Packet Capture Engine                    │  │
│  │                   (Scapy)                             │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │           Threat Detection Engine                     │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐       │  │
│  │  │Port Scan   │ │Brute Force │ │  Malware   │       │  │
│  │  │ Detector   │ │  Detector  │ │  Detector  │       │  │
│  │  └────────────┘ └────────────┘ └────────────┘       │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐       │  │
│  │  │ICMP Scan   │ │Data Exfil  │ │ Attacker   │       │  │
│  │  │ Detector   │ │  Detector  │ │Identifier  │       │  │
│  │  └────────────┘ └────────────┘ └────────────┘       │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Threat Analyzer                          │  │
│  │         (Severity Classification)                     │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │           Notification Service                        │  │
│  │         (Email Alerts, Batching)                      │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────────────┐
│                  Network Interface                           │
│                  (eth0, wlan0, etc.)                         │
└─────────────────────────────────────────────────────────────┘
```


### Data Flow

1. **Packet Capture**: Network packets are captured from the specified interface
2. **Detection**: Each packet is analyzed by registered threat detectors
3. **Analysis**: Detected threats are analyzed and classified by severity
4. **Storage**: Threats are stored in-memory (ThreatStore) for web UI access
5. **Notification**: Email alerts are sent based on configuration
6. **Broadcasting**: Events are broadcast via EventBus to web clients
7. **Display**: Web UI updates in real-time via WebSocket

### Threading Model

- **Main Thread**: Flask web server and WebSocket handling
- **IDS Thread**: Packet capture and threat detection (daemon thread)
- **Event Bus**: Asynchronous event broadcasting to connected clients

---

## Core Components

### 1. IDSApplication (`ids/ids_application.py`)

Main orchestrator for the IDS engine.

**Responsibilities:**
- Initialize all IDS components
- Manage packet capture lifecycle
- Coordinate threat detection
- Handle graceful shutdown

**Key Methods:**
```python
def __init__(config_path: str, event_bus=None, threat_store=None)
def initialize() -> None
def start() -> None
def stop() -> None
def is_running() -> bool
```

**Usage:**
```python
from ids.ids_application import IDSApplication

# Create IDS instance
ids = IDSApplication('config.yaml')

# Initialize components
ids.initialize()

# Start monitoring
ids.start()

# Stop monitoring
ids.stop()
```


### 2. PacketCaptureEngine (`ids/services/packet_capture.py`)

Handles network packet capture using Scapy.

**Responsibilities:**
- Capture packets from network interface
- Filter packets based on configuration
- Pass packets to detection engine

**Key Methods:**
```python
def start_capture(interface: str, packet_handler: Callable)
def stop_capture()
def get_packet_count() -> int
```

### 3. ThreatDetectionEngine (`ids/services/threat_detection_engine.py`)

Coordinates all threat detectors.

**Responsibilities:**
- Register and manage threat detectors
- Route packets to appropriate detectors
- Aggregate detection results

**Key Methods:**
```python
def register_detector(detector: ThreatDetector)
def analyze_packet(packet: Packet) -> List[Threat]
def enable_detector(name: str)
def disable_detector(name: str)
def get_detector_status() -> Dict[str, bool]
```

### 4. Threat Detectors (`ids/detectors/`)

Individual detection modules for specific threat types.

#### PortScanDetector
- Detects TCP/UDP port scanning attempts
- Tracks connection attempts per source IP
- Threshold-based detection

#### ICMPScanDetector
- Detects ICMP ping sweeps
- Monitors ICMP echo requests
- Pattern-based detection

#### BruteForceDetector
- Detects authentication brute force attempts
- Tracks failed login attempts
- Time-window based analysis

#### MalwareDetector
- Signature-based payload analysis
- Pattern matching against known malware signatures
- Heuristic analysis

#### DataExfiltrationDetector
- Monitors outbound data transfers
- Tracks data volume per destination
- Threshold-based alerting

#### AttackerIdentifier
- Correlates threats from same source
- Behavioral analysis
- Multi-vector threat identification


### 5. ThreatAnalyzer (`ids/services/threat_analyzer.py`)

Analyzes and enriches threat information.

**Responsibilities:**
- Classify threat severity
- Add contextual information
- Generate recommendations

**Severity Levels:**
- **CRITICAL**: Immediate action required (malware, active attacks)
- **HIGH**: Serious threat (port scans, brute force)
- **MEDIUM**: Suspicious activity (unusual patterns)
- **LOW**: Informational (minor anomalies)

### 6. NotificationService (`ids/services/notification_service.py`)

Manages email notifications.

**Responsibilities:**
- Send email alerts
- Batch notifications to prevent flooding
- Retry failed deliveries
- Format HTML emails

**Key Features:**
- Configurable batch window
- Batch threshold
- Retry mechanism with exponential backoff
- Rich HTML formatting

### 7. EmailService (`ids/services/email_service.py`)

Low-level email sending functionality.

**Responsibilities:**
- SMTP connection management
- Email composition
- TLS/SSL support

**Supported SMTP Servers:**
- Gmail (smtp.gmail.com:587)
- Outlook (smtp.office365.com:587)
- Yahoo (smtp.mail.yahoo.com:587)
- Custom SMTP servers

---

## Web UI Components

### 1. Flask Application (`web_ui/app.py`)

Main web server application.

**Responsibilities:**
- Serve web pages
- Handle HTTP requests
- Manage WebSocket connections
- Session management

**Key Routes:**
- `/` - Dashboard
- `/threats` - Threat browser
- `/analytics` - Analytics and charts
- `/config` - Configuration management
- `/logs` - Log viewer


### 2. IDSController (`web_ui/controllers/ids_controller.py`)

Bridge between web UI and IDS engine.

**Responsibilities:**
- Start/stop IDS monitoring
- Retrieve system status
- Manage configuration
- Control detectors

**Key Methods:**
```python
def start_monitoring() -> Dict[str, Any]
def stop_monitoring() -> Dict[str, Any]
def restart_monitoring() -> Dict[str, Any]
def get_status() -> Dict[str, Any]
def get_threats(filters: Dict) -> List[Dict]
def update_config(config: Dict) -> Dict[str, Any]
def toggle_detector(name: str, enabled: bool) -> Dict[str, Any]
```

### 3. EventBus (`web_ui/controllers/event_bus.py`)

Real-time event broadcasting system.

**Responsibilities:**
- Broadcast events to web clients
- Manage WebSocket connections
- Event queuing and delivery

**Events:**
- `threat_detected` - New threat detected
- `status_changed` - IDS status changed
- `stats_updated` - Statistics updated
- `notification_sent` - Email notification sent
- `detector_toggled` - Detector enabled/disabled

**Usage:**
```python
from web_ui.controllers.event_bus import EventBus

event_bus = EventBus()

# Subscribe to events
event_bus.on_threat_detected(threat_data)
event_bus.on_status_changed(status, details)
```

### 4. ThreatStore (`web_ui/controllers/threat_store.py`)

In-memory threat storage for web UI.

**Responsibilities:**
- Store detected threats
- Provide filtering and search
- Calculate statistics
- Manage storage limits

**Key Methods:**
```python
def add_threat(threat: Dict) -> None
def get_threats(filters: Dict) -> List[Dict]
def get_threat_by_id(threat_id: str) -> Optional[Dict]
def get_statistics() -> Dict[str, Any]
def clear_threats() -> None
```

**Storage Limits:**
- Default: 1000 threats
- Oldest threats removed when limit reached
- Configurable via constructor


### 5. API Routes (`web_ui/api/routes.py`)

RESTful API endpoints.

**System Control:**
- `GET /api/status` - Get IDS status
- `POST /api/start` - Start monitoring
- `POST /api/stop` - Stop monitoring
- `POST /api/restart` - Restart monitoring

**Threats:**
- `GET /api/threats` - Get all threats (with filters)
- `GET /api/threats/<id>` - Get specific threat
- `GET /api/threats/stats` - Get threat statistics

**Configuration:**
- `GET /api/config` - Get configuration
- `PUT /api/config` - Update configuration
- `POST /api/config/test-email` - Test email settings

**Detectors:**
- `GET /api/detectors` - Get detector status
- `PUT /api/detectors/<name>` - Toggle detector

**Logs:**
- `GET /api/logs` - Get logs (with pagination)
- `GET /api/logs/search` - Search logs

**Analytics:**
- `GET /api/analytics/summary` - Get analytics summary
- `GET /api/analytics/timeline` - Get threat timeline

### 6. WebSocket Events (`web_ui/api/websocket_events.py`)

Real-time WebSocket event handlers.

**Client Events:**
- `connect` - Client connected
- `disconnect` - Client disconnected

**Server Events:**
- `threat_detected` - New threat detected
- `status_changed` - IDS status changed
- `stats_updated` - Statistics updated
- `notification_sent` - Email sent

**Client-Side Usage:**
```javascript
const socket = io('http://localhost:5000');

socket.on('threat_detected', (data) => {
    console.log('New threat:', data);
    // Update UI
});

socket.on('status_changed', (data) => {
    console.log('Status:', data.status);
    // Update status display
});
```


---

## Detection Mechanisms

### Port Scan Detection

**Algorithm:**
1. Track unique destination ports per source IP
2. Count ports accessed within time window
3. Alert when threshold exceeded

**Configuration:**
```yaml
detection:
  port_scan_threshold: 10  # Number of ports
  time_window: 300         # Seconds
```

**Detection Logic:**
```python
if unique_ports_count >= threshold:
    severity = "HIGH"
    threat_type = "port_scan"
    alert()
```

### ICMP Scan Detection

**Algorithm:**
1. Monitor ICMP echo requests
2. Track unique destinations per source
3. Alert on ping sweep patterns

**Configuration:**
```yaml
detection:
  icmp_scan_threshold: 5  # Number of ICMP requests
```

**Detection Logic:**
```python
if icmp_requests >= threshold:
    severity = "MEDIUM"
    threat_type = "icmp_scan"
    alert()
```

### Brute Force Detection

**Algorithm:**
1. Monitor authentication attempts
2. Track failed attempts per source
3. Alert when threshold exceeded

**Configuration:**
```yaml
detection:
  brute_force_threshold: 5  # Failed attempts
  time_window: 300          # Seconds
```

**Detection Logic:**
```python
if failed_attempts >= threshold:
    severity = "HIGH"
    threat_type = "brute_force"
    alert()
```

### Malware Detection

**Algorithm:**
1. Signature-based payload analysis
2. Pattern matching against known signatures
3. Heuristic analysis for suspicious patterns

**Signatures:**
- Known malware patterns
- Suspicious byte sequences
- Command and control patterns

**Detection Logic:**
```python
for signature in malware_signatures:
    if signature in packet_payload:
        severity = "CRITICAL"
        threat_type = "malware"
        alert()
```


### Data Exfiltration Detection

**Algorithm:**
1. Monitor outbound data transfers
2. Track data volume per destination
3. Alert on unusual transfer volumes

**Configuration:**
```yaml
detection:
  data_exfiltration_threshold_mb: 100  # Megabytes
  time_window: 300                      # Seconds
```

**Detection Logic:**
```python
if data_transferred_mb >= threshold:
    severity = "CRITICAL"
    threat_type = "data_exfiltration"
    alert()
```

### Attacker Identification

**Algorithm:**
1. Correlate threats from same source IP
2. Analyze attack patterns
3. Identify persistent attackers

**Correlation Factors:**
- Multiple threat types from same source
- Repeated attacks over time
- Attack sophistication level

**Detection Logic:**
```python
if threat_count_from_ip >= 3:
    severity = "CRITICAL"
    threat_type = "attacker_identified"
    alert()
```

---

## API Reference

### Authentication

Currently, the API does not require authentication. For production deployments, implement authentication using:
- Flask-Login
- JWT tokens
- OAuth2
- API keys

**Example with Flask-HTTPAuth:**
```python
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    # Verify credentials
    return check_credentials(username, password)

@app.route('/api/status')
@auth.login_required
def get_status():
    # Protected endpoint
    pass
```


### API Endpoints

#### GET /api/status

Get current IDS status.

**Response:**
```json
{
  "running": true,
  "interface": "eth0",
  "uptime": 3600,
  "uptime_formatted": "1h 0m",
  "packet_count": 15234,
  "threat_count": 25,
  "start_time": "2025-10-15T14:30:00Z"
}
```

#### POST /api/start

Start IDS monitoring.

**Response:**
```json
{
  "success": true,
  "message": "IDS monitoring started successfully",
  "status": { /* status object */ }
}
```

#### POST /api/stop

Stop IDS monitoring.

**Response:**
```json
{
  "success": true,
  "message": "IDS monitoring stopped successfully",
  "status": { /* status object */ }
}
```

#### GET /api/threats

Get all threats with optional filters.

**Query Parameters:**
- `severity` - Filter by severity (critical, high, medium, low)
- `type` - Filter by threat type
- `source_ip` - Filter by source IP
- `limit` - Limit number of results
- `offset` - Pagination offset

**Example:**
```bash
GET /api/threats?severity=high&type=port_scan&limit=10
```

**Response:**
```json
{
  "threats": [
    {
      "id": "threat_123",
      "type": "port_scan",
      "severity": "high",
      "source_ip": "192.168.1.100",
      "destination_ip": "10.0.0.5",
      "timestamp": "2025-10-15T14:30:25Z",
      "details": {
        "ports_scanned": 15,
        "threshold": 10
      }
    }
  ],
  "total": 25,
  "limit": 10,
  "offset": 0
}
```


#### GET /api/threats/stats

Get threat statistics.

**Response:**
```json
{
  "total_threats": 25,
  "by_severity": {
    "critical": 2,
    "high": 5,
    "medium": 10,
    "low": 8
  },
  "by_type": {
    "port_scan": 10,
    "brute_force": 5,
    "malware": 2,
    "icmp_scan": 3,
    "data_exfiltration": 3,
    "attacker_identified": 2
  },
  "top_sources": [
    {"ip": "192.168.1.100", "count": 8},
    {"ip": "192.168.1.101", "count": 5}
  ]
}
```

#### GET /api/config

Get current configuration.

**Response:**
```json
{
  "detection": {
    "network_interface": "eth0",
    "port_scan_threshold": 10,
    "brute_force_threshold": 5
  },
  "email": {
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "recipients": ["admin@example.com"]
  },
  "logging": {
    "log_level": "INFO",
    "log_file": "ids.log"
  }
}
```

#### PUT /api/config

Update configuration.

**Request Body:**
```json
{
  "detection": {
    "port_scan_threshold": 15
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Configuration updated successfully",
  "config": { /* updated config */ }
}
```

#### GET /api/detectors

Get detector status.

**Response:**
```json
{
  "detectors": [
    {"name": "port_scan", "enabled": true},
    {"name": "brute_force", "enabled": true},
    {"name": "malware", "enabled": false}
  ]
}
```

#### PUT /api/detectors/<name>

Toggle detector status.

**Request Body:**
```json
{
  "enabled": false
}
```

**Response:**
```json
{
  "success": true,
  "message": "Detector 'port_scan' disabled",
  "detector": {
    "name": "port_scan",
    "enabled": false
  }
}
```


---

## Configuration Reference

### Complete Configuration File

```yaml
# Email Notification Settings
email:
  smtp_host: "smtp.gmail.com"        # SMTP server hostname
  smtp_port: 587                      # SMTP server port
  use_tls: true                       # Use TLS encryption
  username: "your-email@gmail.com"    # SMTP username
  password: "your-app-password"       # SMTP password (use app password for Gmail)
  recipients:                         # List of email recipients
    - "admin@company.com"
    - "security@company.com"

# Detection Settings
detection:
  network_interface: "eth0"                    # Network interface to monitor
  port_scan_threshold: 10                      # Ports scanned before alert
  icmp_scan_threshold: 5                       # ICMP requests before alert
  brute_force_threshold: 5                     # Failed attempts before alert
  data_exfiltration_threshold_mb: 100          # MB transferred before alert
  time_window: 300                             # Time window in seconds

# Logging Settings
logging:
  log_level: "INFO"                  # DEBUG, INFO, WARNING, ERROR, CRITICAL
  log_file: "ids.log"                # Log file path
  max_log_size_mb: 10                # Maximum log file size in MB
  backup_count: 5                    # Number of backup log files to keep

# Notification Settings
notification:
  batch_window_seconds: 300          # Batch notifications within this window
  batch_threshold: 3                 # Send batch after this many threats
  retry_attempts: 3                  # Number of retry attempts for failed emails
  retry_delay_seconds: 10            # Delay between retry attempts
```

### Configuration Validation

The system validates configuration on startup:

**Required Fields:**
- `email.smtp_host`
- `email.smtp_port`
- `email.username`
- `email.password`
- `email.recipients` (at least one)
- `detection.network_interface`

**Optional Fields:**
- All threshold values (have defaults)
- Logging settings (have defaults)
- Notification settings (have defaults)

**Validation Errors:**
- Missing required fields
- Invalid data types
- Invalid network interface
- Invalid email format
- Invalid threshold values (must be positive integers)


---

## Database and Storage

### In-Memory Storage

The system uses in-memory storage for real-time threat data:

**ThreatStore:**
- Stores up to 1000 threats (configurable)
- FIFO eviction when limit reached
- Fast access for web UI
- No persistence (data lost on restart)

**Advantages:**
- Fast read/write operations
- No database setup required
- Simple deployment

**Limitations:**
- Data lost on restart
- Limited storage capacity
- No historical analysis beyond current session

### Adding Persistent Storage

For production deployments requiring persistent storage, integrate a database:

#### Option 1: SQLite (Simple)

```python
import sqlite3
from datetime import datetime

class ThreatDatabase:
    def __init__(self, db_path='threats.db'):
        self.conn = sqlite3.connect(db_path)
        self.create_tables()
    
    def create_tables(self):
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY,
                type TEXT,
                severity TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                timestamp TEXT,
                details TEXT
            )
        ''')
        self.conn.commit()
    
    def add_threat(self, threat):
        self.conn.execute('''
            INSERT INTO threats VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            threat['id'],
            threat['type'],
            threat['severity'],
            threat['source_ip'],
            threat['destination_ip'],
            threat['timestamp'],
            json.dumps(threat['details'])
        ))
        self.conn.commit()
```

#### Option 2: PostgreSQL (Production)

```python
import psycopg2
from psycopg2.extras import RealDictCursor

class ThreatDatabase:
    def __init__(self, connection_string):
        self.conn = psycopg2.connect(connection_string)
        self.create_tables()
    
    def create_tables(self):
        with self.conn.cursor() as cur:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id VARCHAR(255) PRIMARY KEY,
                    type VARCHAR(50),
                    severity VARCHAR(20),
                    source_ip INET,
                    destination_ip INET,
                    timestamp TIMESTAMP,
                    details JSONB
                )
            ''')
            cur.execute('''
                CREATE INDEX IF NOT EXISTS idx_threats_timestamp 
                ON threats(timestamp DESC)
            ''')
            cur.execute('''
                CREATE INDEX IF NOT EXISTS idx_threats_severity 
                ON threats(severity)
            ''')
        self.conn.commit()
```


#### Option 3: MongoDB (NoSQL)

```python
from pymongo import MongoClient
from datetime import datetime

class ThreatDatabase:
    def __init__(self, connection_string='mongodb://localhost:27017/'):
        self.client = MongoClient(connection_string)
        self.db = self.client['ids']
        self.threats = self.db['threats']
        self.create_indexes()
    
    def create_indexes(self):
        self.threats.create_index([('timestamp', -1)])
        self.threats.create_index([('severity', 1)])
        self.threats.create_index([('source_ip', 1)])
    
    def add_threat(self, threat):
        self.threats.insert_one(threat)
    
    def get_threats(self, filters=None, limit=100):
        query = filters or {}
        return list(self.threats.find(query).limit(limit))
```

### Log Storage

Logs are stored in files with automatic rotation:

**Configuration:**
```yaml
logging:
  log_file: "ids.log"
  max_log_size_mb: 10
  backup_count: 5
```

**Log Files:**
- `ids.log` - Current log file
- `ids.log.1` - First backup
- `ids.log.2` - Second backup
- ... up to `backup_count`

**Log Format:**
```
2025-10-15 14:30:25,123 - ids.detection - INFO - Threat detected: port_scan from 192.168.1.100
```

---

## Security Considerations

### Network Security

1. **Firewall Configuration:**
   - Block direct access to Flask port (5000)
   - Only allow access through reverse proxy
   - Restrict SSH access to specific IPs

2. **Network Segmentation:**
   - Deploy IDS on dedicated monitoring network
   - Separate management and monitoring interfaces
   - Use VLANs for isolation

### Application Security

1. **Authentication:**
   - Implement authentication for web interface
   - Use strong passwords
   - Consider multi-factor authentication

2. **Authorization:**
   - Role-based access control
   - Separate read-only and admin users
   - Audit user actions

3. **Input Validation:**
   - Validate all user inputs
   - Sanitize configuration updates
   - Prevent injection attacks

4. **Session Management:**
   - Use secure session cookies
   - Implement session timeouts
   - Regenerate session IDs


### Configuration Security

1. **File Permissions:**
   ```bash
   # Linux/macOS
   chmod 600 config.yaml
   chown ids:ids config.yaml
   ```

2. **Credential Management:**
   - Use environment variables for sensitive data
   - Consider using secrets management (HashiCorp Vault, AWS Secrets Manager)
   - Never commit credentials to version control

3. **Example with Environment Variables:**
   ```python
   import os
   
   config = {
       'email': {
           'username': os.getenv('IDS_EMAIL_USER'),
           'password': os.getenv('IDS_EMAIL_PASS')
       }
   }
   ```

### HTTPS/TLS

Always use HTTPS in production:

1. **Let's Encrypt (Free):**
   ```bash
   sudo certbot --nginx -d ids.example.com
   ```

2. **Strong TLS Configuration:**
   ```nginx
   ssl_protocols TLSv1.2 TLSv1.3;
   ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
   ssl_prefer_server_ciphers off;
   ```

3. **HSTS Header:**
   ```nginx
   add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
   ```

### Logging Security

1. **Log Sensitive Data:**
   - Don't log passwords or credentials
   - Mask sensitive information
   - Implement log retention policies

2. **Log Access Control:**
   ```bash
   # Linux/macOS
   chmod 640 ids.log
   chown ids:ids ids.log
   ```

3. **Log Monitoring:**
   - Monitor logs for security events
   - Alert on suspicious patterns
   - Regular log review

---

## Performance Optimization

### System Resources

**CPU Optimization:**
- Adjust detection thresholds to reduce processing
- Disable unused detectors
- Use packet filtering to reduce capture volume

**Memory Optimization:**
- Limit ThreatStore size
- Configure log rotation
- Monitor memory usage

**Disk I/O Optimization:**
- Use SSD for log storage
- Configure appropriate log levels
- Implement log compression


### Network Performance

**Packet Capture Optimization:**
```python
# Use BPF filters to reduce captured packets
filter_expression = "tcp or udp or icmp"
sniff(filter=filter_expression, prn=packet_handler)
```

**Interface Selection:**
- Use dedicated monitoring interface
- Consider using port mirroring/SPAN
- Avoid monitoring high-traffic interfaces directly

### Web UI Performance

**Frontend Optimization:**
- Minimize JavaScript bundle size
- Use CDN for libraries (Chart.js, Bootstrap)
- Implement lazy loading
- Cache static assets

**Backend Optimization:**
- Implement pagination for large datasets
- Use database indexes
- Cache frequently accessed data
- Implement rate limiting

**WebSocket Optimization:**
- Batch events when possible
- Implement reconnection logic
- Use compression for large payloads

### Monitoring Performance

**System Metrics:**
```bash
# Linux/macOS
# CPU usage
top -p $(pgrep -f run_ids_with_ui)

# Memory usage
ps aux | grep run_ids_with_ui | awk '{print $4}'

# Network usage
iftop -i eth0
```

**Application Metrics:**
- Packet capture rate
- Detection processing time
- Threat detection rate
- Email delivery time
- WebSocket message rate

---

## Extending the System

### Adding a New Detector

1. **Create Detector Class:**

```python
# ids/detectors/custom_detector.py
from ids.detectors.base_detector import BaseDetector
from ids.models.threat import Threat

class CustomDetector(BaseDetector):
    def __init__(self, config):
        super().__init__("custom_detector", config)
        self.threshold = config.get('custom_threshold', 10)
    
    def analyze_packet(self, packet):
        """Analyze packet for custom threat."""
        threats = []
        
        # Your detection logic here
        if self.is_threat(packet):
            threat = Threat(
                threat_type="custom_threat",
                source_ip=packet.src,
                destination_ip=packet.dst,
                severity="high",
                details={
                    'custom_field': 'value'
                }
            )
            threats.append(threat)
        
        return threats
    
    def is_threat(self, packet):
        """Implement your detection logic."""
        # Example: Check for specific pattern
        return False
```

2. **Register Detector:**

```python
# ids/ids_application.py
from ids.detectors.custom_detector import CustomDetector

# In initialize() method
custom_detector = CustomDetector(config.detection_config)
self.detection_engine.register_detector(custom_detector)
```


### Adding a New API Endpoint

1. **Define Route Handler:**

```python
# web_ui/api/routes.py

def get_custom_data():
    """
    GET /api/custom
    
    Get custom data.
    """
    try:
        data = ids_controller.get_custom_data()
        return jsonify(data), 200
    except Exception as e:
        logger.error(f"Error retrieving custom data: {e}")
        return jsonify({'error': str(e)}), 500
```

2. **Register Route:**

```python
# In register_routes() function
app.add_url_rule('/api/custom', 'get_custom_data', get_custom_data, methods=['GET'])
```

3. **Add Controller Method:**

```python
# web_ui/controllers/ids_controller.py

def get_custom_data(self) -> Dict[str, Any]:
    """Get custom data."""
    return {
        'data': 'custom_value'
    }
```

### Adding a New Web Page

1. **Create HTML Template:**

```html
<!-- web_ui/templates/custom.html -->
{% extends "base.html" %}

{% block title %}Custom Page{% endblock %}

{% block content %}
<div class="container mt-4">
    <h1>Custom Page</h1>
    <div id="custom-content">
        <!-- Your content here -->
    </div>
</div>
{% endblock %}

{% block scripts %}
<script src="{{ url_for('static', filename='js/custom.js') }}"></script>
{% endblock %}
```

2. **Create JavaScript File:**

```javascript
// web_ui/static/js/custom.js

document.addEventListener('DOMContentLoaded', function() {
    loadCustomData();
});

function loadCustomData() {
    fetch('/api/custom')
        .then(response => response.json())
        .then(data => {
            displayCustomData(data);
        })
        .catch(error => {
            console.error('Error loading custom data:', error);
        });
}

function displayCustomData(data) {
    const container = document.getElementById('custom-content');
    container.innerHTML = `<p>${data.data}</p>`;
}
```

3. **Add Route:**

```python
# web_ui/app.py

@app.route('/custom')
def custom_page():
    return render_template('custom.html')
```

4. **Add Navigation Link:**

```html
<!-- web_ui/templates/base.html -->
<li class="nav-item">
    <a class="nav-link" href="{{ url_for('custom_page') }}">Custom</a>
</li>
```


### Adding External Integrations

#### Slack Integration

```python
# ids/services/slack_service.py
import requests

class SlackService:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url
    
    def send_alert(self, threat):
        """Send threat alert to Slack."""
        message = {
            'text': f'🚨 Threat Detected: {threat.threat_type}',
            'attachments': [{
                'color': self.get_color(threat.severity),
                'fields': [
                    {'title': 'Source IP', 'value': threat.source_ip, 'short': True},
                    {'title': 'Severity', 'value': threat.severity, 'short': True},
                    {'title': 'Timestamp', 'value': threat.timestamp, 'short': False}
                ]
            }]
        }
        
        response = requests.post(self.webhook_url, json=message)
        return response.status_code == 200
    
    def get_color(self, severity):
        colors = {
            'critical': 'danger',
            'high': 'warning',
            'medium': '#ffcc00',
            'low': 'good'
        }
        return colors.get(severity, 'good')
```

#### Syslog Integration

```python
# ids/services/syslog_service.py
import syslog

class SyslogService:
    def __init__(self):
        syslog.openlog('IDS', syslog.LOG_PID, syslog.LOG_LOCAL0)
    
    def log_threat(self, threat):
        """Log threat to syslog."""
        priority = self.get_priority(threat.severity)
        message = f"Threat detected: {threat.threat_type} from {threat.source_ip}"
        syslog.syslog(priority, message)
    
    def get_priority(self, severity):
        priorities = {
            'critical': syslog.LOG_CRIT,
            'high': syslog.LOG_WARNING,
            'medium': syslog.LOG_NOTICE,
            'low': syslog.LOG_INFO
        }
        return priorities.get(severity, syslog.LOG_INFO)
```

#### SIEM Integration

```python
# ids/services/siem_service.py
import json
import socket

class SIEMService:
    def __init__(self, siem_host, siem_port):
        self.siem_host = siem_host
        self.siem_port = siem_port
    
    def send_event(self, threat):
        """Send threat event to SIEM."""
        event = {
            'timestamp': threat.timestamp,
            'event_type': 'ids_alert',
            'severity': threat.severity,
            'source_ip': threat.source_ip,
            'destination_ip': threat.destination_ip,
            'threat_type': threat.threat_type,
            'details': threat.details
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.siem_host, self.siem_port))
            sock.sendall(json.dumps(event).encode() + b'\n')
            sock.close()
            return True
        except Exception as e:
            print(f"Error sending to SIEM: {e}")
            return False
```


### Custom Notification Channels

```python
# ids/services/notification_service.py

class NotificationService:
    def __init__(self, config):
        self.email_service = EmailService(config.email)
        self.slack_service = SlackService(config.slack_webhook) if config.slack_webhook else None
        self.syslog_service = SyslogService() if config.enable_syslog else None
    
    def send_notification(self, threat):
        """Send notification through all configured channels."""
        # Email
        if self.email_service:
            self.email_service.send_alert(threat)
        
        # Slack
        if self.slack_service:
            self.slack_service.send_alert(threat)
        
        # Syslog
        if self.syslog_service:
            self.syslog_service.log_threat(threat)
```

---

## Troubleshooting Guide

### Common Issues

#### High CPU Usage

**Symptoms:**
- System slow
- High CPU usage by Python process

**Solutions:**
1. Increase detection thresholds
2. Disable unused detectors
3. Use packet filtering
4. Reduce log level

**Commands:**
```bash
# Check CPU usage
top -p $(pgrep -f run_ids_with_ui)

# Adjust thresholds in config.yaml
nano config.yaml
```

#### Memory Leaks

**Symptoms:**
- Increasing memory usage over time
- System becomes unresponsive

**Solutions:**
1. Limit ThreatStore size
2. Implement periodic cleanup
3. Monitor memory usage

**Commands:**
```bash
# Monitor memory
watch -n 1 'ps aux | grep run_ids_with_ui'

# Restart service
sudo systemctl restart ids-webui
```

#### WebSocket Disconnections

**Symptoms:**
- Real-time updates stop working
- Browser console shows connection errors

**Solutions:**
1. Check network connectivity
2. Verify firewall settings
3. Check proxy configuration
4. Implement reconnection logic

**Client-Side Fix:**
```javascript
const socket = io('http://localhost:5000', {
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionAttempts: 5
});

socket.on('disconnect', () => {
    console.log('Disconnected, attempting to reconnect...');
});

socket.on('reconnect', () => {
    console.log('Reconnected successfully');
    location.reload();  // Reload page to refresh data
});
```


### Debugging Tips

#### Enable Debug Logging

```bash
# Linux/macOS
sudo python3 run_ids_with_ui.py --debug --log-level DEBUG

# Windows
python run_ids_with_ui.py --debug --log-level DEBUG
```

#### Check Component Status

```python
# Test IDS components
python3 -c "
from ids.ids_application import IDSApplication
ids = IDSApplication('config.yaml')
ids.initialize()
print('IDS initialized successfully')
"

# Test Web UI
python3 -c "
from web_ui.app import app
print('Web UI loaded successfully')
"
```

#### Network Diagnostics

```bash
# Linux/macOS
# Check interface status
ip link show eth0

# Monitor packets
sudo tcpdump -i eth0 -c 10

# Check port availability
sudo lsof -i :5000

# Windows
# Check interface status
netsh interface show interface

# Check port availability
netstat -ano | findstr :5000
```

---

## Best Practices

### Development

1. **Use Virtual Environments:**
   - Isolate project dependencies
   - Avoid conflicts with system packages

2. **Version Control:**
   - Use Git for version control
   - Don't commit sensitive data
   - Use .gitignore for config files

3. **Code Quality:**
   - Follow PEP 8 style guide
   - Write docstrings
   - Add type hints
   - Write unit tests

4. **Testing:**
   - Test on target platform
   - Test with real network traffic
   - Test error conditions
   - Test performance under load

### Deployment

1. **Security:**
   - Use HTTPS in production
   - Implement authentication
   - Secure configuration files
   - Regular security updates

2. **Monitoring:**
   - Monitor system resources
   - Monitor application logs
   - Set up alerts
   - Regular health checks

3. **Backup:**
   - Backup configuration files
   - Backup logs (if needed)
   - Document deployment process
   - Test recovery procedures

4. **Documentation:**
   - Document custom configurations
   - Document integrations
   - Keep runbooks updated
   - Document troubleshooting steps


### Maintenance

1. **Regular Updates:**
   - Update Python packages
   - Update system packages
   - Review security advisories
   - Test updates in staging

2. **Log Management:**
   - Configure log rotation
   - Archive old logs
   - Monitor log disk usage
   - Implement log analysis

3. **Performance Tuning:**
   - Monitor resource usage
   - Adjust thresholds as needed
   - Optimize database queries
   - Review detector efficiency

4. **Capacity Planning:**
   - Monitor growth trends
   - Plan for scaling
   - Review storage requirements
   - Assess network capacity

---

## Glossary

**IDS**: Intrusion Detection System - System that monitors network traffic for suspicious activity

**Packet**: Unit of data transmitted over a network

**Threat**: Detected suspicious or malicious activity

**Detector**: Component that analyzes packets for specific threat types

**Severity**: Classification of threat importance (Critical, High, Medium, Low)

**WebSocket**: Protocol for real-time bidirectional communication

**SMTP**: Simple Mail Transfer Protocol - Protocol for sending email

**TLS/SSL**: Transport Layer Security / Secure Sockets Layer - Encryption protocols

**API**: Application Programming Interface - Interface for programmatic access

**REST**: Representational State Transfer - Architectural style for APIs

**YAML**: YAML Ain't Markup Language - Human-readable data serialization format

**Scapy**: Python library for packet manipulation and analysis

**Flask**: Python web framework

**Nginx**: Web server and reverse proxy

**Systemd**: System and service manager for Linux

---

## Additional Resources

### Documentation

- [README.md](README.md) - Project overview and quick start
- [HOW_TO_RUN.md](HOW_TO_RUN.md) - Detailed setup instructions
- [deployment/DEPLOYMENT_GUIDE.md](deployment/DEPLOYMENT_GUIDE.md) - Production deployment
- [web_ui/api/API_REFERENCE.md](web_ui/api/API_REFERENCE.md) - API documentation

### External Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Flask-SocketIO Documentation](https://flask-socketio.readthedocs.io/)
- [Nginx Documentation](https://nginx.org/en/docs/)
- [Systemd Documentation](https://www.freedesktop.org/software/systemd/man/)

### Security Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

**Version:** 1.0.0  
**Last Updated:** October 15, 2025  
**Python Version:** 3.8+  
**Supported Platforms:** Linux, macOS, Windows

*For setup instructions, see [HOW_TO_RUN.md](HOW_TO_RUN.md)*
