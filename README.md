# Intrusion Detection System (IDS)

A comprehensive network intrusion detection system with real-time threat monitoring, analysis, and a modern web-based dashboard.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Threat Detection](#threat-detection)
- [Web Dashboard](#web-dashboard)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Technologies](#technologies)
- [Security](#security)

## 🎯 Overview

This IDS is a Python-based network security monitoring system that captures and analyzes network packets in real-time to detect various types of cyber threats. It features a modern web interface for monitoring, analytics, and configuration management.

### Key Capabilities

- **Real-time Packet Capture**: Monitors network traffic using Scapy
- **Multi-Threat Detection**: Identifies port scans, brute force attacks, malware, data exfiltration, and ICMP scans
- **Severity Classification**: Automatically classifies threats as Critical, High, Medium, or Low
- **Web Dashboard**: Modern, responsive interface with live updates via WebSockets
- **Email Notifications**: Automated alerts for detected threats
- **Analytics & Reporting**: Visual threat analytics with charts and statistics
- **Configurable**: Flexible configuration for detection thresholds and system behavior

## ✨ Features

### Detection Capabilities

- **Port Scan Detection**: Identifies reconnaissance activities and port scanning attempts
- **Brute Force Detection**: Detects repeated authentication attempts
- **Malware Detection**: Identifies suspicious patterns and known malware signatures
- **Data Exfiltration Detection**: Monitors for unusual data transfer patterns
- **ICMP Scan Detection**: Detects network mapping and ping sweeps
- **Attacker Identification**: Tracks and profiles malicious actors

### Web Interface Features

- **Real-time Dashboard**: Live threat monitoring with WebSocket updates
- **Threat Management**: View, filter, and analyze detected threats
- **Analytics**: Visual charts showing threat trends, severity distribution, and top attackers
- **Configuration Management**: Web-based configuration editor
- **Log Viewer**: Browse and search system logs
- **System Control**: Start/stop monitoring from the web interface

### Notification System

- **Email Alerts**: Automated email notifications for threats
- **Batch Processing**: Intelligent batching to prevent alert fatigue
- **Retry Mechanism**: Ensures critical alerts are delivered
- **Customizable Recipients**: Configure multiple email recipients

## 🏗️ Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                     Web Interface (Flask)                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │Dashboard │  │ Threats  │  │Analytics │  │  Config  │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└────────────────────────┬────────────────────────────────────┘
                         │ WebSocket + REST API
┌────────────────────────┴────────────────────────────────────┐
│                   IDS Controller Layer                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  Event Bus   │  │ Threat Store │  │IDS Controller│     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────────────┐
│                   IDS Core Engine                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         Threat Detection Engine                       │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │Port Scan │  │Brute Force│ │ Malware  │  │   ICMP   │  │
│  │ Detector │  │ Detector  │ │ Detector │  │ Detector │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         Packet Capture Service (Scapy)               │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Packet Capture**: Scapy captures network packets from the specified interface
2. **Detection**: Multiple detectors analyze packets for threats
3. **Classification**: Severity classifier assigns threat levels
4. **Storage**: Threats are stored in-memory with automatic cleanup
5. **Notification**: Email service sends alerts based on severity
6. **Broadcasting**: Event bus broadcasts threats to web interface
7. **Visualization**: Web dashboard displays threats in real-time

## 🔍 Threat Detection

### Detection Algorithms

#### Port Scan Detector
- Monitors connection attempts to multiple ports
- Tracks SYN packets without established connections
- Configurable threshold for detection sensitivity
- **Severity**: Medium to High based on scan intensity

#### Brute Force Detector
- Detects repeated authentication attempts
- Monitors failed login patterns
- Tracks source IPs with multiple attempts
- **Severity**: High to Critical based on attempt frequency

#### Malware Detector
- Analyzes packet payloads for malicious patterns
- Checks against known malware signatures
- Detects suspicious DNS queries
- **Severity**: Critical for confirmed malware

#### Data Exfiltration Detector
- Monitors unusual data transfer volumes
- Tracks outbound traffic patterns
- Identifies potential data theft
- **Severity**: High to Critical based on data volume

#### ICMP Scan Detector
- Detects network reconnaissance via ICMP
- Identifies ping sweeps and network mapping
- Monitors ICMP echo requests
- **Severity**: Low to Medium

### Severity Classification

| Severity | Color | Description | Response |
|----------|-------|-------------|----------|
| **Critical** | ⚫ Black | Immediate threat requiring urgent action | Instant email alert |
| **High** | 🔴 Red | Serious threat requiring prompt attention | Email alert |
| **Medium** | 🟡 Yellow | Moderate threat requiring investigation | Batched email alert |
| **Low** | 🔵 Cyan | Minor threat for awareness | Logged only |

## 🖥️ Web Dashboard

### Dashboard Pages

#### 1. Dashboard (Home)
- System status (running/stopped, interface, uptime, packets analyzed)
- Quick stats cards showing threat counts by severity
- Recent threats list with real-time updates
- Start/Stop monitoring controls

#### 2. Threats
- Complete threat list with filtering by type and severity
- Search functionality for IP addresses
- Detailed threat information modal
- Color-coded severity badges
- Real-time threat updates

#### 3. Analytics
- Threat timeline charts (line graph)
- Threat distribution by type (pie chart)
- Threat distribution by severity (bar chart)
- Top attackers table with threat counts
- Time range selector (1h, 24h, 7d, 30d)

#### 4. Configuration
- Email settings (SMTP configuration)
- Detection thresholds for each detector
- Logging configuration
- Notification batching settings
- Detector enable/disable toggles
- Test email functionality

#### 5. Logs
- System log viewer with pagination
- Event type filtering (threat, notification, system)
- Search functionality
- Real-time log updates

### Real-time Features

- **WebSocket Connection**: Live updates without page refresh
- **Connection Status Indicator**: Shows connection state in header
- **Auto-reconnection**: Automatically reconnects on connection loss
- **Toast Notifications**: User-friendly alerts for actions and events

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- Administrator/Root privileges (required for packet capture)
- Network interface access
- Windows/Linux/macOS

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Dependencies Include

- **scapy**: Packet capture and analysis
- **flask**: Web framework
- **flask-socketio**: WebSocket support
- **flask-cors**: Cross-origin resource sharing
- **pyyaml**: Configuration file parsing
- **python-socketio**: WebSocket client/server

## ⚙️ Configuration

### Configuration File: `config.yaml`

```yaml
email:
  smtp_host: smtp.gmail.com          # SMTP server address
  smtp_port: 587                      # SMTP port (587 for TLS)
  use_tls: true                       # Enable TLS encryption
  username: your-email@gmail.com      # Email username
  password: your-app-password         # Email password/app password
  recipients:                         # List of alert recipients
    - admin@example.com
    - security-team@example.com

detection:
  network_interface: Wi-Fi            # Network interface to monitor
  port_scan_threshold: 5              # Ports scanned before alert
  icmp_scan_threshold: 5              # ICMP requests before alert
  brute_force_threshold: 5            # Failed attempts before alert
  data_exfiltration_threshold: 100    # MB transferred before alert

logging:
  log_level: INFO                     # Log level (DEBUG, INFO, WARNING, ERROR)
  log_file: ids.log                   # Log file path
  max_log_size_mb: 100               # Max log file size before rotation
  backup_count: 5                     # Number of backup log files

notification:
  batch_window_seconds: 300           # Time window for batching alerts
  batch_threshold: 3                  # Threats before sending batch
  retry_attempts: 3                   # Email retry attempts
  retry_delay_seconds: 10            # Delay between retries
```

### Email Configuration

For Gmail, use an App Password:
1. Enable 2-Factor Authentication
2. Generate App Password: Google Account → Security → App Passwords
3. Use the generated password in `config.yaml`

### Network Interface

Find your network interface name:

**Windows:**
```cmd
ipconfig
```

**Linux/Mac:**
```bash
ifconfig
```

Use the interface name (e.g., "Wi-Fi", "eth0", "en0") in `config.yaml`.

## 🚀 Usage

### Start the IDS

```bash
python run_ids_with_ui.py
```

**Important**: Run as Administrator (Windows) or with sudo (Linux/Mac) for packet capture.

### Access Web Dashboard

Open your browser to: **http://localhost:5000**

### Start Monitoring

1. Click "Start Monitoring" button on the dashboard
2. The system will begin capturing and analyzing packets
3. Threats will appear in real-time on the dashboard

### Stop Monitoring

Click "Stop Monitoring" button to stop packet capture.

### View Threats

Navigate to the "Threats" page to:
- View all detected threats
- Filter by type or severity
- Search for specific IP addresses
- View detailed threat information

### Analyze Trends

Navigate to the "Analytics" page to:
- View threat trends over time
- See distribution by type and severity
- Identify top attackers
- Select different time ranges

### Configure System

Navigate to the "Configuration" page to:
- Update email settings
- Adjust detection thresholds
- Configure logging
- Enable/disable specific detectors
- Test email notifications

## 📁 Project Structure

```
IDS/
├── ids/                              # Core IDS Engine
│   ├── detectors/                    # Threat Detection Modules
│   │   ├── attacker_identifier.py    # Attacker profiling
│   │   ├── base_detector.py          # Base detector class
│   │   ├── brute_force_detector.py   # Brute force detection
│   │   ├── data_exfiltration_detector.py  # Data theft detection
│   │   ├── icmp_scan_detector.py     # ICMP scan detection
│   │   ├── malware_detector.py       # Malware detection
│   │   └── port_scan_detector.py     # Port scan detection
│   ├── models/                       # Data Models
│   │   ├── data_models.py            # Threat and packet models
│   │   └── exceptions.py             # Custom exceptions
│   ├── services/                     # Core Services
│   │   ├── email_service.py          # Email notification service
│   │   ├── notification_service.py   # Notification management
│   │   ├── packet_capture.py         # Packet capture service
│   │   ├── severity_classifier.py    # Threat severity classification
│   │   ├── threat_analyzer.py        # Threat analysis
│   │   └── threat_detection_engine.py # Main detection engine
│   ├── utils/                        # Utilities
│   │   ├── config_manager.py         # Configuration management
│   │   └── logger.py                 # Logging utilities
│   ├── cli.py                        # Command-line interface
│   └── ids_application.py            # Main IDS application
│
├── web_ui/                           # Web Interface
│   ├── api/                          # API Layer
│   │   ├── routes.py                 # REST API endpoints
│   │   └── websocket_events.py       # WebSocket event handlers
│   ├── controllers/                  # Controllers
│   │   ├── event_bus.py              # Event broadcasting
│   │   ├── ids_controller.py         # IDS control interface
│   │   └── threat_store.py           # In-memory threat storage
│   ├── static/                       # Static Assets
│   │   ├── css/
│   │   │   └── style.css             # Custom styles
│   │   └── js/
│   │       ├── analytics.js          # Analytics page logic
│   │       ├── common.js             # Shared utilities
│   │       ├── config.js             # Configuration page logic
│   │       ├── dashboard.js          # Dashboard page logic
│   │       ├── logs.js               # Logs page logic
│   │       └── threats.js            # Threats page logic
│   ├── templates/                    # HTML Templates
│   │   ├── analytics.html            # Analytics page
│   │   ├── base.html                 # Base template
│   │   ├── config.html               # Configuration page
│   │   ├── dashboard.html            # Dashboard page
│   │   ├── logs.html                 # Logs page
│   │   └── threats.html              # Threats page
│   └── app.py                        # Flask application
│
├── config.yaml                       # Configuration file
├── config.yaml.example               # Example configuration
├── requirements.txt                  # Python dependencies
├── run_ids_with_ui.py               # Main entry point
├── start_ids.bat                    # Windows batch starter
└── README.md                         # This file
```

## 🛠️ Technologies

### Backend
- **Python 3.8+**: Core programming language
- **Scapy**: Packet capture and manipulation
- **Flask**: Web framework
- **Flask-SocketIO**: WebSocket support for real-time updates
- **PyYAML**: Configuration file parsing

### Frontend
- **HTML5/CSS3**: Modern web standards
- **JavaScript (ES6+)**: Client-side logic
- **Bootstrap 5**: Responsive UI framework
- **Bootstrap Icons**: Icon library
- **Chart.js**: Data visualization
- **Socket.IO Client**: WebSocket client

### Architecture Patterns
- **MVC Pattern**: Model-View-Controller architecture
- **Event-Driven**: Event bus for component communication
- **Repository Pattern**: Data access abstraction
- **Observer Pattern**: Real-time updates via WebSocket

## 🔒 Security

### Security Considerations

1. **Credential Management**
   - Never commit `config.yaml` with real credentials
   - Use environment variables for sensitive data in production
   - Use app-specific passwords for email services

2. **Network Access**
   - Requires administrator/root privileges for packet capture
   - Monitors network traffic (ensure compliance with policies)
   - Bind web interface to localhost by default

3. **Data Storage**
   - Threats stored in-memory (not persisted to disk)
   - Automatic cleanup of old threats (keeps last 1000)
   - Logs rotated automatically to prevent disk fill

4. **Web Interface**
   - No authentication by default (add authentication for production)
   - CORS enabled for development (restrict in production)
   - Input validation on all API endpoints

### Production Deployment

For production use:
- Add authentication to web interface
- Use HTTPS with SSL certificates
- Restrict CORS to specific origins
- Use environment variables for configuration
- Implement rate limiting
- Add database persistence for threats
- Set up proper logging and monitoring

## 📝 License

This project is for educational and research purposes.

## 🤝 Contributing

Contributions are welcome! Please ensure:
- Code follows existing style
- All detectors include proper documentation
- Web UI changes are responsive
- Configuration changes are documented

## 📧 Support

For issues or questions:
- Check the logs in `ids.log`
- Verify configuration in `config.yaml`
- Ensure running with administrator privileges
- Check network interface name is correct

## 🎓 Educational Purpose

This IDS is designed for:
- Learning network security concepts
- Understanding intrusion detection systems
- Practicing threat analysis
- Studying network protocols
- Web application development with real-time features

---

**⚠️ Disclaimer**: This tool is for educational and authorized testing purposes only. Always ensure you have permission to monitor network traffic.
