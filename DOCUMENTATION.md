# Intrusion Detection System (IDS) - Complete Documentation

This document serves as the comprehensive documentation hub for the Intrusion Detection System (IDS).

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Features](#features)
4. [Installation and Setup](#installation-and-setup)
5. [Configuration](#configuration)
6. [Usage](#usage)
7. [Deployment](#deployment)
8. [API Reference](#api-reference)
9. [Troubleshooting](#troubleshooting)
10. [Contributing](#contributing)
11. [License](#license)

## Overview

The Intrusion Detection System (IDS) is a Python-based network security monitoring tool designed to detect and alert on various types of network threats and suspicious activities. It provides real-time network traffic analysis, threat detection, and automated notification capabilities.

### Key Capabilities

- **Real-time Network Monitoring**: Continuous packet capture and analysis
- **Multi-threat Detection**: Port scans, brute force attacks, malware, data exfiltration
- **Automated Alerting**: Email notifications for detected threats
- **Flexible Deployment**: Command-line interface and systemd service support
- **Configurable Thresholds**: Customizable detection sensitivity
- **Comprehensive Logging**: Detailed audit trails and monitoring

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                    IDS Application                          │
├─────────────────────────────────────────────────────────────┤
│  CLI Interface (ids/cli.py)                                │
├─────────────────────────────────────────────────────────────┤
│  Core Application (ids/ids_application.py)                 │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │   Services      │  │   Detectors     │  │   Utils      │ │
│  │                 │  │                 │  │              │ │
│  │ • Packet        │  │ • Port Scanner  │  │ • Config     │ │
│  │   Capture       │  │ • Brute Force   │  │   Manager    │ │
│  │ • Threat        │  │ • Malware       │  │ • Logger     │ │
│  │   Detection     │  │ • Data Exfil    │  │              │ │
│  │ • Notification  │  │ • ICMP Scan     │  │              │ │
│  │ • Email         │  │ • Attacker ID   │  │              │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  Data Models (ids/models/)                                 │
└─────────────────────────────────────────────────────────────┘
```

### Component Details

#### Services Layer
- **Packet Capture**: Network traffic monitoring using Scapy
- **Threat Detection Engine**: Coordinates multiple detection modules
- **Threat Analyzer**: Analyzes captured packets for threats
- **Severity Classifier**: Categorizes threat severity levels
- **Notification Service**: Manages alert distribution
- **Email Service**: Handles email notifications

#### Detectors Layer
- **Port Scan Detector**: Identifies port scanning activities
- **Brute Force Detector**: Detects authentication brute force attempts
- **Malware Detector**: Identifies malware-related network patterns
- **Data Exfiltration Detector**: Monitors for data theft attempts
- **ICMP Scan Detector**: Detects ICMP-based reconnaissance
- **Attacker Identifier**: Tracks and identifies repeat offenders

#### Utilities Layer
- **Configuration Manager**: Handles YAML configuration files
- **Logger**: Centralized logging with rotation support

## Features

### Detection Capabilities

#### 1. Port Scan Detection
- **TCP Connect Scans**: Detects full TCP connection attempts
- **SYN Scans**: Identifies half-open scanning techniques
- **UDP Scans**: Monitors UDP port probing
- **Threshold-based**: Configurable number of ports before alert

#### 2. Brute Force Detection
- **SSH Brute Force**: Monitors SSH authentication failures
- **HTTP/HTTPS Login**: Detects web application brute force
- **FTP Brute Force**: Identifies FTP authentication attacks
- **Time-window Analysis**: Configurable time periods for detection

#### 3. Malware Detection
- **Payload Analysis**: Scans packet payloads for malware signatures
- **Command & Control**: Identifies C&C communication patterns
- **Suspicious Downloads**: Monitors for malware download attempts
- **PowerShell Patterns**: Detects malicious PowerShell usage

#### 4. Data Exfiltration Detection
- **Large Data Transfers**: Monitors unusual data volumes
- **Suspicious Protocols**: Identifies uncommon data transfer methods
- **External Communications**: Tracks data leaving the network
- **Pattern Recognition**: Identifies exfiltration techniques

#### 5. Network Reconnaissance
- **ICMP Scanning**: Detects ping sweeps and ICMP probes
- **Network Mapping**: Identifies network discovery attempts
- **Service Enumeration**: Monitors service discovery activities

### Alerting and Notification

#### Email Notifications
- **SMTP Support**: Compatible with major email providers
- **HTML Formatting**: Rich email alerts with threat details
- **Multiple Recipients**: Support for distribution lists
- **Severity-based**: Different alert levels based on threat severity

#### Logging
- **Structured Logging**: JSON and text format support
- **Log Rotation**: Automatic log file management
- **Syslog Integration**: Compatible with system logging
- **Real-time Monitoring**: Live log streaming capabilities

## Installation and Setup

For detailed installation instructions, see [HOW_TO_RUN.md](HOW_TO_RUN.md).

### Quick Start

```bash
# Clone repository
git clone <repository-url>
cd ids

# Install dependencies
pip install -r requirements.txt

# Configure
cp config.yaml.example config.yaml
# Edit config.yaml with your settings

# Run
sudo python3 ids_main.py --config config.yaml
```

## Configuration

### Configuration File Structure

The IDS uses a YAML configuration file with the following sections:

```yaml
# Network and Detection Configuration
detection_config:
  network_interface: "eth0"
  port_scan_threshold: 10
  brute_force_threshold: 5
  time_window: 300
  enable_malware_detection: true
  enable_data_exfiltration_detection: true

# Email Notification Settings
email_config:
  smtp_server: "smtp.gmail.com"
  smtp_port: 587
  username: "your-email@gmail.com"
  password: "your-password"
  sender_email: "your-email@gmail.com"
  recipient_emails:
    - "admin@company.com"

# Logging Configuration
logging_config:
  level: "INFO"
  log_file: "ids.log"
  max_file_size: 10485760
  backup_count: 5
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
```

### Configuration Options

#### Detection Settings
- `network_interface`: Network interface to monitor
- `port_scan_threshold`: Number of ports scanned before alert
- `brute_force_threshold`: Failed authentication attempts before alert
- `time_window`: Time window for threat detection (seconds)
- `enable_*_detection`: Enable/disable specific detection modules

#### Email Settings
- `smtp_server`: SMTP server hostname
- `smtp_port`: SMTP server port (587 for TLS, 465 for SSL)
- `username/password`: SMTP authentication credentials
- `sender_email`: Email address for outgoing alerts
- `recipient_emails`: List of alert recipients

#### Logging Settings
- `level`: Log level (DEBUG, INFO, WARNING, ERROR)
- `log_file`: Log file path
- `max_file_size`: Maximum log file size before rotation
- `backup_count`: Number of backup log files to keep

## Usage

### Command Line Interface

The IDS provides a comprehensive CLI with the following options:

```bash
# Basic usage
sudo python3 ids_main.py [OPTIONS]

# Options:
-c, --config FILE     Configuration file path
-i, --interface IFACE Network interface to monitor
-v, --verbose         Enable verbose logging
--dry-run            Run without sending emails
--no-banner          Suppress startup banner
--help               Show help message
--version            Show version information
```

### Examples

```bash
# Standard operation
sudo python3 ids_main.py --config config.yaml

# Development testing
sudo python3 ids_main.py --config config.yaml --verbose --dry-run

# Specific interface
sudo python3 ids_main.py --config config.yaml --interface wlan0

# Background operation
sudo nohup python3 ids_main.py --config config.yaml > ids.log 2>&1 &
```

## Deployment

The IDS supports multiple deployment methods:

### 1. Development/Testing Deployment
- Direct Python execution
- Manual configuration
- Interactive monitoring

### 2. Production Deployment (Linux)
- Systemd service integration
- Automatic startup
- System-level logging
- Resource management

### 3. Containerized Deployment
- Docker support
- Isolated environment
- Scalable deployment

---

# Systemd Service Deployment

This section describes how to deploy the Intrusion Detection System (IDS) as a systemd service on Linux systems.

## Files

- `ids.service` - Systemd service unit file
- `install-service.sh` - Automated installation script

## Quick Installation

For automated installation, run the installation script as root:

```bash
sudo ./install-service.sh
```

This script will:
1. Create necessary directories (`/opt/ids`, `/etc/ids`, `/var/log/ids`)
2. Copy IDS files to `/opt/ids`
3. Install Python dependencies
4. Install and configure the systemd service
5. Set up proper permissions

## Manual Installation

### 1. Create Directories

```bash
sudo mkdir -p /opt/ids
sudo mkdir -p /etc/ids
sudo mkdir -p /var/log/ids
```

### 2. Copy Files

```bash
# Copy IDS application files
sudo cp -r ids/ /opt/ids/
sudo cp ids_main.py /opt/ids/
sudo cp main.py /opt/ids/
sudo cp ids.py /opt/ids/
sudo cp requirements.txt /opt/ids/
sudo cp README.md /opt/ids/

# Copy configuration
sudo cp config.yaml.example /etc/ids/config.yaml
```

### 3. Install Dependencies

```bash
sudo pip3 install -r /opt/ids/requirements.txt
```

### 4. Set Permissions

```bash
sudo chown -R root:root /opt/ids
sudo chown -R root:root /etc/ids
sudo chown -R root:root /var/log/ids
sudo chmod +x /opt/ids/ids_main.py
```

### 5. Install Service

```bash
sudo cp ids.service /etc/systemd/system/
sudo systemctl daemon-reload
```

## Configuration

Edit the configuration file:

```bash
sudo nano /etc/ids/config.yaml
```

Make sure to configure:
- Email settings (SMTP server, credentials, recipients)
- Network interface to monitor
- Detection thresholds
- Logging preferences

## Service Management

### Enable and Start Service

```bash
# Enable service to start on boot
sudo systemctl enable ids

# Start the service
sudo systemctl start ids
```

### Check Service Status

```bash
# Check if service is running
sudo systemctl status ids

# View recent logs
sudo journalctl -u ids -n 50

# Follow logs in real-time
sudo journalctl -u ids -f
```

### Stop and Disable Service

```bash
# Stop the service
sudo systemctl stop ids

# Disable service from starting on boot
sudo systemctl disable ids
```

### Restart Service

```bash
# Restart the service (useful after config changes)
sudo systemctl restart ids

# Reload configuration without full restart
sudo systemctl reload ids
```

## Service Configuration Details

The systemd service is configured with the following features:

### Security Features
- Runs as root (required for packet capture)
- Private temporary directory
- Protected system directories
- Restricted access to home directories
- Kernel protection enabled

### Reliability Features
- Automatic restart on failure
- Start limit protection (max 3 restarts in 60 seconds)
- Proper timeout handling
- Graceful shutdown support

### Resource Limits
- File descriptor limit: 65536
- Process limit: 4096

### Logging
- All output goes to systemd journal
- Logs tagged with 'ids' identifier
- Unbuffered Python output for real-time logging

## Troubleshooting

### Service Won't Start

1. Check service status:
   ```bash
   sudo systemctl status ids
   ```

2. Check logs for errors:
   ```bash
   sudo journalctl -u ids -n 100
   ```

3. Verify configuration:
   ```bash
   sudo python3 /opt/ids/ids_main.py --config /etc/ids/config.yaml --dry-run
   ```

### Permission Issues

Ensure the service is running as root and has access to network interfaces:

```bash
# Check if service is running as root
ps aux | grep ids_main

# Verify network interface permissions
sudo python3 -c "from scapy.all import *; print('Scapy can access network interfaces')"
```

### Configuration Issues

1. Validate YAML syntax:
   ```bash
   python3 -c "import yaml; yaml.safe_load(open('/etc/ids/config.yaml'))"
   ```

2. Test email configuration:
   ```bash
   sudo python3 /opt/ids/ids_main.py --config /etc/ids/config.yaml --test-email
   ```

### High Resource Usage

Monitor resource usage:

```bash
# Check memory usage
sudo systemctl status ids

# Check detailed resource usage
sudo systemd-cgtop
```

## Log Management

Logs are managed by systemd journal. To configure log retention:

```bash
# Edit journald configuration
sudo nano /etc/systemd/journald.conf

# Set log retention (example: keep 1 month)
SystemMaxUse=1G
MaxRetentionSec=2592000
```

## Uninstallation

To completely remove the IDS service:

```bash
# Stop and disable service
sudo systemctl stop ids
sudo systemctl disable ids

# Remove service file
sudo rm /etc/systemd/system/ids.service
sudo systemctl daemon-reload

# Remove files (optional)
sudo rm -rf /opt/ids
sudo rm -rf /etc/ids
sudo rm -rf /var/log/ids
```

## Security Considerations

1. **Root Privileges**: The service runs as root for packet capture. Ensure the system is properly secured.

2. **Configuration Security**: Protect the configuration file containing email credentials:
   ```bash
   sudo chmod 600 /etc/ids/config.yaml
   ```

3. **Log Security**: Ensure log files are properly protected:
   ```bash
   sudo chmod 640 /var/log/ids/*
   ```

4. **Network Security**: The IDS monitors network traffic. Ensure it's deployed on trusted systems.

## Performance Tuning

For high-traffic environments, consider:

1. **CPU Affinity**: Pin the service to specific CPU cores
2. **Memory Limits**: Adjust memory limits in the service file
3. **Buffer Sizes**: Tune packet capture buffer sizes in configuration
4. **Detection Thresholds**: Adjust thresholds to reduce false positives

Example service modifications for high-performance environments:

```ini
[Service]
# Pin to specific CPU cores
CPUAffinity=0-3

# Increase memory limit
MemoryMax=2G

# Higher priority
Nice=-10
```

---

## API Reference

### Core Classes

#### IDSApplication
Main application class that coordinates all IDS components.

```python
class IDSApplication:
    def __init__(self, config_path: str)
    def initialize(self) -> None
    def run(self) -> None
    def shutdown(self) -> None
```

#### ThreatDetectionEngine
Coordinates threat detection across multiple detector modules.

```python
class ThreatDetectionEngine:
    def __init__(self, config: Dict[str, Any])
    def add_detector(self, detector: BaseDetector) -> None
    def analyze_packet(self, packet: Packet) -> List[ThreatAlert]
```

#### BaseDetector
Abstract base class for all threat detectors.

```python
class BaseDetector:
    def detect(self, packet: Packet) -> Optional[ThreatAlert]
    def reset(self) -> None
```

### Configuration Classes

#### ConfigManager
Handles configuration file loading and validation.

```python
class ConfigManager:
    def __init__(self, config_path: str)
    def load_config(self) -> Dict[str, Any]
    def validate_config(self) -> bool
```

### Data Models

#### ThreatAlert
Represents a detected threat.

```python
@dataclass
class ThreatAlert:
    threat_type: str
    severity: str
    source_ip: str
    destination_ip: str
    timestamp: datetime
    details: Dict[str, Any]
```

#### NetworkPacket
Wrapper for network packet data.

```python
@dataclass
class NetworkPacket:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    payload: bytes
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Import Errors
```bash
# Error: ModuleNotFoundError: No module named 'scapy'
# Solution:
pip install -r requirements.txt
```

#### 2. Permission Errors
```bash
# Error: PermissionError: [Errno 1] Operation not permitted
# Solution:
sudo python3 ids_main.py --config config.yaml
```

#### 3. Network Interface Issues
```bash
# Error: Interface 'eth0' not found
# Solution: Check available interfaces
ip addr show  # Linux
ifconfig      # Linux/macOS
```

#### 4. Email Configuration
```bash
# Error: SMTP authentication failed
# Solution: Check email settings, use app passwords for Gmail
```

### Debug Mode

Enable verbose logging for detailed troubleshooting:

```bash
sudo python3 ids_main.py --config config.yaml --verbose
```

### Log Analysis

```bash
# View recent logs
tail -n 100 ids.log

# Search for specific threats
grep -i "port scan" ids.log

# Monitor real-time activity
tail -f ids.log | grep -i "alert"
```

## Contributing

### Development Setup

1. Fork the repository
2. Create a virtual environment
3. Install development dependencies
4. Make changes and test
5. Submit pull request

### Code Style

- Follow PEP 8 guidelines
- Use type hints
- Include docstrings
- Write unit tests

### Testing

```bash
# Run tests (if available)
python -m pytest tests/

# Manual testing
sudo python3 ids_main.py --config config.yaml --dry-run --verbose
```

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Support

For support and questions:

1. Check this documentation
2. Review [HOW_TO_RUN.md](HOW_TO_RUN.md) for setup issues
3. Enable verbose logging for debugging
4. Check system logs for additional context

## Version History

- **v1.0.0**: Initial release with core detection capabilities
- **v1.1.0**: Added systemd service support
- **v1.2.0**: Enhanced email notifications and logging

---

*Last updated: December 2024*