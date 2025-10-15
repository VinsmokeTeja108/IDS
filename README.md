# Intrusion Detection System (IDS)

A comprehensive Python-based network intrusion detection system that monitors network traffic in real-time to detect security threats and automatically sends email notifications with detailed analysis and remediation recommendations.

## 📚 Documentation

- **[HOW_TO_RUN.md](HOW_TO_RUN.md)** - Detailed step-by-step setup and usage instructions
- **[DOCUMENTATION.md](DOCUMENTATION.md)** - Complete technical documentation and API reference
- **[SYSTEMD_DEPLOYMENT.md](SYSTEMD_DEPLOYMENT.md)** - Linux systemd service deployment guide

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure
cp config.yaml.example config.yaml
# Edit config.yaml with your settings

# 3. Run (requires root/admin privileges)
sudo python3 ids_main.py --config config.yaml
```

For detailed instructions, see [HOW_TO_RUN.md](HOW_TO_RUN.md).

## ✨ Features

### 🔍 Threat Detection
- **Real-time Network Monitoring**: Continuous packet capture and analysis
- **Multi-threat Detection**: Port scans, brute force attacks, malware, data exfiltration, ICMP scans
- **Behavioral Analysis**: Attacker identification and pattern recognition
- **Configurable Thresholds**: Customizable detection sensitivity

### 📧 Alerting & Notifications
- **Automated Email Alerts**: Rich HTML notifications with threat details
- **Severity Classification**: Intelligent threat severity assessment
- **Batch Notifications**: Smart batching to prevent email flooding
- **Multiple Recipients**: Support for distribution lists

### 🛠️ Deployment & Management
- **Cross-platform Support**: Linux, Windows, macOS
- **Systemd Integration**: Production-ready Linux service deployment
- **Comprehensive Logging**: JSON-formatted logs with automatic rotation
- **CLI Interface**: Full command-line control with multiple options

### 🔧 Configuration & Monitoring
- **YAML Configuration**: Easy-to-edit configuration files
- **Real-time Monitoring**: Live log streaming and status monitoring
- **Performance Optimization**: Resource limits and tuning options
- **Security Hardening**: Built-in security features and best practices

## 🎯 Detected Threats

| Threat Type | Description | Detection Method |
|-------------|-------------|------------------|
| **Port Scanning** | TCP/UDP port scans and connection attempts | Threshold-based port access monitoring |
| **ICMP Scanning** | Ping sweeps and ICMP reconnaissance | ICMP packet pattern analysis |
| **Brute Force Attacks** | Repeated authentication failures | Failed login attempt tracking |
| **Malware Detection** | Signature-based payload analysis | Payload pattern matching |
| **Data Exfiltration** | Unusual outbound data transfers | Data volume and pattern analysis |
| **Attacker Identification** | Behavioral analysis of suspicious IPs | Multi-vector threat correlation |

## 📋 Requirements

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **OS** | Linux, Windows 10+, macOS 10.14+ | Linux (Ubuntu 20.04+) |
| **Python** | 3.8+ | 3.9+ |
| **RAM** | 512 MB | 2 GB+ |
| **Storage** | 100 MB | 1 GB+ (SSD) |
| **Privileges** | Root/Administrator | Root/Administrator |

### Python Dependencies

```bash
scapy>=2.5.0,<3.0.0      # Packet capture and analysis
pyyaml>=6.0,<7.0.0       # Configuration file parsing
psutil>=5.8.0            # System monitoring
colorama>=0.4.4          # Cross-platform colored output
```

**Note**: All dependencies are automatically installed via `pip install -r requirements.txt`

## 🔧 Installation

### Quick Installation

```bash
# 1. Download/Clone the project
git clone <repository-url>
cd ids

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure
cp config.yaml.example config.yaml
nano config.yaml  # Edit with your settings

# 4. Run
sudo python3 ids_main.py --config config.yaml
```

### Detailed Installation

For comprehensive setup instructions including virtual environments, systemd service deployment, and troubleshooting, see **[HOW_TO_RUN.md](HOW_TO_RUN.md)**.

### Production Deployment

For production Linux environments with systemd service:

```bash
# Automated installation
sudo ./install-service.sh

# Manual service setup - see SYSTEMD_DEPLOYMENT.md
sudo cp ids.service /etc/systemd/system/
sudo systemctl enable ids
sudo systemctl start ids
```

See **[SYSTEMD_DEPLOYMENT.md](SYSTEMD_DEPLOYMENT.md)** for complete deployment instructions.

## ⚙️ Configuration

### Quick Configuration

```bash
# 1. Copy example configuration
cp config.yaml.example config.yaml

# 2. Edit key settings
nano config.yaml
```

### Essential Settings

```yaml
# Email notifications
email_config:
  smtp_server: "smtp.gmail.com"
  smtp_port: 587
  username: "your-email@gmail.com"
  password: "your-app-password"    # Use App Password for Gmail
  recipient_emails:
    - "admin@company.com"

# Network monitoring
detection_config:
  network_interface: "eth0"        # Your network interface
  port_scan_threshold: 10          # Sensitivity level
  brute_force_threshold: 5
  time_window: 300

# Logging
logging_config:
  level: "INFO"                    # DEBUG, INFO, WARNING, ERROR
  log_file: "ids.log"
```

### Find Your Network Interface

```bash
# Linux
ip addr show

# Windows
ipconfig

# macOS
ifconfig
```

For complete configuration options and examples, see **[DOCUMENTATION.md](DOCUMENTATION.md)**.

## 🚀 Usage

### Basic Commands

```bash
# Standard operation
sudo python3 ids_main.py --config config.yaml

# Development/testing
sudo python3 ids_main.py --config config.yaml --verbose --dry-run

# Specific interface
sudo python3 ids_main.py --config config.yaml --interface eth0

# Background operation
sudo nohup python3 ids_main.py --config config.yaml > ids.log 2>&1 &
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-c, --config FILE` | Configuration file path |
| `-i, --interface IFACE` | Network interface to monitor |
| `-v, --verbose` | Enable verbose logging |
| `--dry-run` | Test mode (no emails sent) |
| `--no-banner` | Suppress startup banner |
| `--help` | Show help message |

### Service Deployment

#### Linux (Systemd) - Recommended

```bash
# Quick setup
sudo ./install-service.sh

# Manual setup
sudo systemctl enable ids
sudo systemctl start ids
sudo systemctl status ids
```

#### Monitoring Service

```bash
# Check status
sudo systemctl status ids

# View logs
sudo journalctl -u ids -f

# Restart service
sudo systemctl restart ids
```

For detailed usage instructions, see **[HOW_TO_RUN.md](HOW_TO_RUN.md)**.

## 🔐 Privilege Requirements

**Root/Administrator access is required** for packet capture operations.

### Why Elevated Privileges?

- Network packet capture from interfaces
- Low-level network operations
- System network traffic monitoring
- Raw socket access

### Platform-Specific

| Platform | Command |
|----------|---------|
| **Linux/macOS** | `sudo python3 ids_main.py` |
| **Windows** | Run Command Prompt as Administrator |

### Security Note

The IDS runs with elevated privileges only for packet capture. All security best practices are implemented in the systemd service configuration.

## 📧 Email Notifications

### Alert Features

- **Rich HTML Format**: Detailed threat information with formatting
- **Severity Classification**: High, Medium, Low severity levels
- **Actionable Recommendations**: Specific remediation steps
- **Technical Details**: Complete packet and network information
- **Batch Processing**: Multiple threats in single email to prevent flooding

### Example Alert

```
Subject: [IDS ALERT - HIGH] Port Scan Detected

=== THREAT DETECTED ===
Type: Port Scan
Severity: High
Source: 192.168.1.100 → 10.0.0.5
Timestamp: 2025-10-15 14:30:25

=== ANALYSIS ===
15 ports scanned within 60 seconds (threshold: 10)
Protocols: TCP
Ports: 22, 80, 443, 3389, 5432...

=== RECOMMENDED ACTIONS ===
1. Block source IP at firewall
2. Review open ports
3. Monitor for additional activity
```

### Email Configuration

```yaml
email_config:
  smtp_server: "smtp.gmail.com"
  smtp_port: 587
  username: "alerts@company.com"
  password: "app-password"
  recipient_emails:
    - "security@company.com"
    - "admin@company.com"
```

## 📊 Logging & Monitoring

### Log Features

- **JSON Format**: Structured logs for easy parsing and analysis
- **Automatic Rotation**: Configurable size limits and backup retention
- **Real-time Streaming**: Live log monitoring capabilities
- **Severity Levels**: DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Systemd Integration**: Native journal logging for service deployment

### Log Example

```json
{
  "timestamp": "2025-10-15T14:30:25Z",
  "event_type": "threat_detected",
  "threat_type": "port_scan",
  "severity": "high",
  "source_ip": "192.168.1.100",
  "destination_ip": "10.0.0.5",
  "details": {
    "ports_scanned": 15,
    "threshold": 10,
    "protocol": "TCP"
  }
}
```

### Monitoring Commands

```bash
# Real-time log monitoring
tail -f ids.log

# Service logs (systemd)
sudo journalctl -u ids -f

# Search for threats
grep "threat_detected" ids.log | jq '.'

# Monitor specific threat types
tail -f ids.log | grep "port_scan"
```

## 🔧 Troubleshooting

### Quick Fixes

| Issue | Solution |
|-------|----------|
| **Permission Denied** | Run with `sudo` (Linux/macOS) or as Administrator (Windows) |
| **Interface Not Found** | Check interface name with `ip addr show` or `ipconfig` |
| **Email Auth Failed** | Use App Password for Gmail, check SMTP settings |
| **No Threats Detected** | Verify interface is active, test with `--verbose` |
| **High CPU Usage** | Increase detection thresholds, reduce log level |

### Debug Mode

```bash
# Enable verbose logging
sudo python3 ids_main.py --config config.yaml --verbose

# Test configuration without emails
sudo python3 ids_main.py --config config.yaml --dry-run

# Check specific interface
sudo python3 ids_main.py --config config.yaml --interface eth0 --verbose
```

### Common Commands

```bash
# Test packet capture
sudo python3 -c "from scapy.all import sniff; print('Testing...'); sniff(count=5)"

# Check interface status
ip addr show  # Linux
ipconfig      # Windows

# Monitor logs
tail -f ids.log | grep -i "error\|threat"

# Service status (systemd)
sudo systemctl status ids
sudo journalctl -u ids -n 50
```

For comprehensive troubleshooting, see **[HOW_TO_RUN.md](HOW_TO_RUN.md)** and **[DOCUMENTATION.md](DOCUMENTATION.md)**.

## 📈 Performance & Security

### System Resources

| Resource | Usage | Optimization |
|----------|-------|--------------|
| **CPU** | Moderate (packet analysis) | Tune detection thresholds |
| **Memory** | Low (detection state) | Monitor with `top` |
| **Disk** | Variable (log files) | Configure log rotation |
| **Network** | Minimal impact | Use dedicated monitoring interface |

### Security Best Practices

- **Configuration Security**: Protect config files (`chmod 600 config.yaml`)
- **Email Security**: Use dedicated accounts with App Passwords
- **Network Security**: Deploy on trusted systems with proper segmentation
- **Operational Security**: Regular backups, health monitoring, threshold tuning

### Performance Monitoring

```bash
# Resource usage
top -p $(pgrep -f ids_main.py)

# Log file sizes
du -sh *.log

# Service performance (systemd)
sudo systemctl status ids
```

## 📚 Documentation & Support

### Complete Documentation

| Document | Purpose |
|----------|---------|
| **[HOW_TO_RUN.md](HOW_TO_RUN.md)** | Step-by-step setup and usage guide |
| **[DOCUMENTATION.md](DOCUMENTATION.md)** | Complete technical documentation |
| **[SYSTEMD_DEPLOYMENT.md](SYSTEMD_DEPLOYMENT.md)** | Linux service deployment |

### Getting Help

1. **Check Documentation**: Review the guides above for detailed instructions
2. **Enable Debug Mode**: Use `--verbose` flag for detailed logging
3. **Test Configuration**: Use `--dry-run` mode to test without sending emails
4. **Check Logs**: Review `ids.log` or `journalctl -u ids` for errors

### Project Structure

```
ids/
├── ids/                    # Main IDS package
│   ├── detectors/         # Threat detection modules
│   ├── services/          # Core services
│   ├── utils/             # Utilities and helpers
│   └── models/            # Data models
├── config.yaml.example    # Configuration template
├── ids_main.py            # Main entry point
├── ids.service            # Systemd service file
├── install-service.sh     # Automated installer
└── requirements.txt       # Python dependencies
```

### File Overview

| File | Purpose |
|------|---------|
| `ids_main.py` | Main application entry point |
| `config.yaml.example` | Configuration template |
| `ids.service` | Systemd service configuration |
| `install-service.sh` | Automated Linux installation |
| `requirements.txt` | Python package dependencies |

## ⚖️ License & Legal

This project is provided for **educational and security monitoring purposes**. 

### Important Legal Notes

- ⚠️ **Authorization Required**: Ensure proper authorization before monitoring network traffic
- 🏢 **Corporate Environments**: Check with IT/Legal before deployment
- 🌍 **Compliance**: Use in accordance with local laws and regulations
- 🔒 **Privacy**: Respect privacy laws and data protection regulations

### Disclaimer

This software is provided "as-is" without warranty. Users are responsible for ensuring compliance with applicable laws and regulations.

---

## 🚀 Quick Reference

### Essential Commands

```bash
# Install and configure
pip install -r requirements.txt
cp config.yaml.example config.yaml

# Run (development)
sudo python3 ids_main.py --config config.yaml --verbose

# Deploy (production)
sudo ./install-service.sh
sudo systemctl start ids

# Monitor
sudo journalctl -u ids -f
tail -f ids.log
```

### Key Features Summary

✅ **Real-time threat detection** - Port scans, brute force, malware, data exfiltration  
✅ **Email notifications** - Rich HTML alerts with remediation steps  
✅ **Production deployment** - Systemd service with auto-restart  
✅ **Cross-platform** - Linux, Windows, macOS support  
✅ **Configurable** - YAML configuration with flexible thresholds  
✅ **Comprehensive logging** - JSON logs with rotation  

---

*For detailed setup instructions, see [HOW_TO_RUN.md](HOW_TO_RUN.md)*