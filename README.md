# Intrusion Detection System (IDS)

A Python-based network intrusion detection system that monitors network traffic in real-time to detect security threats and automatically sends email notifications with detailed analysis and remediation recommendations.

## Features

- **Real-time Threat Detection**: Monitors network traffic for various attack patterns
- **Multiple Detection Types**: Port scans, ICMP scans, brute force attacks, malware, data exfiltration
- **Automated Email Alerts**: Sends detailed notifications with severity levels and remediation steps
- **Configurable Thresholds**: Customizable detection sensitivity and notification settings
- **Comprehensive Logging**: JSON-formatted logs with automatic rotation
- **Batch Notifications**: Intelligent batching to prevent email flooding
- **Cross-platform Support**: Works on Linux, Windows, and macOS

## Detected Threats

- **Port Scanning**: TCP/UDP port scans and connection attempts
- **ICMP Scanning**: Ping sweeps and ICMP reconnaissance
- **Brute Force Attacks**: Repeated authentication failures
- **Malware Detection**: Signature-based payload analysis
- **Data Exfiltration**: Unusual outbound data transfers
- **Attacker Identification**: Behavioral analysis of suspicious IPs

## Requirements

### System Requirements

- **Operating System**: Linux (recommended), Windows 10+, or macOS 10.14+
- **Python**: 3.8 or higher
- **Privileges**: Administrator/root access for packet capture
- **Network**: Access to network interface for monitoring
- **Memory**: Minimum 512MB RAM (1GB+ recommended)

### Python Dependencies

```bash
scapy>=2.5.0,<3.0.0
pyyaml>=6.0,<7.0.0
```

## Installation

### 1. Clone or Download

```bash
# Clone the repository (if using git)
git clone <repository-url>
cd intrusion-detection-system

# Or download and extract the source code
```

### 2. Install Python Dependencies

```bash
# Install required packages
pip install -r requirements.txt

# Or install manually
pip install scapy pyyaml
```

### 3. Set Up Configuration

```bash
# Copy the example configuration file
cp config.yaml.example config.yaml

# Edit the configuration file with your settings
nano config.yaml  # or use your preferred editor
```

### 4. Configure Email Settings

Edit `config.yaml` and update the email section:

```yaml
email:
  smtp_host: smtp.gmail.com
  smtp_port: 587
  use_tls: true
  username: your-email@example.com
  password: your-app-password
  recipients:
    - admin@example.com
```

**Important**: For Gmail, use an App Password instead of your regular password. See [Gmail App Passwords](https://support.google.com/accounts/answer/185833) for setup instructions.

## Configuration

### Configuration File Format

The `config.yaml` file contains all system settings:

```yaml
# Email notification settings
email:
  smtp_host: smtp.gmail.com          # SMTP server hostname
  smtp_port: 587                     # SMTP server port
  use_tls: true                      # Enable TLS encryption
  username: your-email@example.com   # SMTP username
  password: your-app-password        # SMTP password/app password
  recipients:                        # List of alert recipients
    - admin@example.com
    - security@example.com

# Threat detection settings
detection:
  network_interface: eth0            # Network interface to monitor
  port_scan_threshold: 10            # Ports scanned before alert (60s window)
  icmp_scan_threshold: 5             # Hosts pinged before alert (30s window)
  brute_force_threshold: 5           # Failed attempts before alert (60s window)

# Logging configuration
logging:
  log_level: INFO                    # DEBUG, INFO, WARNING, ERROR, CRITICAL
  log_file: ids.log                  # Log file path
  max_log_size_mb: 100              # Max log size before rotation
  backup_count: 5                    # Number of backup logs to keep

# Notification behavior
notification:
  batch_window_seconds: 300          # Time window for batching alerts
  batch_threshold: 3                 # Min threats before batching
  retry_attempts: 3                  # Email retry attempts
  retry_delay_seconds: 10            # Delay between retries
```

### Network Interface Selection

Find your network interface name:

**Linux:**
```bash
# List all interfaces
ip link show
# or
ifconfig

# Common names: eth0, wlan0, enp0s3
```

**Windows:**
```cmd
# List interfaces
ipconfig /all

# Common names: Ethernet, Wi-Fi, Local Area Connection
```

**macOS:**
```bash
# List interfaces
ifconfig

# Common names: en0, en1, en2
```

## Running the IDS

### Basic Usage

```bash
# Run with default configuration
sudo python3 ids_main.py

# Specify custom config file
sudo python3 ids_main.py -c /path/to/config.yaml

# Override network interface
sudo python3 ids_main.py -i eth0

# Enable verbose logging
sudo python3 ids_main.py -v

# Dry-run mode (no emails sent)
sudo python3 ids_main.py --dry-run
```

### Command-Line Options

```
usage: ids [-h] [-c FILE] [-i INTERFACE] [-v] [--dry-run] [--no-banner] [--version]

Intrusion Detection System - Network threat monitoring and analysis

options:
  -h, --help            show this help message and exit
  -c FILE, --config FILE
                        Path to configuration file (default: config.yaml)
  -i INTERFACE, --interface INTERFACE
                        Network interface to monitor (overrides config file)
  -v, --verbose         Enable verbose logging output
  --dry-run             Run in dry-run mode (no emails sent, logging only)
  --no-banner           Suppress startup banner
  --version             show program's version number and exit

Examples:
  ids -c config.yaml -i eth0
  ids --config config.yaml --interface wlan0 --verbose
  ids -c config.yaml -i eth0 --dry-run

Note: This application requires root/administrator privileges for packet capture.
```

### Running as a Service

#### Linux (systemd)

Create a systemd service file:

```bash
sudo nano /etc/systemd/system/ids.service
```

```ini
[Unit]
Description=Intrusion Detection System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/ids
ExecStart=/usr/bin/python3 /path/to/ids/ids_main.py -c /path/to/ids/config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable ids.service
sudo systemctl start ids.service
sudo systemctl status ids.service
```

#### Windows

Use Task Scheduler or install as a Windows Service using tools like NSSM.

## Privilege Requirements

### Why Root/Administrator Access is Required

The IDS requires elevated privileges to:
- Capture network packets from network interfaces
- Access low-level network operations
- Monitor system network traffic
- Bind to network interfaces for packet sniffing

### Linux/macOS

```bash
# Run with sudo
sudo python3 ids_main.py

# Or run as root user
su -
python3 ids_main.py
```

### Windows

1. Right-click on Command Prompt or PowerShell
2. Select "Run as administrator"
3. Navigate to the IDS directory
4. Run the script: `python ids_main.py`

## Email Notification Examples

### Single Threat Alert

```
Subject: [IDS ALERT - HIGH] Port Scan Detected

=== THREAT DETECTED ===
Type: Port Scan
Severity: High
Timestamp: 2025-10-15 14:30:25
Source: 192.168.1.100
Destination: 10.0.0.5

=== ANALYSIS ===
Port scan detected from 192.168.1.100 targeting multiple ports on 10.0.0.5.
15 ports were scanned within 60 seconds, exceeding the threshold of 10.

=== SEVERITY JUSTIFICATION ===
High severity assigned due to: Multiple ports scanned (15) exceeding threshold (10)

=== RECOMMENDED ACTIONS ===
1. Block source IP 192.168.1.100 at firewall level
2. Review firewall rules for unnecessary open ports
3. Monitor for additional scanning activity from this source
4. Consider implementing port knocking for sensitive services

=== TECHNICAL DETAILS ===
Protocol: TCP
Ports Scanned: 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 8080
Detection Time: 2025-10-15 14:30:25
```

### Batched Alerts

```
Subject: [IDS ALERT - BATCH] Multiple Threats Detected (5 threats)

=== BATCH ALERT SUMMARY ===
Time Window: 2025-10-15 14:25:00 - 14:30:00
Total Threats: 5
Highest Severity: High

=== THREAT 1 ===
Type: Port Scan | Severity: High | Source: 192.168.1.100
...

=== THREAT 2 ===
Type: ICMP Scan | Severity: Medium | Source: 192.168.1.101
...
```

## Logging

### Log Format

Logs are written in JSON format for easy parsing:

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

### Log Rotation

Logs automatically rotate when they reach the configured size limit:
- Default: 100MB per log file
- Keeps 5 backup files by default
- Configurable in `config.yaml`

### Viewing Logs

```bash
# View current log
tail -f ids.log

# View JSON logs with formatting
tail -f ids.log | python3 -m json.tool

# Search for specific threats
grep "port_scan" ids.log | python3 -m json.tool
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied Errors

**Problem**: `PermissionError: [Errno 1] Operation not permitted`

**Solution**:
```bash
# Linux/macOS: Run with sudo
sudo python3 ids_main.py

# Windows: Run as Administrator
# Right-click Command Prompt → "Run as administrator"
```

#### 2. Network Interface Not Found

**Problem**: `OSError: No such device exists`

**Solution**:
```bash
# List available interfaces
ip link show  # Linux
ifconfig      # Linux/macOS
ipconfig /all # Windows

# Update config.yaml with correct interface name
detection:
  network_interface: eth0  # Use actual interface name
```

#### 3. Email Authentication Failed

**Problem**: `SMTPAuthenticationError: Username and Password not accepted`

**Solutions**:
- **Gmail**: Use App Password instead of regular password
- **Outlook**: Enable "Less secure app access" or use App Password
- **Corporate Email**: Check with IT for SMTP settings
- **Two-Factor Auth**: Generate application-specific password

#### 4. No Packets Captured

**Problem**: IDS starts but no threats detected

**Troubleshooting**:
```bash
# Test packet capture manually
sudo python3 -c "
from scapy.all import sniff
print('Testing packet capture...')
packets = sniff(iface='eth0', count=5, timeout=10)
print(f'Captured {len(packets)} packets')
"

# Check interface is active
ping google.com  # Generate some traffic

# Verify interface name in config
```

#### 5. High CPU Usage

**Problem**: IDS consuming too much CPU

**Solutions**:
- Increase detection thresholds in config
- Use more specific network filters
- Monitor on less busy network interface
- Reduce log level from DEBUG to INFO

#### 6. Email Flooding

**Problem**: Too many email notifications

**Solutions**:
```yaml
# Adjust batching settings in config.yaml
notification:
  batch_window_seconds: 600    # Increase batching window
  batch_threshold: 2           # Lower threshold for batching
  
# Or increase detection thresholds
detection:
  port_scan_threshold: 20      # Require more activity
  icmp_scan_threshold: 10
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
# Run with verbose output
sudo python3 ids_main.py -v

# Or set in config.yaml
logging:
  log_level: DEBUG
```

### Testing Configuration

Test your setup without sending emails:

```bash
# Dry-run mode
sudo python3 ids_main.py --dry-run

# This will:
# - Load configuration
# - Start packet capture
# - Detect threats
# - Log everything
# - Skip email sending
```

### Log Analysis

Analyze logs for patterns:

```bash
# Count threats by type
grep "threat_detected" ids.log | jq -r '.threat_type' | sort | uniq -c

# Find high severity threats
grep "high\|critical" ids.log | jq '.'

# Monitor real-time threats
tail -f ids.log | grep "threat_detected" | jq '.'
```

## Performance Considerations

### System Resources

- **CPU**: Packet analysis is CPU-intensive
- **Memory**: Keeps detection state in memory
- **Disk**: Log files can grow large
- **Network**: Minimal impact on network performance

### Optimization Tips

1. **Interface Selection**: Monitor specific interfaces only
2. **Threshold Tuning**: Adjust thresholds to reduce false positives
3. **Log Management**: Regular log rotation and cleanup
4. **Batch Notifications**: Use batching to reduce email load

### Monitoring Performance

```bash
# Monitor CPU and memory usage
top -p $(pgrep -f ids_main.py)

# Check log file sizes
ls -lh *.log

# Monitor packet capture rate
# (Check verbose logs for packet processing statistics)
```

## Security Considerations

### Configuration Security

- Store email passwords securely (consider environment variables)
- Restrict access to configuration files: `chmod 600 config.yaml`
- Use dedicated email account for IDS notifications
- Enable two-factor authentication on email accounts

### Network Security

- Run IDS on dedicated monitoring interface when possible
- Consider network segmentation for IDS deployment
- Regular updates of malware signatures
- Monitor IDS logs for tampering attempts

### Operational Security

- Regular backup of configuration and logs
- Monitor IDS availability and health
- Test email notifications periodically
- Review and tune detection thresholds regularly

## Support and Contributing

### Getting Help

1. Check this README for common issues
2. Review log files for error messages
3. Test with `--dry-run` mode first
4. Verify configuration file syntax

### Reporting Issues

When reporting issues, include:
- Operating system and version
- Python version
- Complete error messages
- Configuration file (remove sensitive data)
- Steps to reproduce the issue

### Development

For development and testing:

```bash
# Install development dependencies
pip install pytest

# Run tests
python -m pytest

# Run specific detector tests
python test_port_scan_detector.py
python test_threat_detection_engine.py
```

## License

This project is provided as-is for educational and security monitoring purposes. Use responsibly and in compliance with local laws and regulations.

---

**⚠️ Important**: This IDS is designed for network monitoring and security analysis. Ensure you have proper authorization before monitoring network traffic, especially in corporate or shared environments.