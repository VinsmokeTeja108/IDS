# How to Run the Intrusion Detection System (IDS)

This guide provides detailed step-by-step instructions for setting up and running the IDS on different platforms.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Running the IDS](#running-the-ids)
5. [Deployment Options](#deployment-options)
6. [Troubleshooting](#troubleshooting)
7. [Monitoring and Maintenance](#monitoring-and-maintenance)

## Prerequisites

### System Requirements

**Minimum Requirements:**
- **OS**: Linux (Ubuntu 18.04+, CentOS 7+, RHEL 7+), Windows 10+, macOS 10.14+
- **Python**: 3.8 or higher
- **RAM**: 512 MB minimum, 2 GB recommended
- **Storage**: 100 MB for application, additional space for logs
- **Network**: Access to network interfaces for packet capture

**Recommended Requirements:**
- **OS**: Linux (for production deployment)
- **Python**: 3.9 or higher
- **RAM**: 4 GB or more
- **CPU**: Multi-core processor
- **Storage**: SSD with 1 GB+ free space

### Required Privileges

The IDS requires elevated privileges for packet capture:
- **Linux/macOS**: Root privileges (`sudo`)
- **Windows**: Administrator privileges

### Dependencies

The following Python packages are required (automatically installed):
- `scapy` - Packet capture and analysis
- `pyyaml` - Configuration file parsing
- `psutil` - System monitoring
- `colorama` - Cross-platform colored terminal output

## Installation

### Step 1: Download/Clone the Project

```bash
# If using git
git clone <repository-url>
cd ids

# Or extract from archive
unzip ids.zip
cd ids
```

### Step 2: Set Up Python Environment (Recommended)

Create a virtual environment to isolate dependencies:

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
# On Linux/macOS:
source .venv/bin/activate

# On Windows:
.venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
# Install required packages
pip install -r requirements.txt
```

### Step 4: Verify Installation

```bash
# Test basic functionality
python3 ids_main.py --help
```

You should see the help message without errors.

## Configuration

### Step 1: Create Configuration File

```bash
# Copy the example configuration
cp config.yaml.example config.yaml
```

### Step 2: Edit Configuration

Open `config.yaml` in your preferred text editor:

```bash
# Linux/macOS
nano config.yaml

# Or use any text editor
vim config.yaml
gedit config.yaml
```

### Step 3: Configure Network Interface

Find your network interface name:

```bash
# Linux
ip addr show
# or
ifconfig

# Windows
ipconfig

# macOS
ifconfig
```

Update the configuration:

```yaml
detection_config:
  network_interface: "eth0"  # Replace with your interface
```

### Step 4: Configure Email Notifications

Set up email settings for alerts:

```yaml
email_config:
  smtp_server: "smtp.gmail.com"
  smtp_port: 587
  username: "your-email@gmail.com"
  password: "your-app-password"  # Use app password for Gmail
  sender_email: "your-email@gmail.com"
  recipient_emails:
    - "admin@company.com"
    - "security@company.com"
```

**Important**: For Gmail, use an App Password instead of your regular password.

### Step 5: Configure Detection Thresholds

Adjust detection sensitivity:

```yaml
detection_config:
  port_scan_threshold: 10      # Ports scanned before alert
  brute_force_threshold: 5     # Failed attempts before alert
  time_window: 300             # Time window in seconds
```

### Step 6: Configure Logging

Set up logging preferences:

```yaml
logging_config:
  level: "INFO"                # DEBUG, INFO, WARNING, ERROR
  log_file: "ids.log"
  max_file_size: 10485760      # 10 MB
  backup_count: 5
```

## Running the IDS

### Method 1: Direct Execution (Development/Testing)

#### Basic Usage

```bash
# Run with default configuration
sudo python3 ids_main.py

# Run with custom configuration
sudo python3 ids_main.py --config config.yaml

# Run with specific network interface
sudo python3 ids_main.py --config config.yaml --interface eth0
```

#### Advanced Options

```bash
# Verbose mode (detailed logging)
sudo python3 ids_main.py --config config.yaml --verbose

# Dry-run mode (no email notifications)
sudo python3 ids_main.py --config config.yaml --dry-run

# Suppress startup banner
sudo python3 ids_main.py --config config.yaml --no-banner
```

#### Example Commands

```bash
# Development testing
sudo python3 ids_main.py --config config.yaml --interface eth0 --verbose --dry-run

# Production run
sudo python3 ids_main.py --config config.yaml --interface eth0

# Quick test
sudo python3 ids_main.py --help
```

### Method 2: Background Execution

#### Using nohup (Linux/macOS)

```bash
# Run in background
sudo nohup python3 ids_main.py --config config.yaml > ids.log 2>&1 &

# Check if running
ps aux | grep ids_main

# Stop the process
sudo pkill -f ids_main.py
```

#### Using screen (Linux/macOS)

```bash
# Start screen session
sudo screen -S ids

# Run IDS in screen
python3 ids_main.py --config config.yaml

# Detach from screen (Ctrl+A, then D)
# Reattach to screen
sudo screen -r ids
```

## Deployment Options

### Option 1: Manual Deployment

For development and testing environments:

1. Follow the installation steps above
2. Run directly using `python3 ids_main.py`
3. Monitor logs manually

### Option 2: Systemd Service (Linux - Recommended)

For production Linux environments:

#### Quick Installation

```bash
# Run the automated installer
sudo ./install-service.sh
```

#### Manual Service Installation

```bash
# Copy files to system directories
sudo mkdir -p /opt/ids /etc/ids /var/log/ids
sudo cp -r ids/ /opt/ids/
sudo cp ids_main.py requirements.txt /opt/ids/
sudo cp config.yaml /etc/ids/

# Install dependencies
sudo pip3 install -r /opt/ids/requirements.txt

# Install service
sudo cp ids.service /etc/systemd/system/
sudo systemctl daemon-reload

# Enable and start service
sudo systemctl enable ids
sudo systemctl start ids

# Check status
sudo systemctl status ids
```

See [DOCUMENTATION.md](DOCUMENTATION.md) for detailed systemd deployment instructions.

### Option 3: Docker Deployment (Advanced)

Create a Dockerfile for containerized deployment:

```dockerfile
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy application files
COPY . .

# Run as root (required for packet capture)
USER root

# Expose any necessary ports
# EXPOSE 8080

# Run the IDS
CMD ["python3", "ids_main.py", "--config", "config.yaml"]
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied Errors

**Problem**: `PermissionError: [Errno 1] Operation not permitted`

**Solution**:
```bash
# Ensure running with sudo/root privileges
sudo python3 ids_main.py --config config.yaml

# On Linux, check if user is in required groups
sudo usermod -a -G netdev $USER
```

#### 2. Network Interface Not Found

**Problem**: `Interface 'eth0' not found`

**Solution**:
```bash
# List available interfaces
ip addr show  # Linux
ifconfig      # Linux/macOS
ipconfig      # Windows

# Update config.yaml with correct interface name
```

#### 3. Email Configuration Issues

**Problem**: Email notifications not working

**Solution**:
```bash
# Test email configuration
sudo python3 ids_main.py --config config.yaml --dry-run

# Check email settings in config.yaml
# For Gmail, ensure you're using an App Password
# Enable "Less secure app access" if needed
```

#### 4. Python Module Import Errors

**Problem**: `ModuleNotFoundError: No module named 'scapy'`

**Solution**:
```bash
# Reinstall dependencies
pip install -r requirements.txt

# If using virtual environment, ensure it's activated
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows
```

#### 5. High CPU/Memory Usage

**Problem**: IDS consuming too many resources

**Solution**:
```bash
# Adjust detection thresholds in config.yaml
# Reduce logging level from DEBUG to INFO
# Monitor specific processes:
top -p $(pgrep -f ids_main)
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
# Run with maximum verbosity
sudo python3 ids_main.py --config config.yaml --verbose

# Check log files
tail -f ids.log

# For systemd service
sudo journalctl -u ids -f
```

### Log Analysis

```bash
# View recent logs
tail -n 100 ids.log

# Search for errors
grep -i error ids.log

# Monitor real-time logs
tail -f ids.log | grep -i "threat\|alert\|error"
```

## Monitoring and Maintenance

### Regular Monitoring

#### Check System Status

```bash
# For direct execution
ps aux | grep ids_main

# For systemd service
sudo systemctl status ids
```

#### Monitor Logs

```bash
# View recent activity
tail -n 50 ids.log

# Monitor real-time
tail -f ids.log

# For systemd
sudo journalctl -u ids -f
```

#### Resource Monitoring

```bash
# Check memory usage
ps aux | grep ids_main | awk '{print $4}'

# Check CPU usage
top -p $(pgrep -f ids_main)

# Disk usage
du -sh /var/log/ids/
```

### Maintenance Tasks

#### Log Rotation

```bash
# Manual log rotation
sudo logrotate -f /etc/logrotate.d/ids

# Or use built-in Python logging rotation (configured in config.yaml)
```

#### Configuration Updates

```bash
# After updating config.yaml, restart the service
sudo systemctl restart ids

# Or for direct execution, stop and restart
sudo pkill -f ids_main.py
sudo python3 ids_main.py --config config.yaml
```

#### Dependency Updates

```bash
# Update Python packages
pip install -r requirements.txt --upgrade

# Check for security updates
pip audit
```

### Performance Optimization

#### For High-Traffic Networks

1. **Increase buffer sizes** in configuration
2. **Adjust detection thresholds** to reduce false positives
3. **Use SSD storage** for better I/O performance
4. **Allocate more RAM** to the system
5. **Consider CPU affinity** for systemd service

#### Configuration Tuning

```yaml
# Example optimized configuration for high-traffic
detection_config:
  port_scan_threshold: 20      # Higher threshold
  brute_force_threshold: 10    # Higher threshold
  time_window: 600             # Longer time window
  
logging_config:
  level: "WARNING"             # Reduce log verbosity
  max_file_size: 52428800      # 50 MB log files
```

### Backup and Recovery

#### Configuration Backup

```bash
# Backup configuration
sudo cp /etc/ids/config.yaml /etc/ids/config.yaml.backup.$(date +%Y%m%d)

# Backup entire IDS directory
sudo tar -czf ids-backup-$(date +%Y%m%d).tar.gz /opt/ids /etc/ids
```

#### Recovery

```bash
# Restore configuration
sudo cp /etc/ids/config.yaml.backup.20231201 /etc/ids/config.yaml

# Restart service
sudo systemctl restart ids
```

## Security Considerations

1. **Secure Configuration Files**: Protect config files containing credentials
2. **Regular Updates**: Keep Python packages updated
3. **Log Security**: Ensure log files are properly protected
4. **Network Security**: Deploy on trusted systems only
5. **Access Control**: Limit who can modify IDS configuration

## Getting Help

If you encounter issues not covered in this guide:

1. Check the [README.md](README.md) for additional information
2. Review the [DOCUMENTATION.md](DOCUMENTATION.md) for service-specific issues
3. Enable verbose logging to get more detailed error information
4. Check system logs for additional context

## Quick Reference

### Essential Commands

```bash
# Start IDS
sudo python3 ids_main.py --config config.yaml

# Start with verbose logging
sudo python3 ids_main.py --config config.yaml --verbose

# Test configuration (dry-run)
sudo python3 ids_main.py --config config.yaml --dry-run

# Check systemd service status
sudo systemctl status ids

# View real-time logs
sudo journalctl -u ids -f

# Stop IDS
sudo pkill -f ids_main.py
# or for systemd
sudo systemctl stop ids
```

### Configuration Files

- `config.yaml` - Main configuration file
- `config.yaml.example` - Example configuration template
- `ids.service` - Systemd service configuration
- `requirements.txt` - Python dependencies

### Log Files

- `ids.log` - Application logs (configurable location)
- `/var/log/ids/` - System logs (for systemd deployment)
- System journal - `journalctl -u ids` (for systemd deployment)

## Platform-Specific Instructions

### Linux (Ubuntu/Debian)

```bash
# Install Python and pip
sudo apt update
sudo apt install python3 python3-pip python3-venv

# Install system dependencies
sudo apt install tcpdump

# Follow standard installation steps above
```

### Linux (CentOS/RHEL)

```bash
# Install Python and pip
sudo yum install python3 python3-pip

# Install system dependencies
sudo yum install tcpdump

# Follow standard installation steps above
```

### Windows

```powershell
# Install Python from python.org
# Download and install Python 3.8+

# Install dependencies
pip install -r requirements.txt

# Run as Administrator
# Right-click Command Prompt -> "Run as administrator"
python ids_main.py --config config.yaml
```

### macOS

```bash
# Install Python using Homebrew
brew install python3

# Install system dependencies
brew install tcpdump

# Follow standard installation steps above
```

---

*This guide covers all aspects of running the IDS. For additional technical details, see [DOCUMENTATION.md](DOCUMENTATION.md).*