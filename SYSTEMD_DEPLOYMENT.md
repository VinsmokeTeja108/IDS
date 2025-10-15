# IDS Systemd Service Deployment

This document describes how to deploy the Intrusion Detection System (IDS) as a systemd service on Linux systems.

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