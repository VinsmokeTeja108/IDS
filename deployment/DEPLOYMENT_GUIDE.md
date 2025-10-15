# IDS Web UI - Production Deployment Guide

This guide provides comprehensive instructions for deploying the IDS Web UI in a production environment with proper security, performance, and reliability configurations.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation Steps](#installation-steps)
3. [HTTPS/SSL Setup](#httpsssl-setup)
4. [Nginx Configuration](#nginx-configuration)
5. [Systemd Service Setup](#systemd-service-setup)
6. [Security Hardening](#security-hardening)
7. [Monitoring and Maintenance](#monitoring-and-maintenance)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+, or similar)
- **Python**: 3.8 or higher
- **Memory**: Minimum 2GB RAM (4GB+ recommended)
- **Disk Space**: Minimum 1GB free space
- **Network**: Root/sudo access for packet capture capabilities

### Required Software

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y  # Ubuntu/Debian
# OR
sudo yum update -y  # CentOS/RHEL

# Install required packages
sudo apt install python3 python3-pip python3-venv nginx -y  # Ubuntu/Debian
# OR
sudo yum install python3 python3-pip nginx -y  # CentOS/RHEL
```

---

## Installation Steps

### 1. Create Dedicated User

Create a dedicated user for running the IDS service:

```bash
# Create ids user and group
sudo useradd -r -s /bin/false -d /opt/ids-web-ui ids

# Grant packet capture capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.8
# OR use a specific Python binary in your venv
```

### 2. Install Application

```bash
# Create installation directory
sudo mkdir -p /opt/ids-web-ui
cd /opt/ids-web-ui

# Clone or copy your application files
sudo git clone https://github.com/yourusername/ids-web-ui.git .
# OR
sudo cp -r /path/to/your/ids-web-ui/* .

# Create virtual environment
sudo python3 -m venv .venv
sudo .venv/bin/pip install --upgrade pip

# Install dependencies
sudo .venv/bin/pip install -r requirements.txt
sudo .venv/bin/pip install -r web_ui/requirements.txt

# For production with Gunicorn (recommended)
sudo .venv/bin/pip install gunicorn gevent-websocket

# Set ownership
sudo chown -R ids:ids /opt/ids-web-ui
```

### 3. Configure Application

```bash
# Copy and edit configuration
sudo cp config.yaml.example config.yaml
sudo nano config.yaml

# Update the following settings:
# - Network interface to monitor
# - Email notification settings
# - Detection thresholds
# - Logging paths

# Create log directory
sudo mkdir -p /var/log/ids-webui
sudo chown ids:ids /var/log/ids-webui
```

---

## HTTPS/SSL Setup

### Option 1: Let's Encrypt (Recommended - Free)

Let's Encrypt provides free, automated SSL certificates:

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx -y  # Ubuntu/Debian
# OR
sudo yum install certbot python3-certbot-nginx -y  # CentOS/RHEL

# Obtain certificate (replace with your domain)
sudo certbot --nginx -d ids.example.com

# Certbot will automatically:
# - Obtain the certificate
# - Configure Nginx
# - Set up auto-renewal

# Test auto-renewal
sudo certbot renew --dry-run
```

**Certificate Locations** (Let's Encrypt):
- Certificate: `/etc/letsencrypt/live/ids.example.com/fullchain.pem`
- Private Key: `/etc/letsencrypt/live/ids.example.com/privkey.pem`

### Option 2: Self-Signed Certificate (Development/Testing)

For testing or internal use only:

```bash
# Create directory for certificates
sudo mkdir -p /etc/ssl/ids-webui

# Generate self-signed certificate (valid for 365 days)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/ids-webui/ids-webui.key \
  -out /etc/ssl/ids-webui/ids-webui.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=ids.example.com"

# Set proper permissions
sudo chmod 600 /etc/ssl/ids-webui/ids-webui.key
sudo chmod 644 /etc/ssl/ids-webui/ids-webui.crt
```

**Note**: Self-signed certificates will show browser warnings. Use only for development/testing.

### Option 3: Commercial Certificate

If you have a commercial SSL certificate:

```bash
# Create directory
sudo mkdir -p /etc/ssl/ids-webui

# Copy your certificate files
sudo cp /path/to/your/certificate.crt /etc/ssl/ids-webui/ids-webui.crt
sudo cp /path/to/your/private.key /etc/ssl/ids-webui/ids-webui.key

# If you have a CA bundle
sudo cp /path/to/ca-bundle.crt /etc/ssl/ids-webui/ca-bundle.crt

# Set permissions
sudo chmod 600 /etc/ssl/ids-webui/ids-webui.key
sudo chmod 644 /etc/ssl/ids-webui/ids-webui.crt
```

### SSL Best Practices

1. **Use Strong Protocols**: Only TLS 1.2 and TLS 1.3
2. **Strong Ciphers**: Use modern cipher suites
3. **HSTS**: Enable HTTP Strict Transport Security
4. **Certificate Renewal**: Automate renewal (Let's Encrypt does this automatically)
5. **Regular Updates**: Keep OpenSSL and Nginx updated

---

## Nginx Configuration

### 1. Install and Configure Nginx

```bash
# Copy the provided Nginx configuration
sudo cp deployment/nginx-ids-webui.conf /etc/nginx/sites-available/ids-webui

# Edit configuration
sudo nano /etc/nginx/sites-available/ids-webui

# Update the following:
# - server_name: Your domain name
# - ssl_certificate: Path to your SSL certificate
# - ssl_certificate_key: Path to your SSL private key
# - proxy_pass: Backend port (default 5000)

# Enable the site
sudo ln -s /etc/nginx/sites-available/ids-webui /etc/nginx/sites-enabled/

# Remove default site (optional)
sudo rm /etc/nginx/sites-enabled/default

# Test configuration
sudo nginx -t

# If test passes, reload Nginx
sudo systemctl reload nginx
```

### 2. Nginx Security Headers

The provided configuration includes security headers:

- **HSTS**: Forces HTTPS connections
- **X-Frame-Options**: Prevents clickjacking
- **X-Content-Type-Options**: Prevents MIME sniffing
- **X-XSS-Protection**: Enables XSS filtering
- **Referrer-Policy**: Controls referrer information

### 3. Firewall Configuration

```bash
# Allow HTTP and HTTPS through firewall
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# OR for firewalld
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload

# Block direct access to Flask port (5000)
# The application should only be accessible through Nginx
sudo ufw deny 5000/tcp
```

---

## Systemd Service Setup

### 1. Install Service File

```bash
# Copy service file
sudo cp deployment/ids-webui.service /etc/systemd/system/

# Edit service file
sudo nano /etc/systemd/system/ids-webui.service

# Update the following:
# - User and Group (default: ids)
# - WorkingDirectory: Path to installation
# - ExecStart: Path to Python and script
# - Environment variables

# Reload systemd
sudo systemctl daemon-reload
```

### 2. Grant Packet Capture Capabilities

The service needs permission to capture network packets:

```bash
# Option 1: Set capabilities on Python binary
sudo setcap cap_net_raw,cap_net_admin=eip /opt/ids-web-ui/.venv/bin/python3

# Option 2: Run as root (NOT RECOMMENDED for security)
# Modify service file: User=root, Group=root

# Verify capabilities
getcap /opt/ids-web-ui/.venv/bin/python3
```

### 3. Start and Enable Service

```bash
# Start the service
sudo systemctl start ids-webui

# Check status
sudo systemctl status ids-webui

# View logs
sudo journalctl -u ids-webui -f

# Enable service to start on boot
sudo systemctl enable ids-webui
```

### 4. Service Management Commands

```bash
# Start service
sudo systemctl start ids-webui

# Stop service
sudo systemctl stop ids-webui

# Restart service
sudo systemctl restart ids-webui

# Reload configuration (if supported)
sudo systemctl reload ids-webui

# Check status
sudo systemctl status ids-webui

# View logs (follow mode)
sudo journalctl -u ids-webui -f

# View logs (last 100 lines)
sudo journalctl -u ids-webui -n 100

# View logs (since specific time)
sudo journalctl -u ids-webui --since "1 hour ago"
```

---

## Security Hardening

### 1. Application Security

```bash
# Set proper file permissions
sudo chown -R ids:ids /opt/ids-web-ui
sudo chmod 750 /opt/ids-web-ui
sudo chmod 640 /opt/ids-web-ui/config.yaml

# Protect sensitive files
sudo chmod 600 /opt/ids-web-ui/config.yaml
```

### 2. Network Security

```bash
# Configure firewall to only allow necessary ports
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS

# Rate limiting (optional)
sudo ufw limit 22/tcp   # Rate limit SSH
```

### 3. System Security

```bash
# Keep system updated
sudo apt update && sudo apt upgrade -y

# Enable automatic security updates (Ubuntu/Debian)
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades

# Disable root login via SSH
sudo nano /etc/ssh/sshd_config
# Set: PermitRootLogin no
sudo systemctl restart sshd
```

### 4. Application Authentication

Add authentication to the web interface:

```python
# In web_ui/app.py, add Flask-Login or similar
# Example with basic authentication:

from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

auth = HTTPBasicAuth()

users = {
    "admin": generate_password_hash("your-secure-password")
}

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username

# Protect routes with @auth.login_required decorator
```

---

## Monitoring and Maintenance

### 1. Log Monitoring

```bash
# Application logs
sudo tail -f /var/log/ids-webui/ids.log

# Nginx access logs
sudo tail -f /var/log/nginx/ids-webui-access.log

# Nginx error logs
sudo tail -f /var/log/nginx/ids-webui-error.log

# Systemd journal
sudo journalctl -u ids-webui -f
```

### 2. Log Rotation

Create log rotation configuration:

```bash
# Create logrotate config
sudo nano /etc/logrotate.d/ids-webui
```

Add the following content:

```
/var/log/ids-webui/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 ids ids
    sharedscripts
    postrotate
        systemctl reload ids-webui > /dev/null 2>&1 || true
    endscript
}
```

### 3. Health Monitoring

Set up monitoring with tools like:

- **Nagios/Icinga**: System and service monitoring
- **Prometheus + Grafana**: Metrics and visualization
- **Uptime Robot**: External uptime monitoring

Example health check script:

```bash
#!/bin/bash
# /usr/local/bin/check-ids-health.sh

# Check if service is running
if ! systemctl is-active --quiet ids-webui; then
    echo "ERROR: IDS service is not running"
    exit 1
fi

# Check if web interface is responding
if ! curl -f -s -o /dev/null https://ids.example.com/api/status; then
    echo "ERROR: Web interface is not responding"
    exit 1
fi

echo "OK: IDS is healthy"
exit 0
```

### 4. Backup Strategy

```bash
# Backup configuration
sudo cp /opt/ids-web-ui/config.yaml /backup/config.yaml.$(date +%Y%m%d)

# Backup logs (if needed)
sudo tar -czf /backup/ids-logs-$(date +%Y%m%d).tar.gz /var/log/ids-webui/

# Automated backup script
sudo nano /usr/local/bin/backup-ids.sh
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check service status
sudo systemctl status ids-webui

# View detailed logs
sudo journalctl -u ids-webui -n 50 --no-pager

# Check for permission issues
ls -la /opt/ids-web-ui
ls -la /var/log/ids-webui

# Verify Python dependencies
/opt/ids-web-ui/.venv/bin/pip list

# Test application manually
sudo -u ids /opt/ids-web-ui/.venv/bin/python /opt/ids-web-ui/run_ids_with_ui.py
```

### WebSocket Connection Issues

```bash
# Check Nginx configuration
sudo nginx -t

# Verify WebSocket proxy settings
sudo grep -A 10 "socket.io" /etc/nginx/sites-available/ids-webui

# Check Nginx error logs
sudo tail -f /var/log/nginx/ids-webui-error.log

# Test WebSocket connection
# Use browser developer tools (Network tab) to inspect WebSocket frames
```

### Permission Denied Errors

```bash
# Check file ownership
ls -la /opt/ids-web-ui

# Fix ownership
sudo chown -R ids:ids /opt/ids-web-ui

# Check capabilities
getcap /opt/ids-web-ui/.venv/bin/python3

# Re-apply capabilities if needed
sudo setcap cap_net_raw,cap_net_admin=eip /opt/ids-web-ui/.venv/bin/python3
```

### High CPU/Memory Usage

```bash
# Check resource usage
top -u ids
htop -u ids

# Check for memory leaks
sudo journalctl -u ids-webui | grep -i memory

# Adjust systemd resource limits
sudo nano /etc/systemd/system/ids-webui.service
# Add: MemoryLimit=2G, CPUQuota=200%
sudo systemctl daemon-reload
sudo systemctl restart ids-webui
```

### SSL Certificate Issues

```bash
# Test SSL certificate
openssl s_client -connect ids.example.com:443 -servername ids.example.com

# Check certificate expiration
echo | openssl s_client -connect ids.example.com:443 2>/dev/null | openssl x509 -noout -dates

# Renew Let's Encrypt certificate
sudo certbot renew

# Test Nginx SSL configuration
sudo nginx -t
```

### Cannot Access Web Interface

```bash
# Check if Nginx is running
sudo systemctl status nginx

# Check if IDS service is running
sudo systemctl status ids-webui

# Check firewall rules
sudo ufw status
sudo iptables -L -n

# Test local connection
curl -k https://localhost/api/status

# Check DNS resolution
nslookup ids.example.com
```

---

## Performance Tuning

### Nginx Optimization

```nginx
# Add to nginx.conf or site config
worker_processes auto;
worker_connections 1024;

# Enable gzip compression
gzip on;
gzip_vary on;
gzip_types text/plain text/css application/json application/javascript text/xml application/xml;
```

### Application Optimization

```bash
# Use Gunicorn with multiple workers (if traffic is high)
# Edit systemd service file:
ExecStart=/opt/ids-web-ui/.venv/bin/gunicorn \
    --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker \
    --workers 2 \
    --bind 127.0.0.1:5000 \
    --timeout 120 \
    web_ui.app:app
```

---

## Additional Resources

- [Nginx Documentation](https://nginx.org/en/docs/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [Systemd Documentation](https://www.freedesktop.org/software/systemd/man/)
- [Flask Deployment Options](https://flask.palletsprojects.com/en/latest/deploying/)
- [Security Best Practices](https://owasp.org/www-project-top-ten/)

---

## Support

For issues or questions:
- Check the troubleshooting section above
- Review application logs
- Consult the main README.md
- Open an issue on GitHub

---

**Last Updated**: October 2025
