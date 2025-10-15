# How to Run the Intrusion Detection System (IDS) with Web UI

This guide provides detailed step-by-step instructions for setting up and running the IDS with its web interface on Linux, macOS, and Windows.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Running the IDS](#running-the-ids)
5. [Accessing the Web Interface](#accessing-the-web-interface)
6. [Production Deployment](#production-deployment)
7. [Troubleshooting](#troubleshooting)
8. [Monitoring and Maintenance](#monitoring-and-maintenance)

---

## Prerequisites

### System Requirements

**Minimum Requirements:**
- **OS**: Linux (Ubuntu 18.04+), macOS 10.14+, Windows 10+
- **Python**: 3.8 or higher
- **RAM**: 512 MB minimum, 2 GB recommended
- **Storage**: 100 MB for application, additional space for logs
- **Network**: Access to network interfaces for packet capture
- **Privileges**: Root (Linux/macOS) or Administrator (Windows)

**Recommended Requirements:**
- **OS**: Linux (Ubuntu 20.04+ or similar) for production
- **Python**: 3.9 or higher
- **RAM**: 4 GB or more
- **CPU**: Multi-core processor
- **Storage**: SSD with 1 GB+ free space

### Required Software

The following will be installed during setup:
- Python 3.8+
- pip (Python package manager)
- Virtual environment (recommended)
- Network packet capture libraries

---

## Installation

### Step 1: Install Python and pip

Choose your operating system:


#### Linux (Ubuntu/Debian)

```bash
# Update package list
sudo apt update

# Install Python 3 and pip
sudo apt install python3 python3-pip python3-venv -y

# Verify installation
python3 --version
pip3 --version
```

#### Linux (CentOS/RHEL/Fedora)

```bash
# Update package list
sudo yum update -y
# or for Fedora
sudo dnf update -y

# Install Python 3 and pip
sudo yum install python3 python3-pip -y
# or for Fedora
sudo dnf install python3 python3-pip -y

# Verify installation
python3 --version
pip3 --version
```

#### macOS

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3
brew install python3

# Verify installation
python3 --version
pip3 --version
```

#### Windows

1. Download Python from [python.org](https://www.python.org/downloads/)
2. Run the installer
3. **Important**: Check "Add Python to PATH" during installation
4. Verify installation:

```cmd
python --version
pip --version
```


### Step 2: Download the Project

#### Option A: Using Git

**Linux/macOS:**
```bash
# Install git if not already installed
# Ubuntu/Debian
sudo apt install git -y

# CentOS/RHEL
sudo yum install git -y

# macOS
brew install git

# Clone the repository
git clone <repository-url>
cd ids
```

**Windows:**
```cmd
# Install Git from https://git-scm.com/download/win
# Then clone the repository
git clone <repository-url>
cd ids
```

#### Option B: Download ZIP

1. Download the project ZIP file
2. Extract to a directory

**Linux/macOS:**
```bash
unzip ids.zip
cd ids
```

**Windows:**
```cmd
# Extract using Windows Explorer or
# PowerShell:
Expand-Archive ids.zip -DestinationPath .
cd ids
```


### Step 3: Set Up Virtual Environment (Recommended)

Using a virtual environment isolates the project dependencies.

#### Linux/macOS

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Your prompt should now show (.venv)
```

#### Windows

```cmd
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.venv\Scripts\activate

# Your prompt should now show (.venv)
```

**Note**: To deactivate the virtual environment later, simply type `deactivate`.


### Step 4: Install Dependencies

Install all required Python packages:

#### Linux/macOS

```bash
# Make sure virtual environment is activated
# Install IDS dependencies
pip install -r requirements.txt

# Install Web UI dependencies
pip install -r web_ui/requirements.txt

# Verify installation
pip list
```

#### Windows

```cmd
# Make sure virtual environment is activated
# Install IDS dependencies
pip install -r requirements.txt

# Install Web UI dependencies
pip install -r web_ui\requirements.txt

# Verify installation
pip list
```

**Common Installation Issues:**

If you encounter errors during installation:

**Linux - Missing Development Tools:**
```bash
# Ubuntu/Debian
sudo apt install build-essential python3-dev libpcap-dev -y

# CentOS/RHEL
sudo yum groupinstall "Development Tools" -y
sudo yum install python3-devel libpcap-devel -y
```

**macOS - Missing Xcode Tools:**
```bash
xcode-select --install
```

**Windows - Missing Visual C++:**
- Download and install [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)


### Step 5: Verify Installation

Test that all components are installed correctly:

#### Linux/macOS

```bash
# Test IDS application
python3 -c "from ids.ids_application import IDSApplication; print('IDS OK')"

# Test Web UI
python3 -c "from web_ui.app import app; print('Web UI OK')"

# Test scapy (packet capture library)
python3 -c "from scapy.all import sniff; print('Scapy OK')"
```

#### Windows

```cmd
# Test IDS application
python -c "from ids.ids_application import IDSApplication; print('IDS OK')"

# Test Web UI
python -c "from web_ui.app import app; print('Web UI OK')"

# Test scapy (packet capture library)
python -c "from scapy.all import sniff; print('Scapy OK')"
```

If all tests print "OK", the installation is successful!

---

## Configuration

### Step 1: Create Configuration File

#### Linux/macOS

```bash
# Copy example configuration
cp config.yaml.example config.yaml

# Set appropriate permissions
chmod 600 config.yaml
```

#### Windows

```cmd
# Copy example configuration
copy config.yaml.example config.yaml
```


### Step 2: Find Your Network Interface

You need to identify the network interface to monitor.

#### Linux

```bash
# Method 1: Using ip command (modern)
ip addr show

# Method 2: Using ifconfig (traditional)
ifconfig

# Method 3: List only interface names
ip link show | grep -E '^[0-9]+:' | awk '{print $2}' | sed 's/://'

# Common interface names:
# - eth0, eth1: Ethernet interfaces
# - wlan0, wlan1: Wireless interfaces
# - enp0s3, enp0s8: Predictable network interface names
```

#### macOS

```bash
# List all interfaces
ifconfig

# List only interface names
ifconfig | grep -E '^[a-z]' | awk '{print $1}' | sed 's/://'

# Common interface names:
# - en0: Primary Ethernet/Wi-Fi
# - en1: Secondary network interface
# - lo0: Loopback interface (don't use this)
```

#### Windows

```cmd
# Using Command Prompt
ipconfig

# Using PowerShell (more detailed)
Get-NetAdapter

# Common interface names:
# - Ethernet
# - Wi-Fi
# - Local Area Connection
```

**Example Output:**
```
Linux: eth0, wlan0, enp0s3
macOS: en0, en1
Windows: Ethernet, Wi-Fi
```


### Step 3: Edit Configuration File

Open `config.yaml` in your preferred text editor:

#### Linux

```bash
# Using nano (beginner-friendly)
nano config.yaml

# Using vim
vim config.yaml

# Using gedit (GUI)
gedit config.yaml

# Using VS Code
code config.yaml
```

#### macOS

```bash
# Using nano
nano config.yaml

# Using TextEdit (GUI)
open -a TextEdit config.yaml

# Using VS Code
code config.yaml
```

#### Windows

```cmd
# Using Notepad
notepad config.yaml

# Using VS Code
code config.yaml

# Using PowerShell ISE
powershell_ise config.yaml
```


### Step 4: Configure Essential Settings

Update the following sections in `config.yaml`:

#### Network Interface Configuration

```yaml
detection:
  network_interface: "eth0"  # Replace with your interface from Step 2
  port_scan_threshold: 10
  icmp_scan_threshold: 5
  brute_force_threshold: 5
```

#### Email Notification Configuration

```yaml
email:
  smtp_host: "smtp.gmail.com"
  smtp_port: 587
  use_tls: true
  username: "your-email@gmail.com"
  password: "your-app-password"  # See note below
  recipients:
    - "admin@company.com"
    - "security@company.com"
```

**Important - Gmail App Password:**

If using Gmail, you must create an App Password:

1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Enable 2-Step Verification (if not already enabled)
3. Go to [App Passwords](https://myaccount.google.com/apppasswords)
4. Select "Mail" and "Other (Custom name)"
5. Enter "IDS" as the name
6. Copy the generated 16-character password
7. Use this password in `config.yaml` (not your regular Gmail password)

#### Logging Configuration

```yaml
logging:
  log_level: "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
  log_file: "ids.log"
  max_log_size_mb: 10
  backup_count: 5
```

#### Notification Configuration

```yaml
notification:
  batch_window_seconds: 300  # 5 minutes
  batch_threshold: 3         # Send batch after 3 threats
  retry_attempts: 3
  retry_delay_seconds: 10
```


### Step 5: Test Configuration

Verify your configuration file is valid:

#### Linux/macOS

```bash
# Test YAML syntax
python3 -c "import yaml; yaml.safe_load(open('config.yaml'))" && echo "Config OK"

# Test with IDS (dry-run mode - no emails sent)
sudo python3 run_ids_with_ui.py --config config.yaml --debug
```

#### Windows

```cmd
# Test YAML syntax
python -c "import yaml; yaml.safe_load(open('config.yaml'))" && echo Config OK

# Test with IDS (dry-run mode - no emails sent)
# Run Command Prompt as Administrator first
python run_ids_with_ui.py --config config.yaml --debug
```

---

## Running the IDS

### Method 1: Integrated Mode (IDS + Web UI) - Recommended

This starts both the IDS monitoring and web interface together.

#### Linux/macOS

```bash
# Basic start (IDS not started automatically)
sudo python3 run_ids_with_ui.py

# Start with IDS monitoring enabled
sudo python3 run_ids_with_ui.py --auto-start

# Custom host and port
sudo python3 run_ids_with_ui.py --host 0.0.0.0 --port 8080

# With custom config file
sudo python3 run_ids_with_ui.py --config /path/to/config.yaml

# Debug mode (verbose logging)
sudo python3 run_ids_with_ui.py --debug --log-level DEBUG

# All options combined
sudo python3 run_ids_with_ui.py \
  --auto-start \
  --host 0.0.0.0 \
  --port 8080 \
  --config config.yaml \
  --log-level INFO
```


#### Windows

**Important**: Run Command Prompt as Administrator:
1. Search for "Command Prompt" or "cmd"
2. Right-click and select "Run as administrator"
3. Navigate to the project directory

```cmd
# Basic start (IDS not started automatically)
python run_ids_with_ui.py

# Start with IDS monitoring enabled
python run_ids_with_ui.py --auto-start

# Custom host and port
python run_ids_with_ui.py --host 0.0.0.0 --port 8080

# With custom config file
python run_ids_with_ui.py --config C:\path\to\config.yaml

# Debug mode (verbose logging)
python run_ids_with_ui.py --debug --log-level DEBUG

# All options combined
python run_ids_with_ui.py --auto-start --host 0.0.0.0 --port 8080 --config config.yaml --log-level INFO
```

### Command-Line Options Reference

```
--host HOST          Host to bind the web server to (default: 0.0.0.0)
--port PORT          Port to bind the web server to (default: 5000)
--config PATH        Path to IDS configuration file (default: config.yaml)
--auto-start         Automatically start IDS monitoring on startup
--debug              Run in debug mode (not recommended for production)
--log-level LEVEL    Set logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL
```

### Expected Output

When you start the IDS, you should see:

```
======================================================================
  IDS + Web UI - Integrated Intrusion Detection System
======================================================================
Configuration file: /path/to/config.yaml
Web server host:    0.0.0.0
Web server port:    5000
Auto-start IDS:     True
Debug mode:         False
Log level:          INFO
======================================================================
Initializing EventBus...
Initializing ThreatStore...
Initializing IDS controller...
Initializing Flask application...
Auto-starting IDS monitoring...
IDS monitoring started successfully
======================================================================
Web UI is now available at: http://0.0.0.0:5000
======================================================================
Features:
  - Real-time threat monitoring
  - System control (start/stop/restart)
  - Threat analytics and statistics
  - Configuration management
  - System logs viewer
  - Detector management
======================================================================
Press Ctrl+C to stop the server
======================================================================
```


### Method 2: Background Execution

Run the IDS in the background while you continue using the terminal.

#### Linux/macOS - Using nohup

```bash
# Start in background
sudo nohup python3 run_ids_with_ui.py --auto-start > ids_output.log 2>&1 &

# Get the process ID
echo $!

# Check if running
ps aux | grep run_ids_with_ui

# View logs in real-time
tail -f ids_output.log

# Stop the process
sudo pkill -f run_ids_with_ui.py
# or
sudo kill <PID>
```

#### Linux/macOS - Using screen

```bash
# Install screen if not available
# Ubuntu/Debian
sudo apt install screen -y

# CentOS/RHEL
sudo yum install screen -y

# macOS
brew install screen

# Start screen session
sudo screen -S ids

# Run IDS in screen
python3 run_ids_with_ui.py --auto-start

# Detach from screen: Press Ctrl+A, then D

# List screen sessions
screen -ls

# Reattach to screen
sudo screen -r ids

# Kill screen session
sudo screen -X -S ids quit
```

#### Windows - Using PowerShell

```powershell
# Start in background (PowerShell as Administrator)
Start-Process python -ArgumentList "run_ids_with_ui.py --auto-start" -WindowStyle Hidden

# Or start in new window
Start-Process python -ArgumentList "run_ids_with_ui.py --auto-start"

# List Python processes
Get-Process python

# Stop process
Stop-Process -Name python
```


---

## Accessing the Web Interface

### Step 1: Open Your Browser

Once the IDS is running, open your web browser and navigate to:

```
http://localhost:5000
```

**Alternative URLs:**
- Local access: `http://127.0.0.1:5000`
- Network access: `http://<your-ip-address>:5000`
- Custom port: `http://localhost:<your-port>`

### Step 2: Navigate the Web Interface

#### Dashboard Page (`/`)

The main dashboard shows:
- System status (running/stopped, interface, uptime)
- Quick statistics (threats by severity)
- Recent threats (last 5)
- Start/Stop monitoring controls

#### Threats Page (`/threats`)

Browse and manage detected threats:
- Filter by threat type (port scan, malware, etc.)
- Filter by severity (critical, high, medium, low)
- Search by IP address or keyword
- View detailed threat information
- Real-time updates via WebSocket

#### Analytics Page (`/analytics`)

View threat analytics and statistics:
- Threats over time (line chart)
- Threats by type (pie chart)
- Threats by severity (bar chart)
- Top attacking IPs table
- Time range selector (1h, 24h, 7d, 30d)

#### Configuration Page (`/config`)

Manage IDS settings:
- Email configuration (SMTP settings)
- Detection thresholds
- Logging configuration
- Notification settings
- Detector management (enable/disable)
- Test email functionality

#### Logs Page (`/logs`)

View system logs:
- Browse logs with pagination
- Filter by event type
- Search by keyword or IP
- Real-time log updates


### Step 3: Start IDS Monitoring

If you didn't use `--auto-start`, you can start monitoring from the web interface:

1. Go to the Dashboard page
2. Click the "Start Monitoring" button
3. Wait for confirmation message
4. System status will change to "ACTIVE"

### Step 4: Monitor Threats

Threats will appear in real-time on:
- Dashboard (recent threats)
- Threats page (complete list)
- Analytics page (statistics and charts)

You'll also receive email notifications based on your configuration.

---

## Production Deployment

For production environments, use systemd service and Nginx reverse proxy.

### Linux - Systemd Service

#### Step 1: Copy Service File

```bash
# Copy service file to systemd directory
sudo cp deployment/ids-webui.service /etc/systemd/system/

# Make it readable
sudo chmod 644 /etc/systemd/system/ids-webui.service
```

#### Step 2: Edit Service File

```bash
# Edit with your paths
sudo nano /etc/systemd/system/ids-webui.service
```

Update these lines:
```ini
WorkingDirectory=/path/to/your/ids
ExecStart=/path/to/your/python3 /path/to/your/ids/run_ids_with_ui.py --auto-start --config /path/to/config.yaml
```

#### Step 3: Enable and Start Service

```bash
# Reload systemd daemon
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable ids-webui

# Start service
sudo systemctl start ids-webui

# Check status
sudo systemctl status ids-webui
```

#### Step 4: Manage Service

```bash
# Start service
sudo systemctl start ids-webui

# Stop service
sudo systemctl stop ids-webui

# Restart service
sudo systemctl restart ids-webui

# View logs
sudo journalctl -u ids-webui -f

# View last 100 lines
sudo journalctl -u ids-webui -n 100

# Disable service (don't start on boot)
sudo systemctl disable ids-webui
```


### Linux - Nginx Reverse Proxy

#### Step 1: Install Nginx

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nginx -y

# CentOS/RHEL
sudo yum install nginx -y

# Fedora
sudo dnf install nginx -y

# Start and enable Nginx
sudo systemctl start nginx
sudo systemctl enable nginx
```

#### Step 2: Copy Nginx Configuration

```bash
# Copy configuration file
sudo cp deployment/nginx-ids-webui.conf /etc/nginx/sites-available/ids-webui

# For CentOS/RHEL (no sites-available directory)
sudo cp deployment/nginx-ids-webui.conf /etc/nginx/conf.d/ids-webui.conf
```

#### Step 3: Edit Nginx Configuration

```bash
# Ubuntu/Debian
sudo nano /etc/nginx/sites-available/ids-webui

# CentOS/RHEL
sudo nano /etc/nginx/conf.d/ids-webui.conf
```

Update these settings:
- `server_name`: Your domain name
- `ssl_certificate`: Path to your SSL certificate
- `ssl_certificate_key`: Path to your SSL private key

#### Step 4: Enable Site (Ubuntu/Debian only)

```bash
# Create symbolic link
sudo ln -s /etc/nginx/sites-available/ids-webui /etc/nginx/sites-enabled/

# Remove default site (optional)
sudo rm /etc/nginx/sites-enabled/default
```

#### Step 5: Test and Reload Nginx

```bash
# Test configuration
sudo nginx -t

# If test passes, reload Nginx
sudo systemctl reload nginx

# Check status
sudo systemctl status nginx
```


### HTTPS/SSL Setup

#### Option 1: Let's Encrypt (Free, Recommended)

```bash
# Ubuntu/Debian
sudo apt install certbot python3-certbot-nginx -y

# CentOS/RHEL
sudo yum install certbot python3-certbot-nginx -y

# Obtain certificate (replace with your domain)
sudo certbot --nginx -d ids.example.com

# Test auto-renewal
sudo certbot renew --dry-run

# Certificates are automatically renewed
```

#### Option 2: Self-Signed Certificate (Testing Only)

```bash
# Create directory for certificates
sudo mkdir -p /etc/ssl/ids-webui

# Generate self-signed certificate (valid for 365 days)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/ids-webui/ids-webui.key \
  -out /etc/ssl/ids-webui/ids-webui.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=ids.example.com"

# Set permissions
sudo chmod 600 /etc/ssl/ids-webui/ids-webui.key
sudo chmod 644 /etc/ssl/ids-webui/ids-webui.crt
```

**Note**: Self-signed certificates will show browser warnings.

### Firewall Configuration

#### Linux - UFW (Ubuntu/Debian)

```bash
# Enable firewall
sudo ufw enable

# Allow SSH (important!)
sudo ufw allow 22/tcp

# Allow HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Block direct access to Flask port
sudo ufw deny 5000/tcp

# Check status
sudo ufw status
```

#### Linux - firewalld (CentOS/RHEL)

```bash
# Start and enable firewalld
sudo systemctl start firewalld
sudo systemctl enable firewalld

# Allow HTTP and HTTPS
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https

# Block direct access to Flask port
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" port port="5000" protocol="tcp" reject'

# Reload firewall
sudo firewall-cmd --reload

# Check status
sudo firewall-cmd --list-all
```


---

## Troubleshooting

### Common Issues and Solutions

#### 1. Permission Denied Errors

**Problem**: `PermissionError: [Errno 1] Operation not permitted`

**Solution**:

**Linux/macOS:**
```bash
# Run with sudo
sudo python3 run_ids_with_ui.py

# Or grant capabilities to Python (Linux only)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

**Windows:**
```cmd
# Run Command Prompt as Administrator
# Right-click Command Prompt → "Run as administrator"
python run_ids_with_ui.py
```

#### 2. Network Interface Not Found

**Problem**: `Interface 'eth0' not found`

**Solution**:

**Linux:**
```bash
# List available interfaces
ip addr show
# or
ifconfig

# Update config.yaml with correct interface name
nano config.yaml
```

**macOS:**
```bash
# List available interfaces
ifconfig

# Update config.yaml
nano config.yaml
```

**Windows:**
```cmd
# List available interfaces
ipconfig
# or
Get-NetAdapter

# Update config.yaml
notepad config.yaml
```


#### 3. Python Module Import Errors

**Problem**: `ModuleNotFoundError: No module named 'scapy'`

**Solution**:

**All Platforms:**
```bash
# Ensure virtual environment is activated
# Linux/macOS
source .venv/bin/activate

# Windows
.venv\Scripts\activate

# Reinstall dependencies
pip install -r requirements.txt
pip install -r web_ui/requirements.txt

# Verify installation
pip list | grep scapy
```

#### 4. Email Configuration Issues

**Problem**: Email notifications not working

**Solution**:

**For Gmail:**
1. Use an App Password (not your regular password)
2. Go to: https://myaccount.google.com/apppasswords
3. Generate a new app password
4. Update `config.yaml` with the app password

**Test email configuration:**

**Linux/macOS:**
```bash
# Test from Python
python3 -c "
import yaml
from ids.services.email_service import EmailService
config = yaml.safe_load(open('config.yaml'))
email = EmailService(config['email'])
print('Email service initialized successfully')
"
```

**Windows:**
```cmd
python -c "import yaml; from ids.services.email_service import EmailService; config = yaml.safe_load(open('config.yaml')); email = EmailService(config['email']); print('Email service initialized successfully')"
```


#### 5. Web UI Not Accessible

**Problem**: Cannot access `http://localhost:5000`

**Solution**:

**Check if service is running:**

**Linux/macOS:**
```bash
# Check process
ps aux | grep run_ids_with_ui

# Check port
sudo lsof -i :5000
# or
sudo netstat -tulpn | grep 5000
```

**Windows:**
```cmd
# Check process
tasklist | findstr python

# Check port
netstat -ano | findstr :5000
```

**Check firewall:**

**Linux:**
```bash
# Allow port 5000
sudo ufw allow 5000/tcp

# Check firewall status
sudo ufw status
```

**Windows:**
```cmd
# Add firewall rule (as Administrator)
netsh advfirewall firewall add rule name="IDS Web UI" dir=in action=allow protocol=TCP localport=5000
```

**macOS:**
```bash
# Check if firewall is blocking
# System Preferences → Security & Privacy → Firewall → Firewall Options
# Allow Python to accept incoming connections
```

#### 6. Port Already in Use

**Problem**: `Address already in use`

**Solution**:

**Linux/macOS:**
```bash
# Find process using port 5000
sudo lsof -i :5000

# Kill the process
sudo kill -9 <PID>

# Or use a different port
sudo python3 run_ids_with_ui.py --port 8080
```

**Windows:**
```cmd
# Find process using port 5000
netstat -ano | findstr :5000

# Kill the process (as Administrator)
taskkill /PID <PID> /F

# Or use a different port
python run_ids_with_ui.py --port 8080
```


#### 7. WebSocket Connection Fails

**Problem**: Browser console shows `WebSocket connection failed`

**Solution**:

1. Check if server is running
2. Verify firewall allows port 5000
3. Check browser console for errors
4. Try disabling browser extensions
5. If using proxy, ensure WebSocket upgrade headers are configured

**Test WebSocket:**

Open browser console (F12) and run:
```javascript
const socket = io('http://localhost:5000');
socket.on('connect', () => console.log('Connected!'));
socket.on('connect_error', (err) => console.log('Error:', err));
```

#### 8. No Threats Detected

**Problem**: IDS is running but no threats appear

**Solution**:

1. **Verify correct network interface:**

**Linux/macOS:**
```bash
# Check active interfaces
ip addr show | grep UP
# or
ifconfig | grep UP
```

**Windows:**
```cmd
# Check active interfaces
ipconfig | findstr "IPv4"
```

2. **Ensure there's network traffic:**

**Linux/macOS:**
```bash
# Monitor traffic on interface
sudo tcpdump -i eth0 -c 10
```

**Windows:**
```cmd
# Use Wireshark or check network activity in Task Manager
```

3. **Check detector status in Configuration page**

4. **Lower detection thresholds for testing:**

Edit `config.yaml`:
```yaml
detection:
  port_scan_threshold: 3  # Lower threshold
  brute_force_threshold: 2
```


### Debug Mode

Enable verbose logging for troubleshooting:

**Linux/macOS:**
```bash
# Run with maximum verbosity
sudo python3 run_ids_with_ui.py --debug --log-level DEBUG

# Check log files
tail -f ids.log

# For systemd service
sudo journalctl -u ids-webui -f
```

**Windows:**
```cmd
# Run with maximum verbosity (as Administrator)
python run_ids_with_ui.py --debug --log-level DEBUG

# Check log files
type ids.log

# Or use PowerShell
Get-Content ids.log -Wait
```

### Log Analysis

**Linux/macOS:**
```bash
# View recent logs
tail -n 100 ids.log

# Search for errors
grep -i error ids.log

# Search for threats
grep -i threat ids.log

# Monitor real-time logs
tail -f ids.log | grep -i "threat\|alert\|error"

# View logs with timestamps
cat ids.log | grep "$(date +%Y-%m-%d)"
```

**Windows:**
```cmd
# View recent logs
powershell "Get-Content ids.log -Tail 100"

# Search for errors
findstr /i "error" ids.log

# Search for threats
findstr /i "threat" ids.log
```

---

## Monitoring and Maintenance

### Check System Status

**Linux/macOS:**
```bash
# Check if process is running
ps aux | grep run_ids_with_ui

# For systemd service
sudo systemctl status ids-webui

# Check resource usage
top -p $(pgrep -f run_ids_with_ui)
# or
htop -p $(pgrep -f run_ids_with_ui)
```

**Windows:**
```cmd
# Check if process is running
tasklist | findstr python

# Check resource usage
# Open Task Manager (Ctrl+Shift+Esc)
# Look for python.exe process
```


### Monitor Logs

**Linux/macOS:**
```bash
# View recent activity
tail -n 50 ids.log

# Monitor real-time
tail -f ids.log

# For systemd service
sudo journalctl -u ids-webui -f

# View logs from last hour
sudo journalctl -u ids-webui --since "1 hour ago"
```

**Windows:**
```cmd
# View recent activity
powershell "Get-Content ids.log -Tail 50"

# Monitor real-time
powershell "Get-Content ids.log -Wait"
```

### Resource Monitoring

**Linux/macOS:**
```bash
# Check memory usage
ps aux | grep run_ids_with_ui | awk '{print $4}'

# Check CPU usage
top -p $(pgrep -f run_ids_with_ui) -n 1

# Check disk usage
du -sh /var/log/ids/
du -sh *.log
```

**Windows:**
```cmd
# Check resource usage in Task Manager
# Ctrl+Shift+Esc → Details tab → Find python.exe

# Or use PowerShell
Get-Process python | Select-Object CPU,WorkingSet
```

### Maintenance Tasks

#### Log Rotation

**Linux:**
```bash
# Manual log rotation
sudo logrotate -f /etc/logrotate.d/ids

# Or use built-in Python logging rotation (configured in config.yaml)
```

**Windows:**
```cmd
# Logs are automatically rotated based on config.yaml settings
# max_log_size_mb and backup_count
```

#### Configuration Updates

**Linux/macOS:**
```bash
# After updating config.yaml, restart the service
sudo systemctl restart ids-webui

# Or for direct execution, stop and restart
sudo pkill -f run_ids_with_ui.py
sudo python3 run_ids_with_ui.py --auto-start
```

**Windows:**
```cmd
# Stop the process
taskkill /F /IM python.exe

# Restart (as Administrator)
python run_ids_with_ui.py --auto-start
```


#### Dependency Updates

**All Platforms:**
```bash
# Activate virtual environment first
# Linux/macOS
source .venv/bin/activate

# Windows
.venv\Scripts\activate

# Update all packages
pip install -r requirements.txt --upgrade
pip install -r web_ui/requirements.txt --upgrade

# Check for security updates
pip list --outdated
```

### Backup and Recovery

#### Configuration Backup

**Linux/macOS:**
```bash
# Backup configuration
cp config.yaml config.yaml.backup.$(date +%Y%m%d)

# Backup entire IDS directory
tar -czf ids-backup-$(date +%Y%m%d).tar.gz \
  config.yaml ids.log ids/ web_ui/

# Restore configuration
cp config.yaml.backup.20231201 config.yaml
```

**Windows:**
```cmd
# Backup configuration
copy config.yaml config.yaml.backup.%date:~-4,4%%date:~-10,2%%date:~-7,2%

# Or use PowerShell
Copy-Item config.yaml -Destination "config.yaml.backup.$(Get-Date -Format 'yyyyMMdd')"

# Restore configuration
copy config.yaml.backup.20231201 config.yaml
```

---

## Quick Reference

### Essential Commands

#### Linux/macOS

```bash
# Install dependencies
pip install -r requirements.txt
pip install -r web_ui/requirements.txt

# Configure
cp config.yaml.example config.yaml
nano config.yaml

# Run
sudo python3 run_ids_with_ui.py --auto-start

# Monitor
tail -f ids.log

# Stop
sudo pkill -f run_ids_with_ui.py

# Service management (systemd)
sudo systemctl start ids-webui
sudo systemctl stop ids-webui
sudo systemctl status ids-webui
sudo journalctl -u ids-webui -f
```

#### Windows

```cmd
# Install dependencies
pip install -r requirements.txt
pip install -r web_ui\requirements.txt

# Configure
copy config.yaml.example config.yaml
notepad config.yaml

# Run (as Administrator)
python run_ids_with_ui.py --auto-start

# Monitor
powershell "Get-Content ids.log -Wait"

# Stop
taskkill /F /IM python.exe
```


### Configuration Files

- `config.yaml` - Main configuration file
- `config.yaml.example` - Example configuration template
- `ids.log` - Application logs (configurable location)

### Log Files

- `ids.log` - Application logs (default location)
- `/var/log/ids/` - System logs (for systemd deployment)
- System journal - `journalctl -u ids-webui` (for systemd deployment)

### Network Interfaces

**Common interface names:**
- **Linux**: eth0, eth1, wlan0, enp0s3, enp0s8
- **macOS**: en0, en1, en2
- **Windows**: Ethernet, Wi-Fi, Local Area Connection

### Default Ports

- **Web UI**: 5000 (configurable with `--port`)
- **HTTP**: 80 (for Nginx reverse proxy)
- **HTTPS**: 443 (for Nginx reverse proxy with SSL)

---

## Getting Help

If you encounter issues not covered in this guide:

1. **Check Documentation**:
   - [README.md](README.md) - Project overview
   - [DOCUMENTATION.md](DOCUMENTATION.md) - Technical documentation
   - [deployment/DEPLOYMENT_GUIDE.md](deployment/DEPLOYMENT_GUIDE.md) - Deployment guide

2. **Enable Debug Mode**:
   ```bash
   # Linux/macOS
   sudo python3 run_ids_with_ui.py --debug --log-level DEBUG
   
   # Windows
   python run_ids_with_ui.py --debug --log-level DEBUG
   ```

3. **Check Logs**:
   ```bash
   # Linux/macOS
   tail -f ids.log
   sudo journalctl -u ids-webui -f
   
   # Windows
   type ids.log
   ```

4. **Verify Installation**:
   ```bash
   # Check Python version
   python3 --version  # Linux/macOS
   python --version   # Windows
   
   # Check installed packages
   pip list
   
   # Test imports
   python3 -c "from ids.ids_application import IDSApplication; print('OK')"
   ```

5. **Test Configuration**:
   ```bash
   # Validate YAML syntax
   python3 -c "import yaml; yaml.safe_load(open('config.yaml'))"
   ```

---

**Version:** 1.0.0  
**Last Updated:** October 15, 2025  
**Supported Platforms:** Linux, macOS, Windows

*For technical documentation, see [DOCUMENTATION.md](DOCUMENTATION.md)*
