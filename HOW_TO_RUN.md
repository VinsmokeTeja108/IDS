# How to Run the Intrusion Detection System

This guide provides step-by-step instructions for running the IDS on different platforms.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Installation Steps](#installation-steps)
- [Configuration](#configuration)
- [Running the IDS](#running-the-ids)
- [Accessing the Web Interface](#accessing-the-web-interface)
- [Using the System](#using-the-system)
- [Troubleshooting](#troubleshooting)
- [Stopping the System](#stopping-the-system)

## ✅ Prerequisites

### System Requirements

- **Operating System**: Windows 10/11, Linux, or macOS
- **Python**: Version 3.8 or higher
- **RAM**: Minimum 2GB (4GB recommended)
- **Network**: Active network interface
- **Privileges**: Administrator (Windows) or Root (Linux/Mac)

### Check Python Version

```bash
python --version
```

If Python is not installed, download from: https://www.python.org/downloads/

## 📦 Installation Steps

### Step 1: Download/Clone the Project

If you have the project folder, navigate to it:

```bash
cd path/to/IDS
```

### Step 2: Install Python Dependencies

Install all required packages:

```bash
pip install -r requirements.txt
```

**Expected packages:**
- scapy
- flask
- flask-socketio
- flask-cors
- pyyaml
- python-socketio

### Step 3: Verify Installation

Check if packages are installed:

```bash
pip list
```

Look for the packages listed above.

## ⚙️ Configuration

### Step 1: Copy Example Configuration

If `config.yaml` doesn't exist, copy from example:

```bash
# Windows
copy config.yaml.example config.yaml

# Linux/Mac
cp config.yaml.example config.yaml
```

### Step 2: Find Your Network Interface

**Windows:**
```cmd
ipconfig
```
Look for your active adapter name (e.g., "Wi-Fi", "Ethernet")

**Linux:**
```bash
ifconfig
# or
ip addr show
```
Look for your interface name (e.g., "eth0", "wlan0")

**macOS:**
```bash
ifconfig
```
Look for your interface name (e.g., "en0", "en1")

### Step 3: Edit Configuration File

Open `config.yaml` in a text editor and update:

```yaml
detection:
  network_interface: YOUR_INTERFACE_NAME  # Replace with your interface
```

### Step 4: Configure Email (Optional)

If you want email notifications, update the email section:

```yaml
email:
  smtp_host: smtp.gmail.com
  smtp_port: 587
  use_tls: true
  username: your-email@gmail.com
  password: your-app-password
  recipients:
    - recipient1@example.com
    - recipient2@example.com
```

**For Gmail:**
1. Enable 2-Factor Authentication
2. Go to: Google Account → Security → App Passwords
3. Generate an app password
4. Use that password in the config file

## 🚀 Running the IDS

### Windows

#### Method 1: Using Batch File (Easiest)

1. Right-click on `start_ids.bat`
2. Select "Run as administrator"
3. The system will start automatically

#### Method 2: Using Command Prompt

1. Open Command Prompt as Administrator:
   - Press `Win + X`
   - Select "Command Prompt (Admin)" or "PowerShell (Admin)"

2. Navigate to the project folder:
   ```cmd
   cd C:\path\to\IDS
   ```

3. Run the IDS:
   ```cmd
   python run_ids_with_ui.py
   ```

### Linux

1. Open Terminal

2. Navigate to the project folder:
   ```bash
   cd /path/to/IDS
   ```

3. Run with sudo (required for packet capture):
   ```bash
   sudo python3 run_ids_with_ui.py
   ```

### macOS

1. Open Terminal

2. Navigate to the project folder:
   ```bash
   cd /path/to/IDS
   ```

3. Run with sudo (required for packet capture):
   ```bash
   sudo python3 run_ids_with_ui.py
   ```

### Expected Output

You should see output similar to:

```
INFO - Starting IDS Application...
INFO - Initializing detectors...
INFO - Web UI starting on http://localhost:5000
 * Running on http://127.0.0.1:5000
 * Running on http://192.168.1.100:5000
```

## 🌐 Accessing the Web Interface

### Step 1: Open Your Browser

Open any modern web browser:
- Google Chrome (recommended)
- Mozilla Firefox
- Microsoft Edge
- Safari

### Step 2: Navigate to the Dashboard

Enter one of these URLs:

```
http://localhost:5000
```
or
```
http://127.0.0.1:5000
```

### Step 3: Verify Connection

You should see:
- Green "Connected" indicator in the top-right corner
- Dashboard with system status
- Four colored cards showing threat counts (all zeros initially)

## 🎮 Using the System

### Starting Monitoring

1. On the Dashboard page, locate the "Start Monitoring" button (blue button in the System Status card)
2. Click "Start Monitoring"
3. The button will change to "Stop Monitoring" (red)
4. Status will change to "ACTIVE" (green badge)
5. Packet count will start increasing

### Viewing Threats

1. Click "Threats" in the navigation menu
2. You'll see a list of all detected threats
3. Use filters to narrow down by:
   - Threat Type (Port Scan, Brute Force, etc.)
   - Severity (Critical, High, Medium, Low)
4. Click "View Details" on any threat for more information

### Analyzing Data

1. Click "Analytics" in the navigation menu
2. View charts showing:
   - Threats over time (line chart)
   - Threats by type (pie chart)
   - Threats by severity (bar chart)
   - Top attackers (table)
3. Use the time range selector to view different periods:
   - Last 1 hour
   - Last 24 hours
   - Last 7 days
   - Last 30 days

### Configuring the System

1. Click "Configuration" in the navigation menu
2. Tabs available:
   - **Email**: Configure SMTP settings
   - **Detection**: Adjust detection thresholds
   - **Logging**: Configure log settings
   - **Notifications**: Set up alert batching
3. Make changes and click "Save Changes"
4. Use "Test Email" button to verify email configuration

### Viewing Logs

1. Click "Logs" in the navigation menu
2. Browse system logs with pagination
3. Filter by event type:
   - All Events
   - Threats
   - Notifications
   - System Events
4. Use search box to find specific entries

### Stopping Monitoring

1. Return to the Dashboard
2. Click "Stop Monitoring" button (red)
3. Status will change to "STOPPED" (gray badge)
4. Packet capture will stop

## 🔧 Troubleshooting

### Issue: "Permission Denied" Error

**Solution:**
- Windows: Run Command Prompt as Administrator
- Linux/Mac: Use `sudo` before the command

### Issue: "Network Interface Not Found"

**Solution:**
1. Check your interface name using `ipconfig` (Windows) or `ifconfig` (Linux/Mac)
2. Update `config.yaml` with the correct interface name
3. Restart the IDS

### Issue: Web Page Won't Load

**Solution:**
1. Check if the IDS is running (look for "Running on http://..." message)
2. Try `http://127.0.0.1:5000` instead of `localhost`
3. Check if port 5000 is already in use
4. Try a different browser

### Issue: "WebSocket Disconnected"

**Solution:**
1. Check if the IDS is still running in the terminal
2. Refresh the web page (F5)
3. Check browser console for errors (F12)

### Issue: No Threats Detected

**Possible Reasons:**
1. Network interface is not receiving traffic
2. Detection thresholds are too high
3. No actual threats on the network (this is good!)

**To Test:**
- Lower detection thresholds in Configuration
- Generate test traffic (e.g., port scan with nmap)
- Check logs for any errors

### Issue: Email Notifications Not Working

**Solution:**
1. Verify SMTP settings in `config.yaml`
2. For Gmail, ensure you're using an App Password (not your regular password)
3. Check if 2-Factor Authentication is enabled
4. Use "Test Email" button in Configuration page
5. Check `ids.log` for email errors

### Issue: High CPU Usage

**Solution:**
1. This is normal during active packet capture
2. Reduce detection thresholds if too many false positives
3. Stop monitoring when not needed
4. Close other resource-intensive applications

### Issue: Python Package Import Errors

**Solution:**
```bash
# Reinstall all dependencies
pip install -r requirements.txt --force-reinstall

# Or install individually
pip install scapy flask flask-socketio flask-cors pyyaml python-socketio
```

### Issue: Port 5000 Already in Use

**Solution:**
1. Find what's using port 5000:
   ```bash
   # Windows
   netstat -ano | findstr :5000
   
   # Linux/Mac
   lsof -i :5000
   ```
2. Stop that process or modify `run_ids_with_ui.py` to use a different port

## 🛑 Stopping the System

### Graceful Shutdown

1. In the web interface, click "Stop Monitoring"
2. In the terminal/command prompt, press `Ctrl + C`
3. Wait for the system to shut down gracefully

### Force Stop (if needed)

**Windows:**
- Press `Ctrl + C` in the command prompt
- If that doesn't work, close the command prompt window

**Linux/Mac:**
- Press `Ctrl + C` in the terminal
- If that doesn't work, press `Ctrl + Z` then type `kill %1`

## 📊 Monitoring Tips

### Best Practices

1. **Start with Default Settings**: Use default thresholds initially
2. **Monitor Regularly**: Check the dashboard periodically
3. **Review Analytics**: Look for patterns in the Analytics page
4. **Adjust Thresholds**: Fine-tune based on your network
5. **Check Logs**: Review logs for any issues
6. **Test Email**: Verify email notifications work before relying on them

### Performance Tips

1. **Close Unused Applications**: Free up system resources
2. **Use Wired Connection**: More stable than Wi-Fi for monitoring
3. **Monitor During Peak Hours**: Capture more traffic
4. **Regular Restarts**: Restart the IDS daily for optimal performance

### Security Tips

1. **Keep Config Secure**: Don't share `config.yaml` with credentials
2. **Use Strong Passwords**: For email accounts
3. **Monitor Authorized Networks Only**: Ensure you have permission
4. **Review Threats Regularly**: Don't ignore alerts
5. **Update Regularly**: Keep Python and packages updated

## 🎯 Quick Reference

### Start IDS
```bash
# Windows (as Administrator)
python run_ids_with_ui.py

# Linux/Mac (with sudo)
sudo python3 run_ids_with_ui.py
```

### Access Dashboard
```
http://localhost:5000
```

### Stop IDS
```
Press Ctrl + C in terminal
```

### View Logs
```
Open ids.log in text editor
```

### Edit Configuration
```
Open config.yaml in text editor
```

## 📞 Getting Help

If you encounter issues:

1. **Check the logs**: Look in `ids.log` for error messages
2. **Verify configuration**: Ensure `config.yaml` is correct
3. **Check privileges**: Make sure running as Administrator/root
4. **Test network**: Verify network interface is active
5. **Review this guide**: Re-read relevant sections

## ✅ Success Checklist

Before considering the system operational, verify:

- [ ] Python 3.8+ is installed
- [ ] All dependencies are installed (`pip list`)
- [ ] `config.yaml` exists and is configured
- [ ] Network interface name is correct
- [ ] Running with Administrator/root privileges
- [ ] Web interface loads at http://localhost:5000
- [ ] WebSocket shows "Connected" (green)
- [ ] "Start Monitoring" button works
- [ ] Packet count increases when monitoring
- [ ] Can navigate to all pages (Dashboard, Threats, Analytics, Config, Logs)
- [ ] Email test works (if configured)

---

**🎉 Congratulations!** You're now ready to use the Intrusion Detection System!

For detailed information about features and architecture, see [README.md](README.md).