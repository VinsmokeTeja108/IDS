# IDS Quick Start Guide

## ✅ Setup Complete!

Your Intrusion Detection System is now properly configured and ready to use!

## What Was Fixed:

1. **Npcap Installation** - Packet capture library installed correctly
2. **Network Interface** - Configured to use your Wi-Fi adapter (192.168.29.29)
3. **API Error Handling** - Fixed "Failed to fetch threats/detectors" errors
4. **Frontend JavaScript** - Improved error handling for empty states

## How to Use Your IDS:

### Step 1: Start the Web UI

Open PowerShell (you don't need Administrator for basic operation):

```powershell
cd C:\Users\HP\Desktop\IDS
python run_ids_with_ui.py
```

You should see:
```
Web UI is now available at: http://0.0.0.0:5000
```

### Step 2: Access the Dashboard

Open your web browser and go to:
```
http://localhost:5000
```

Or from another device on your network:
```
http://192.168.29.29:5000
```

### Step 3: Start Monitoring

1. On the Dashboard, click the **"Start Monitoring"** button
2. Wait a few seconds for initialization
3. You should see:
   - Status changes to "Running"
   - Packet count starts increasing
   - Interface shows "Wi-Fi"

### Step 4: Generate Traffic

Just use your computer normally:
- Browse websites
- Download files
- Stream videos
- Use any internet applications

The packet counter will increase as traffic flows through your network.

## Understanding the Dashboard:

### System Status Card
- **Status**: Running/Stopped
- **Interface**: Wi-Fi (your active network adapter)
- **Uptime**: How long monitoring has been running
- **Packets Analyzed**: Total packets captured
- **Threats Detected**: Number of threats found

### Quick Stats
- **Critical**: Severe threats requiring immediate action
- **High**: Important threats to investigate
- **Medium**: Moderate threats to monitor
- **Low**: Minor suspicious activity

### Recent Threats
Shows the last 5 detected threats with:
- Timestamp
- Threat type
- Severity level
- Source IP address

## Testing Threat Detection:

### Safe Self-Testing

You can safely test the IDS by scanning your own machine:

#### Test 1: Port Scan Detection
```powershell
# Install nmap if you don't have it
# Then scan your own machine:
nmap -p 1-100 localhost
```

This should trigger a **Port Scan** detection.

#### Test 2: ICMP Scan Detection
```powershell
# Ping sweep on your local network
ping 192.168.29.1
ping 192.168.29.2
# ... repeat several times quickly
```

This might trigger an **ICMP Scan** detection.

#### Test 3: Generate Normal Traffic
- Open multiple websites simultaneously
- Download a large file
- Stream a video
- This generates normal traffic for the IDS to analyze

## Exploring the Web UI:

### 📊 Dashboard
- Real-time system status
- Quick threat statistics
- Recent threats list
- Start/Stop monitoring controls

### ⚠️ Threats
- View all detected threats
- Filter by type and severity
- Search by IP address
- View detailed threat information

### 📈 Analytics
- Threat trends over time
- Threats by type (pie chart)
- Threats by severity (bar chart)
- Top attacking IP addresses
- Time range selector (1h, 24h, 7d, 30d)

### ⚙️ Configuration
- **Email Settings**: Configure SMTP for notifications
- **Detection**: Adjust detection thresholds
- **Logging**: Configure log levels and rotation
- **Notifications**: Set up email batching
- **Detectors**: View and manage threat detectors

### 📝 Logs
- View system logs
- Filter by event type
- Search logs
- Pagination support

## Common Scenarios:

### Scenario 1: No Threats Detected

This is normal! If you're just browsing normally, you might not see threats. The IDS is working correctly - it's just that there's no malicious activity.

**To verify it's working:**
- Check that packet count is increasing
- Try the safe self-testing methods above

### Scenario 2: Many Low Severity Threats

This is also normal. Low severity threats are often false positives or minor suspicious patterns. Focus on High and Critical threats.

### Scenario 3: Packet Count Not Increasing

If packets aren't being captured:
1. Make sure you clicked "Start Monitoring"
2. Generate some network traffic (browse websites)
3. Check that Wi-Fi is your active connection
4. Try restarting the IDS

### Scenario 4: High CPU Usage

Packet capture can be CPU-intensive. This is normal, especially with high network traffic. You can:
- Adjust detection thresholds higher
- Monitor during specific time periods
- Use a more powerful machine for production

## Stopping the IDS:

### From the Web UI:
1. Go to the Dashboard
2. Click **"Stop Monitoring"**
3. Wait for graceful shutdown

### From the Terminal:
Press `Ctrl+C` in the PowerShell window

## Configuration Tips:

### Adjust Detection Sensitivity

If you're getting too many false positives:

1. Go to **Configuration** > **Detection** tab
2. Increase the thresholds:
   - Port Scan Threshold: 12 → 20
   - ICMP Scan Threshold: 5 → 10
   - Brute Force Threshold: 5 → 10

### Set Up Email Notifications

1. Go to **Configuration** > **Email Settings**
2. Configure your SMTP settings:
   - Gmail: smtp.gmail.com:587
   - Outlook: smtp-mail.outlook.com:587
3. Add recipient email addresses
4. Click **"Test Email"** to verify
5. Click **"Save Changes"**

### View Detector Status

1. Go to **Configuration** > **Detectors** tab
2. See all active detectors:
   - Port Scan Detector
   - ICMP Scan Detector
   - Brute Force Detector
   - Malware Detector
   - Data Exfiltration Detector

## Troubleshooting:

### "Failed to fetch threats"
- This is normal when IDS isn't started yet
- Click "Start Monitoring" first
- The error will disappear once monitoring starts

### "Failed to fetch detectors"
- This is also normal before starting
- Detectors are initialized when monitoring starts
- You'll see the detector list after starting

### "Permission Denied"
- Run PowerShell as Administrator
- Right-click PowerShell → "Run as Administrator"

### "Interface not found"
- Check your network connection
- Run: `python check_network_interfaces.py`
- Update config.yaml with correct interface

## Next Steps:

1. **Run the IDS regularly** to build a baseline of normal traffic
2. **Review threats daily** to understand your network patterns
3. **Adjust thresholds** based on your environment
4. **Set up email notifications** for critical threats
5. **Export logs** for compliance or analysis

## Support Files:

- `WINDOWS_SETUP.md` - Detailed Windows setup instructions
- `HOW_TO_RUN.md` - Complete running instructions
- `DOCUMENTATION.md` - Full system documentation
- `README.md` - Project overview
- `check_network_interfaces.py` - Network interface checker
- `test_packet_capture.py` - Packet capture tester

## Summary:

✅ Npcap installed and working
✅ Network interface configured (Wi-Fi)
✅ Web UI accessible at http://localhost:5000
✅ Packet capture tested and functional
✅ API errors fixed
✅ Ready to detect threats!

**You're all set! Start the IDS and begin monitoring your network.**

---

**Need Help?**
- Check the documentation files
- Run diagnostic scripts
- Review the logs in the web UI
