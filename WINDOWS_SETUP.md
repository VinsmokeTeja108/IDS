# Windows Setup Guide for IDS

## Critical Issue: Npcap Installation

Your system shows: `WARNING: No libpcap provider available ! pcap won't be used`

This means **Npcap is not properly installed**, which is why you're seeing 0 packets captured.

## Step-by-Step Fix:

### 1. Install Npcap (Required for Packet Capture on Windows)

1. **Download Npcap:**
   - Go to: https://npcap.com/#download
   - Download the latest Npcap installer

2. **Install with Correct Options:**
   - Run the installer **as Administrator**
   - **IMPORTANT:** Check these options during installation:
     - ✅ **Install Npcap in WinPcap API-compatible Mode** (CRITICAL!)
     - ✅ **Support raw 802.11 traffic** (optional, but recommended)
   - Complete the installation
   - **Restart your computer** after installation

3. **Verify Installation:**
   ```cmd
   python check_network_interfaces.py
   ```
   - You should NO LONGER see the warning: "No libpcap provider available"
   - You should see your network interfaces listed

### 2. Run as Administrator

Packet capture on Windows requires administrator privileges:

```cmd
# Right-click Command Prompt or PowerShell
# Select "Run as Administrator"

# Then run:
python run_ids_with_ui.py
```

### 3. Configure Your Network Interface

Your active Wi-Fi interface has been detected:
- **Interface Name:** `Wi-Fi`
- **IP Address:** `192.168.29.29`
- **Adapter:** Realtek RTL8821CE 802.11ac PCIe Adapter

This is already configured in your `config.yaml` file.

## Testing After Npcap Installation:

### Test 1: Check Interfaces
```cmd
python check_network_interfaces.py
```
Expected: No warnings, interfaces listed with IPs

### Test 2: Start the IDS
```cmd
# Run as Administrator!
python run_ids_with_ui.py
```

### Test 3: Generate Traffic
Once the IDS is running:
1. Open your web browser
2. Visit a few websites
3. Check the web UI dashboard - you should see packet counts increasing

### Test 4: Test Threat Detection (Safe)
```cmd
# In a separate Administrator terminal, scan your own machine:
nmap -p 1-100 localhost
```
This should trigger a port scan detection.

## Troubleshooting:

### Still seeing "No libpcap provider available"?

1. **Uninstall Npcap completely:**
   - Go to Windows Settings > Apps
   - Find "Npcap" and uninstall
   - Restart your computer

2. **Reinstall Npcap:**
   - Download fresh installer from https://npcap.com/
   - Run as Administrator
   - **MUST check "WinPcap API-compatible Mode"**
   - Restart computer

3. **Reinstall Scapy:**
   ```cmd
   pip uninstall scapy
   pip install scapy
   ```

### Permission Denied Errors?

- Always run as Administrator on Windows
- Check Windows Firewall isn't blocking Python

### Interface Not Found?

Try using the full device path instead:
```yaml
detection:
  network_interface: "\\Device\\NPF_{7BC4BD57-F8F9-47A4-8C38-CD7A840DBD7B}"
```

### Firewall Blocking?

Windows Defender might block packet capture:
1. Open Windows Security
2. Go to Firewall & network protection
3. Allow Python through the firewall

## Alternative: Use Ethernet

If Wi-Fi continues to have issues, try using Ethernet:
```yaml
detection:
  network_interface: "Ethernet"
```

Your Ethernet interface: `Realtek PCIe GbE Family Controller` (IP: 169.254.212.54)

## Why This Happens:

- **Windows doesn't have native packet capture** like Linux
- **Npcap** provides the WinPcap library that Scapy needs
- Without Npcap, Scapy can't access the network card
- The "WinPcap API-compatible Mode" is critical for Scapy compatibility

## Next Steps After Fixing:

Once Npcap is installed and you can capture packets:

1. **Start the Web UI:**
   ```cmd
   python run_ids_with_ui.py
   ```

2. **Access the dashboard:**
   - Open browser: http://localhost:5000
   - Click "Start Monitoring"
   - You should see packet counts increasing

3. **Generate normal traffic:**
   - Browse websites
   - Download files
   - Stream videos
   - Watch the packet counter increase

4. **Test threat detection:**
   - Use `nmap` to scan your own machine
   - Try multiple failed SSH/RDP login attempts
   - Send large file transfers

## Summary:

**The main issue is NOT your configuration - it's that Npcap is not installed properly.**

1. Install Npcap with WinPcap compatibility mode
2. Restart your computer
3. Run IDS as Administrator
4. You should see packets being captured

Your configuration is correct, and your interface name "Wi-Fi" is valid!
