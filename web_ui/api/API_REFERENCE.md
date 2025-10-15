# IDS Web UI API Reference

## Base URL
```
http://localhost:5000/api
```

## System Control Endpoints

### Get Status
```http
GET /api/status
```
Returns current IDS status including running state, interface, uptime, and packet count.

**Response:**
```json
{
  "running": true,
  "interface": "eth0",
  "uptime": 3600,
  "uptime_formatted": "1h 0m 0s",
  "packet_count": 15234,
  "threat_count": 42,
  "start_time": "2025-10-15T14:30:00"
}
```

### Start Monitoring
```http
POST /api/start
```
Starts IDS monitoring.

**Response:**
```json
{
  "success": true,
  "message": "IDS monitoring started successfully",
  "status": { ... }
}
```

### Stop Monitoring
```http
POST /api/stop
```
Stops IDS monitoring.

### Restart Monitoring
```http
POST /api/restart
```
Restarts IDS monitoring (stops and starts).

---

## Threats Endpoints

### Get Threats
```http
GET /api/threats?type=port_scan&severity=high&limit=10
```
Retrieves threats with optional filtering.

**Query Parameters:**
- `type` - Filter by threat type (comma-separated)
- `severity` - Filter by severity (comma-separated)
- `start_time` - ISO timestamp
- `end_time` - ISO timestamp
- `limit` - Maximum results
- `source_ip` - Filter by source IP

**Response:**
```json
{
  "threats": [
    {
      "id": "uuid",
      "timestamp": "2025-10-15T14:30:00",
      "type": "port_scan",
      "severity": "high",
      "source_ip": "192.168.1.100",
      "destination_ip": "10.0.0.5",
      "protocol": "TCP",
      "description": "Port scan detected...",
      "recommendations": ["Block IP...", "Review firewall..."],
      "justification": "Multiple ports scanned..."
    }
  ],
  "count": 1
}
```

### Get Threat by ID
```http
GET /api/threats/{id}
```
Retrieves detailed information for a specific threat.

### Get Threat Statistics
```http
GET /api/threats/stats
```
Returns threat statistics.

**Response:**
```json
{
  "total_threats": 42,
  "by_severity": {
    "critical": 2,
    "high": 10,
    "medium": 20,
    "low": 10
  },
  "by_type": {
    "port_scan": 15,
    "icmp_scan": 10,
    "malware": 5,
    ...
  },
  "top_attackers": [
    {"ip": "192.168.1.100", "count": 15}
  ],
  "recent_count": 5,
  "last_threat_time": "2025-10-15T14:30:00"
}
```

---

## Configuration Endpoints

### Get Configuration
```http
GET /api/config
```
Returns current configuration (passwords masked).

**Response:**
```json
{
  "email": {
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "[email]",
    "password": "********",
    "use_tls": true,
    "recipients": ["[email]"]
  },
  "detection": {
    "network_interface": "eth0",
    "port_scan_threshold": 10,
    ...
  },
  "logging": { ... },
  "notification": { ... }
}
```

### Update Configuration
```http
PUT /api/config
Content-Type: application/json

{
  "detection": {
    "port_scan_threshold": 15
  },
  "email": {
    "recipients": ["[email]", "[email]"]
  }
}
```
Updates configuration with validation.

**Response:**
```json
{
  "success": true,
  "message": "Configuration updated successfully",
  "requires_restart": true
}
```

### Test Email
```http
POST /api/config/test-email
Content-Type: application/json

{
  "recipient": "[email]"
}
```
Sends a test email.

**Response:**
```json
{
  "success": true,
  "message": "Test email sent successfully",
  "recipient": "[email]"
}
```

---

## Detector Management Endpoints

### Get Detectors
```http
GET /api/detectors
```
Lists all threat detectors with their status.

**Response:**
```json
{
  "detectors": [
    {
      "name": "PortScanDetector",
      "type": "port_scan",
      "enabled": true,
      "description": "Detects port scanning attempts"
    }
  ],
  "count": 6
}
```

### Toggle Detector
```http
PUT /api/detectors/PortScanDetector
Content-Type: application/json

{
  "enabled": false
}
```
Enables or disables a specific detector.

**Response:**
```json
{
  "success": true,
  "message": "Detector PortScanDetector toggle requested",
  "detector": "PortScanDetector",
  "enabled": false
}
```

---

## Logs Endpoints

### Get Logs
```http
GET /api/logs?page=1&limit=50&event_type=threat
```
Retrieves system logs with pagination.

**Query Parameters:**
- `page` - Page number (default: 1)
- `limit` - Logs per page (default: 50, max: 1000)
- `event_type` - Filter by type (threat, notification, system)

**Response:**
```json
{
  "logs": [
    {
      "timestamp": "2025-10-15T14:30:00",
      "level": "INFO",
      "event_type": "threat",
      "message": "Port scan detected",
      "details": { ... }
    }
  ],
  "page": 1,
  "limit": 50,
  "total": 150,
  "total_pages": 3
}
```

### Search Logs
```http
GET /api/logs/search?query=192.168.1.100&event_type=threat&limit=100
```
Searches logs by keyword or IP address.

**Query Parameters:**
- `query` - Search keyword (required)
- `event_type` - Filter by type
- `limit` - Maximum results (default: 100, max: 1000)

**Response:**
```json
{
  "logs": [ ... ],
  "query": "192.168.1.100",
  "count": 15
}
```

---

## Notifications Endpoints

### Get Notifications
```http
GET /api/notifications?limit=50&status=sent
```
Retrieves notification history.

**Query Parameters:**
- `limit` - Maximum results (default: 100, max: 1000)
- `status` - Filter by status (sent, failed)

**Response:**
```json
{
  "notifications": [
    {
      "timestamp": "2025-10-15T14:30:00",
      "status": "sent",
      "recipients": ["[email]"],
      "subject": "IDS Alert: Port Scan Detected",
      "threat_type": "port_scan",
      "error": null
    }
  ],
  "count": 1
}
```

### Update Notification Settings
```http
PUT /api/notifications/settings
Content-Type: application/json

{
  "recipients": ["[email]", "[email]"],
  "batch_window": 300,
  "batch_threshold": 5
}
```
Updates email recipients and batching settings.

**Response:**
```json
{
  "success": true,
  "message": "Configuration updated successfully",
  "requires_restart": true
}
```

---

## Analytics Endpoints

### Get Analytics Summary
```http
GET /api/analytics/summary
```
Returns threat analytics summary.

**Response:**
```json
{
  "total_threats": 42,
  "by_severity": {
    "critical": 2,
    "high": 10,
    "medium": 20,
    "low": 10
  },
  "by_type": {
    "port_scan": 15,
    "icmp_scan": 10,
    ...
  },
  "top_attackers": [
    {"ip": "192.168.1.100", "count": 15}
  ]
}
```

### Get Analytics Timeline
```http
GET /api/analytics/timeline?range=24h
```
Returns timeline data for Chart.js visualization.

**Query Parameters:**
- `range` - Time range: `1h`, `24h`, `7d`, `30d` (default: 24h)

**Response:**
```json
{
  "labels": ["00:00", "01:00", "02:00", ...],
  "datasets": [
    {
      "label": "Total Threats",
      "data": [5, 3, 8, ...],
      "by_severity": {
        "critical": [1, 0, 2, ...],
        "high": [2, 1, 3, ...],
        "medium": [1, 2, 2, ...],
        "low": [1, 0, 1, ...]
      },
      "by_type": {
        "port_scan": [3, 2, 4, ...],
        "icmp_scan": [1, 1, 2, ...],
        ...
      }
    }
  ],
  "range": "24h",
  "total_threats": 42
}
```

---

## Error Responses

All endpoints return errors in the following format:

```json
{
  "error": "Error type",
  "message": "Detailed error message"
}
```

### HTTP Status Codes
- `200` - Success
- `400` - Bad Request (invalid parameters or validation failed)
- `404` - Not Found (resource doesn't exist)
- `500` - Internal Server Error
- `503` - Service Unavailable (IDS not initialized)

---

## Notes

- All timestamps are in ISO 8601 format
- All request/response bodies use JSON
- CORS is enabled for cross-origin requests
- The API is stateless and RESTful
