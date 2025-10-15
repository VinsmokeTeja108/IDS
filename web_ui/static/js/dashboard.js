// Dashboard page JavaScript

let statusRefreshInterval = null;
let currentStatus = null;

// Fetch and display system status
async function fetchSystemStatus() {
    try {
        const response = await fetch('/api/status');
        if (!response.ok) {
            throw new Error('Failed to fetch status');
        }
        
        const status = await response.json();
        currentStatus = status;
        updateSystemStatus(status);
    } catch (error) {
        console.error('Error fetching system status:', error);
        showToast('Error', 'Failed to fetch system status', 'danger');
    }
}

// Update system status display
function updateSystemStatus(status) {
    // Update status badge
    const statusElement = document.getElementById('system-status');
    if (statusElement) {
        if (status.running) {
            statusElement.innerHTML = '<span class="badge bg-success"><i class="bi bi-circle-fill"></i> ACTIVE</span>';
        } else {
            statusElement.innerHTML = '<span class="badge bg-secondary"><i class="bi bi-circle-fill"></i> STOPPED</span>';
        }
    }
    
    // Update interface
    const interfaceElement = document.getElementById('system-interface');
    if (interfaceElement) {
        interfaceElement.textContent = status.interface || '-';
    }
    
    // Update uptime
    const uptimeElement = document.getElementById('system-uptime');
    if (uptimeElement) {
        uptimeElement.textContent = formatUptime(status.uptime);
    }
    
    // Update packet count
    const packetsElement = document.getElementById('system-packets');
    if (packetsElement) {
        packetsElement.textContent = (status.packet_count || 0).toLocaleString();
    }
    
    // Update toggle button
    updateToggleButton(status.running);
}

// Update toggle monitoring button
function updateToggleButton(isRunning) {
    const toggleBtn = document.getElementById('toggle-monitoring-btn');
    if (!toggleBtn) return;
    
    if (isRunning) {
        toggleBtn.innerHTML = '<i class="bi bi-stop-fill"></i> Stop Monitoring';
        toggleBtn.classList.remove('btn-primary');
        toggleBtn.classList.add('btn-danger');
    } else {
        toggleBtn.innerHTML = '<i class="bi bi-play-fill"></i> Start Monitoring';
        toggleBtn.classList.remove('btn-danger');
        toggleBtn.classList.add('btn-primary');
    }
}

// Handle start/stop monitoring
async function toggleMonitoring() {
    const toggleBtn = document.getElementById('toggle-monitoring-btn');
    if (!toggleBtn) return;
    
    // Disable button during operation
    toggleBtn.disabled = true;
    
    try {
        const endpoint = currentStatus && currentStatus.running ? '/api/stop' : '/api/start';
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Operation failed');
        }
        
        const result = await response.json();
        showToast('Success', result.message || 'Operation completed', 'success');
        
        // Refresh status
        await fetchSystemStatus();
    } catch (error) {
        console.error('Error toggling monitoring:', error);
        showToast('Error', error.message || 'Failed to toggle monitoring', 'danger');
    } finally {
        toggleBtn.disabled = false;
    }
}

// Fetch and display threat statistics
async function fetchThreatStats() {
    try {
        const response = await fetch('/api/threats/stats');
        if (!response.ok) {
            throw new Error('Failed to fetch threat stats');
        }
        
        const stats = await response.json();
        updateThreatStats(stats);
    } catch (error) {
        console.error('Error fetching threat stats:', error);
    }
}

// Update threat statistics cards
function updateThreatStats(stats) {
    const bySeverity = stats.by_severity || {};
    
    document.getElementById('stat-critical').textContent = bySeverity.critical || 0;
    document.getElementById('stat-high').textContent = bySeverity.high || 0;
    document.getElementById('stat-medium').textContent = bySeverity.medium || 0;
    document.getElementById('stat-low').textContent = bySeverity.low || 0;
}

// Fetch and display recent threats
async function fetchRecentThreats() {
    try {
        const response = await fetch('/api/threats?limit=5');
        if (!response.ok) {
            throw new Error('Failed to fetch recent threats');
        }
        
        const threats = await response.json();
        updateRecentThreatsList(threats);
    } catch (error) {
        console.error('Error fetching recent threats:', error);
    }
}

// Update recent threats list
function updateRecentThreatsList(threats) {
    const listElement = document.getElementById('recent-threats-list');
    if (!listElement) return;
    
    if (!threats || threats.length === 0) {
        listElement.innerHTML = `
            <div class="text-center text-muted py-4">
                <i class="bi bi-shield-check" style="font-size: 3rem;"></i>
                <p class="mt-2">No threats detected</p>
            </div>
        `;
        return;
    }
    
    let html = '<div class="list-group list-group-flush">';
    threats.forEach(threat => {
        html += `
            <div class="list-group-item">
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <div class="d-flex align-items-center mb-1">
                            ${getSeverityBadge(threat.severity)}
                            <span class="ms-2 fw-bold">${getThreatTypeDisplay(threat.type)}</span>
                        </div>
                        <div class="text-muted small">
                            <i class="bi bi-arrow-right"></i> ${threat.source_ip}
                            ${threat.destination_ip ? ' → ' + threat.destination_ip : ''}
                            <span class="ms-3"><i class="bi bi-clock"></i> ${formatTimestamp(threat.timestamp)}</span>
                        </div>
                    </div>
                    <a href="/threats" class="btn btn-sm btn-outline-primary">Details</a>
                </div>
            </div>
        `;
    });
    html += '</div>';
    
    listElement.innerHTML = html;
}

// Handle real-time threat updates via WebSocket
function handleThreatDetected(threat) {
    // Update stats
    fetchThreatStats();
    
    // Update recent threats list
    fetchRecentThreats();
    
    // Show notification for critical/high threats
    if (threat.severity === 'critical' || threat.severity === 'high') {
        showToast(
            'Threat Detected',
            `${getThreatTypeDisplay(threat.type)} from ${threat.source_ip}`,
            'danger'
        );
    }
}

// Handle real-time status updates via WebSocket
function handleStatusChanged(status) {
    updateSystemStatus(status);
    showToast('Status Changed', `IDS is now ${status.running ? 'active' : 'stopped'}`, 'info');
}

// Handle real-time stats updates via WebSocket
function handleStatsUpdated(stats) {
    updateThreatStats(stats);
}

// Start auto-refresh for uptime and packet count
function startAutoRefresh() {
    // Refresh status every 5 seconds
    statusRefreshInterval = setInterval(() => {
        if (currentStatus && currentStatus.running) {
            fetchSystemStatus();
        }
    }, 5000);
}

// Stop auto-refresh
function stopAutoRefresh() {
    if (statusRefreshInterval) {
        clearInterval(statusRefreshInterval);
        statusRefreshInterval = null;
    }
}

// Initialize dashboard
function initializeDashboard() {
    // Fetch initial data
    fetchSystemStatus();
    fetchThreatStats();
    fetchRecentThreats();
    
    // Set up event listeners
    const toggleBtn = document.getElementById('toggle-monitoring-btn');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', toggleMonitoring);
    }
    
    // Set up WebSocket event handlers
    if (socket) {
        socket.on('threat_detected', handleThreatDetected);
        socket.on('status_changed', handleStatusChanged);
        socket.on('stats_updated', handleStatsUpdated);
    }
    
    // Start auto-refresh
    startAutoRefresh();
}

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    stopAutoRefresh();
});

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Wait a bit for socket to be initialized in common.js
    setTimeout(initializeDashboard, 100);
});
