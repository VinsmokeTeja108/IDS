// Threats page JavaScript

let allThreats = [];
let filteredThreats = [];
let currentFilters = {
    type: '',
    severity: '',
    search: ''
};

// Fetch and display threats
async function fetchThreats() {
    showLoading(true);
    
    try {
        const response = await fetch('/api/threats');
        if (!response.ok) {
            throw new Error('Failed to fetch threats');
        }
        
        const data = await response.json();
        // Handle both array and object responses
        allThreats = Array.isArray(data) ? data : (data.threats || []);
        applyFilters();
    } catch (error) {
        console.error('Error fetching threats:', error);
        showToast('Error', 'Failed to fetch threats', 'danger');
        allThreats = [];
        applyFilters();
    } finally {
        showLoading(false);
    }
}

// Show/hide loading indicator
function showLoading(show) {
    const loadingIndicator = document.getElementById('loading-indicator');
    const threatsList = document.getElementById('threats-list');
    
    if (loadingIndicator) {
        loadingIndicator.style.display = show ? 'block' : 'none';
    }
    if (threatsList && show) {
        threatsList.style.display = 'none';
    } else if (threatsList) {
        threatsList.style.display = 'block';
    }
}

// Apply filters to threats
function applyFilters() {
    filteredThreats = allThreats.filter(threat => {
        // Filter by type
        if (currentFilters.type && threat.type !== currentFilters.type) {
            return false;
        }
        
        // Filter by severity
        if (currentFilters.severity && threat.severity.toLowerCase() !== currentFilters.severity.toLowerCase()) {
            return false;
        }
        
        // Filter by search
        if (currentFilters.search) {
            const searchLower = currentFilters.search.toLowerCase();
            const matchesIP = threat.source_ip.includes(searchLower) || 
                            (threat.destination_ip && threat.destination_ip.includes(searchLower));
            const matchesType = threat.type.toLowerCase().includes(searchLower);
            const matchesDescription = threat.description.toLowerCase().includes(searchLower);
            
            if (!matchesIP && !matchesType && !matchesDescription) {
                return false;
            }
        }
        
        return true;
    });
    
    updateThreatsList();
}

// Update threats list display
function updateThreatsList() {
    const listElement = document.getElementById('threats-list');
    const countElement = document.getElementById('threat-count');
    
    if (!listElement) return;
    
    // Update count
    if (countElement) {
        countElement.textContent = filteredThreats.length;
    }
    
    // Display threats or empty message
    if (filteredThreats.length === 0) {
        listElement.innerHTML = `
            <div class="text-center text-muted py-4">
                <i class="bi bi-shield-check" style="font-size: 3rem;"></i>
                <p class="mt-2">No threats found</p>
            </div>
        `;
        return;
    }
    
    let html = '<div class="list-group list-group-flush">';
    filteredThreats.forEach(threat => {
        html += createThreatListItem(threat);
    });
    html += '</div>';
    
    listElement.innerHTML = html;
    
    // Add click handlers for view details buttons
    document.querySelectorAll('.view-threat-details').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const threatId = e.target.closest('.view-threat-details').dataset.threatId;
            showThreatDetails(threatId);
        });
    });
    
    // Add click handlers for delete buttons
    document.querySelectorAll('.delete-threat-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const threatId = e.target.closest('.delete-threat-btn').dataset.threatId;
            deleteThreat(threatId);
        });
    });
    
    // Update Clear All button visibility
    updateClearAllButton();
}

// Create threat list item HTML
function createThreatListItem(threat) {
    return `
        <div class="list-group-item threat-item">
            <div class="d-flex justify-content-between align-items-start">
                <div class="flex-grow-1">
                    <div class="d-flex align-items-center mb-2">
                        ${getSeverityBadge(threat.severity)}
                        <span class="ms-2 fw-bold">${getThreatTypeDisplay(threat.type)}</span>
                    </div>
                    <div class="text-muted small mb-1">
                        <i class="bi bi-hdd-network"></i> Source: <strong>${threat.source_ip}</strong>
                        ${threat.destination_ip ? ' → Destination: <strong>' + threat.destination_ip + '</strong>' : ''}
                    </div>
                    <div class="text-muted small">
                        <i class="bi bi-clock"></i> ${formatTimestamp(threat.timestamp)}
                        ${threat.protocol ? ' | <i class="bi bi-diagram-3"></i> ' + threat.protocol : ''}
                    </div>
                    <div class="mt-2 text-muted small">
                        ${threat.description.substring(0, 150)}${threat.description.length > 150 ? '...' : ''}
                    </div>
                </div>
                <div class="ms-3 d-flex flex-column gap-2">
                    <button class="btn btn-sm btn-outline-primary view-threat-details" data-threat-id="${threat.id}">
                        <i class="bi bi-eye"></i> View
                    </button>
                    <button class="btn btn-sm btn-outline-danger delete-threat-btn" data-threat-id="${threat.id}" title="Delete this threat">
                        <i class="bi bi-x-circle"></i>
                    </button>
                </div>
            </div>
        </div>
    `;
}

// Show threat details modal
function showThreatDetails(threatId) {
    const threat = allThreats.find(t => t.id === threatId);
    if (!threat) return;
    
    // Populate modal fields
    document.getElementById('detail-type').textContent = getThreatTypeDisplay(threat.type);
    document.getElementById('detail-severity').innerHTML = getSeverityBadge(threat.severity);
    document.getElementById('detail-timestamp').textContent = formatTimestamp(threat.timestamp);
    document.getElementById('detail-id').textContent = threat.id;
    document.getElementById('detail-source-ip').textContent = threat.source_ip;
    document.getElementById('detail-dest-ip').textContent = threat.destination_ip || 'N/A';
    document.getElementById('detail-protocol').textContent = threat.protocol || 'N/A';
    document.getElementById('detail-description').textContent = threat.description;
    document.getElementById('detail-justification').textContent = threat.justification || 'N/A';
    
    // Populate recommendations
    const recommendationsList = document.getElementById('recommendations-list');
    if (recommendationsList) {
        if (threat.recommendations && threat.recommendations.length > 0) {
            recommendationsList.innerHTML = threat.recommendations
                .map(rec => `<li>${rec}</li>`)
                .join('');
        } else {
            recommendationsList.innerHTML = '<li>No specific recommendations available</li>';
        }
    }
    
    // Populate raw data
    const rawDataElement = document.getElementById('detail-raw-data');
    if (rawDataElement) {
        rawDataElement.textContent = JSON.stringify(threat.raw_data || threat, null, 2);
    }
    
    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('threatDetailsModal'));
    modal.show();
}

// Handle filter changes
function handleFilterChange() {
    currentFilters.type = document.getElementById('filter-type').value;
    currentFilters.severity = document.getElementById('filter-severity').value;
    currentFilters.search = document.getElementById('search-input').value;
    
    applyFilters();
}

// Clear all filters
function clearFilters() {
    document.getElementById('filter-type').value = '';
    document.getElementById('filter-severity').value = '';
    document.getElementById('search-input').value = '';
    
    currentFilters = {
        type: '',
        severity: '',
        search: ''
    };
    
    applyFilters();
}

// Handle real-time threat updates via WebSocket
function handleThreatDetected(threat) {
    // Prepend new threat to the list
    allThreats.unshift(threat);
    
    // Reapply filters and update display
    applyFilters();
    
    // Show notification
    showToast(
        'New Threat Detected',
        `${getThreatTypeDisplay(threat.type)} from ${threat.source_ip}`,
        threat.severity === 'critical' || threat.severity === 'high' ? 'danger' : 'warning'
    );
}

// Initialize threats page
function initializeThreatsPage() {
    // Fetch initial threats
    fetchThreats();
    
    // Set up filter event listeners
    document.getElementById('filter-type').addEventListener('change', handleFilterChange);
    document.getElementById('filter-severity').addEventListener('change', handleFilterChange);
    document.getElementById('search-input').addEventListener('input', handleFilterChange);
    document.getElementById('clear-filters-btn').addEventListener('click', clearFilters);
    
    // Set up Clear All button
    const clearAllBtn = document.getElementById('clear-all-btn');
    if (clearAllBtn) {
        clearAllBtn.addEventListener('click', clearAllThreats);
    }
    
    // Set up WebSocket event handler
    if (socket) {
        socket.on('threat_detected', handleThreatDetected);
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Wait a bit for socket to be initialized in common.js
    setTimeout(initializeThreatsPage, 100);
});


// Delete a single threat
async function deleteThreat(threatId) {
    if (!confirm('Are you sure you want to delete this threat?')) {
        return;
    }
    
    try {
        const response = await fetch(`/api/threats/${threatId}`, {
            method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Success', 'Threat deleted successfully', 'success');
            // Remove from local arrays
            allThreats = allThreats.filter(t => t.id !== threatId);
            applyFilters();
            updateClearAllButton();
        } else {
            showToast('Error', data.message || 'Failed to delete threat', 'danger');
        }
    } catch (error) {
        console.error('Error deleting threat:', error);
        showToast('Error', 'Failed to delete threat', 'danger');
    }
}

// Clear all threats
async function clearAllThreats() {
    if (!confirm('Are you sure you want to delete ALL threats? This cannot be undone!')) {
        return;
    }
    
    try {
        const response = await fetch('/api/threats', {
            method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Success', `Cleared ${data.count} threat(s)`, 'success');
            allThreats = [];
            applyFilters();
            updateClearAllButton();
        } else {
            showToast('Error', data.message || 'Failed to clear threats', 'danger');
        }
    } catch (error) {
        console.error('Error clearing threats:', error);
        showToast('Error', 'Failed to clear threats', 'danger');
    }
}

// Update Clear All button visibility
function updateClearAllButton() {
    const clearAllBtn = document.getElementById('clear-all-btn');
    if (clearAllBtn) {
        clearAllBtn.style.display = allThreats.length > 0 ? 'block' : 'none';
    }
}


