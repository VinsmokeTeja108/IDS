// Common JavaScript functionality for IDS Web UI

// WebSocket connection
let socket = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;
let reconnectTimer = null;
let connectionLostShown = false;

// Initialize Socket.IO connection
function initializeWebSocket() {
    socket = io({
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        reconnectionAttempts: MAX_RECONNECT_ATTEMPTS
    });
    
    socket.on('connect', function() {
        console.log('WebSocket connected');
        reconnectAttempts = 0;
        connectionLostShown = false;
        updateConnectionStatus('connected');
        
        // Show success toast if this was a reconnection
        if (reconnectTimer) {
            clearTimeout(reconnectTimer);
            reconnectTimer = null;
            showToast('Connected', 'Successfully reconnected to server', 'success');
        }
    });
    
    socket.on('disconnect', function(reason) {
        console.log('WebSocket disconnected:', reason);
        updateConnectionStatus('disconnected');
        
        // Show notification after a short delay to avoid flashing on quick reconnects
        if (!connectionLostShown) {
            reconnectTimer = setTimeout(() => {
                showToast('Connection Lost', 'Attempting to reconnect...', 'warning');
                connectionLostShown = true;
            }, 2000);
        }
    });
    
    socket.on('connect_error', function(error) {
        console.error('WebSocket connection error:', error);
        updateConnectionStatus('error');
        reconnectAttempts++;
        
        if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS && !connectionLostShown) {
            showToast('Connection Failed', 'Unable to connect to server. Please check if the backend is running.', 'danger');
            connectionLostShown = true;
        }
    });
    
    socket.on('reconnect_attempt', function(attemptNumber) {
        console.log(`Reconnection attempt ${attemptNumber}`);
        updateConnectionStatus('connecting', attemptNumber);
    });
    
    socket.on('reconnect_failed', function() {
        console.error('Reconnection failed after maximum attempts');
        updateConnectionStatus('error');
        showToast('Connection Failed', 'Unable to reconnect to server. Please refresh the page.', 'danger');
    });
}

// Update connection status indicator
function updateConnectionStatus(status, attemptNumber = null) {
    const statusElement = document.getElementById('connection-status');
    if (!statusElement) return;
    
    statusElement.classList.remove('bg-success', 'bg-danger', 'bg-secondary', 'bg-warning', 'connected', 'disconnected', 'connecting', 'error');
    
    if (status === 'connected') {
        statusElement.classList.add('bg-success', 'connected');
        statusElement.innerHTML = '<i class="bi bi-circle-fill"></i> Connected';
        statusElement.title = 'Connected to server';
        hideConnectionErrorBanner();
    } else if (status === 'disconnected') {
        statusElement.classList.add('bg-warning', 'disconnected');
        statusElement.innerHTML = '<i class="bi bi-circle-fill"></i> Disconnected';
        statusElement.title = 'Disconnected from server';
    } else if (status === 'connecting') {
        statusElement.classList.add('bg-secondary', 'connecting');
        const attemptText = attemptNumber ? ` (${attemptNumber}/${MAX_RECONNECT_ATTEMPTS})` : '';
        statusElement.innerHTML = `<i class="bi bi-arrow-repeat"></i> Reconnecting${attemptText}`;
        statusElement.title = 'Attempting to reconnect...';
    } else if (status === 'error') {
        statusElement.classList.add('bg-danger', 'error');
        statusElement.innerHTML = '<i class="bi bi-x-circle-fill"></i> Error';
        statusElement.title = 'Connection error';
        showConnectionErrorBanner();
    }
}

// Show connection error banner
function showConnectionErrorBanner(message = null) {
    const banner = document.getElementById('connection-error-banner');
    const messageElement = document.getElementById('connection-error-message');
    
    if (!banner) return;
    
    if (message && messageElement) {
        messageElement.textContent = message;
    }
    
    banner.style.display = 'block';
    banner.classList.add('show');
}

// Hide connection error banner
function hideConnectionErrorBanner() {
    const banner = document.getElementById('connection-error-banner');
    
    if (!banner) return;
    
    banner.classList.remove('show');
    setTimeout(() => {
        banner.style.display = 'none';
    }, 150);
}

// Show toast notification
function showToast(title, message, type = 'info') {
    const toastElement = document.getElementById('toast-notification');
    const toastTitle = document.getElementById('toast-title');
    const toastMessage = document.getElementById('toast-message');
    const toastHeader = toastElement.querySelector('.toast-header');
    const toastBody = toastElement.querySelector('.toast-body');
    
    if (!toastElement || !toastTitle || !toastMessage) return;
    
    // Set content
    toastTitle.textContent = title;
    toastMessage.textContent = message;
    
    // Reset all classes
    toastHeader.classList.remove('bg-success', 'bg-danger', 'bg-warning', 'bg-info', 'text-white', 'text-dark');
    toastBody.classList.remove('bg-success', 'bg-danger', 'bg-warning', 'bg-info', 'text-white', 'text-dark');
    
    // Set icon based on type
    let icon = 'bi-info-circle';
    
    // Set color and icon based on type
    if (type === 'success') {
        toastHeader.classList.add('bg-success', 'text-white');
        toastBody.classList.add('bg-success', 'text-white');
        icon = 'bi-check-circle-fill';
    } else if (type === 'danger' || type === 'error') {
        toastHeader.classList.add('bg-danger', 'text-white');
        toastBody.classList.add('bg-danger', 'text-white');
        icon = 'bi-exclamation-triangle-fill';
    } else if (type === 'warning') {
        toastHeader.classList.add('bg-warning', 'text-dark');
        toastBody.classList.add('bg-warning', 'text-dark');
        icon = 'bi-exclamation-circle-fill';
    } else {
        toastHeader.classList.add('bg-info', 'text-white');
        toastBody.classList.add('bg-info', 'text-white');
        icon = 'bi-info-circle-fill';
    }
    
    // Add icon to title
    toastTitle.innerHTML = `<i class="bi ${icon} me-2"></i>${title}`;
    
    // Show toast with auto-dismiss after 5 seconds
    const toast = new bootstrap.Toast(toastElement, { 
        delay: 5000,
        autohide: true 
    });
    toast.show();
}

// Format timestamp
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

// Format uptime
function formatUptime(seconds) {
    if (!seconds || seconds < 0) return '-';
    
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    
    if (hours > 0) {
        return `${hours}h ${minutes}m`;
    } else if (minutes > 0) {
        return `${minutes}m ${secs}s`;
    } else {
        return `${secs}s`;
    }
}

// Get severity badge HTML
function getSeverityBadge(severity) {
    const severityLower = severity.toLowerCase();
    return `<span class="badge severity-${severityLower}">${severity.toUpperCase()}</span>`;
}

// Get threat type display name
function getThreatTypeDisplay(type) {
    const typeMap = {
        'port_scan': 'Port Scan',
        'icmp_scan': 'ICMP Scan',
        'malware': 'Malware',
        'brute_force': 'Brute Force',
        'attacker_identified': 'Attacker Identified',
        'data_exfiltration': 'Data Exfiltration'
    };
    return typeMap[type] || type;
}

// Show loading spinner on button
function showButtonLoading(button) {
    if (!button) return;
    
    // Store original content
    button.dataset.originalContent = button.innerHTML;
    button.dataset.originalDisabled = button.disabled;
    
    // Add loading class and disable button
    button.classList.add('loading');
    button.disabled = true;
    
    // Set loading content
    button.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Loading...';
}

// Hide loading spinner on button
function hideButtonLoading(button) {
    if (!button) return;
    
    // Remove loading class
    button.classList.remove('loading');
    
    // Restore original content and state
    if (button.dataset.originalContent) {
        button.innerHTML = button.dataset.originalContent;
        delete button.dataset.originalContent;
    }
    
    if (button.dataset.originalDisabled !== undefined) {
        button.disabled = button.dataset.originalDisabled === 'true';
        delete button.dataset.originalDisabled;
    } else {
        button.disabled = false;
    }
}

// Show loading overlay on element
function showLoadingOverlay(element, message = 'Loading...') {
    if (!element) return;
    
    // Make element position relative if not already
    const position = window.getComputedStyle(element).position;
    if (position === 'static') {
        element.style.position = 'relative';
    }
    
    // Create overlay
    const overlay = document.createElement('div');
    overlay.className = 'loading-overlay';
    overlay.innerHTML = `
        <div class="text-center">
            <div class="spinner-border text-primary spinner-border-custom" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <div class="mt-3 fw-bold">${message}</div>
        </div>
    `;
    
    element.appendChild(overlay);
}

// Hide loading overlay on element
function hideLoadingOverlay(element) {
    if (!element) return;
    
    const overlay = element.querySelector('.loading-overlay');
    if (overlay) {
        overlay.remove();
    }
}

// Show loading state for card
function showCardLoading(cardElement) {
    if (!cardElement) return;
    
    cardElement.classList.add('loading');
    showLoadingOverlay(cardElement);
}

// Hide loading state for card
function hideCardLoading(cardElement) {
    if (!cardElement) return;
    
    cardElement.classList.remove('loading');
    hideLoadingOverlay(cardElement);
}

// Show skeleton loading for table
function showTableSkeleton(tableBody, rows = 5, cols = 4) {
    if (!tableBody) return;
    
    tableBody.innerHTML = '';
    
    for (let i = 0; i < rows; i++) {
        const row = document.createElement('tr');
        for (let j = 0; j < cols; j++) {
            const cell = document.createElement('td');
            cell.innerHTML = '<div class="skeleton skeleton-text"></div>';
            row.appendChild(cell);
        }
        tableBody.appendChild(row);
    }
}

// Show loading spinner in container
function showLoadingSpinner(container, size = 'md') {
    if (!container) return;
    
    const sizeClass = size === 'sm' ? 'spinner-border-sm' : size === 'lg' ? 'spinner-border-lg' : '';
    
    container.innerHTML = `
        <div class="text-center py-5">
            <div class="spinner-border text-primary ${sizeClass}" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <div class="mt-3 text-muted">Loading data...</div>
        </div>
    `;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeWebSocket();
});
