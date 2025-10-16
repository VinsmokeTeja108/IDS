// Configuration page JavaScript

let currentConfig = null;
let emailRecipients = [];

// Fetch current configuration
async function fetchConfiguration() {
    try {
        const response = await fetch('/api/config');
        if (!response.ok) {
            throw new Error('Failed to fetch configuration');
        }
        
        currentConfig = await response.json();
        populateConfigurationForms(currentConfig);
    } catch (error) {
        console.error('Error fetching configuration:', error);
        showToast('Error', 'Failed to fetch configuration', 'danger');
    }
}

// Populate all configuration forms
function populateConfigurationForms(config) {
    // Email settings
    if (config.email) {
        document.getElementById('smtp-host').value = config.email.smtp_host || '';
        document.getElementById('smtp-port').value = config.email.smtp_port || 587;
        document.getElementById('smtp-username').value = config.email.username || '';
        // Don't populate password for security
        document.getElementById('smtp-use-tls').checked = config.email.use_tls !== false;
        
        emailRecipients = config.email.recipients || [];
        updateRecipientsList();
    }
    
    // Detection settings
    if (config.detection) {
        document.getElementById('network-interface').value = config.detection.network_interface || '';
        document.getElementById('port-scan-threshold').value = config.detection.port_scan_threshold || 10;
        document.getElementById('icmp-scan-threshold').value = config.detection.icmp_scan_threshold || 20;
        document.getElementById('brute-force-threshold').value = config.detection.brute_force_threshold || 5;
        document.getElementById('data-exfil-threshold').value = config.detection.data_exfiltration_threshold || 100;
    }
    
    // Logging settings
    if (config.logging) {
        document.getElementById('log-level').value = config.logging.level || 'INFO';
        document.getElementById('log-file-path').value = config.logging.file_path || 'ids.log';
        document.getElementById('max-log-size').value = config.logging.max_size_mb || 10;
        document.getElementById('log-backup-count').value = config.logging.backup_count || 5;
    }
    
    // Notification settings
    if (config.notifications) {
        document.getElementById('enable-batching').checked = config.notifications.enable_batching !== false;
        document.getElementById('batch-window').value = config.notifications.batch_window_minutes || 5;
        document.getElementById('batch-threshold').value = config.notifications.batch_threshold || 3;
        document.getElementById('min-severity').value = config.notifications.min_severity || 'low';
    }
}

// Update recipients list display
function updateRecipientsList() {
    const listElement = document.getElementById('recipients-list');
    if (!listElement) return;
    
    if (emailRecipients.length === 0) {
        listElement.innerHTML = '<p class="text-muted small">No recipients configured</p>';
        return;
    }
    
    let html = '<div class="d-flex flex-wrap gap-2">';
    emailRecipients.forEach((recipient, index) => {
        html += `
            <span class="badge bg-secondary d-flex align-items-center">
                ${recipient}
                <button type="button" class="btn-close btn-close-white ms-2" 
                        onclick="removeRecipient(${index})" 
                        style="font-size: 0.7rem;"></button>
            </span>
        `;
    });
    html += '</div>';
    
    listElement.innerHTML = html;
}

// Add recipient
function addRecipient() {
    const input = document.getElementById('new-recipient');
    const email = input.value.trim();
    
    if (!email) {
        showToast('Validation Error', 'Please enter an email address', 'warning');
        return;
    }
    
    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        showToast('Validation Error', 'Please enter a valid email address', 'warning');
        return;
    }
    
    if (emailRecipients.includes(email)) {
        showToast('Validation Error', 'This email is already in the list', 'warning');
        return;
    }
    
    emailRecipients.push(email);
    updateRecipientsList();
    input.value = '';
}

// Remove recipient
function removeRecipient(index) {
    emailRecipients.splice(index, 1);
    updateRecipientsList();
}

// Validate email form
function validateEmailForm() {
    const host = document.getElementById('smtp-host').value.trim();
    const port = document.getElementById('smtp-port').value;
    const username = document.getElementById('smtp-username').value.trim();
    
    if (!host) {
        showToast('Validation Error', 'SMTP host is required', 'warning');
        return false;
    }
    
    if (!port || port < 1 || port > 65535) {
        showToast('Validation Error', 'Valid SMTP port is required (1-65535)', 'warning');
        return false;
    }
    
    if (!username) {
        showToast('Validation Error', 'SMTP username is required', 'warning');
        return false;
    }
    
    if (emailRecipients.length === 0) {
        showToast('Validation Error', 'At least one recipient is required', 'warning');
        return false;
    }
    
    return true;
}

// Save email configuration
async function saveEmailConfiguration(e) {
    e.preventDefault();
    
    if (!validateEmailForm()) {
        return;
    }
    
    const emailConfig = {
        smtp_host: document.getElementById('smtp-host').value.trim(),
        smtp_port: parseInt(document.getElementById('smtp-port').value),
        username: document.getElementById('smtp-username').value.trim(),
        use_tls: document.getElementById('smtp-use-tls').checked,
        recipients: emailRecipients
    };
    
    // Include password only if it was changed
    const password = document.getElementById('smtp-password').value;
    if (password) {
        emailConfig.password = password;
    }
    
    await saveConfiguration({ email: emailConfig });
}

// Save detection configuration
async function saveDetectionConfiguration(e) {
    e.preventDefault();
    
    const detectionConfig = {
        network_interface: document.getElementById('network-interface').value.trim(),
        port_scan_threshold: parseInt(document.getElementById('port-scan-threshold').value),
        icmp_scan_threshold: parseInt(document.getElementById('icmp-scan-threshold').value),
        brute_force_threshold: parseInt(document.getElementById('brute-force-threshold').value),
        data_exfiltration_threshold: parseInt(document.getElementById('data-exfil-threshold').value)
    };
    
    await saveConfiguration({ detection: detectionConfig });
}

// Save logging configuration
async function saveLoggingConfiguration(e) {
    e.preventDefault();
    
    const loggingConfig = {
        level: document.getElementById('log-level').value,
        file_path: document.getElementById('log-file-path').value.trim(),
        max_size_mb: parseInt(document.getElementById('max-log-size').value),
        backup_count: parseInt(document.getElementById('log-backup-count').value)
    };
    
    await saveConfiguration({ logging: loggingConfig });
}

// Save notifications configuration
async function saveNotificationsConfiguration(e) {
    e.preventDefault();
    
    const notificationsConfig = {
        enable_batching: document.getElementById('enable-batching').checked,
        batch_window_minutes: parseInt(document.getElementById('batch-window').value),
        batch_threshold: parseInt(document.getElementById('batch-threshold').value),
        min_severity: document.getElementById('min-severity').value
    };
    
    await saveConfiguration({ notifications: notificationsConfig });
}

// Save configuration to server
async function saveConfiguration(configUpdate) {
    try {
        const response = await fetch('/api/config', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(configUpdate)
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to save configuration');
        }
        
        const result = await response.json();
        showToast('Success', result.message || 'Configuration saved successfully', 'success');
        
        // Refresh configuration
        await fetchConfiguration();
    } catch (error) {
        console.error('Error saving configuration:', error);
        showToast('Error', error.message || 'Failed to save configuration', 'danger');
    }
}

// Send test email
async function sendTestEmail() {
    if (!validateEmailForm()) {
        return;
    }
    
    const btn = document.getElementById('test-email-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Sending...';
    
    try {
        const response = await fetch('/api/config/test-email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to send test email');
        }
        
        const result = await response.json();
        showToast('Success', result.message || 'Test email sent successfully', 'success');
    } catch (error) {
        console.error('Error sending test email:', error);
        showToast('Error', error.message || 'Failed to send test email', 'danger');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-send"></i> Send Test Email';
    }
}

// Fetch detectors status
async function fetchDetectors() {
    try {
        const response = await fetch('/api/detectors');
        if (!response.ok) {
            throw new Error('Failed to fetch detectors');
        }
        
        const data = await response.json();
        // Handle both array and object responses
        const detectors = Array.isArray(data) ? data : (data.detectors || []);
        displayDetectors(detectors);
    } catch (error) {
        console.error('Error fetching detectors:', error);
        showToast('Error', 'Failed to fetch detectors', 'danger');
        // Display empty state instead of error
        displayDetectors([]);
    }
}

// Display detectors list
function displayDetectors(detectors) {
    const listElement = document.getElementById('detectors-list');
    if (!listElement) return;
    
    if (!detectors || detectors.length === 0) {
        listElement.innerHTML = `
            <div class="text-center text-muted py-4">
                <i class="bi bi-shield-x" style="font-size: 3rem;"></i>
                <p class="mt-2">No detectors available</p>
            </div>
        `;
        return;
    }
    
    let html = '<div class="list-group list-group-flush">';
    detectors.forEach(detector => {
        html += createDetectorItem(detector);
    });
    html += '</div>';
    
    listElement.innerHTML = html;
    
    // Add toggle event listeners
    document.querySelectorAll('.detector-toggle').forEach(toggle => {
        toggle.addEventListener('change', handleDetectorToggle);
    });
    
    // Check if all detectors are disabled
    checkAllDetectorsDisabled(detectors);
}

// Create detector item HTML
function createDetectorItem(detector) {
    const isEnabled = detector.enabled !== false;
    
    return `
        <div class="list-group-item">
            <div class="d-flex justify-content-between align-items-start">
                <div class="flex-grow-1">
                    <div class="d-flex align-items-center mb-2">
                        <h6 class="mb-0">${detector.name || 'Unknown Detector'}</h6>
                        <span class="badge ${isEnabled ? 'bg-success' : 'bg-secondary'} ms-2">
                            ${isEnabled ? 'Enabled' : 'Disabled'}
                        </span>
                    </div>
                    <p class="text-muted small mb-0">
                        ${detector.description || 'No description available'}
                    </p>
                </div>
                <div class="form-check form-switch ms-3">
                    <input class="form-check-input detector-toggle" 
                           type="checkbox" 
                           id="detector-${detector.name}" 
                           data-detector-name="${detector.name}"
                           ${isEnabled ? 'checked' : ''}>
                    <label class="form-check-label" for="detector-${detector.name}">
                        ${isEnabled ? 'Enabled' : 'Disabled'}
                    </label>
                </div>
            </div>
        </div>
    `;
}

// Handle detector toggle
async function handleDetectorToggle(e) {
    const toggle = e.target;
    const detectorName = toggle.dataset.detectorName;
    const enabled = toggle.checked;
    
    // Disable toggle during operation
    toggle.disabled = true;
    
    try {
        const response = await fetch(`/api/detectors/${detectorName}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ enabled: enabled })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to update detector');
        }
        
        const result = await response.json();
        showToast('Success', result.message || `Detector ${enabled ? 'enabled' : 'disabled'}`, 'success');
        
        // Refresh detectors list
        await fetchDetectors();
    } catch (error) {
        console.error('Error toggling detector:', error);
        showToast('Error', error.message || 'Failed to update detector', 'danger');
        
        // Revert toggle state
        toggle.checked = !enabled;
    } finally {
        toggle.disabled = false;
    }
}

// Check if all detectors are disabled and show warning
function checkAllDetectorsDisabled(detectors) {
    const warningElement = document.getElementById('all-detectors-disabled-warning');
    if (!warningElement) return;
    
    const allDisabled = detectors.every(d => d.enabled === false);
    
    if (allDisabled) {
        warningElement.style.display = 'block';
    } else {
        warningElement.style.display = 'none';
    }
}

// Initialize configuration page
function initializeConfigPage() {
    // Fetch initial configuration
    fetchConfiguration();
    
    // Fetch detectors
    fetchDetectors();
    
    // Set up form submit handlers
    document.getElementById('email-form').addEventListener('submit', saveEmailConfiguration);
    document.getElementById('detection-form').addEventListener('submit', saveDetectionConfiguration);
    document.getElementById('logging-form').addEventListener('submit', saveLoggingConfiguration);
    document.getElementById('notifications-form').addEventListener('submit', saveNotificationsConfiguration);
    
    // Set up button handlers
    document.getElementById('add-recipient-btn').addEventListener('click', addRecipient);
    document.getElementById('test-email-btn').addEventListener('click', sendTestEmail);
    
    // Allow Enter key to add recipient
    document.getElementById('new-recipient').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            addRecipient();
        }
    });
    
    // Refresh detectors when detectors tab is shown
    const detectorsTab = document.getElementById('detectors-tab');
    if (detectorsTab) {
        detectorsTab.addEventListener('shown.bs.tab', () => {
            fetchDetectors();
        });
    }
}

// Make removeRecipient available globally
window.removeRecipient = removeRecipient;

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    initializeConfigPage();
});
