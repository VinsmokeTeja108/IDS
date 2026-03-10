// Logs page JavaScript

let currentPage = 1;
let logsPerPage = 50;
let totalLogs = 0;
let autoRefreshInterval = null;
let currentFilters = {
    eventType: '',
    search: ''
};

// Fetch logs from server
async function fetchLogs() {
    showLoading(true);
    
    try {
        // Build query parameters
        const params = new URLSearchParams({
            page: currentPage,
            limit: logsPerPage
        });
        
        if (currentFilters.eventType) {
            params.append('event_type', currentFilters.eventType);
        }
        
        if (currentFilters.search) {
            params.append('search', currentFilters.search);
        }
        
        const response = await fetch(`/api/logs?${params.toString()}`);
        if (!response.ok) {
            throw new Error('Failed to fetch logs');
        }
        
        const data = await response.json();
        const pageOffset = (currentPage - 1) * logsPerPage;
        displayLogs(data.logs || [], pageOffset);
        updatePagination(data.total || 0, data.page || 1, data.total_pages || 1);
    } catch (error) {
        console.error('Error fetching logs:', error);
        showToast('Error', 'Failed to fetch logs', 'danger');
    } finally {
        showLoading(false);
    }
}

// Show/hide loading indicator
function showLoading(show) {
    const loadingIndicator = document.getElementById('logs-loading');
    const tableBody = document.getElementById('logs-table-body');
    
    if (loadingIndicator) {
        loadingIndicator.style.display = show ? 'block' : 'none';
    }
    if (tableBody && show) {
        tableBody.style.opacity = '0.5';
    } else if (tableBody) {
        tableBody.style.opacity = '1';
    }
}

// Display logs in table
function displayLogs(logs, pageOffset) {
    const tableBody = document.getElementById('logs-table-body');
    if (!tableBody) return;
    
    if (!logs || logs.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="4" class="text-center text-muted">
                    <div class="py-4">
                        <i class="bi bi-file-text" style="font-size: 3rem;"></i>
                        <p class="mt-2">No logs found</p>
                    </div>
                </td>
            </tr>
        `;
        return;
    }
    
    let html = '';
    logs.forEach((log, idx) => {
        // pageOffset is the absolute index of the first item on this page in newest-first order
        html += createLogRow(log, pageOffset + idx);
    });
    
    tableBody.innerHTML = html;
}

// Create log row HTML
function createLogRow(log, logIndex) {
    const eventTypeBadge = getEventTypeBadge(log.event_type || log.level);
    const timestamp = formatTimestamp(log.timestamp);
    
    // Properly render details — could be string, object, or missing
    let details;
    if (log.message) {
        details = typeof log.message === 'object' ? JSON.stringify(log.message) : log.message;
    } else if (log.details) {
        details = typeof log.details === 'object' ? JSON.stringify(log.details, null, 2) : log.details;
    } else {
        // Render all remaining keys as JSON
        const { timestamp: _t, event_type: _et, level: _l, ...rest } = log;
        details = JSON.stringify(rest);
    }
    
    return `
        <tr id="log-row-${logIndex}">
            <td class="text-nowrap">${timestamp}</td>
            <td>${eventTypeBadge}</td>
            <td class="text-break"><small>${escapeHtml(details)}</small></td>
            <td class="text-center">
                <button class="btn btn-sm btn-outline-danger py-0 px-1" title="Delete this log entry"
                    onclick="deleteLog(${logIndex})">
                    <i class="bi bi-trash"></i>
                </button>
            </td>
        </tr>
    `;
}


// Get event type badge
function getEventTypeBadge(eventType) {
    const type = (eventType || '').toLowerCase();
    
    const badges = {
        'threat': '<span class="badge bg-danger">Threat</span>',
        'notification': '<span class="badge bg-info">Notification</span>',
        'system': '<span class="badge bg-secondary">System</span>',
        'error': '<span class="badge bg-danger">Error</span>',
        'warning': '<span class="badge bg-warning">Warning</span>',
        'info': '<span class="badge bg-info">Info</span>',
        'debug': '<span class="badge bg-secondary">Debug</span>'
    };
    
    return badges[type] || `<span class="badge bg-secondary">${eventType}</span>`;
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Update pagination controls
function updatePagination(total, page, totalPages) {
    totalLogs = total;
    currentPage = page;
    
    // Update showing text
    const start = total === 0 ? 0 : (page - 1) * logsPerPage + 1;
    const end = Math.min(page * logsPerPage, total);
    
    document.getElementById('logs-showing-start').textContent = start;
    document.getElementById('logs-showing-end').textContent = end;
    document.getElementById('logs-total').textContent = total;
    
    // Update page numbers
    document.getElementById('current-page').textContent = page;
    document.getElementById('total-pages').textContent = totalPages;
    
    // Update button states
    const prevPageItem = document.getElementById('prev-page-item');
    const nextPageItem = document.getElementById('next-page-item');
    
    if (prevPageItem) {
        if (page <= 1) {
            prevPageItem.classList.add('disabled');
        } else {
            prevPageItem.classList.remove('disabled');
        }
    }
    
    if (nextPageItem) {
        if (page >= totalPages) {
            nextPageItem.classList.add('disabled');
        } else {
            nextPageItem.classList.remove('disabled');
        }
    }
}

// Go to previous page
function goToPreviousPage(e) {
    e.preventDefault();
    if (currentPage > 1) {
        currentPage--;
        fetchLogs();
    }
}

// Go to next page
function goToNextPage(e) {
    e.preventDefault();
    const totalPages = parseInt(document.getElementById('total-pages').textContent);
    if (currentPage < totalPages) {
        currentPage++;
        fetchLogs();
    }
}

// Handle search
function handleSearch() {
    currentFilters.eventType = document.getElementById('log-event-type').value;
    currentFilters.search = document.getElementById('log-search').value.trim();
    currentPage = 1; // Reset to first page
    fetchLogs();
}

// Handle refresh
function handleRefresh() {
    fetchLogs();
}

// Toggle auto-refresh
function toggleAutoRefresh() {
    const checkbox = document.getElementById('auto-refresh-logs');
    
    if (checkbox.checked) {
        startAutoRefresh();
    } else {
        stopAutoRefresh();
    }
}

// Start auto-refresh
function startAutoRefresh() {
    stopAutoRefresh(); // Clear any existing interval
    
    autoRefreshInterval = setInterval(() => {
        fetchLogs();
    }, 10000); // Refresh every 10 seconds
    
    showToast('Auto-refresh Enabled', 'Logs will refresh every 10 seconds', 'info');
}

// Stop auto-refresh
function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }
}

// Clear all logs
async function clearAllLogs() {
    if (!confirm('Are you sure you want to clear ALL log entries? This cannot be undone.')) {
        return;
    }
    try {
        const response = await fetch('/api/logs', { method: 'DELETE' });
        const result = await response.json();
        if (result.success) {
            showToast('Logs Cleared', 'All log entries have been cleared.', 'success');
            currentPage = 1;
            fetchLogs();
        } else {
            showToast('Error', result.message || 'Failed to clear logs', 'danger');
        }
    } catch (error) {
        console.error('Error clearing logs:', error);
        showToast('Error', 'Failed to clear logs', 'danger');
    }
}

// Delete a single log entry by its absolute newest-first index
async function deleteLog(logIndex) {
    try {
        const response = await fetch(`/api/logs/${logIndex}`, { method: 'DELETE' });
        const result = await response.json();
        if (result.success) {
            // Remove row from DOM immediately for instant feedback
            const row = document.getElementById(`log-row-${logIndex}`);
            if (row) row.remove();
            totalLogs = Math.max(0, totalLogs - 1);
            // Re-fetch to keep indices consistent
            fetchLogs();
        } else {
            showToast('Error', result.message || 'Failed to delete log entry', 'danger');
        }
    } catch (error) {
        console.error('Error deleting log entry:', error);
        showToast('Error', 'Failed to delete log entry', 'danger');
    }
}

// Initialize logs page
function initializeLogsPage() {
    // Fetch initial logs
    fetchLogs();
    
    // Set up event listeners
    document.getElementById('search-logs-btn').addEventListener('click', handleSearch);
    document.getElementById('refresh-logs-btn').addEventListener('click', handleRefresh);
    document.getElementById('clear-all-logs-btn').addEventListener('click', clearAllLogs);
    document.getElementById('prev-page-btn').addEventListener('click', goToPreviousPage);
    document.getElementById('next-page-btn').addEventListener('click', goToNextPage);
    document.getElementById('auto-refresh-logs').addEventListener('change', toggleAutoRefresh);
    
    // Allow Enter key to search
    document.getElementById('log-search').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            handleSearch();
        }
    });
    
    // Event type filter change
    document.getElementById('log-event-type').addEventListener('change', handleSearch);
}

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    stopAutoRefresh();
});

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    initializeLogsPage();
});
