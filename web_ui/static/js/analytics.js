// Analytics page JavaScript

let timelineChart = null;
let typeChart = null;
let severityChart = null;
let currentTimeRange = '24h';

// Fetch analytics data
async function fetchAnalyticsData(timeRange) {
    showLoading(true);
    
    try {
        // Fetch summary and timeline data
        const [summaryResponse, timelineResponse] = await Promise.all([
            fetch('/api/analytics/summary'),
            fetch(`/api/analytics/timeline?range=${timeRange}`)
        ]);
        
        if (!summaryResponse.ok || !timelineResponse.ok) {
            throw new Error('Failed to fetch analytics data');
        }
        
        const summary = await summaryResponse.json();
        const timeline = await timelineResponse.json();
        
        updateAnalytics(summary, timeline);
    } catch (error) {
        console.error('Error fetching analytics:', error);
        showToast('Error', 'Failed to fetch analytics data', 'danger');
    } finally {
        showLoading(false);
    }
}

// Show/hide loading indicator
function showLoading(show) {
    const loadingIndicator = document.getElementById('analytics-loading');
    if (loadingIndicator) {
        loadingIndicator.style.display = show ? 'block' : 'none';
    }
}

// Update all analytics displays
function updateAnalytics(summary, timeline) {
    updateSummaryStats(summary);
    updateTimelineChart(timeline);
    updateTypeChart(summary.by_type || {});
    updateSeverityChart(summary.by_severity || {});
    updateTopAttackersTable(summary.top_attackers || []);
}

// Update summary statistics
function updateSummaryStats(summary) {
    document.getElementById('summary-total').textContent = summary.total_threats || 0;
    document.getElementById('summary-attackers').textContent = summary.unique_attackers || 0;
    document.getElementById('summary-avg').textContent = (summary.avg_per_hour || 0).toFixed(1);
}

// Update timeline chart
function updateTimelineChart(timeline) {
    const ctx = document.getElementById('timeline-chart');
    if (!ctx) return;
    
    // Destroy existing chart
    if (timelineChart) {
        timelineChart.destroy();
    }
    
    // Prepare data
    const labels = timeline.labels || [];
    const data = timeline.data || [];
    
    // Create chart
    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Threats Detected',
                data: data,
                borderColor: 'rgb(220, 53, 69)',
                backgroundColor: 'rgba(220, 53, 69, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    mode: 'index',
                    intersect: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });
}

// Update threats by type chart
function updateTypeChart(byType) {
    const ctx = document.getElementById('type-chart');
    if (!ctx) return;
    
    // Destroy existing chart
    if (typeChart) {
        typeChart.destroy();
    }
    
    // Prepare data
    const labels = Object.keys(byType).map(type => getThreatTypeDisplay(type));
    const data = Object.values(byType);
    
    // If no data, show empty chart
    if (data.length === 0 || data.every(v => v === 0)) {
        ctx.getContext('2d').clearRect(0, 0, ctx.width, ctx.height);
        return;
    }
    
    // Create chart
    typeChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: [
                    'rgba(220, 53, 69, 0.8)',
                    'rgba(253, 126, 20, 0.8)',
                    'rgba(255, 193, 7, 0.8)',
                    'rgba(13, 202, 240, 0.8)',
                    'rgba(25, 135, 84, 0.8)',
                    'rgba(108, 117, 125, 0.8)'
                ],
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// Update threats by severity chart
function updateSeverityChart(bySeverity) {
    const ctx = document.getElementById('severity-chart');
    if (!ctx) return;
    
    // Destroy existing chart
    if (severityChart) {
        severityChart.destroy();
    }
    
    // Prepare data in specific order
    const severityOrder = ['critical', 'high', 'medium', 'low'];
    const labels = severityOrder.map(s => s.charAt(0).toUpperCase() + s.slice(1));
    const data = severityOrder.map(s => bySeverity[s] || 0);
    const colors = [
        'rgba(220, 53, 69, 0.8)',   // Critical - red
        'rgba(253, 126, 20, 0.8)',  // High - orange
        'rgba(255, 193, 7, 0.8)',   // Medium - yellow
        'rgba(13, 202, 240, 0.8)'   // Low - blue
    ];
    
    // Create chart
    severityChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Threat Count',
                data: data,
                backgroundColor: colors,
                borderColor: colors.map(c => c.replace('0.8', '1')),
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });
}

// Update top attackers table
function updateTopAttackersTable(topAttackers) {
    const tableBody = document.getElementById('top-attackers-table');
    if (!tableBody) return;
    
    if (!topAttackers || topAttackers.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="5" class="text-center text-muted">No data available</td>
            </tr>
        `;
        return;
    }
    
    let html = '';
    topAttackers.forEach((attacker, index) => {
        html += `
            <tr>
                <td>${index + 1}</td>
                <td><strong>${attacker.ip}</strong></td>
                <td><span class="badge bg-danger">${attacker.count}</span></td>
                <td>${getThreatTypeDisplay(attacker.most_common_type || 'unknown')}</td>
                <td>${attacker.last_seen ? formatTimestamp(attacker.last_seen) : 'N/A'}</td>
            </tr>
        `;
    });
    
    tableBody.innerHTML = html;
}

// Handle time range change
function handleTimeRangeChange() {
    const select = document.getElementById('time-range-select');
    currentTimeRange = select.value;
    fetchAnalyticsData(currentTimeRange);
}

// Initialize analytics page
function initializeAnalyticsPage() {
    // Fetch initial data
    fetchAnalyticsData(currentTimeRange);
    
    // Set up time range selector
    const timeRangeSelect = document.getElementById('time-range-select');
    if (timeRangeSelect) {
        timeRangeSelect.addEventListener('change', handleTimeRangeChange);
    }
}

// Clean up charts on page unload
window.addEventListener('beforeunload', () => {
    if (timelineChart) timelineChart.destroy();
    if (typeChart) typeChart.destroy();
    if (severityChart) severityChart.destroy();
});

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    initializeAnalyticsPage();
});
