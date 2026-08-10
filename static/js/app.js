// static/js/app.js - Professional Real-time Dashboard
class LASAController {
    constructor() {
        this.isRunning = false;
        this.refreshInterval = null;
        this.init();
    }

    init() {
        this.hideLoading();
        this.bindEvents();
        this.startAutoRefresh();
        this.loadAllData();
    }

    hideLoading() {
        document.getElementById('loading-overlay').style.display = 'none';
    }

    bindEvents() {
        // Auto-hide sidebar on desktop
        if (window.innerWidth > 991) {
            document.getElementById('sidebar').classList.remove('offcanvas');
        }
    }

    startAutoRefresh() {
        this.refreshInterval = setInterval(() => this.loadAllData(), 3000);
    }

    showNotification(message, type = 'success') {
        const toast = document.getElementById('notification-toast');
        document.getElementById('toast-message').innerHTML = message;
        toast.className = `toast align-items-center text-white bg-${type} border-0`;
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
    }

    async apiCall(endpoint, options = {}) {
        try {
            const response = await fetch(endpoint, {
                ...options,
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (error) {
            this.showNotification(`Error: ${error.message}`, 'error');
            throw error;
        }
    }

    async loadAllData() {
        try {
            const [status, alerts, blocked, arp] = await Promise.all([
                this.apiCall('/api/arp/'),
                this.apiCall('/api/alerts/'),
                this.apiCall('/api/blocked/'),
                this.apiCall('/api/bans/')
            ]);

            this.updateStatus(status.running || false);
            this.updateStats(alerts, blocked, arp);
            this.updateAlerts(alerts.alerts.slice(-10));
            
        } catch (error) {
            console.error('Auto-refresh failed:', error);
        }
    }

    updateStatus(running) {
        this.isRunning = running;
        const dot = document.getElementById('status-dot');
        const text = document.getElementById('status-text');
        const startBtn = document.getElementById('start-btn');
        const stopBtn = document.getElementById('stop-btn');

        if (running) {
            dot.className = 'fas fa-circle status-dot running';
            text.textContent = 'IDS Active';
            startBtn.disabled = true;
            stopBtn.disabled = false;
        } else {
            dot.className = 'fas fa-circle status-dot stopped';
            text.textContent = 'IDS Stopped';
            startBtn.disabled = false;
            stopBtn.disabled = true;
        }
    }

    updateStats(alerts, blocked, arp) {
        document.getElementById('threat-count').textContent = 
            alerts.filter(a => a.includes('CRITICAL') || a.includes('ALERT')).length;
        document.getElementById('blocked-count').textContent = blocked.blocked_ips.length;
        document.getElementById('arp-devices').textContent = Object.keys(arp.arp_table || {}).length;
        document.getElementById('alert-badge').textContent = alerts.length;
        document.getElementById('blocked-badge').textContent = blocked.blocked_ips.length;
    }

    updateAlerts(alerts) {
        const container = document.getElementById('recent-alerts');
        if (container) {
            container.innerHTML = alerts.map(alert => {
                let alertClass = 'alert-medium';
                if (alert.includes('CRITICAL')) alertClass = 'alert-critical';
                else if (alert.includes('ALERT') || alert.includes('HIGH')) alertClass = 'alert-high';
                
                return `<div class="alert-item ${alertClass}">
                    <div class="d-flex justify-content-between">
                        <span>${alert}</span>
                        <small class="opacity-75">${new Date().toLocaleTimeString()}</small>
                    </div>
                </div>`;
            }).join('');
        }
    }

    async startIDS() {
        await this.apiCall('/api/start/', { method: 'POST' });
        this.showNotification('IDS Started Successfully!', 'success');
    }

    async stopIDS() {
        await this.apiCall('/api/stop/', { method: 'POST' });
        this.showNotification('IDS Stopped', 'warning');
    }

    async resetFirewall() {
        if (!confirm('⚠️ This will remove ALL blocks and bans. Continue?')) return;
        await this.apiCall('/api/reset/', { method: 'POST' });
        this.showNotification('Firewall Reset Complete!', 'warning');
        this.loadAllData();
    }
}

// Global controller instance
const lasa = new LASAController();

// Section switching
function showSection(section) {
    document.querySelectorAll('[id*="-section"]').forEach(el => el.style.display = 'none');
    document.getElementById(`${section}-section`)?.style.display = 'block';
    
    // Update nav
    document.querySelectorAll('.sidebar-nav .nav-link').forEach(link => link.classList.remove('active'));
    event.target.classList.add('active');
}

