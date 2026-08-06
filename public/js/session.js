// ============================================
// FuelTrak - Session Manager with Auto-Logout
// ============================================
(function() {
    'use strict';
    
    let logoutTimer;
    let warningTimer;
    let countdownTimer;
    
    // Show logout warning notification
    function showLogoutWarning(secondsLeft) {
        // Remove existing warning if any
        const existingWarning = document.getElementById('sessionWarning');
        if (existingWarning) existingWarning.remove();
        
        const warning = document.createElement('div');
        warning.id = 'sessionWarning';
        warning.style.cssText = `
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            z-index: 9999;
            background: #f59e0b;
            color: white;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: bold;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            text-align: center;
            animation: slideDown 0.3s ease;
            cursor: pointer;
        `;
        warning.innerHTML = `
            <div style="display: flex; align-items: center; gap: 12px;">
                <i class="fas fa-clock" style="font-size: 20px;"></i>
                <div>
                    <p style="margin: 0; font-size: 14px;">Session expiring in <span id="countdownSeconds">${secondsLeft}</span> seconds</p>
                    <p style="margin: 2px 0 0 0; font-size: 12px; opacity: 0.9;">Click anywhere to stay logged in</p>
                </div>
            </div>
        `;
        document.body.appendChild(warning);
        
        // Add animation style
        if (!document.getElementById('sessionStyles')) {
            const style = document.createElement('style');
            style.id = 'sessionStyles';
            style.textContent = `
                @keyframes slideDown {
                    from { transform: translateX(-50%) translateY(-100px); opacity: 0; }
                    to { transform: translateX(-50%) translateY(0); opacity: 1; }
                }
            `;
            document.head.appendChild(style);
        }
        
        // Start countdown
        let remaining = secondsLeft;
        const countdownEl = document.getElementById('countdownSeconds');
        countdownTimer = setInterval(() => {
            remaining--;
            if (countdownEl) countdownEl.textContent = remaining;
            if (remaining <= 0) {
                clearInterval(countdownTimer);
            }
        }, 1000);
    }
    
    // Remove warning
    function removeWarning() {
        const warning = document.getElementById('sessionWarning');
        if (warning) warning.remove();
        if (countdownTimer) clearInterval(countdownTimer);
    }
    
    // Force logout
    function forceLogout() {
        removeWarning();
        
        // Show logout notification briefly
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            z-index: 9999;
            background: #ef4444;
            color: white;
            padding: 16px 24px;
            border-radius: 8px;
            font-weight: bold;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            text-align: center;
        `;
        notification.innerHTML = `
            <i class="fas fa-sign-out-alt mr-2"></i>
            Session expired. Redirecting to login...
        `;
        document.body.appendChild(notification);
        
        // Clear storage and redirect
        setTimeout(() => {
            localStorage.removeItem('fueltrak_token');
            localStorage.removeItem('fueltrak_user');
            localStorage.removeItem('fueltrak_refresh');
            window.location.href = '/';
        }, 1500);
    }
    
    function startLogoutTimer() {
        const token = localStorage.getItem('fueltrak_token');
        if (!token) return;
        
        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            const expiryTime = payload.exp * 1000;
            const timeUntilExpiry = expiryTime - Date.now();
            
            // Clear existing timers
            if (logoutTimer) clearTimeout(logoutTimer);
            if (warningTimer) clearTimeout(warningTimer);
            removeWarning();
            
            if (timeUntilExpiry <= 0) {
                // Already expired
                forceLogout();
                return;
            }
            
            // Show warning 60 seconds before expiry
            const warningTime = timeUntilExpiry - 60000;
            if (warningTime > 0) {
                warningTimer = setTimeout(() => {
                    showLogoutWarning(60);
                }, warningTime);
            }
            
            // Force logout at expiry
            logoutTimer = setTimeout(() => {
                forceLogout();
            }, timeUntilExpiry);
            
        } catch (e) {
            console.error('Session check error:', e);
        }
    }
    
    function resetLogoutTimer() {
        removeWarning();
        startLogoutTimer();
    }
    
    // Listen for user activity
    ['click', 'keypress', 'scroll', 'mousemove', 'touchstart', 'touchend'].forEach(event => {
        document.addEventListener(event, resetLogoutTimer, { passive: true });
    });
    
    // Start timer on page load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', startLogoutTimer);
    } else {
        startLogoutTimer();
    }
    
    // Check token validity every 5 minutes
    setInterval(async () => {
        const token = localStorage.getItem('fueltrak_token');
        if (!token) return;
        
        try {
            const response = await fetch('/api/auth/profile', {
                headers: { 'Authorization': 'Bearer ' + token }
            });
            
            if (!response.ok && response.status === 401) {
                forceLogout();
            }
        } catch (e) {
            // Network error - don't logout
        }
    }, 300000); // 5 minutes
    
})();