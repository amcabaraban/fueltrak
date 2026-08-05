// ============================================
// FuelTrak - Session Manager with Auto-Logout
// ============================================
(function() {
    'use strict';
    
    let logoutTimer;
    
    function startLogoutTimer() {
        const token = localStorage.getItem('token');
        if (!token) return;
        
        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            const expiryTime = payload.exp * 1000;
            const timeUntilExpiry = expiryTime - Date.now();
            
            if (logoutTimer) clearTimeout(logoutTimer);
            
            if (timeUntilExpiry > 0) {
                // Auto-logout 10 seconds before expiry
                logoutTimer = setTimeout(() => {
                    alert('Your session has expired. Please login again.');
                    localStorage.removeItem('token');
                    localStorage.removeItem('refreshToken');
                    localStorage.removeItem('user');
                    window.location.href = '/';
                }, timeUntilExpiry - 10000);
            } else {
                handleLogout();
            }
        } catch (e) {
            console.error('Session check error:', e);
        }
    }
    
    function resetLogoutTimer() {
        // Reset timer on user activity
        startLogoutTimer();
    }
    
    function handleLogout() {
        localStorage.clear();
        window.location.href = '/';
    }
    
    // Listen for user activity
    ['click', 'keypress', 'scroll', 'mousemove', 'touchstart'].forEach(event => {
        document.addEventListener(event, resetLogoutTimer, { passive: true });
    });
    
    // Start timer on page load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', startLogoutTimer);
    } else {
        startLogoutTimer();
    }
})();