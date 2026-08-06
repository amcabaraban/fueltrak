// ============================================
// FuelTrak - Announcement Bell & Notifications
// ============================================
(function() {
    'use strict';
    
    function getToken() {
        return localStorage.getItem('fueltrak_token');
    }
    
    // Create bell icon
    function createBellIcon() {
        // Check if bell already exists
        if (document.getElementById('announcementBell')) return;
        
        const header = document.querySelector('header') || document.querySelector('nav') || document.body;
        
        const bellContainer = document.createElement('div');
        bellContainer.id = 'announcementBell';
        bellContainer.style.cssText = 'position:relative;cursor:pointer;margin-left:12px;display:inline-flex;align-items:center;';
        bellContainer.innerHTML = `
            <i class="fas fa-bell" style="font-size:20px;color:#1e3a5f;"></i>
            <span id="announcementBadge" class="hidden" style="position:absolute;top:-6px;right:-8px;background:#ef4444;color:white;font-size:10px;min-width:18px;height:18px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:bold;">0</span>
        `;
        bellContainer.onclick = toggleAnnouncementPanel;
        
        // Insert near user profile or at the top
        const profileArea = header.querySelector('.user-profile, .profile, [class*="user"]') || header.lastElementChild;
        if (profileArea) {
            profileArea.parentNode.insertBefore(bellContainer, profileArea);
        } else {
            header.appendChild(bellContainer);
        }
        
        // Create dropdown panel
        createAnnouncementPanel();
        
        // Start polling
        updateUnreadCount();
        setInterval(updateUnreadCount, 30000); // Every 30 seconds
    }
    
    // Create announcement panel
    function createAnnouncementPanel() {
        if (document.getElementById('announcementPanel')) return;
        
        const panel = document.createElement('div');
        panel.id = 'announcementPanel';
        panel.className = 'hidden';
        panel.style.cssText = `
            position: fixed;
            top: 60px;
            right: 20px;
            z-index: 9998;
            width: 380px;
            max-height: 500px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        `;
        
        panel.innerHTML = `
            <div style="background:#1e3a5f;color:white;padding:12px 16px;display:flex;justify-content:space-between;align-items:center;">
                <span style="font-weight:bold;"><i class="fas fa-bullhorn mr-2"></i>Announcements</span>
                <button onclick="markAllAnnouncementsRead()" style="background:none;border:none;color:white;font-size:12px;cursor:pointer;">Mark all read</button>
            </div>
            <div id="announcementList" style="max-height:420px;overflow-y:auto;">
                <div style="padding:20px;text-align:center;color:#9ca3af;">Loading announcements...</div>
            </div>
        `;
        
        document.body.appendChild(panel);
        
        // Close panel when clicking outside
        document.addEventListener('click', function(e) {
            const bell = document.getElementById('announcementBell');
            const panel = document.getElementById('announcementPanel');
            if (panel && !panel.contains(e.target) && bell && !bell.contains(e.target)) {
                panel.classList.add('hidden');
            }
        });
    }
    
    // Toggle panel
    function toggleAnnouncementPanel() {
        const panel = document.getElementById('announcementPanel');
        if (panel) {
            panel.classList.toggle('hidden');
            if (!panel.classList.contains('hidden')) {
                loadAnnouncements();
            }
        }
    }
    
    // Load announcements
    async function loadAnnouncements() {
        try {
            const token = getToken();
            if (!token) return;
            
            const response = await fetch('/api/announcements', {
                headers: { 'Authorization': 'Bearer ' + token }
            });
            
            if (response.status === 401) {
                localStorage.clear();
                window.location.href = '/';
                return;
            }
            
            const data = await response.json();
            const list = document.getElementById('announcementList');
            if (!list) return;
            
            if (data.data.length === 0) {
                list.innerHTML = '<div style="padding:20px;text-align:center;color:#9ca3af;">No announcements</div>';
                return;
            }
            
            const priorityColors = {
                urgent: '#ef4444',
                important: '#f59e0b',
                normal: '#3b82f6'
            };
            
            list.innerHTML = data.data.map(ann => `
                <div class="announcement-item" data-id="${ann.id}" style="padding:14px 16px;border-bottom:1px solid #f3f4f6;cursor:pointer;${ann.is_read ? '' : 'background:#f0f9ff;'}">
                    <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:4px;">
                        <span style="font-weight:600;font-size:14px;flex:1;">${ann.title}</span>
                        <span style="background:${priorityColors[ann.priority]};color:white;font-size:10px;padding:2px 8px;border-radius:10px;margin-left:8px;">${ann.priority}</span>
                    </div>
                    <p style="font-size:13px;color:#4b5563;margin:4px 0;">${ann.message}</p>
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-top:6px;">
                        <span style="font-size:11px;color:#9ca3af;">${new Date(ann.created_at).toLocaleDateString()} by ${ann.created_by_email}</span>
                        ${!ann.is_read ? '<span style="color:#3b82f6;font-size:11px;">● New</span>' : ''}
                    </div>
                </div>
            `).join('');
            
            // Mark as read on click
            list.querySelectorAll('.announcement-item').forEach(item => {
                item.addEventListener('click', async function() {
                    const id = this.dataset.id;
                    await fetch('/api/announcements/' + id + '/read', {
                        method: 'POST',
                        headers: {
                            'Authorization': 'Bearer ' + getToken(),
                            'Content-Type': 'application/json'
                        }
                    });
                    loadAnnouncements();
                    updateUnreadCount();
                });
            });
            
        } catch (e) {
            console.error('Error loading announcements:', e);
        }
    }
    
    // Update unread count badge
    async function updateUnreadCount() {
        try {
            const token = getToken();
            if (!token) return;
            
            const response = await fetch('/api/announcements/unread', {
                headers: { 'Authorization': 'Bearer ' + token }
            });
            const data = await response.json();
            
            const badge = document.getElementById('announcementBadge');
            if (!badge) return;
            
            if (data.unread > 0) {
                badge.textContent = data.unread > 99 ? '99+' : data.unread;
                badge.classList.remove('hidden');
            } else {
                badge.classList.add('hidden');
            }
        } catch (e) {}
    }
    
    // Mark all as read
    window.markAllAnnouncementsRead = async function() {
        try {
            const token = getToken();
            await fetch('/api/announcements/read-all', {
                method: 'POST',
                headers: { 'Authorization': 'Bearer ' + token }
            });
            loadAnnouncements();
            updateUnreadCount();
        } catch (e) {}
    };
    
    // Initialize on page load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', createBellIcon);
    } else {
        createBellIcon();
    }
    
})();