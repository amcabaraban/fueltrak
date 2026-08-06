// ============================================
// FuelTrak - Chat Helper Functions
// ============================================

let currentChatUser = null;
let currentChatUserId = null;
let chatPollingInterval = null;

// Get token from localStorage
function getToken() {
    return localStorage.getItem('fueltrak_token');
}

// Get user from localStorage
function getUser() {
    try {
        return JSON.parse(localStorage.getItem('fueltrak_user') || '{}');
    } catch(e) {
        return {};
    }
}

// Open chat widget
function openChat() {
    document.getElementById('chatWidget').classList.remove('hidden');
    document.getElementById('chatButton').classList.add('hidden');
    loadContactList();
    startChatPolling();
}

// Close chat widget
function closeChat() {
    document.getElementById('chatWidget').classList.add('hidden');
    document.getElementById('chatButton').classList.remove('hidden');
    stopChatPolling();
}

// Load contact list with unread badges per sender
async function loadContactList() {
    try {
        const token = getToken();
        if (!token) {
            console.log('No token found');
            return;
        }
        
        const response = await fetch('/api/chat-list', {
            headers: { 'Authorization': 'Bearer ' + token }
        });
        
        if (response.status === 401) {
            localStorage.clear();
            window.location.href = '/';
            return;
        }
        
        const data = await response.json();
        
        if (data.status === 'success') {
            const contactList = document.getElementById('contactList');
            if (!contactList) return;
            
            contactList.innerHTML = '';
            
            if (data.data.length === 0) {
                contactList.innerHTML = '<div class="p-3 text-center text-gray-400 text-sm">No contacts available</div>';
                return;
            }
            
            data.data.forEach(user => {
                const div = document.createElement('div');
                div.className = 'p-3 hover:bg-gray-100 cursor-pointer border-b flex justify-between items-center';
                div.onclick = () => openChatWithUser(user.id, user.email);
                div.innerHTML = `
                    <span><i class="fas fa-user-circle mr-2 text-gray-400"></i>${user.email}</span>
                    ${user.unread > 0 ? `<span class="bg-red-500 text-white text-xs rounded-full px-2 py-0.5 font-bold">${user.unread > 99 ? '99+' : user.unread}</span>` : ''}
                `;
                contactList.appendChild(div);
            });
        }
    } catch (e) {
        console.error('Error loading contacts:', e);
    }
}

// Open chat with specific user
async function openChatWithUser(userId, userEmail) {
    currentChatUserId = userId;
    currentChatUser = userEmail;
    
    const chatTitle = document.getElementById('chatTitle');
    const contactList = document.getElementById('contactList');
    const chatBody = document.getElementById('chatBody');
    const chatInputArea = document.getElementById('chatInputArea');
    
    if (chatTitle) chatTitle.textContent = userEmail;
    if (contactList) contactList.classList.add('hidden');
    if (chatBody) chatBody.classList.remove('hidden');
    if (chatInputArea) chatInputArea.classList.remove('hidden');
    
    await loadMessages();
}

// Load messages
async function loadMessages() {
    if (!currentChatUserId) return;
    
    try {
        const token = getToken();
        const user = getUser();
        const myId = user.id;
        
        const response = await fetch('/api/chat/' + currentChatUserId, {
            headers: { 'Authorization': 'Bearer ' + token }
        });
        const data = await response.json();
        
        if (data.status === 'success') {
            const chatBody = document.getElementById('chatBody');
            if (!chatBody) return;
            
            chatBody.innerHTML = '';
            
            if (data.data.length === 0) {
                chatBody.innerHTML = '<div class="text-center text-gray-400 text-sm py-4">No messages yet. Say hello!</div>';
                return;
            }
            
            data.data.forEach(msg => {
                const isMe = msg.sender_id === myId;
                const div = document.createElement('div');
                div.className = 'flex ' + (isMe ? 'justify-end' : 'justify-start');
                div.innerHTML = `
                    <div class="${isMe ? 'bg-blue-100' : 'bg-gray-100'} rounded-lg px-3 py-2 max-w-[80%]">
                        <p class="text-xs text-gray-500 font-bold">${isMe ? 'You' : msg.sender_email}</p>
                        <p class="text-sm">${msg.message}</p>
                        <p class="text-xs text-gray-400 mt-1">${new Date(msg.created_at).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}</p>
                    </div>
                `;
                chatBody.appendChild(div);
            });
            
            chatBody.scrollTop = chatBody.scrollHeight;
        }
    } catch (e) {
        console.error('Error loading messages:', e);
    }
}

// Send message
async function sendChat() {
    const input = document.getElementById('chatInput');
    if (!input) return;
    
    const message = input.value.trim();
    if (!message || !currentChatUserId) return;
    
    try {
        const token = getToken();
        await fetch('/api/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token
            },
            body: JSON.stringify({
                receiver_id: currentChatUserId,
                message: message
            })
        });
        
        input.value = '';
        await loadMessages();
        await loadContactList(); // Refresh badges
    } catch (e) {
        console.error('Error sending message:', e);
    }
}

// Show contact list (back button)
function showContactList() {
    const contactList = document.getElementById('contactList');
    const chatBody = document.getElementById('chatBody');
    const chatInputArea = document.getElementById('chatInputArea');
    const chatTitle = document.getElementById('chatTitle');
    
    if (contactList) contactList.classList.remove('hidden');
    if (chatBody) chatBody.classList.add('hidden');
    if (chatInputArea) chatInputArea.classList.add('hidden');
    if (chatTitle) chatTitle.textContent = 'Chat';
    
    currentChatUserId = null;
    loadContactList();
}

// Poll for unread messages
function startChatPolling() {
    updateUnreadBadge();
    chatPollingInterval = setInterval(() => {
        updateUnreadBadge();
        if (currentChatUserId) loadContactList(); // Refresh per-sender badges
    }, 10000);
}

function stopChatPolling() {
    if (chatPollingInterval) {
        clearInterval(chatPollingInterval);
        chatPollingInterval = null;
    }
}

async function updateUnreadBadge() {
    try {
        const token = getToken();
        if (!token) return;
        
        const response = await fetch('/api/chat/unread', {
            headers: { 'Authorization': 'Bearer ' + token }
        });
        
        if (response.status === 401) {
            localStorage.clear();
            window.location.href = '/';
            return;
        }
        
        const data = await response.json();
        const badge = document.getElementById('unreadBadge');
        if (!badge) return;
        
        if (data.unread > 0) {
            badge.textContent = data.unread > 99 ? '99+' : data.unread;
            badge.classList.remove('hidden');
        } else {
            badge.classList.add('hidden');
        }
    } catch (e) {}
}

// Handle Enter key
document.addEventListener('DOMContentLoaded', function() {
    const chatInput = document.getElementById('chatInput');
    if (chatInput) {
        chatInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') sendChat();
        });
    }
});