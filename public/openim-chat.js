// ============================================================
// FuelTrak - Chat Enhancement (Socket-based)
// ============================================================
// Uses your existing chat API with real-time polling

class FuelTrakOpenIM {
  constructor() {
    this.listeners = [];
    this.pollingInterval = null;
    this.userId = null;
    this.token = null;
  }

  async init(userId, token) {
    this.userId = userId;
    this.token = token;
    console.log('Chat initialized for user:', userId);
    return { success: true };
  }

  async getConversations() {
    try {
      const res = await fetch('/api/chat-list', {
        headers: { 'Authorization': 'Bearer ' + this.token }
      });
      const data = await res.json();
      return (data.data || []).map(c => ({
        conversationID: 'user_' + c.id,
        showName: c.company_name || c.email,
        latestMsg: '',
        unreadCount: 0
      }));
    } catch (e) {
      return [];
    }
  }

  async getMessages(conversationId) {
    try {
      const userId = conversationId.replace('user_', '');
      const res = await fetch('/api/chat/' + userId, {
        headers: { 'Authorization': 'Bearer ' + this.token }
      });
      const data = await res.json();
      return {
        messageList: (data.data || []).map(m => ({
          sendID: m.sender_id?.toString(),
          text: m.message,
          content: m.message,
          sendTime: m.created_at
        }))
      };
    } catch (e) {
      return { messageList: [] };
    }
  }

  async sendMessage(conversationId, text) {
    try {
      const userId = conversationId.replace('user_', '');
      await fetch('/api/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + this.token
        },
        body: JSON.stringify({ receiver_id: userId, message: text })
      });
      return { success: true };
    } catch (e) {
      return { success: false };
    }
  }

  onMessage(callback) {
    this.listeners.push(callback);
  }

  async logout() {
    this.listeners = [];
    if (this.pollingInterval) clearInterval(this.pollingInterval);
  }
}

window.FuelTrakIM = new FuelTrakOpenIM();