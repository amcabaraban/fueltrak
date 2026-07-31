// ============================================================
// FuelTrak - OpenIM Chat Integration
// ============================================================

const OpenIMConfig = {
  // OpenIM Server Configuration
  apiUrl: 'https://your-openim-server.com/api',     // Your OpenIM API URL
  wsUrl: 'wss://your-openim-server.com/ws',          // Your OpenIM WebSocket URL
  platformID: 5,                                      // 5 = Web
};

class FuelTrakOpenIM {
  constructor() {
    this.openim = null;
    this.currentConversation = null;
    this.messageListeners = [];
  }

  // Initialize OpenIM
  async init(userId, token) {
    try {
      this.openim = new OpenIMSDK({
        apiUrl: OpenIMConfig.apiUrl,
        wsUrl: OpenIMConfig.wsUrl,
        platformID: OpenIMConfig.platformID
      });

      // Login to OpenIM
      const loginResult = await this.openim.login({
        userID: userId.toString(),
        token: token,
      });

      console.log('OpenIM connected:', loginResult);
      
      // Set up message listener
      this.setupListeners();
      
      return { success: true };
    } catch (error) {
      console.error('OpenIM init error:', error);
      return { success: false, error: error.message };
    }
  }

  // Set up real-time listeners
  setupListeners() {
    // Listen for new messages
    this.openim.on('onRecvNewMessages', (data) => {
      console.log('New messages received:', data);
      this.messageListeners.forEach(callback => callback(data));
    });

    // Listen for conversation changes
    this.openim.on('onConversationChanged', (data) => {
      console.log('Conversations updated:', data);
    });

    // Listen for connection status
    this.openim.on('onConnecting', () => {
      console.log('OpenIM connecting...');
    });

    this.openim.on('onConnectSuccess', () => {
      console.log('OpenIM connected');
    });

    this.openim.on('onConnectFailed', (err) => {
      console.error('OpenIM connection failed:', err);
    });
  }

  // Get conversation list
  async getConversations() {
    try {
      const result = await this.openim.getAllConversationList();
      return result.data;
    } catch (error) {
      console.error('Get conversations error:', error);
      return [];
    }
  }

  // Get messages for a conversation
  async getMessages(conversationId, startClientMsgID = '') {
    try {
      const result = await this.openim.getAdvancedHistoryMessageList({
        conversationID: conversationId,
        count: 50,
        startClientMsgID: startClientMsgID,
      });
      return result.data;
    } catch (error) {
      console.error('Get messages error:', error);
      return [];
    }
  }

  // Send a message
  async sendMessage(conversationId, text) {
    try {
      const message = {
        conversationID: conversationId,
        contentType: 101, // Text message
        text: text,
      };
      const result = await this.openim.createTextMessage(message);
      await this.openim.sendMessage({
        message: result.data,
        recvID: conversationId.replace('si_', '').replace('_'+OpenIMConfig.platformID, ''),
        groupID: '',
      });
      return { success: true };
    } catch (error) {
      console.error('Send message error:', error);
      return { success: false, error: error.message };
    }
  }

  // Create a single conversation
  async createConversation(userId) {
    try {
      const result = await this.openim.getOneConversation({
        sessionType: 1, // Single chat
        sourceID: userId.toString(),
      });
      return result.data;
    } catch (error) {
      console.error('Create conversation error:', error);
      return null;
    }
  }

  // Register message listener
  onMessage(callback) {
    this.messageListeners.push(callback);
  }

  // Logout
  async logout() {
    try {
      await this.openim.logout();
    } catch (error) {
      console.error('Logout error:', error);
    }
  }
}

// Export singleton
window.FuelTrakIM = new FuelTrakOpenIM();