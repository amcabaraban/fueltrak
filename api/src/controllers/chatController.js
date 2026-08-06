const pool = require('../config/database');
const { authenticate } = require('../middleware/auth');

function setupChatRoutes(app) {
    // Get chat list - clients only see dispatchers/management
    app.get('/api/chat-list', authenticate, async (req, res) => {
        try {
            let users;
            if (req.user.role === 'client') {
                // Clients can ONLY see dispatchers and management
                [users] = await pool.execute(
                    "SELECT id, email FROM users WHERE role IN ('dispatcher','management') AND is_active=1 ORDER BY email LIMIT 10"
                );
            } else {
                // Dispatchers/management can see all clients
                [users] = await pool.execute(
                    "SELECT id, email, company_name FROM users WHERE role='client' AND is_active=1 ORDER BY company_name LIMIT 50"
                );
                if (!users.length) [users] = await pool.execute(
                    "SELECT id, email, company_name FROM users WHERE role='client' AND is_active=1 LIMIT 50"
                );
            }
            
            // Get unread counts per sender
            const [unreadCounts] = await pool.execute(
                "SELECT sender_id, COUNT(*) as unread FROM chat_messages WHERE receiver_id=? AND is_read=0 GROUP BY sender_id",
                [req.user.id]
            );
            
            const data = users.map(user => ({
                ...user,
                unread: parseInt((unreadCounts.find(u => u.sender_id === user.id) || {}).unread || 0)
            }));
            
            res.json({ status: 'success', data });
        } catch (e) {
            res.status(500).json({ error: e.message });
        }
    });

    // Get total unread count
    app.get('/api/chat/unread', authenticate, async (req, res) => {
        try {
            const [r] = await pool.execute(
                "SELECT COUNT(*) as unread FROM chat_messages WHERE receiver_id=? AND is_read=0",
                [req.user.id]
            );
            res.json({ status: 'success', unread: r[0].unread || 0 });
        } catch (e) {
            res.json({ status: 'success', unread: 0 });
        }
    });

    // Get messages with specific user - WITH ROLE VALIDATION
    app.get('/api/chat/:userId', authenticate, async (req, res) => {
        try {
            // SECURITY: Verify chat partner
            const [partner] = await pool.execute(
                'SELECT id, role FROM users WHERE id=? AND is_active=1',
                [req.params.userId]
            );
            
            if (!partner.length) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            // BLOCK: Client trying to chat with another client
            if (req.user.role === 'client' && partner[0].role === 'client') {
                return res.status(403).json({ error: 'Clients cannot chat with other clients' });
            }
            
            // BLOCK: Dispatcher trying to chat with another dispatcher/management
            if ((req.user.role === 'dispatcher' || req.user.role === 'management') && 
                (partner[0].role === 'dispatcher' || partner[0].role === 'management')) {
                return res.status(403).json({ error: 'Staff can only chat with clients' });
            }
            
            // Mark messages as read
            await pool.execute(
                "UPDATE chat_messages SET is_read=1 WHERE sender_id=? AND receiver_id=? AND is_read=0",
                [req.params.userId, req.user.id]
            );
            
            const [m] = await pool.execute(
                'SELECT cm.*, u.email as sender_email FROM chat_messages cm JOIN users u ON cm.sender_id=u.id WHERE (cm.sender_id=? AND cm.receiver_id=?) OR (cm.sender_id=? AND cm.receiver_id=?) ORDER BY cm.created_at ASC LIMIT 100',
                [req.user.id, req.params.userId, req.params.userId, req.user.id]
            );
            res.json({ status: 'success', data: m });
        } catch (e) {
            res.status(500).json({ error: e.message });
        }
    });

    // Send message - WITH ROLE VALIDATION
    app.post('/api/chat', authenticate, async (req, res) => {
        try {
            const { receiver_id, message } = req.body;
            
            if (!receiver_id || !message) {
                return res.status(400).json({ error: 'Receiver and message required' });
            }
            
            // SECURITY: Verify receiver exists and is valid
            const [receiver] = await pool.execute(
                'SELECT id, role FROM users WHERE id=? AND is_active=1',
                [receiver_id]
            );
            
            if (!receiver.length) {
                return res.status(404).json({ error: 'Receiver not found' });
            }
            
            // BLOCK: Client sending to another client
            if (req.user.role === 'client' && receiver[0].role === 'client') {
                return res.status(403).json({ error: 'Cannot send messages to other clients' });
            }
            
            // BLOCK: Staff sending to other staff
            if ((req.user.role === 'dispatcher' || req.user.role === 'management') && 
                (receiver[0].role === 'dispatcher' || receiver[0].role === 'management')) {
                return res.status(403).json({ error: 'Staff can only message clients' });
            }
            
            await pool.execute(
                'INSERT INTO chat_messages (sender_id, receiver_id, message, is_read) VALUES (?, ?, ?, 0)',
                [req.user.id, receiver_id, message]
            );
            res.json({ status: 'success', message: 'Sent' });
        } catch (e) {
            res.status(400).json({ error: e.message });
        }
    });
}

module.exports = { setupChatRoutes };