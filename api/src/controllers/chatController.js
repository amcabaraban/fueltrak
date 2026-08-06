const pool = require('../config/database');
const { authenticate } = require('../middleware/auth');

function setupChatRoutes(app) {
    // Get chat list with unread counts per sender
    app.get('/api/chat-list', authenticate, async (req, res) => {
        try {
            let users;
            if (req.user.role === 'client') {
                [users] = await pool.execute(
                    "SELECT id, email FROM users WHERE role IN ('dispatcher','management') LIMIT 5"
                );
            } else {
                [users] = await pool.execute(
                    "SELECT id, email FROM users WHERE role='client' ORDER BY company_name LIMIT 50"
                );
                if (!users.length) [users] = await pool.execute(
                    "SELECT id, email FROM users WHERE role='client' LIMIT 50"
                );
            }
            
            // Get unread counts per sender for current user
            const [unreadCounts] = await pool.execute(
                "SELECT sender_id, COUNT(*) as unread FROM chat_messages WHERE receiver_id=? AND is_read=0 GROUP BY sender_id",
                [req.user.id]
            );
            
            // Map unread counts to users
            const data = users.map(user => ({
                ...user,
                unread: parseInt((unreadCounts.find(u => u.sender_id === user.id) || {}).unread || 0)
            }));
            
            res.json({ status: 'success', data });
        } catch (e) {
            res.status(500).json({ error: e.message });
        }
    });

    // Get total unread count (for main badge)
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

    // Get messages with a specific user
    app.get('/api/chat/:userId', authenticate, async (req, res) => {
        try {
            // Mark messages as read when opening chat
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

    // Send message
    app.post('/api/chat', authenticate, async (req, res) => {
        try {
            await pool.execute(
                'INSERT INTO chat_messages (sender_id, receiver_id, message, is_read) VALUES (?, ?, ?, 0)',
                [req.user.id, req.body.receiver_id, req.body.message]
            );
            res.json({ status: 'success', message: 'Sent' });
        } catch (e) {
            res.status(400).json({ error: e.message });
        }
    });
}

module.exports = { setupChatRoutes };