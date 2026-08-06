const pool = require('../config/database');
const { authenticate } = require('../middleware/auth');

function setupChatRoutes(app) {
    app.get('/api/chat-list', authenticate, async (req, res) => {
        try { let u; if(req.user.role==='client'){[u]=await pool.execute("SELECT id,email FROM users WHERE role IN ('dispatcher','management') LIMIT 5");}else{[u]=await pool.execute("SELECT id,email FROM users WHERE role='client' ORDER BY company_name LIMIT 50");if(!u.length)[u]=await pool.execute("SELECT id,email FROM users WHERE role='client' LIMIT 50");} res.json({status:'success',data:u}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.get('/api/chat/unread', authenticate, async (req, res) => {
        try { const [r]=await pool.execute("SELECT COUNT(*) as unread FROM chat_messages WHERE receiver_id=? AND sender_id!=? AND created_at>DATE_SUB(NOW(),INTERVAL 24 HOUR)",[req.user.id,req.user.id]); res.json({status:'success',unread:r[0].unread||0}); } catch(e) { res.json({status:'success',unread:0}); }
    });

    app.get('/api/chat/:clientId', authenticate, async (req, res) => {
        try { const [m]=await pool.execute('SELECT cm.*,u.email as sender_email FROM chat_messages cm JOIN users u ON cm.sender_id=u.id WHERE (cm.sender_id=? AND cm.receiver_id=?) OR (cm.sender_id=? AND cm.receiver_id=?) ORDER BY cm.created_at ASC LIMIT 50',[req.user.id,req.params.clientId,req.params.clientId,req.user.id]); res.json({status:'success',data:m}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.post('/api/chat', authenticate, async (req, res) => {
        try { await pool.execute('INSERT INTO chat_messages (sender_id,receiver_id,message) VALUES (?,?,?)',[req.user.id,req.body.receiver_id,req.body.message]); res.json({status:'success',message:'Sent'}); } catch(e) { res.status(400).json({error:e.message}); }
    });
}

module.exports = { setupChatRoutes };