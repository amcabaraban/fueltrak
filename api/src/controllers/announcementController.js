const pool = require('../config/database');
const { authenticate, authorize } = require('../middleware/auth');

function setupAnnouncementRoutes(app) {
    // Admin: Create announcement
    app.post('/api/announcements', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try {
            const { title, message, priority, expires_at } = req.body;
            if (!title || !message) {
                return res.status(400).json({ error: 'Title and message required' });
            }
            
            const [result] = await pool.execute(
                'INSERT INTO announcements (title, message, priority, created_by, expires_at) VALUES (?, ?, ?, ?, ?)',
                [title, message, priority || 'normal', req.user.id, expires_at || null]
            );
            
            res.status(201).json({ status: 'success', message: 'Announcement created', data: { id: result.insertId } });
        } catch (e) {
            res.status(400).json({ error: e.message });
        }
    });

    // Admin: Get all announcements (for management)
    app.get('/api/announcements/admin', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try {
            const [announcements] = await pool.execute(
                'SELECT a.*, u.email as created_by_email FROM announcements a JOIN users u ON a.created_by=u.id ORDER BY a.created_at DESC LIMIT 50'
            );
            res.json({ status: 'success', data: announcements });
        } catch (e) {
            res.status(500).json({ error: e.message });
        }
    });

    // Admin: Delete announcement
    app.delete('/api/announcements/:id', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try {
            await pool.execute('DELETE FROM announcements WHERE id=?', [req.params.id]);
            res.json({ status: 'success', message: 'Deleted' });
        } catch (e) {
            res.status(400).json({ error: e.message });
        }
    });

    // Admin: Toggle announcement active status
    app.patch('/api/announcements/:id/toggle', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try {
            const [ann] = await pool.execute('SELECT is_active FROM announcements WHERE id=?', [req.params.id]);
            if (!ann.length) return res.status(404).json({ error: 'Not found' });
            const newStatus = ann[0].is_active ? 0 : 1;
            await pool.execute('UPDATE announcements SET is_active=? WHERE id=?', [newStatus, req.params.id]);
            res.json({ status: 'success', is_active: newStatus });
        } catch (e) {
            res.status(400).json({ error: e.message });
        }
    });

    // Client: Get active announcements
    app.get('/api/announcements', authenticate, async (req, res) => {
        try {
            const [announcements] = await pool.execute(
                "SELECT a.*, u.email as created_by_email, CASE WHEN ar.id IS NOT NULL THEN 1 ELSE 0 END as is_read FROM announcements a JOIN users u ON a.created_by=u.id LEFT JOIN announcement_reads ar ON a.id=ar.announcement_id AND ar.user_id=? WHERE a.is_active=1 AND (a.expires_at IS NULL OR a.expires_at > NOW()) ORDER BY a.created_at DESC LIMIT 20",
                [req.user.id]
            );
            
            const [unreadCount] = await pool.execute(
                "SELECT COUNT(*) as unread FROM announcements a LEFT JOIN announcement_reads ar ON a.id=ar.announcement_id AND ar.user_id=? WHERE a.is_active=1 AND (a.expires_at IS NULL OR a.expires_at > NOW()) AND ar.id IS NULL",
                [req.user.id]
            );
            
            res.json({ 
                status: 'success', 
                data: announcements,
                unread: unreadCount[0].unread || 0
            });
        } catch (e) {
            res.status(500).json({ error: e.message });
        }
    });

    // Client: Get unread count only
    app.get('/api/announcements/unread', authenticate, async (req, res) => {
        try {
            const [unreadCount] = await pool.execute(
                "SELECT COUNT(*) as unread FROM announcements a LEFT JOIN announcement_reads ar ON a.id=ar.announcement_id AND ar.user_id=? WHERE a.is_active=1 AND (a.expires_at IS NULL OR a.expires_at > NOW()) AND ar.id IS NULL",
                [req.user.id]
            );
            res.json({ status: 'success', unread: unreadCount[0].unread || 0 });
        } catch (e) {
            res.json({ status: 'success', unread: 0 });
        }
    });

    // Mark announcement as read
    app.post('/api/announcements/:id/read', authenticate, async (req, res) => {
        try {
            await pool.execute(
                'INSERT IGNORE INTO announcement_reads (announcement_id, user_id) VALUES (?, ?)',
                [req.params.id, req.user.id]
            );
            res.json({ status: 'success', message: 'Marked as read' });
        } catch (e) {
            res.status(400).json({ error: e.message });
        }
    });

    // Mark all as read
    app.post('/api/announcements/read-all', authenticate, async (req, res) => {
        try {
            const [announcements] = await pool.execute(
                'SELECT id FROM announcements WHERE is_active=1 AND (expires_at IS NULL OR expires_at > NOW())'
            );
            for (const ann of announcements) {
                await pool.execute(
                    'INSERT IGNORE INTO announcement_reads (announcement_id, user_id) VALUES (?, ?)',
                    [ann.id, req.user.id]
                );
            }
            res.json({ status: 'success', message: 'All marked as read' });
        } catch (e) {
            res.status(400).json({ error: e.message });
        }
    });
}

module.exports = { setupAnnouncementRoutes };