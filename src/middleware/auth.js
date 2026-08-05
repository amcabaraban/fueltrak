const jwt = require('jsonwebtoken');
const pool = require('../config/database');

const tokenBlacklist = new Set();
setInterval(() => { tokenBlacklist.forEach(t => { try { jwt.verify(t, process.env.JWT_SECRET); } catch(e) { tokenBlacklist.delete(t); } }); }, 3600000);

const authenticate = async (req, res, next) => {
    try {
        const t = req.header('Authorization')?.replace('Bearer ', '');
        if (!t) return res.status(401).json({ error: 'Please authenticate' });
        if (tokenBlacklist.has(t)) return res.status(401).json({ error: 'Token revoked' });
        const d = jwt.verify(t, process.env.JWT_SECRET);
        if (d.type === 'refresh') return res.status(401).json({ error: 'Use access token' });
        const [u] = await pool.execute('SELECT id,email,role,mobile,company_name,is_active FROM users WHERE id=?', [d.id]);
        if (!u.length || !u[0].is_active) return res.status(401).json({ error: 'Invalid token' });
        req.user = u[0]; next();
    } catch(e) { res.status(401).json({ error: 'Invalid token' }); }
};

const authorize = (...roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Access denied' });
    next();
};

module.exports = { authenticate, authorize, tokenBlacklist };