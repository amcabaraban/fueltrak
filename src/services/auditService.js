const pool = require('../config/database');

async function logAudit(uid, action, table, rid, details) {
    try {
        await pool.execute('INSERT INTO audit_logs (user_id, action, table_name, record_id, details) VALUES (?, ?, ?, ?, ?)', [uid, action, table, rid, JSON.stringify(details)]);
    } catch (e) {}
}

module.exports = { logAudit };