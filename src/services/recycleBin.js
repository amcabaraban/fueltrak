const pool = require('../config/database');
const logger = require('./logger');
const { RECYCLE_BIN_DAYS, AUDIT_LOG_RETENTION_DAYS } = require('../constants');

async function softDelete(tableName, recordId, deletedBy, deletedByEmail, daysToKeep = RECYCLE_BIN_DAYS) {
    try { const [records] = await pool.execute('SELECT * FROM '+tableName+' WHERE id = ?',[recordId]); if(!records.length) return false; const recordData = records[0]; delete recordData.password; delete recordData.current_token; delete recordData.openim_token; const expiresAt = new Date(); expiresAt.setDate(expiresAt.getDate()+daysToKeep); await pool.execute('INSERT INTO recycle_bin (table_name, record_id, record_data, deleted_by, deleted_by_email, expires_at) VALUES (?,?,?,?,?,?)',[tableName,recordId,JSON.stringify(recordData),deletedBy,deletedByEmail,expiresAt]); return true; } catch(e) { logger.error('Soft delete failed',{error:e.message}); return false; }
}

async function restoreFromBin(binId, restoredBy) {
    try { const [bins] = await pool.execute('SELECT * FROM recycle_bin WHERE id = ? AND restored = 0',[binId]); if(!bins.length) return {success:false,error:'Not found'}; const bin = bins[0]; const recordData = JSON.parse(bin.record_data); delete recordData.id; const columns = Object.keys(recordData).join(', '); const placeholders = Object.keys(recordData).map(()=>'?').join(', '); const values = Object.values(recordData); const [result] = await pool.execute('INSERT INTO '+bin.table_name+' ('+columns+') VALUES ('+placeholders+')',values); await pool.execute('UPDATE recycle_bin SET restored=1,restored_at=NOW(),restored_by=? WHERE id=?',[restoredBy,binId]); return {success:true,newId:result.insertId}; } catch(e) { return {success:false,error:e.message}; }
}

async function cleanupRecycleBin() { try { const [r] = await pool.execute('DELETE FROM recycle_bin WHERE expires_at < NOW() AND restored = 0'); if(r.affectedRows>0) logger.info('Recycle bin cleaned',{deleted:r.affectedRows}); } catch(e) {} }

async function cleanupAuditLogs() { try { const [r] = await pool.execute('DELETE FROM audit_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY) LIMIT 1000',[AUDIT_LOG_RETENTION_DAYS]); if(r.affectedRows>0) console.log('Cleaned '+r.affectedRows+' old audit logs'); } catch(e) {} }

module.exports = { softDelete, restoreFromBin, cleanupRecycleBin, cleanupAuditLogs };