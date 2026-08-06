const pool = require('../config/database');
const { authenticate, authorize } = require('../middleware/auth');
const { hashPassword } = require('../services/utilities');
const { softDelete, restoreFromBin } = require('../services/recycleBin');
const { logAudit } = require('../services/auditService');
const { RECYCLE_BIN_DAYS } = require('../constants');

function setupAdminRoutes(app) {
    app.get('/api/demo-credentials', async (req, res) => {
        try { const [users]=await pool.execute("SELECT email, role FROM users WHERE email IN (?, ?, ?)",['admin@fueltrak.com','dispatcher@fueltrak.com','client1@hauler.com']); const credentials={}; users.forEach(u=>{if(u.role==='management') credentials.admin=u.email;if(u.role==='dispatcher') credentials.dispatcher=u.email;if(u.role==='client') credentials.client=u.email;}); res.json({status:'success',data:credentials}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.post('/api/sync-all-documents', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const {batch=0}=req.body; const [t]=await pool.execute('SELECT id FROM trucks ORDER BY id LIMIT 30 OFFSET ?',[String(batch*30)]); if(!t.length) return res.json({status:'success',message:'Done!',done:true}); let c=0; for(const x of t){for(const ty of ['lto_registration','fire_permit','dost_calibration']){try{await pool.execute("INSERT IGNORE INTO truck_documents (truck_id,document_type,expiry_date,status,createdAt) VALUES (?,?,?,'valid',NOW())",[x.id,ty,'2030-12-31']);c++;}catch(e){}}} res.json({status:'success',message:'Batch '+(batch+1)+': '+c+' docs',count:c,done:false,nextBatch:batch+1}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.get('/api/admin/optimize-database', authenticate, authorize('dispatcher','management'), async (req, res) => {
        const idx=['CREATE INDEX idx_atl_status_client ON authority_to_load(status,client_id)','CREATE INDEX idx_atl_client_created ON authority_to_load(client_id,createdAt)','CREATE INDEX idx_atl_truck_status ON authority_to_load(truck_id,status)','CREATE INDEX idx_atl_so_status ON authority_to_load(so_number,status)','CREATE INDEX idx_trucks_plate_active ON trucks(plate_no,is_active)','CREATE INDEX idx_docs_truck_type_expiry ON truck_documents(truck_id,document_type,expiry_date)','CREATE INDEX idx_so_client_status ON sales_orders(client_id,status)','CREATE INDEX idx_soc_so_client ON sales_order_clients(sales_order_id,client_id)','CREATE INDEX idx_chat_receiver_created ON chat_messages(receiver_id,created_at)','CREATE INDEX idx_users_role_active ON users(role,is_active)']; let cr=0,sk=0,fa=0; for(const s of idx){try{await pool.execute(s);cr++;}catch(e){if(e.code==='ER_DUP_KEYNAME')sk++;else fa++;}} res.json({status:'success',message:'Created:'+cr+',Skipped:'+sk+',Failed:'+fa});
    });

    app.get('/api/admin/create-so-table', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { await pool.execute("CREATE TABLE IF NOT EXISTS sales_orders (id INT AUTO_INCREMENT PRIMARY KEY,so_number VARCHAR(50) NOT NULL,client_id INT NOT NULL,company_name VARCHAR(100),total_volume DECIMAL(12,2) DEFAULT 0,used_volume DECIMAL(12,2) DEFAULT 0,is_multi_client TINYINT(1) DEFAULT 0,status ENUM('active','completed','cancelled') DEFAULT 'active',notes TEXT,created_by INT,createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,UNIQUE KEY unique_so_client (so_number,client_id),INDEX idx_so_number (so_number),INDEX idx_client_id (client_id),INDEX idx_status (status),FOREIGN KEY (client_id) REFERENCES users(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"); await pool.execute("CREATE TABLE IF NOT EXISTS sales_order_clients (id INT AUTO_INCREMENT PRIMARY KEY,sales_order_id INT NOT NULL,client_id INT NOT NULL,company_name VARCHAR(100),allocated_volume DECIMAL(12,2) DEFAULT 0,used_volume DECIMAL(12,2) DEFAULT 0,createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY (sales_order_id) REFERENCES sales_orders(id) ON DELETE CASCADE,FOREIGN KEY (client_id) REFERENCES users(id) ON DELETE CASCADE,UNIQUE KEY unique_so_allocation (sales_order_id,client_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"); try{await pool.execute('CREATE INDEX idx_atl_so_number ON authority_to_load(so_number)');}catch(e){} res.json({status:'success',message:'Tables created'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.get('/api/admin/create-login-attempts-table', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { await pool.execute("CREATE TABLE IF NOT EXISTS login_attempts (id INT AUTO_INCREMENT PRIMARY KEY,email VARCHAR(100) NOT NULL,attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,INDEX idx_email_time (email,attempted_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"); res.json({status:'success',message:'Login attempts table created'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.post('/api/admin/verify-user', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { await pool.execute('UPDATE users SET is_verified=1 WHERE email=?',[req.body.email]); res.json({status:'success',message:'Verified'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.post('/api/admin/cleanup-loading', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { await pool.execute('DELETE FROM authority_to_load'); res.json({status:'success',message:'Cleared'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.post('/api/admin/add-first-login-column', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { await pool.execute('ALTER TABLE authority_to_load ADD COLUMN special_instructions TEXT'); res.json({status:'success'}); } catch(e) { if(e.code==='ER_DUP_FIELDNAME') res.json({status:'success',message:'Exists'}); else res.status(400).json({error:e.message}); }
    });

    app.get('/api/clients', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [c]=await pool.execute("SELECT id,email,mobile,company_name,is_active,is_verified,last_login,createdAt FROM users WHERE role='client' ORDER BY createdAt DESC"); const r=[]; for(const x of c){const [a]=await pool.execute('SELECT COUNT(*) as total FROM authority_to_load WHERE client_id=?',[x.id]);r.push({...x,total_atls:a[0].total});} res.json({status:'success',data:r,total:r.length}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.get('/api/clients/:id', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [c]=await pool.execute("SELECT id,email,mobile,company_name,is_active,is_verified,last_login,createdAt FROM users WHERE id=? AND role='client'",[req.params.id]); if(!c.length) return res.status(404).json({error:'Not found'}); res.json({status:'success',data:c[0]}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.post('/api/clients', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const {email,password,mobile,company_name}=req.body; if(!email||!password||!mobile) return res.status(400).json({error:'All fields required'}); const [ex]=await pool.execute('SELECT id FROM users WHERE email=?',[email]); if(ex.length) return res.status(400).json({error:'Exists'}); await pool.execute('INSERT INTO users (email,password,mobile,company_name,role,is_verified,is_active,first_login,createdAt,updatedAt) VALUES (?,?,?,?,?,1,1,1,NOW(),NOW())',[email,await hashPassword(password),mobile,company_name||null,'client']); res.status(201).json({status:'success',message:'Created'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.put('/api/clients/:id', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const {email,mobile,company_name,password}=req.body; if(email){const [d]=await pool.execute('SELECT id FROM users WHERE email=? AND id!=?',[email,req.params.id]);if(d.length)return res.status(400).json({error:'Email in use'});} let q='UPDATE users SET email=?,mobile=?,company_name=?'; let p=[email,mobile,company_name]; if(password&&password.length>=8){q+=',password=?';p.push(await hashPassword(password));} p.push(req.params.id); await pool.execute(q+' WHERE id=?',p); res.json({status:'success',message:'Updated'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.patch('/api/clients/:id/toggle-status', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [c]=await pool.execute("SELECT is_active FROM users WHERE id=? AND role='client'",[req.params.id]); if(!c.length) return res.status(404).json({error:'Not found'}); const ns=c[0].is_active?0:1; await pool.execute('UPDATE users SET is_active=? WHERE id=?',[ns,req.params.id]); res.json({status:'success',message:'Client '+(ns?'activated':'deactivated')}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.delete('/api/clients/:id', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [clients]=await pool.execute("SELECT * FROM users WHERE id=? AND role='client'",[req.params.id]); if(!clients.length) return res.status(404).json({error:'Client not found'}); await softDelete('users',req.params.id,req.user.id,req.user.email); await pool.execute("DELETE FROM users WHERE id=? AND role='client'",[req.params.id]); await logAudit(req.user.id,'DELETE_CLIENT','users',req.params.id,{email:clients[0].email,soft_delete:true}); res.json({status:'success',message:'Client deleted (moved to recycle bin)'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.get('/api/users', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [u]=await pool.execute('SELECT id,email,role,mobile,company_name,is_active,is_verified,last_login,createdAt FROM users ORDER BY role,email'); res.json({status:'success',data:u}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.post('/api/users', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const {email,password,mobile,company_name,role}=req.body; if(!email||!password||!role) return res.status(400).json({error:'Required'}); const [ex]=await pool.execute('SELECT id FROM users WHERE email=?',[email]); if(ex.length) return res.status(400).json({error:'Exists'}); await pool.execute('INSERT INTO users (email,password,mobile,company_name,role,is_verified,is_active,createdAt,updatedAt) VALUES (?,?,?,?,?,1,1,NOW(),NOW())',[email,await hashPassword(password),mobile||null,company_name||null,role]); res.status(201).json({status:'success',message:'Created'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.put('/api/users/:id', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const {email,mobile,company_name,role,password,is_active}=req.body; let q='UPDATE users SET email=?,mobile=?,company_name=?,role=?,is_active=?'; let p=[email,mobile||null,company_name||null,role,is_active!==undefined?is_active:1]; if(password){q+=',password=?';p.push(await hashPassword(password));} p.push(req.params.id); await pool.execute(q+' WHERE id=?',p); res.json({status:'success',message:'Updated'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.delete('/api/users/:id', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [users]=await pool.execute('SELECT * FROM users WHERE id=?',[req.params.id]); if(!users.length) return res.status(404).json({error:'User not found'}); await softDelete('users',req.params.id,req.user.id,req.user.email); await pool.execute('DELETE FROM users WHERE id=?',[req.params.id]); await logAudit(req.user.id,'DELETE_USER','users',req.params.id,{email:users[0].email,soft_delete:true}); res.json({status:'success',message:'User deleted (moved to recycle bin)'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.get('/api/audit-logs', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [l]=await pool.execute('SELECT al.*,u.email FROM audit_logs al JOIN users u ON al.user_id=u.id ORDER BY al.created_at DESC LIMIT 500'); res.json({status:'success',data:l}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.post('/api/migrate', authenticate, authorize('dispatcher','management'), async (req, res) => {
        const idx=['CREATE INDEX idx_atl_status ON authority_to_load(status)','CREATE INDEX idx_atl_client_id ON authority_to_load(client_id)','CREATE INDEX idx_atl_truck_id ON authority_to_load(truck_id)','CREATE INDEX idx_atl_created ON authority_to_load(createdAt)','CREATE INDEX idx_atl_plate ON authority_to_load(plate_no)','CREATE INDEX idx_trucks_plate ON trucks(plate_no)','CREATE INDEX idx_trucks_active ON trucks(is_active)','CREATE INDEX idx_docs_truck ON truck_documents(truck_id)','CREATE INDEX idx_docs_type ON truck_documents(document_type)','CREATE INDEX idx_docs_expiry ON truck_documents(expiry_date)','CREATE INDEX idx_users_email ON users(email)','CREATE INDEX idx_users_role ON users(role)','CREATE INDEX idx_master_plate ON truck_masterlist(plate_no)','CREATE INDEX idx_audit_user ON audit_logs(user_id)','CREATE INDEX idx_audit_created ON audit_logs(created_at)','CREATE INDEX idx_chat_users ON chat_messages(sender_id,receiver_id)','CREATE INDEX idx_chat_created ON chat_messages(created_at)']; let cr=0,sk=0,fa=0; for(const s of idx){try{await pool.execute(s);cr++;}catch(e){if(e.code==='ER_DUP_KEYNAME')sk++;else fa++;}} res.json({status:'success',message:'Created:'+cr+',Skipped:'+sk+',Failed:'+fa});
    });

    app.post('/api/sync-truck-capacities', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const {batch=0}=req.body; const [t]=await pool.execute('SELECT id,plate_no FROM trucks WHERE total_capacity=0 OR total_capacity IS NULL ORDER BY id LIMIT 50 OFFSET ?',[String(batch*50)]); if(!t.length) return res.json({status:'success',message:'Done!',done:true}); let c=0; for(const x of t){const [m]=await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no=?',[x.plate_no]); if(m.length){const cap=[m[0].cot1,m[0].cot2,m[0].cot3,m[0].cot4,m[0].cot5,m[0].cot6,m[0].cot7,m[0].cot8,m[0].cot9,m[0].cot10].reduce((s,v)=>s+parseFloat(v||0),0);if(cap>0){await pool.execute('UPDATE trucks SET total_capacity=? WHERE id=?',[cap,x.id]);c++;}}} res.json({status:'success',message:'Batch '+(batch+1)+': '+c+' updated',count:c,done:false,nextBatch:batch+1}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.get('/api/admin/recycle-bin', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const {table,search}=req.query; let q='SELECT * FROM recycle_bin WHERE restored=0'; const p=[]; if(table){q+=' AND table_name=?';p.push(table);} if(search){q+=' AND (record_data LIKE ? OR deleted_by_email LIKE ?)';p.push('%'+search+'%','%'+search+'%');} q+=' ORDER BY deleted_at DESC LIMIT 200'; const [items]=await pool.execute(q,p); const result=items.map(item=>({...item,record_data:JSON.parse(item.record_data||'{}'),days_remaining:Math.max(0,Math.ceil((new Date(item.expires_at)-new Date())/86400000))})); res.json({status:'success',data:result,total:result.length}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.post('/api/admin/recycle-bin/:id/restore', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const result=await restoreFromBin(req.params.id,req.user.id); if(result.success) res.json({status:'success',message:'Record restored',newId:result.newId}); else res.status(400).json({error:result.error}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.delete('/api/admin/recycle-bin/:id', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { await pool.execute('DELETE FROM recycle_bin WHERE id=?',[req.params.id]); res.json({status:'success',message:'Permanently deleted'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.post('/api/admin/recycle-bin/empty', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [r]=await pool.execute('DELETE FROM recycle_bin WHERE restored=0'); res.json({status:'success',message:'Emptied '+r.affectedRows+' items'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.get('/api/admin/recycle-bin/stats', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [s]=await pool.execute("SELECT COUNT(*) as total_items,SUM(CASE WHEN restored=0 THEN 1 ELSE 0 END) as active_items,SUM(CASE WHEN restored=1 THEN 1 ELSE 0 END) as restored_items,SUM(CASE WHEN expires_at<NOW() AND restored=0 THEN 1 ELSE 0 END) as expired_items,COUNT(DISTINCT table_name) as unique_tables FROM recycle_bin"); const [bt]=await pool.execute("SELECT table_name,COUNT(*) as count FROM recycle_bin WHERE restored=0 GROUP BY table_name ORDER BY count DESC"); res.json({status:'success',data:{...s[0],by_table:bt,retention_days:RECYCLE_BIN_DAYS}}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.post('/api/admin/backup', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const tables=['authority_to_load','audit_logs','backup_logs','chat_messages','recycle_bin','sales_order_clients','sales_orders','truck_documents','truck_masterlist','trucks','users']; let backup={},totalRecords=0; for(const table of tables){try{const [rows]=await pool.execute('SELECT * FROM '+table);backup[table]=rows;totalRecords+=rows.length;}catch(e){backup[table]=[];}} const timestamp=new Date().toISOString().replace(/[:.]/g,'-'); const filename='fueltrak_backup_'+timestamp+'.json'; const backupJSON=JSON.stringify(backup); const fileSize=Buffer.byteLength(backupJSON,'utf8'); await pool.execute('INSERT INTO backup_logs (backup_type,filename,file_size,tables_backed_up,records_count,status,created_by) VALUES (?,?,?,?,?,?,?)',['manual',filename,fileSize,tables.join(', '),totalRecords,'success',req.user.id]); res.setHeader('Content-Type','application/json');res.setHeader('Content-Disposition','attachment; filename="'+filename+'"');res.send(backupJSON); } catch(e) { await pool.execute('INSERT INTO backup_logs (backup_type,filename,status,error_message,created_by) VALUES (?,?,?,?,?)',['manual','failed_backup.json','failed',e.message,req.user.id]); res.status(500).json({error:e.message}); }
    });

    app.get('/api/admin/backup-logs', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [logs]=await pool.execute('SELECT bl.*,u.email as created_by_email FROM backup_logs bl LEFT JOIN users u ON bl.created_by=u.id ORDER BY bl.created_at DESC LIMIT 50'); res.json({status:'success',data:logs}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.post('/api/admin/restore', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const {backup,mode='merge'}=req.body; if(!backup||typeof backup!=='object') return res.status(400).json({error:'Invalid backup data'}); let restored=0,errors=[]; for(const [table,records] of Object.entries(backup)){if(!Array.isArray(records)||!records.length) continue; try{if(mode==='replace') await pool.execute('DELETE FROM '+table); for(const record of records){try{const columns=Object.keys(record).join(', ');const placeholders=Object.keys(record).map(()=>'?').join(', ');const values=Object.values(record);await pool.execute('INSERT IGNORE INTO '+table+' ('+columns+') VALUES ('+placeholders+')',values);restored++;}catch(e){errors.push(table+': '+e.message);}}}catch(e){errors.push('Table '+table+': '+e.message);}} await logAudit(req.user.id,'RESTORE_BACKUP','system',0,{restored,errors:errors.length}); res.json({status:'success',message:'Restored '+restored+' records',errors:errors.slice(0,10),mode}); } catch(e) { res.status(400).json({error:e.message}); }
    });
}

module.exports = { setupAdminRoutes };