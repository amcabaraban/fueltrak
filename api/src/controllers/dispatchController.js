const pool = require('../config/database');
const { authenticate, authorize } = require('../middleware/auth');
const { serverCache, clearCache } = require('../services/cacheService');
const { ALLOWED_UPDATE_FIELDS } = require('../constants');

function setupDispatchRoutes(app) {
    app.get('/api/dispatch/dashboard', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [[{pending}],[{dispatched}],[{completed}],[{trucks}]]=await Promise.all([pool.execute("SELECT COUNT(*) as pending FROM authority_to_load WHERE status='pending'"),pool.execute("SELECT COUNT(*) as dispatched FROM authority_to_load WHERE status='dispatched'"),pool.execute("SELECT COUNT(*) as completed FROM authority_to_load WHERE status='completed'"),pool.execute('SELECT COUNT(*) as trucks FROM trucks WHERE is_active=1')]); res.json({status:'success',data:{loadedToday:dispatched,pendingCount:pending,completedCount:completed,totalTrucks:trucks}}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.get('/api/dispatch/enhanced-stats', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const ck='dispatch_enhanced_stats',c=serverCache.get(ck); if(c) return res.json(c); const [s]=await pool.execute("SELECT SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as pending,SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) as approved,SUM(CASE WHEN status='dispatched' THEN 1 ELSE 0 END) as loading,SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed,SUM(CASE WHEN status IN ('dispatched','completed') AND DATE(dispatch_date)=CURDATE() THEN 1 ELSE 0 END) as loadedToday,COALESCE(SUM(CASE WHEN status IN ('dispatched','completed') THEN volume ELSE 0 END),0) as totalVolume,COALESCE(SUM(CASE WHEN status IN ('dispatched','completed') AND DATE(dispatch_date)=CURDATE() THEN volume ELSE 0 END),0) as todayVolume FROM authority_to_load"); const r={status:'success',data:{pending:s[0].pending,approved:s[0].approved,loading:s[0].loading,completed:s[0].completed,loadedToday:s[0].loadedToday,totalVolume:s[0].totalVolume,todayVolume:s[0].todayVolume,totalBackload:0,todayBackload:0}}; serverCache.set(ck,r,30); res.json(r); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.get('/api/dispatch/truck-stats', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const ck='dispatch_truck_stats',c=serverCache.get(ck); if(c) return res.json(c); const [s]=await pool.execute("SELECT COUNT(*) as total,SUM(is_active) as active,SUM(CASE WHEN is_active=0 THEN 1 ELSE 0 END) as inactive,COALESCE(SUM(total_capacity),0) as totalCapacity,(SELECT COUNT(DISTINCT t.id) FROM trucks t INNER JOIN truck_documents td1 ON t.id=td1.truck_id AND td1.document_type='lto_registration' AND td1.expiry_date>=NOW() INNER JOIN truck_documents td2 ON t.id=td2.truck_id AND td2.document_type='fire_permit' AND td2.expiry_date>=NOW() INNER JOIN truck_documents td3 ON t.id=td3.truck_id AND td3.document_type='dost_calibration' AND td3.expiry_date>=NOW()) as withValidDocs,(SELECT COUNT(DISTINCT t.id) FROM trucks t INNER JOIN truck_documents td ON t.id=td.truck_id AND td.expiry_date<NOW()) as withExpiredDocs FROM trucks"); const r={status:'success',data:{total:s[0].total,active:s[0].active,inactive:s[0].inactive,withExpiredDocs:s[0].withExpiredDocs,withValidDocs:s[0].withValidDocs,expiringSoon:0,totalCapacity:s[0].totalCapacity,documentBreakdown:{lto:{},fire:{},dost:{}},trucksNeedingAttention:[]}}; serverCache.set(ck,r,60); res.json(r); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.get('/api/dispatch/pending', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [a]=await pool.execute("SELECT * FROM authority_to_load WHERE status IN ('pending','verified') ORDER BY createdAt DESC"); const r=[]; for(const x of a){const [t]=await pool.execute('SELECT * FROM trucks WHERE id=?',[x.truck_id]);const [c]=await pool.execute('SELECT id,email,company_name FROM users WHERE id=?',[x.client_id]);r.push({...x,truck:t[0]||null,client:c[0]||null});} res.json({status:'success',data:r}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.post('/api/dispatch/verify/:id', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const {action,remarks}=req.body; const s=action==='approve'?'approved':action==='reject'?'rejected':null; if(!s) return res.status(400).json({error:'Invalid action'}); await pool.execute('UPDATE authority_to_load SET status=?,verified_by=?,remarks=? WHERE id=?',[s,req.user.id,remarks||null,req.params.id]); serverCache.del('dispatch_enhanced_stats');serverCache.del('dispatch_truck_stats'); const [u]=await pool.execute('SELECT * FROM authority_to_load WHERE id=?',[req.params.id]); res.json({status:'success',data:u[0]}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.post('/api/dispatch/start-loading/:id', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { await pool.execute("UPDATE authority_to_load SET status='dispatched',dispatch_date=NOW() WHERE id=?",[req.params.id]); serverCache.del('dispatch_enhanced_stats'); const [u]=await pool.execute('SELECT * FROM authority_to_load WHERE id=?',[req.params.id]); res.json({status:'success',message:'Loading started',data:u[0]}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.post('/api/dispatch/complete-loading/:id', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const {actual_volume,remarks,printed_wc}=req.body; await pool.execute("UPDATE authority_to_load SET status='completed',completed_date=NOW(),completed_by=?,actual_volume=?,remarks=?,printed_wc=? WHERE id=?",[req.user.id,actual_volume||null,remarks||'Loading completed',printed_wc||null,req.params.id]); serverCache.del('dispatch_enhanced_stats');serverCache.del('dispatch_truck_stats'); const [u]=await pool.execute('SELECT * FROM authority_to_load WHERE id=?',[req.params.id]); res.json({status:'success',data:u[0]}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.put('/api/dispatch/update-wc/:id', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { await pool.execute('UPDATE authority_to_load SET printed_wc=? WHERE id=?',[req.body.printed_wc||null,req.params.id]); res.json({status:'success',message:'WC updated'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.put('/api/dispatch/update-si/:id', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { await pool.execute('UPDATE authority_to_load SET has_si=? WHERE id=?',[req.body.has_si,req.params.id]); res.json({status:'success'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.put('/api/dispatch/update-tps/:id', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const u=[],p=[]; for(const[k,v] of Object.entries(req.body)){if(ALLOWED_UPDATE_FIELDS.includes(k)){u.push(k+'=?');p.push(v);}} if(u.length){p.push(req.params.id);await pool.execute('UPDATE authority_to_load SET '+u.join(',')+' WHERE id=?',p);} res.json({status:'success'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.put('/api/dispatch/update-so/:id', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { await pool.execute('UPDATE authority_to_load SET so_number=? WHERE id=?',[req.body.so_number,req.params.id]); res.json({status:'success'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.get('/api/dispatch/approved-for-loading', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [a]=await pool.execute("SELECT * FROM authority_to_load WHERE status='approved' ORDER BY createdAt DESC"); const r=[]; for(const x of a){const [t]=await pool.execute('SELECT * FROM trucks WHERE id=?',[x.truck_id]);const [c]=await pool.execute('SELECT id,email,company_name FROM users WHERE id=?',[x.client_id]);r.push({...x,truck:t[0]||null,client:c[0]||null});} res.json({status:'success',data:r}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.get('/api/dispatch/ongoing-loading', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [a]=await pool.execute("SELECT * FROM authority_to_load WHERE status='dispatched' ORDER BY dispatch_date DESC"); const r=[]; for(const x of a){const [t]=await pool.execute('SELECT * FROM trucks WHERE id=?',[x.truck_id]);const [c]=await pool.execute('SELECT id,email,company_name FROM users WHERE id=?',[x.client_id]);r.push({...x,truck:t[0]||null,client:c[0]||null});} res.json({status:'success',data:r}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.post('/api/dispatch/cancel-loading/:id', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { await pool.execute("UPDATE authority_to_load SET status='pending',dispatch_date=NULL,remarks=? WHERE id=?",['Loading cancelled: '+(req.body.reason||'No reason'),req.params.id]); res.json({status:'success',message:'Cancelled'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.post('/api/dispatch/handle-cancellation/:id', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const s=req.body.action==='approve_cancel'?'cancelled':'approved'; await pool.execute('UPDATE authority_to_load SET status=? WHERE id=?',[s,req.params.id]); res.json({status:'success',message:'Done'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.post('/api/sync-masterlist', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [m]=await pool.execute('SELECT tm.* FROM truck_masterlist tm WHERE tm.plate_no NOT IN (SELECT plate_no FROM trucks)'); let c=0,errs=[]; for(const x of m){try{await pool.execute('INSERT INTO trucks (plate_no,make,driver_name,hauler_name,total_capacity,is_active,createdAt,updatedAt) VALUES (?,?,?,?,?,1,NOW(),NOW())',[(x.plate_no||'').substring(0,20).toUpperCase(),(x.truck_make||'Unknown').substring(0,50),(x.driver_name||'').replace(/"/g,'').substring(0,100),(x.hauler_name||'').substring(0,100),parseFloat(x.total_capacity)||0]);c++;}catch(e){errs.push(x.plate_no+': '+e.message);}} res.json({status:'success',message:'Synced '+c+' trucks',count:c,errors:errs.slice(0,5)}); } catch(e) { res.status(400).json({error:e.message}); }
    });
}

module.exports = { setupDispatchRoutes };