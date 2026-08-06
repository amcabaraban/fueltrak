const pool = require('../config/database');
const { authenticate, authorize } = require('../middleware/auth');
const { serverCache } = require('../services/cacheService');
const { softDelete } = require('../services/recycleBin');

function setupTruckRoutes(app) {
    app.get('/api/truck-masterlist', authenticate, async (req, res) => {
        try { const ck='truck_masterlist_plates',c=serverCache.get(ck); if(c) return res.json(c); const [r]=await pool.execute('SELECT plate_no FROM truck_masterlist ORDER BY plate_no ASC'); const d={status:'success',data:r}; serverCache.set(ck,d,300); res.json(d); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.get('/api/truck-masterlist/:plateNo', authenticate, async (req, res) => {
        try { const [r]=await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no=?',[req.params.plateNo.toUpperCase()]); res.json(r.length?{status:'success',data:r[0]}:{status:'error',message:'Not found'}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.get('/api/truck-masterlist-all', authenticate, async (req, res) => {
        try {
            if (req.user.role === 'client') {
                // Clients only see trucks they've used
                const [r] = await pool.execute(
                    'SELECT DISTINCT tm.* FROM truck_masterlist tm INNER JOIN authority_to_load atl ON tm.plate_no = atl.plate_no WHERE atl.client_id=? ORDER BY tm.plate_no ASC',
                    [req.user.id]
                );
                return res.json({ status: 'success', data: r });
            }
            // Dispatchers/management see all
            const [r] = await pool.execute('SELECT * FROM truck_masterlist ORDER BY plate_no ASC');
            res.json({ status: 'success', data: r });
        } catch (e) {
            res.status(500).json({ error: e.message });
        }
    });

    app.put('/api/update-truck-masterlist/:id', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const allowed=['truck_make','driver_name','hauler_name','tps_count','plate_no','cot1','cot2','cot3','cot4','cot5','cot6','cot7','cot8','cot9','cot10','total_capacity']; const u=[],p=[]; for(const k in req.body){if(allowed.includes(k)){u.push(k+'=?');p.push(req.body[k]);}} if(!u.length) return res.status(400).json({error:'No valid fields'}); p.push(req.params.id); await pool.execute('UPDATE truck_masterlist SET '+u.join(',')+' WHERE id=?',p); res.json({status:'success',message:'Updated'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.post('/api/truck-masterlist-add', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const {plate_no,truck_make,driver_name,hauler_name,tps_count,cot1,cot2,cot3,cot4,cot5,cot6,cot7,cot8,cot9,cot10,total_capacity}=req.body; await pool.execute('INSERT INTO truck_masterlist (plate_no,truck_make,driver_name,hauler_name,tps_count,cot1,cot2,cot3,cot4,cot5,cot6,cot7,cot8,cot9,cot10,total_capacity) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',[plate_no.toUpperCase(),truck_make,driver_name,hauler_name,tps_count,cot1,cot2,cot3,cot4,cot5,cot6,cot7,cot8,cot9,cot10,total_capacity]); res.json({status:'success',message:'Truck added'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.post('/api/truck-masterlist-clear', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { await pool.execute('DELETE FROM truck_masterlist');await pool.execute('DELETE FROM truck_documents');await pool.execute('DELETE FROM trucks'); res.json({status:'success',message:'Cleared'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.post('/api/truck-masterlist-bulk', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const {trucks}=req.body; let c=0; for(const t of trucks){await pool.execute('INSERT INTO truck_masterlist (truck_make,plate_no,driver_name,hauler_name,cot1,cot2,cot3,cot4,cot5,cot6,cot7,cot8,cot9,cot10,total_capacity,tps_count) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',[t.truck_make||'',t.plate_no||'',t.driver_name||'',t.hauler_name||'',t.cot1||'0',t.cot2||'0',t.cot3||'0',t.cot4||'0',t.cot5||'0',t.cot6||'0',t.cot7||'0',t.cot8||'0',t.cot9||'0',t.cot10||'0',t.total_capacity||'0',t.tps_count||0]);c++;} res.json({status:'success',message:c+' uploaded'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.get('/api/trucks/all', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [t]=await pool.execute('SELECT * FROM trucks ORDER BY plate_no ASC'); const r=[]; for(const x of t){const [d]=await pool.execute('SELECT * FROM truck_documents WHERE truck_id=?',[x.id]);r.push({...x,documents:d});} res.json({status:'success',data:r}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.delete('/api/trucks/delete/:id', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [truck]=await pool.execute('SELECT * FROM trucks WHERE id=?',[req.params.id]); if(!truck.length) return res.status(404).json({error:'Truck not found'}); await softDelete('trucks', req.params.id, req.user.id, req.user.email); await pool.execute('DELETE FROM truck_documents WHERE truck_id=?',[req.params.id]); await pool.execute('DELETE FROM trucks WHERE id=?',[req.params.id]); await pool.execute('DELETE FROM truck_masterlist WHERE plate_no=?',[truck[0].plate_no]); res.json({status:'success',message:'Truck deleted (moved to recycle bin)'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.get('/api/truck-documents/:truckId', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [d]=await pool.execute('SELECT * FROM truck_documents WHERE truck_id=?',[req.params.truckId]); res.json({status:'success',data:d}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.post('/api/truck-documents/:truckId', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const {document_type,document_number,issue_date,expiry_date}=req.body; const [ex]=await pool.execute('SELECT id FROM truck_documents WHERE truck_id=? AND document_type=?',[req.params.truckId,document_type]); if(ex.length){await pool.execute('UPDATE truck_documents SET document_number=?,issue_date=?,expiry_date=?,status=? WHERE id=?',[document_number||'',issue_date||new Date().toISOString().split('T')[0],expiry_date,new Date(expiry_date)>=new Date()?'valid':'expired',ex[0].id]);}else{await pool.execute('INSERT INTO truck_documents (truck_id,document_type,document_number,issue_date,expiry_date,status,createdAt) VALUES (?,?,?,?,?,?,NOW())',[req.params.truckId,document_type,document_number||'',issue_date||new Date().toISOString().split('T')[0],expiry_date,'valid']);} res.json({status:'success',message:'Document saved'}); } catch(e) { res.status(400).json({error:e.message}); }
    });

    app.get('/api/docs-report/summary', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [s]=await pool.execute("SELECT COUNT(DISTINCT t.id) as totalTrucks,COUNT(DISTINCT CASE WHEN td.expiry_date>=NOW() THEN t.id END) as validDocs,COUNT(DISTINCT CASE WHEN td.expiry_date<NOW() THEN t.id END) as expiredDocs,COUNT(DISTINCT CASE WHEN td.id IS NULL THEN t.id END) as missingDocs FROM trucks t LEFT JOIN truck_documents td ON t.id=td.truck_id"); const [r]=await pool.execute("SELECT t.plate_no,t.make,t.driver_name,t.hauler_name,MAX(CASE WHEN td.document_type='lto_registration' THEN td.expiry_date END) as lto_expiry,MAX(CASE WHEN td.document_type='fire_permit' THEN td.expiry_date END) as fire_expiry,MAX(CASE WHEN td.document_type='dost_calibration' THEN td.expiry_date END) as dost_expiry FROM trucks t LEFT JOIN truck_documents td ON t.id=td.truck_id GROUP BY t.id ORDER BY t.plate_no"); res.json({status:'success',data:{stats:s[0],records:r}}); } catch(e) { res.status(500).json({error:e.message}); }
    });
}

module.exports = { setupTruckRoutes };