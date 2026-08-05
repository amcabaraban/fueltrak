const pool = require('../config/database');
const { authenticate, authorize } = require('../middleware/auth');

function setupReportRoutes(app) {
    app.get('/api/reports/filters', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const [cl]=await pool.execute("SELECT id,email,company_name FROM users WHERE role='client'"); const [tr]=await pool.execute('SELECT id,plate_no,make FROM trucks'); res.json({status:'success',data:{clients:cl.map(c=>({id:c.id,label:(c.company_name||c.email)+' ('+c.email+')'})),trucks:tr.map(t=>({id:t.id,label:t.plate_no+' - '+t.make}))}}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.get('/api/reports/summary', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const {startDate,endDate}=req.query; let q="SELECT * FROM authority_to_load WHERE status IN ('completed','cancelled','dispatched','rejected')"; const p=[]; if(startDate){q+=' AND (DATE(completed_date)>=? OR DATE(createdAt)>=? OR DATE(scheduled_date)>=?)';p.push(startDate,startDate,startDate);}if(endDate){q+=' AND (DATE(completed_date)<=? OR DATE(createdAt)<=? OR DATE(scheduled_date)<=?)';p.push(endDate,endDate,endDate);}q+=' ORDER BY createdAt DESC'; const [a]=await pool.execute(q,p); const r=[]; let tv=0,ta=0,cc=0,ca=0,dc=0; for(const x of a){const [t]=await pool.execute('SELECT plate_no,make,total_capacity FROM trucks WHERE id=?',[x.truck_id]);const [cl]=await pool.execute('SELECT email,company_name FROM users WHERE id=?',[x.client_id]);const v=parseFloat(x.volume)||0,av=parseFloat(x.actual_volume)||v;tv+=v;ta+=av;if(x.status==='completed')cc++;if(x.status==='cancelled')ca++;if(x.status==='dispatched')dc++;r.push({...x,truck:t[0]||null,client:cl[0]||null});} res.json({status:'success',data:{records:r,summary:{total_records:r.length,completed:cc,cancelled:ca,dispatched:dc,total_volume:tv,total_actual_volume:ta}}}); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.get('/api/reports/export', authenticate, authorize('dispatcher','management'), async (req, res) => {
        try { const {startDate,endDate}=req.query; let q="SELECT * FROM authority_to_load WHERE status IN ('completed','cancelled','dispatched','rejected')"; const p=[]; if(startDate){q+=' AND DATE(createdAt)>=?';p.push(startDate);}if(endDate){q+=' AND DATE(createdAt)<=?';p.push(endDate);} const [a]=await pool.execute(q,p); let csv='ATL Code,SO Number,Company,Plate No,Driver,Hauler,Contact,Volume (L),Actual Volume (L),SI,Status,Scheduled Date,Dispatch Date,Completed Date,Printed WC,TPS From,TPS To,Remarks\n'; for(const x of a){csv+='"'+x.atl_code+'","'+x.so_number+'","'+x.company+'","'+x.plate_no+'","'+x.driver_name+'","'+x.hauler+'","'+x.contact_number+'","'+x.volume+'","'+x.actual_volume+'","'+(x.has_si==1?'With SI':'No SI')+'","'+x.status+'","'+x.scheduled_date+'","'+x.dispatch_date+'","'+x.completed_date+'","'+x.printed_wc+'","'+x.tps_start+'","'+x.tps_end+'","'+(x.remarks||'').replace(/"/g,'""')+'"\n';} res.setHeader('Content-Type','text/csv');res.setHeader('Content-Disposition','attachment;filename=report.csv');res.send(csv); } catch(e) { res.status(500).json({error:e.message}); }
    });

    app.get('/api/atl/summary', authenticate, async (req, res) => {
        try { const [a]=await pool.execute('SELECT * FROM authority_to_load WHERE client_id=? ORDER BY createdAt DESC LIMIT 50',[req.user.id]); const r=[]; for(const x of a){const [t]=await pool.execute('SELECT plate_no,make FROM trucks WHERE id=?',[x.truck_id]);r.push({...x,truck:t[0]||null});} res.json({status:'success',data:{recent:r}}); } catch(e) { res.status(500).json({error:e.message}); }
    });
}

module.exports = { setupReportRoutes };