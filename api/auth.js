const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const NodeCache = require('node-cache');
const path = require('path');

const app = express();
const otpCache = new NodeCache({ stdTTL: 600 });

app.set('trust proxy', 1);
app.use(express.json({ limit: "10kb" }));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(cors({ origin: ['https://fueltrak-seven.vercel.app', 'http://localhost:3000'], credentials: true }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: "Too many requests" },
  keyGenerator: (req) => req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress,
  validate: { xForwardedForHeader: false }
});
app.use("/api/", limiter);

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 16287,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false },
  waitForConnections: true,
  connectionLimit: 10
});

async function logAudit(userId, action, tableName, recordId, details) {
  try {
    await pool.execute("INSERT INTO audit_logs (user_id, action, table_name, record_id, details) VALUES (?, ?, ?, ?, ?)", [userId, action, tableName, recordId, JSON.stringify(details)]);
  } catch(e) {}
}

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function generateATLCode(company) {
  const prefix = (company || 'ATL').replace(/[^a-zA-Z]/g, '').substring(0, 3).toUpperCase().padEnd(3, 'X');
  const [rows] = await pool.execute('SELECT COUNT(*) as count FROM authority_to_load');
  const series = String(rows[0].count + 1).padStart(9, '0');
  return prefix + '-' + series;
}

const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Please authenticate' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    const [rows] = await pool.execute('SELECT id, email, role, mobile, company_name, is_active FROM users WHERE id = ?', [decoded.id]);
    if (!rows.length || !rows[0].is_active) return res.status(401).json({ error: 'Invalid token' });
    req.user = rows[0];
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const authorize = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Access denied' });
  next();
};

// ============ AUTH ROUTES ============
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, mobile, company_name } = req.body;
    const mobileRegex = /^(09\d{9}|\+639\d{9})$/;
    if (!mobileRegex.test(mobile)) return res.status(400).json({ error: 'Invalid mobile format' });
    const [existing] = await pool.execute('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length) return res.status(400).json({ error: 'Email already registered' });
    const hashedPassword = await bcrypt.hash(password, 12);
    await pool.execute('INSERT INTO users (email, password, mobile, company_name, role, is_verified, is_active, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())',
      [email, hashedPassword, mobile, company_name || null, 'client', false, true]);
    const otp = generateOTP();
    otpCache.set(email, otp);
    console.log('OTP for ' + email + ': ' + otp);
    res.status(201).json({ status: 'success', message: 'Registration successful. Check console for OTP.', email, otp });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (!users.length) return res.status(404).json({ error: 'User not found' });
    if (users[0].is_verified) return res.json({ message: 'Already verified' });
    const storedOTP = otpCache.get(email);
    if (!storedOTP || storedOTP !== otp) return res.status(400).json({ error: 'Invalid OTP' });
    otpCache.del(email);
    await pool.execute('UPDATE users SET is_verified = 1 WHERE email = ?', [email]);
    res.json({ status: 'success', message: 'Email verified. You can now login.' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/auth/resend-otp', async (req, res) => {
  const { email } = req.body;
  const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
  if (!users.length) return res.status(404).json({ error: 'User not found' });
  if (users[0].is_verified) return res.json({ message: 'Already verified' });
  const otp = generateOTP();
  otpCache.set(email, otp);
  console.log('OTP for ' + email + ': ' + otp);
  res.json({ message: 'OTP resent', otp });
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (!users.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = users[0];
    if (!user.is_verified) return res.status(401).json({ error: 'Please verify your email first' });
    if (!user.is_active) return res.status(403).json({ error: 'Account deactivated' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET || 'secret', { expiresIn: '24h' });
    if (user.current_token) {
      try { jwt.verify(user.current_token, process.env.JWT_SECRET || 'secret'); return res.json({ status: 'existing_session', message: 'Already logged in on another device.', user: { id: user.id, email: user.email, role: user.role } }); } catch(e) {}
    }
    await pool.execute('UPDATE users SET current_token = ?, last_login = NOW() WHERE id = ?', [token, user.id]);
    res.json({ status: 'success', token, user: { id: user.id, email: user.email, role: user.role, mobile: user.mobile, company_name: user.company_name } });
  } catch (error) { res.status(500).json({ error: 'Internal server error' }); }
});

app.get('/api/auth/profile', authenticate, (req, res) => res.json({ status: 'success', user: req.user }));

app.post('/api/auth/force-login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (!users.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET || 'secret', { expiresIn: '24h' });
    await pool.execute('UPDATE users SET current_token = ?, last_login = NOW() WHERE id = ?', [token, user.id]);
    res.json({ status: 'success', token, user: { id: user.id, email: user.email, role: user.role, mobile: user.mobile, company_name: user.company_name } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const [users] = await pool.execute('SELECT id FROM users WHERE email = ?', [email]);
    if (!users.length) return res.status(404).json({ error: 'Email not found' });
    const otp = generateOTP();
    otpCache.set('reset_' + email, otp);
    console.log('Reset OTP for ' + email + ': ' + otp);
    res.json({ status: 'success', message: 'OTP sent. Check console.', otp });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/auth/verify-reset-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const storedOTP = otpCache.get('reset_' + email);
    if (!storedOTP || storedOTP !== otp) return res.status(400).json({ error: 'Invalid or expired OTP' });
    otpCache.del('reset_' + email);
    const resetToken = jwt.sign({ email, purpose: 'reset' }, process.env.JWT_SECRET || 'secret', { expiresIn: '15m' });
    res.json({ status: 'success', message: 'OTP verified.', resetToken });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    const decoded = jwt.verify(resetToken, process.env.JWT_SECRET || 'secret');
    if (decoded.purpose !== 'reset') return res.status(400).json({ error: 'Invalid reset token' });
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    await pool.execute('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, decoded.email]);
    res.json({ status: 'success', message: 'Password reset successfully.' });
  } catch (error) {
    if (error.name === 'TokenExpiredError') return res.status(400).json({ error: 'Reset token expired.' });
    res.status(400).json({ error: error.message });
  }
});

// ============ HEALTH ============
app.get('/api/health', (req, res) => res.json({ status: 'OK', db: process.env.DB_NAME }));

// ============ DISPATCH ROUTES ============
app.get('/api/dispatch/dashboard', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [[{pending}], [{dispatched}], [{completed}], [{trucks}]] = await Promise.all([
      pool.execute('SELECT COUNT(*) as pending FROM authority_to_load WHERE status = ?', ['pending']),
      pool.execute('SELECT COUNT(*) as dispatched FROM authority_to_load WHERE status = ?', ['dispatched']),
      pool.execute('SELECT COUNT(*) as completed FROM authority_to_load WHERE status = ?', ['completed']),
      pool.execute('SELECT COUNT(*) as trucks FROM trucks WHERE is_active = 1')
    ]);
    res.json({ status: 'success', data: { loadedToday: dispatched, pendingCount: pending, completedCount: completed, totalTrucks: trucks } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/dispatch/enhanced-stats', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [pending] = await pool.execute('SELECT COUNT(*) as count FROM authority_to_load WHERE status = ?', ['pending']);
    const [approved] = await pool.execute('SELECT COUNT(*) as count FROM authority_to_load WHERE status = ?', ['approved']);
    const [loading] = await pool.execute('SELECT COUNT(*) as count FROM authority_to_load WHERE status = ?', ['dispatched']);
    const [completed] = await pool.execute('SELECT COUNT(*) as count FROM authority_to_load WHERE status = ?', ['completed']);
    const today = new Date().toISOString().split('T')[0];
    const [loadedToday] = await pool.execute("SELECT COUNT(*) as count FROM authority_to_load WHERE status IN ('dispatched','completed') AND DATE(dispatch_date) = ?", [today]);
    const [volumeRows] = await pool.execute("SELECT COALESCE(SUM(atl.volume),0) as totalVolume, COALESCE(SUM(CASE WHEN DATE(atl.dispatch_date) = ? THEN atl.volume ELSE 0 END),0) as todayVolume FROM authority_to_load atl WHERE atl.status IN ('dispatched','completed')", [today]);
    res.json({ status: 'success', data: { pending: pending[0].count, approved: approved[0].count, loading: loading[0].count, completed: completed[0].count, loadedToday: loadedToday[0].count, totalVolume: volumeRows[0].totalVolume || 0, todayVolume: volumeRows[0].todayVolume || 0, totalBackload: 0, todayBackload: 0 }});
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/dispatch/pending', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [atls] = await pool.execute("SELECT * FROM authority_to_load WHERE status IN ('pending','verified') ORDER BY createdAt DESC");
    const result = [];
    for (const atl of atls) {
      const [trucks] = await pool.execute('SELECT * FROM trucks WHERE id = ?', [atl.truck_id]);
      const [clients] = await pool.execute('SELECT id, email, company_name FROM users WHERE id = ?', [atl.client_id]);
      result.push({ ...atl, truck: trucks[0] || null, client: clients[0] || null });
    }
    res.json({ status: 'success', data: result });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/dispatch/verify/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { action, remarks } = req.body;
    const status = action === 'approve' ? 'approved' : action === 'reject' ? 'rejected' : null;
    if (!status) return res.status(400).json({ error: 'Invalid action' });
    await pool.execute('UPDATE authority_to_load SET status = ?, verified_by = ?, remarks = ? WHERE id = ?', [status, req.user.id, remarks || null, req.params.id]);
    const [updated] = await pool.execute('SELECT * FROM authority_to_load WHERE id = ?', [req.params.id]);
    res.json({ status: 'success', data: updated[0] });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/dispatch/start-loading/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute("UPDATE authority_to_load SET status = 'dispatched', dispatch_date = NOW() WHERE id = ?", [req.params.id]);
    const [updated] = await pool.execute('SELECT * FROM authority_to_load WHERE id = ?', [req.params.id]);
    res.json({ status: 'success', message: 'Loading started', data: updated[0] });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/dispatch/complete-loading/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { actual_volume, remarks, printed_wc } = req.body;
    await pool.execute("UPDATE authority_to_load SET status = 'completed', completed_date = NOW(), completed_by = ?, actual_volume = ?, remarks = ?, printed_wc = ? WHERE id = ?",
      [req.user.id, actual_volume || null, remarks || 'Loading completed', printed_wc || null, req.params.id]);
    const [updated] = await pool.execute('SELECT * FROM authority_to_load WHERE id = ?', [req.params.id]);
    res.json({ status: 'success', data: updated[0] });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.put('/api/dispatch/update-wc/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute("UPDATE authority_to_load SET printed_wc = ? WHERE id = ?", [req.body.printed_wc || null, req.params.id]);
    res.json({ status: "success", message: "WC updated" });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.put('/api/dispatch/update-si/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute('UPDATE authority_to_load SET has_si = ? WHERE id = ?', [req.body.has_si, req.params.id]);
    res.json({ status: 'success' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

// ============ CLIENT ATL ROUTES ============
app.get('/api/client/dashboard', authenticate, authorize('client'), async (req, res) => {
  try {
    const [atls] = await pool.execute('SELECT * FROM authority_to_load WHERE client_id = ? ORDER BY createdAt DESC', [req.user.id]);
    const result = [];
    for (const atl of atls) {
      const [trucks] = await pool.execute('SELECT * FROM trucks WHERE id = ?', [atl.truck_id]);
      result.push({ ...atl, truck: trucks[0] || null });
    }
    const stats = { total: atls.length, pending: atls.filter(a => a.status === 'pending').length, approved: atls.filter(a => a.status === 'approved').length, dispatched: atls.filter(a => a.status === 'dispatched').length, completed: atls.filter(a => a.status === 'completed').length, cancelled: atls.filter(a => a.status === 'cancelled' || a.status === 'rejected').length };
    res.json({ status: 'success', data: { stats, recent: result, recentATLs: result } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/client/verify-truck/:plateNo', authenticate, authorize('client'), async (req, res) => {
  try {
    const plateNo = req.params.plateNo.toUpperCase();
    const [trucks] = await pool.execute('SELECT * FROM trucks WHERE plate_no = ? AND is_active = 1', [plateNo]);
    if (trucks.length > 0) {
      const truck = trucks[0];
      const [docs] = await pool.execute('SELECT * FROM truck_documents WHERE truck_id = ?', [truck.id]);
      const docStatus = {}; let allValid = true;
      ['lto_registration','fire_permit','dost_calibration'].forEach(type => {
        const doc = docs.find(d => d.document_type === type);
        const days = doc ? Math.ceil((new Date(doc.expiry_date) - new Date()) / 86400000) : -1;
        docStatus[type] = { status: days < 0 ? 'expired' : days <= 30 ? 'expiring_soon' : 'valid', valid: days >= 0, days_remaining: days };
        if (days < 0) allValid = false;
      });
      return res.json({ status: 'success', data: { truck: { id: truck.id, plate_no: truck.plate_no, make: truck.make, driver_name: truck.driver_name, hauler_name: truck.hauler_name, total_capacity: truck.total_capacity }, documents: docStatus, can_proceed: allValid } });
    }
    const [master] = await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no = ?', [plateNo]);
    if (master.length > 0) {
      const [newTruck] = await pool.execute(
        'INSERT INTO trucks (plate_no, make, driver_name, hauler_name, total_capacity, is_active, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, 1, NOW(), NOW())',
        [master[0].plate_no, master[0].truck_make || 'Unknown', (master[0].driver_name || '').replace(/"/g, ''), master[0].hauler_name || '', master[0].total_capacity || 0]
      );
      return res.json({ status: 'success', data: { truck: { id: newTruck.insertId, plate_no: master[0].plate_no, make: master[0].truck_make, driver_name: master[0].driver_name, hauler_name: master[0].hauler_name, total_capacity: master[0].total_capacity }, documents: {}, can_proceed: true } });
    }
    res.status(404).json({ error: 'Truck not found', can_proceed: false });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/client/submit-atl', authenticate, authorize('client'), async (req, res) => {
  try {
    const { truck_id, plate_no, volume, driver_name, hauler_name, remarks, company, so_number, scheduled_date, contact_number, has_si } = req.body;
    
    let truckId = truck_id;
    let plateNo = plate_no;
    let driver = driver_name;
    let hauler = hauler_name;
    
    if (truckId) {
      const [trucks] = await pool.execute('SELECT * FROM trucks WHERE id = ? AND is_active = 1', [truckId]);
      if (!trucks.length) return res.status(404).json({ error: 'Truck not found' });
      plateNo = trucks[0].plate_no;
      if (!driver) driver = trucks[0].driver_name;
      if (!hauler) hauler = trucks[0].hauler_name;
    } else if (plateNo) {
      const [trucks] = await pool.execute('SELECT * FROM trucks WHERE plate_no = ? AND is_active = 1', [plateNo.toUpperCase()]);
      if (trucks.length > 0) {
        truckId = trucks[0].id;
        if (!driver) driver = trucks[0].driver_name;
        if (!hauler) hauler = trucks[0].hauler_name;
      } else {
        const [master] = await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no = ?', [plateNo.toUpperCase()]);
        if (master.length > 0) {
          const [newTruck] = await pool.execute(
            'INSERT INTO trucks (plate_no, make, driver_name, hauler_name, total_capacity, is_active, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, 1, NOW(), NOW())',
            [master[0].plate_no, master[0].truck_make || 'Unknown', (master[0].driver_name || '').replace(/"/g, ''), master[0].hauler_name || '', master[0].total_capacity || 0]
          );
          truckId = newTruck.insertId;
          if (!driver) driver = master[0].driver_name;
          if (!hauler) hauler = master[0].hauler_name;
        }
      }
    }
    
    if (!truckId) return res.status(400).json({ error: 'Truck not found. Please verify the plate number.' });
    
    const [existing] = await pool.execute("SELECT id FROM authority_to_load WHERE client_id = ? AND truck_id = ? AND status IN ('pending','approved')", [req.user.id, truckId]);
    if (existing.length) return res.status(400).json({ error: 'You already have a pending ATL for this truck' });
    
    const atlCode = await generateATLCode(company || req.user.company_name);
    
    await pool.execute(
      `INSERT INTO authority_to_load 
      (atl_code, client_id, truck_id, company, so_number, volume, hauler, plate_no, driver_name, contact_number, has_si, scheduled_date, remarks, status, createdAt) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [atlCode, req.user.id, truckId, company || req.user.company_name || '', so_number || null, volume || null, hauler || '', plateNo || '', driver || '', contact_number || null, has_si || false, scheduled_date || new Date().toISOString().split('T')[0], remarks || '', 'pending']
    );
    
    res.status(201).json({ status: 'success', message: 'ATL ' + atlCode + ' Submitted!', data: { atl_code: atlCode } });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/client/cancel-atl/:id', authenticate, authorize('client'), async (req, res) => {
  try {
    await pool.execute("UPDATE authority_to_load SET status = 'cancelled', remarks = ? WHERE id = ? AND client_id = ?", ['Cancellation: ' + (req.body.reason || ''), req.params.id, req.user.id]);
    res.json({ status: 'success', message: 'Cancellation requested' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.get("/api/client/atl/:id", authenticate, authorize("client"), async (req, res) => {
  try {
    const [atls] = await pool.execute("SELECT * FROM authority_to_load WHERE id = ? AND client_id = ?", [req.params.id, req.user.id]);
    if (!atls.length) return res.status(404).json({ error: "ATL not found" });
    res.json({ status: "success", data: atls[0] });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ============ TRUCK MASTERLIST ============
app.get('/api/truck-masterlist', authenticate, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT plate_no FROM truck_masterlist ORDER BY plate_no ASC');
    res.json({ status: 'success', data: rows });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/truck-masterlist-all', authenticate, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM truck_masterlist ORDER BY plate_no ASC');
    res.json({ status: 'success', data: rows });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.put('/api/update-truck-masterlist/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const allowed = ['truck_make', 'driver_name', 'hauler_name', 'tps_count'];
    const updates = [];
    const params = [];
    for (const key in req.body) {
      if (allowed.includes(key)) { updates.push(key + ' = ?'); params.push(req.body[key]); }
    }
    if (updates.length === 0) return res.status(400).json({ error: 'No valid fields' });
    params.push(req.params.id);
    await pool.execute('UPDATE truck_masterlist SET ' + updates.join(', ') + ' WHERE id = ?', params);
    res.json({ status: 'success', message: 'Updated' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

// ============ CHAT ============
app.get('/api/chat-list', authenticate, async (req, res) => {
  try {
    let users;
    if (req.user.role === 'client') {
      [users] = await pool.execute("SELECT id, email FROM users WHERE role IN ('dispatcher','management') LIMIT 5");
    } else {
      [users] = await pool.execute("SELECT DISTINCT u.id, u.email FROM users u JOIN chat_messages cm ON (cm.sender_id = u.id OR cm.receiver_id = u.id) WHERE u.role = 'client' AND (cm.sender_id = ? OR cm.receiver_id = ?) LIMIT 20", [req.user.id, req.user.id]);
      if (users.length === 0) [users] = await pool.execute("SELECT id, email FROM users WHERE role = 'client' LIMIT 10");
    }
    res.json({ status: 'success', data: users });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/chat/:clientId', authenticate, async (req, res) => {
  try {
    const [messages] = await pool.execute('SELECT cm.*, u.email as sender_email FROM chat_messages cm JOIN users u ON cm.sender_id = u.id WHERE (cm.sender_id = ? AND cm.receiver_id = ?) OR (cm.sender_id = ? AND cm.receiver_id = ?) ORDER BY cm.created_at ASC LIMIT 50', [req.user.id, req.params.clientId, req.params.clientId, req.user.id]);
    res.json({ status: 'success', data: messages });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/chat', authenticate, async (req, res) => {
  try {
    await pool.execute('INSERT INTO chat_messages (sender_id, receiver_id, message) VALUES (?, ?, ?)', [req.user.id, req.body.receiver_id, req.body.message]);
    res.json({ status: 'success', message: 'Sent' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.get('/api/demo-credentials', async (req, res) => {
  try {
    const [users] = await pool.execute("SELECT email, role FROM users WHERE email IN (?, ?, ?)", ['admin@fueltrak.com', 'dispatcher@fueltrak.com', 'client1@hauler.com']);
    const credentials = {};
    users.forEach(u => { if (u.role === 'management') credentials.admin = u.email; if (u.role === 'dispatcher') credentials.dispatcher = u.email; if (u.role === 'client') credentials.client = u.email; });
    res.json({ status: 'success', data: credentials });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ============ PAGE ROUTES ============
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'index.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'dashboard.html')));
app.get('/dashboard.html', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'dashboard.html')));
app.get('/client', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'client.html')));
app.get('/client.html', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'client.html')));
app.get('/docs-report', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'docs-report.html')));
app.get('/reports', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'reports.html')));
app.get('/reports.html', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'reports.html')));
app.get('/atl.html', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'atl.html')));
app.get('/trucks', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'trucks.html')));
app.get('/ttsd-checklist', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'ttsd-checklist.html')));
app.get('/tutorial', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'tutorial.html')));
app.get('/audit-logs', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'audit-logs.html')));

module.exports = app;