const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const NodeCache = require('node-cache');

const app = express();
const otpCache = new NodeCache({ stdTTL: 600 });

app.use(express.json({ limit: "10kb" }));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(cors({ origin: ['https://fueltrak-seven.vercel.app', 'http://localhost:3000'], credentials: true }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: "Too many requests" }
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

// ============ HELPERS ============
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function generateATLCode(company) {
  const prefix = (company || 'ATL').replace(/[^a-zA-Z]/g, '').substring(0, 3).toUpperCase().padEnd(3, 'X');
  const [rows] = await pool.execute('SELECT COUNT(*) as count FROM authority_to_load');
  const series = String(rows[0].count + 1).padStart(9, '0');
  return prefix + '-' + series;
}

// ============ AUTH MIDDLEWARE ============
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
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
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
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
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
    await pool.execute('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET || 'secret', { expiresIn: '24h' });

    // Check if already logged in on another device
    if (user.current_token) {
        try {
            jwt.verify(user.current_token, process.env.JWT_SECRET || 'secret');
            // Old token still valid - return special response asking to logout
            return res.json({ 
                status: 'existing_session', 
                message: 'Already logged in on another device. Do you want to logout the other device and continue here?',
                user: { id: user.id, email: user.email, role: user.role }
            });
        } catch(e) {
            // Old token expired, proceed
        }
    }

    await pool.execute('UPDATE users SET current_token = ?, last_login = NOW() WHERE id = ?', [token, user.id]);

    res.json({
        status: 'success',
        token,
        user: { id: user.id, email: user.email, role: user.role, mobile: user.mobile, company_name: user.company_name }
    });
  
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/auth/profile', authenticate, (req, res) => {
  res.json({ status: 'success', user: req.user });
});

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
    
    res.json({
      status: 'success',
      token,
      user: { id: user.id, email: user.email, role: user.role, mobile: user.mobile, company_name: user.company_name }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
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
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/verify-reset-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const storedOTP = otpCache.get('reset_' + email);
    if (!storedOTP || storedOTP !== otp) return res.status(400).json({ error: 'Invalid or expired OTP' });
    otpCache.del('reset_' + email);
    const resetToken = jwt.sign({ email, purpose: 'reset' }, process.env.JWT_SECRET || 'secret', { expiresIn: '15m' });
    res.json({ status: 'success', message: 'OTP verified.', resetToken });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
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

// ============ DISPATCH DASHBOARD ============
app.get('/api/dispatch/dashboard', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [[{pending}], [{dispatched}], [{completed}], [{trucks}]] = await Promise.all([
      pool.execute('SELECT COUNT(*) as pending FROM authority_to_load WHERE status = ?', ['pending']),
      pool.execute('SELECT COUNT(*) as dispatched FROM authority_to_load WHERE status = ?', ['dispatched']),
      pool.execute('SELECT COUNT(*) as completed FROM authority_to_load WHERE status = ?', ['completed']),
      pool.execute('SELECT COUNT(*) as trucks FROM trucks WHERE is_active = 1')
    ]);
    res.json({ status: 'success', data: { loadedToday: dispatched, pendingCount: pending, completedCount: completed, totalTrucks: trucks } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/dispatch/enhanced-stats', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [pending] = await pool.execute('SELECT COUNT(*) as count FROM authority_to_load WHERE status = ?', ['pending']);
    const [approved] = await pool.execute('SELECT COUNT(*) as count FROM authority_to_load WHERE status = ?', ['approved']);
    const [loading] = await pool.execute('SELECT COUNT(*) as count FROM authority_to_load WHERE status = ?', ['dispatched']);
    const [completed] = await pool.execute('SELECT COUNT(*) as count FROM authority_to_load WHERE status = ?', ['completed']);
    const today = new Date().toISOString().split('T')[0];
    const [loadedToday] = await pool.execute("SELECT COUNT(*) as count FROM authority_to_load WHERE status IN ('dispatched','completed') AND DATE(dispatch_date) = ?", [today]);
    const [volumeRows] = await pool.execute("SELECT COALESCE(SUM(atl.volume),0) as totalVolume, COALESCE(SUM(CASE WHEN DATE(atl.dispatch_date) = ? THEN atl.volume ELSE 0 END),0) as todayVolume, COALESCE((SELECT SUM(volume) FROM backloads),0) as totalBackload, COALESCE((SELECT SUM(volume) FROM backloads WHERE DATE(created_at) = ?),0) as todayBackload FROM authority_to_load atl WHERE atl.status IN ('dispatched','completed')", [today, today]);
    res.json({ status: 'success', data: {
      pending: pending[0].count, approved: approved[0].count, loading: loading[0].count,
      completed: completed[0].count, loadedToday: loadedToday[0].count,
      totalVolume: volumeRows[0].totalVolume - (volumeRows[0].totalBackload || 0), todayVolume: volumeRows[0].todayVolume - (volumeRows[0].todayBackload || 0), totalBackload: volumeRows[0].totalBackload || 0, todayBackload: volumeRows[0].todayBackload || 0
    }});
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ DISPATCH PENDING ============
app.get('/api/dispatch/pending', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [atls] = await pool.execute("SELECT * FROM authority_to_load WHERE status IN ('pending','verified') ORDER BY createdAt DESC");
    const result = [];
    for (const atl of atls) {
      const [trucks] = await pool.execute('SELECT * FROM trucks WHERE id = ?', [atl.truck_id]);
      const [clients] = await pool.execute('SELECT id, email, company_name FROM users WHERE id = ?', [atl.client_id]);
      result.push({ ...atl, truck: trucks[0] || null, client: clients[0] || null, completed_by_user: completedBy[0] || null });
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
    await logAudit(req.user.id, 'VERIFY_ATL', 'authority_to_load', req.params.id, {status, remarks});
    const [updated] = await pool.execute('SELECT * FROM authority_to_load WHERE id = ?', [req.params.id]);
    if (!updated.length) return res.status(404).json({ error: 'ATL not found' });
    res.json({ status: 'success', data: updated[0] });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/dispatch/handle-cancellation/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const status = req.body.action === 'approve_cancel' ? 'cancelled' : 'approved';
    await pool.execute('UPDATE authority_to_load SET status = ? WHERE id = ?', [status, req.params.id]);
    const [updated] = await pool.execute('SELECT * FROM authority_to_load WHERE id = ?', [req.params.id]);
    res.json({ status: 'success', data: updated[0] });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

// ============ LOADING MANAGEMENT ============
app.get('/api/dispatch/approved-for-loading', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [atls] = await pool.execute("SELECT * FROM authority_to_load WHERE status = 'approved' ORDER BY createdAt DESC");
    const result = [];
    for (const atl of atls) {
      const [trucks] = await pool.execute('SELECT * FROM trucks WHERE id = ?', [atl.truck_id]);
      const [clients] = await pool.execute('SELECT id, email, company_name FROM users WHERE id = ?', [atl.client_id]);
      result.push({ ...atl, truck: trucks[0] || null, client: clients[0] || null, completed_by_user: completedBy[0] || null });
    }
    res.json({ status: 'success', data: result });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/dispatch/ongoing-loading', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [atls] = await pool.execute("SELECT * FROM authority_to_load WHERE status = 'dispatched' ORDER BY dispatch_date DESC");
    const result = [];
    for (const atl of atls) {
      const [trucks] = await pool.execute('SELECT * FROM trucks WHERE id = ?', [atl.truck_id]);
      const [clients] = await pool.execute('SELECT id, email, company_name FROM users WHERE id = ?', [atl.client_id]);
      result.push({ ...atl, truck: trucks[0] || null, client: clients[0] || null, completed_by_user: completedBy[0] || null });
    }
    res.json({ status: 'success', data: result });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/dispatch/loading-history', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [atls] = await pool.execute("SELECT * FROM authority_to_load WHERE status IN ('dispatched','completed') ORDER BY dispatch_date DESC LIMIT 50");
    const result = [];
    for (const atl of atls) {
      const [trucks] = await pool.execute('SELECT * FROM trucks WHERE id = ?', [atl.truck_id]);
      const [clients] = await pool.execute('SELECT id, email, company_name FROM users WHERE id = ?', [atl.client_id]);
      result.push({ ...atl, truck: trucks[0] || null, client: clients[0] || null, completed_by_user: completedBy[0] || null });
    }
    res.json({ status: 'success', data: result });
  } catch (error) { res.status(500).json({ error: error.message }); }
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
    const { actual_volume, remarks, printed_wc, tps_series } = req.body;
    await logAudit(req.user.id, "COMPLETE_LOADING", "authority_to_load", req.params.id, {actual_volume, printed_wc, tps_series});
    await pool.execute("UPDATE authority_to_load SET status = 'completed', completed_date = NOW(), completed_by = ?, actual_volume = ?, remarks = ?, printed_wc = ?, tps_start = ? WHERE id = ?",
      [req.user.id, actual_volume || null, remarks || 'Loading completed', printed_wc || null, tps_series || null, req.params.id]);
    const [updated] = await pool.execute('SELECT * FROM authority_to_load WHERE id = ?', [req.params.id]);
    res.json({ status: 'success', data: updated[0] });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/dispatch/cancel-loading/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute("UPDATE authority_to_load SET status = 'pending', dispatch_date = NULL, remarks = ? WHERE id = ?",
      ['Loading cancelled: ' + (req.body.reason || 'No reason'), req.params.id]);
    const [updated] = await pool.execute('SELECT * FROM authority_to_load WHERE id = ?', [req.params.id]);
    res.json({ status: 'success', data: updated[0] });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.put('/api/dispatch/update-loading/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { volume, actual_volume, driver_name, hauler, remarks } = req.body;
    await pool.execute('UPDATE authority_to_load SET volume = ?, actual_volume = ?, driver_name = ?, hauler = ?, remarks = ? WHERE id = ?',
      [volume || null, actual_volume || null, driver_name || null, hauler || null, remarks || null, req.params.id]);
    const [updated] = await pool.execute('SELECT * FROM authority_to_load WHERE id = ?', [req.params.id]);
    res.json({ status: 'success', data: updated[0] });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

// ============ TRUCK STATS ============
app.get('/api/dispatch/truck-stats', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [trucks] = await pool.execute('SELECT * FROM trucks');
    const today = new Date();
    const stats = { total: trucks.length, active: 0, inactive: 0, withExpiredDocs: 0, withValidDocs: 0, expiringSoon: 0, totalCapacity: 0, documentBreakdown: { lto: { valid: 0, expired: 0, missing: 0 }, fire: { valid: 0, expired: 0, missing: 0 }, dost: { valid: 0, expired: 0, missing: 0 } }, trucksNeedingAttention: [] };
    for (const truck of trucks) {
      if (truck.is_active) { stats.active++; stats.totalCapacity += parseFloat(truck.total_capacity) || 0; }
      else { stats.inactive++; }
      const [docs] = await pool.execute('SELECT * FROM truck_documents WHERE truck_id = ?', [truck.id]);
      let hasExpired = false, hasExpiring = false;
      ['lto_registration','fire_permit','dost_calibration'].forEach(type => {
        const doc = docs.find(d => d.document_type === type);
        const key = type === 'lto_registration' ? 'lto' : type === 'fire_permit' ? 'fire' : 'dost';
        if (!doc) { stats.documentBreakdown[key].missing++; if (truck.is_active) hasExpired = true; }
        else {
          const days = Math.ceil((new Date(doc.expiry_date) - today) / 86400000);
          if (days < 0) { stats.documentBreakdown[key].expired++; if (truck.is_active) hasExpired = true; }
          else if (days <= 30) { stats.documentBreakdown[key].valid++; if (truck.is_active) hasExpiring = true; }
          else { stats.documentBreakdown[key].valid++; }
        }
      });
      if (truck.is_active && hasExpired) { stats.withExpiredDocs++; }
      else if (truck.is_active && hasExpiring) { stats.expiringSoon++; }
      else if (truck.is_active) { stats.withValidDocs++; }
    }
    res.json({ status: 'success', data: stats });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ============ TRUCKS CRUD ============
app.get('/api/trucks', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [trucks] = await pool.execute('SELECT * FROM trucks ORDER BY plate_no ASC');
    const result = [];
    for (const truck of trucks) {
      const [docs] = await pool.execute('SELECT * FROM truck_documents WHERE truck_id = ?', [truck.id]);
      result.push({ ...truck, documents: docs });
    }
    res.json({ status: 'success', data: result, total: result.length });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/trucks/all', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [trucks] = await pool.execute('SELECT * FROM trucks ORDER BY plate_no ASC');
    const result = [];
    for (const truck of trucks) {
      const [docs] = await pool.execute('SELECT * FROM truck_documents WHERE truck_id = ?', [truck.id]);
      result.push({ ...truck, documents: docs });
    }
    res.json({ status: 'success', data: result });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/trucks/:id', authenticate, async (req, res) => {
  try {
    const [trucks] = await pool.execute('SELECT * FROM trucks WHERE id = ?', [req.params.id]);
    if (!trucks.length) return res.status(404).json({ error: 'Truck not found' });
    const [docs] = await pool.execute('SELECT * FROM truck_documents WHERE truck_id = ?', [req.params.id]);
    res.json({ status: 'success', data: { ...trucks[0], documents: docs } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/trucks', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { plate_no, make, driver_name, hauler_name, total_capacity, num_tps, calibration_date, next_calibration_date, discharge_line, remarks, documents } = req.body;
    const [existing] = await pool.execute('SELECT id FROM trucks WHERE plate_no = ?', [plate_no.toUpperCase()]);
    if (existing.length) return res.status(400).json({ error: 'Truck already exists' });
    const [result] = await pool.execute(
      'INSERT INTO trucks (plate_no, make, driver_name, hauler_name, total_capacity, num_tps, calibration_date, next_calibration_date, discharge_line, remarks, is_active, createdAt, updatedAt) VALUES (?,?,?,?,?,?,?,?,?,?,1,NOW(),NOW())',
      [plate_no.toUpperCase(), make, driver_name || null, hauler_name || null, total_capacity || 0, num_tps || 0, calibration_date || null, next_calibration_date || null, discharge_line || 'including', remarks || null]
    );
    if (documents && Array.isArray(documents)) {
      for (const doc of documents) {
        if (doc.expiry_date) {
          await pool.execute('INSERT INTO truck_documents (truck_id, document_type, document_number, issue_date, expiry_date, status, createdAt) VALUES (?,?,?,?,?,?,NOW())',
            [result.insertId, doc.type, doc.number || null, doc.issue_date || new Date(), doc.expiry_date, 'valid']);
        }
      }
    }
    res.status(201).json({ status: 'success', message: 'Truck created', data: { id: result.insertId } });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.put('/api/trucks/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { plate_no, make, driver_name, hauler_name, total_capacity, num_tps, documents } = req.body;
    await pool.execute('UPDATE trucks SET plate_no=?, make=?, driver_name=?, hauler_name=?, total_capacity=?, num_tps=? WHERE id=?',
      [plate_no?.toUpperCase(), make, driver_name, hauler_name, total_capacity || 0, num_tps || 0, req.params.id]);
    if (documents && Array.isArray(documents)) {
      for (const doc of documents) {
        if (doc.expiry_date) {
          const [existing] = await pool.execute('SELECT id FROM truck_documents WHERE truck_id=? AND document_type=?', [req.params.id, doc.type]);
          if (existing.length) {
            await pool.execute('UPDATE truck_documents SET expiry_date=?, status=? WHERE id=?', [doc.expiry_date, new Date(doc.expiry_date) >= new Date() ? 'valid' : 'expired', existing[0].id]);
          } else {
            await pool.execute('INSERT INTO truck_documents (truck_id,document_type,expiry_date,status,createdAt) VALUES (?,?,?,?,NOW())', [req.params.id, doc.type, doc.expiry_date, 'valid']);
          }
        }
      }
    }
    res.json({ status: 'success', message: 'Truck updated' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.delete('/api/trucks/:id', authenticate, authorize('management'), async (req, res) => {
  try {
    await pool.execute('UPDATE trucks SET is_active = 0 WHERE id = ?', [req.params.id]);
    res.json({ status: 'success', message: 'Truck deactivated' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.patch('/api/trucks/:id/restore', authenticate, authorize('management'), async (req, res) => {
  try {
    await pool.execute('UPDATE trucks SET is_active = 1 WHERE id = ?', [req.params.id]);
    res.json({ status: 'success', message: 'Truck reactivated' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

// ============ CLIENTS ============
app.get('/api/clients', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [clients] = await pool.execute("SELECT id, email, mobile, company_name, is_active, is_verified, last_login, createdAt FROM users WHERE role = 'client' ORDER BY createdAt DESC");
    const result = [];
    for (const client of clients) {
      const [atls] = await pool.execute('SELECT COUNT(*) as total FROM authority_to_load WHERE client_id = ?', [client.id]);
      result.push({ ...client, total_atls: atls[0].total });
    }
    res.json({ status: 'success', data: result, total: result.length });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/dispatcher/clients', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [clients] = await pool.execute("SELECT id, email, company_name, mobile, is_active FROM users WHERE role = 'client'");
    res.json({ status: 'success', data: clients });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/clients/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [clients] = await pool.execute("SELECT id, email, mobile, company_name, is_active, is_verified, last_login, createdAt FROM users WHERE id = ? AND role = 'client'", [req.params.id]);
    if (!clients.length) return res.status(404).json({ error: 'Client not found' });
    const [atls] = await pool.execute("SELECT COUNT(*) as total, SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as pending, SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) as approved, SUM(CASE WHEN status='dispatched' THEN 1 ELSE 0 END) as dispatched, SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed FROM authority_to_load WHERE client_id = ?", [req.params.id]);
    res.json({ status: 'success', data: { ...clients[0], atl_stats: atls[0] } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/clients', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { email, password, mobile, company_name } = req.body;
    if (!email || !password || !mobile) return res.status(400).json({ error: 'Email, password, and mobile are required' });
    const [existing] = await pool.execute('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length) return res.status(400).json({ error: 'Email already registered' });
    const hashedPassword = await bcrypt.hash(password, 12);
    await pool.execute('INSERT INTO users (email, password, mobile, company_name, role, is_verified, is_active, createdAt) VALUES (?,?,?,?,?,1,1,NOW())',
      [email, hashedPassword, mobile, company_name || null, 'client']);
    res.status(201).json({ status: 'success', message: 'Client created' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.put('/api/clients/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { email, mobile, company_name, password } = req.body;
    const [clients] = await pool.execute("SELECT * FROM users WHERE id = ? AND role = 'client'", [req.params.id]);
    if (!clients.length) return res.status(404).json({ error: 'Client not found' });
    if (email && email !== clients[0].email) {
      const [dup] = await pool.execute('SELECT id FROM users WHERE email = ?', [email]);
      if (dup.length) return res.status(400).json({ error: 'Email already in use' });
    }
    let query = 'UPDATE users SET email=?, mobile=?, company_name=?';
    let params = [email || clients[0].email, mobile || clients[0].mobile, company_name !== undefined ? company_name : clients[0].company_name];
    if (password && password.length >= 8) {
      const hashed = await bcrypt.hash(password, 12);
      query = 'UPDATE users SET email=?, mobile=?, company_name=?, password=?';
      params = [email || clients[0].email, mobile || clients[0].mobile, company_name !== undefined ? company_name : clients[0].company_name, hashed];
    }
    await pool.execute(query + ' WHERE id = ?', [...params, req.params.id]);
    res.json({ status: 'success', message: 'Client updated' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.patch('/api/clients/:id/toggle-status', authenticate, authorize('management'), async (req, res) => {
  try {
    const [clients] = await pool.execute("SELECT is_active FROM users WHERE id = ? AND role = 'client'", [req.params.id]);
    if (!clients.length) return res.status(404).json({ error: 'Client not found' });
    const newStatus = clients[0].is_active ? 0 : 1;
    await pool.execute('UPDATE users SET is_active = ? WHERE id = ?', [newStatus, req.params.id]);
    res.json({ status: 'success', message: 'Client ' + (newStatus ? 'activated' : 'deactivated') });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.delete('/api/clients/:id', authenticate, authorize('management'), async (req, res) => {
  try {
    const [active] = await pool.execute("SELECT COUNT(*) as count FROM authority_to_load WHERE client_id = ? AND status IN ('pending','approved','dispatched')", [req.params.id]);
    if (active[0].count > 0) return res.status(400).json({ error: 'Cannot delete. Client has ' + active[0].count + ' active ATL(s).' });
    await pool.execute("DELETE FROM users WHERE id = ? AND role = 'client'", [req.params.id]);
    res.json({ status: 'success', message: 'Client deleted' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});



// ============ UPDATE WC ============
app.put("/api/dispatch/update-wc/:id", authenticate, authorize("dispatcher", "management"), async (req, res) => {
  try {
    const { printed_wc } = req.body;
    await pool.execute("UPDATE authority_to_load SET printed_wc = ? WHERE id = ?", [printed_wc || null, req.params.id]);
    res.json({ status: "success", message: "WC updated" });
  } catch (error) { res.status(400).json({ error: error.message }); }
});
// ============ HEALTH ============
app.get('/api/health', (req, res) => res.json({ status: 'OK', db: process.env.DB_NAME }));

const path = require('path');

app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'dashboard.html')));
app.get('/dashboard.html', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'dashboard.html')));
app.get('/client', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'client.html')));
app.get('/client.html', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'client.html')));

app.get('/docs-report', (req, res) => res.sendFile(require('path').join(__dirname, '..', 'public', 'docs-report.html')));
app.get('/reports', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'reports.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'index.html')));
app.get('/api/health', (req, res) => res.json({ status: 'OK', db: process.env.DB_NAME }));


// ============ CLIENT ATL ROUTES ============
app.get('/api/client/dashboard', authenticate, authorize('client'), async (req, res) => {
  try {
    const [atls] = await pool.execute('SELECT * FROM authority_to_load WHERE client_id = ? ORDER BY createdAt DESC', [req.user.id]);
    const result = [];
    for (const atl of atls) {
      const [trucks] = await pool.execute('SELECT * FROM trucks WHERE id = ?', [atl.truck_id]);
      result.push({ ...atl, truck_details: trucks[0] ? { plate_no: trucks[0].plate_no, make: trucks[0].make, capacity: trucks[0].total_capacity } : null });
    }
    const stats = { total: atls.length, successful: atls.filter(a => a.status === 'completed').length, failed: atls.filter(a => a.status === 'rejected').length, pending: atls.filter(a => a.status === 'pending').length, approved: atls.filter(a => a.status === 'approved').length, cancelled: atls.filter(a => a.status === 'cancelled').length, dispatched: atls.filter(a => a.status === 'dispatched').length };
    res.json({ status: 'success', data: { stats, recentATLs: result } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/client/verify-truck/:plateNo', authenticate, authorize('client'), async (req, res) => {
  try {
    const [trucks] = await pool.execute('SELECT * FROM trucks WHERE plate_no = ? AND is_active = 1', [req.params.plateNo.toUpperCase()]);
    if (!trucks.length) return res.status(404).json({ error: 'Truck not found', can_proceed: false });
    const truck = trucks[0];
    const [docs] = await pool.execute('SELECT * FROM truck_documents WHERE truck_id = ?', [truck.id]);
    const docStatus = {}; let allValid = true;
    ['lto_registration','fire_permit','dost_calibration'].forEach(type => { const doc = docs.find(d => d.document_type === type); const days = doc ? Math.ceil((new Date(doc.expiry_date) - new Date()) / 86400000) : -1; docStatus[type] = { status: days < 0 ? 'expired' : days <= 30 ? 'expiring_soon' : 'valid', valid: days >= 0, days_remaining: days }; if (days < 0) allValid = false; });
    var [masterlist] = await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no = ?', [req.params.plateNo.toUpperCase()]);
    res.json({ status: 'success', data: { truck: { id: truck.id, plate_no: truck.plate_no, make: truck.make, driver_name: truck.driver_name, total_capacity: truck.total_capacity, masterlist: masterlist[0] || null }, documents: docStatus, can_proceed: allValid } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/client/submit-atl', authenticate, authorize('client'), async (req, res) => {
  try {
    const { plate_no, scheduled_date, company, so_number, volume, hauler, driver_name, contact_number, has_si } = req.body;
    const [trucks] = await pool.execute('SELECT * FROM trucks WHERE plate_no = ? AND is_active = 1', [plate_no.toUpperCase()]);
    if (!trucks.length) return res.status(404).json({ error: 'Truck not found' });
    const truck = trucks[0];
    const [existing] = await pool.execute("SELECT id FROM authority_to_load WHERE client_id = ? AND truck_id = ? AND status IN ('pending','approved')", [req.user.id, truck.id]);
    if (existing.length) return res.status(400).json({ error: 'You already have a pending ATL' });
    const atlCode = await generateATLCode(company || req.user.company_name);
    await pool.execute('INSERT INTO authority_to_load (client_id, truck_id, atl_code, company, so_number, volume, hauler, plate_no, driver_name, contact_number, has_si, scheduled_date, status, createdAt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,NOW())', [req.user.id, truck.id, atlCode, company || req.user.company_name, so_number || null, volume || null, hauler || truck.hauler_name, truck.plate_no, driver_name || truck.driver_name, contact_number || req.user.mobile, has_si || false, scheduled_date, 'pending']);
    res.status(201).json({ status: 'success', message: 'ATL ' + atlCode + ' Submitted!', atl_code: atlCode });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/client/cancel-atl/:id', authenticate, authorize('client'), async (req, res) => {
  try {
    await pool.execute("UPDATE authority_to_load SET status = 'cancelled', remarks = ? WHERE id = ? AND client_id = ?", ['Cancellation: ' + (req.body.reason || ''), req.params.id, req.user.id]);
    res.json({ status: 'success', message: 'Cancellation requested' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});


// ============ ATL PAGE ROUTES ============
app.get('/api/atl/summary', authenticate, async (req, res) => {
  try {
    const [atls] = await pool.execute('SELECT * FROM authority_to_load WHERE client_id = ? ORDER BY createdAt DESC LIMIT 20', [req.user.id]);
    const result = [];
    for (const atl of atls) {
      const [trucks] = await pool.execute('SELECT plate_no, make FROM trucks WHERE id = ?', [atl.truck_id]);
      result.push({ ...atl, truck: trucks[0] || null });
    }
    res.json({ status: 'success', data: { recent: result } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/atl/submit', authenticate, async (req, res) => {
  try {
    const { company, so_number, scheduled_date, hauler, plate_no, driver_name, contact_number } = req.body;
    const [trucks] = await pool.execute('SELECT * FROM trucks WHERE plate_no = ? AND is_active = 1', [plate_no.toUpperCase()]);
    if (!trucks.length) return res.status(404).json({ error: 'Truck not found' });
    const truck = trucks[0];
    const atlCode = await generateATLCode(company);
    await pool.execute('INSERT INTO authority_to_load (client_id, truck_id, atl_code, company, so_number, hauler, plate_no, driver_name, contact_number, has_si, scheduled_date, status, createdAt) VALUES (?,?,?,?,?,?,?,?,?,?,?,NOW())',
      [req.user.id, truck.id, atlCode, company, so_number, hauler || truck.hauler_name, truck.plate_no, driver_name || truck.driver_name, contact_number, scheduled_date, 'pending']);
    res.status(201).json({ status: 'success', message: 'ATL ' + atlCode + ' Submitted!', atl_code: atlCode });
  } catch (error) { res.status(400).json({ error: error.message }); }
});


// ============ REPORTS ============
app.get('/api/reports/filters', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [clients] = await pool.execute("SELECT id, email, company_name FROM users WHERE role = 'client'");
    const [trucks] = await pool.execute('SELECT id, plate_no, make FROM trucks');
    res.json({ status: 'success', data: { clients: clients.map(c => ({ id: c.id, label: (c.company_name || c.email) + ' (' + c.email + ')' })), trucks: trucks.map(t => ({ id: t.id, label: t.plate_no + ' - ' + t.make })) } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/reports/summary', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { startDate, endDate, status, clientId, truckId } = req.query;
    let query = 'SELECT atl.*, (SELECT COUNT(*) FROM backloads WHERE atl_id = atl.id) as backload_count, (SELECT COALESCE(SUM(volume),0) FROM backloads WHERE atl_id = atl.id) as backload_volume FROM authority_to_load atl WHERE 1=1';
    const params = [];
    if (status) { const statuses = status.split(','); query += ' AND status IN (' + statuses.map(() => '?').join(',') + ')'; params.push(...statuses); }
    else { query += " AND status IN ('completed','cancelled','dispatched')"; }
    if (startDate) { query += ' AND DATE(atl.createdAt) >= ?'; params.push(startDate); }
    if (endDate) { query += ' AND DATE(atl.createdAt) <= ?'; params.push(endDate); }
    if (clientId) { query += ' AND client_id = ?'; params.push(clientId); }
    if (truckId) { query += ' AND truck_id = ?'; params.push(truckId); } if (req.query.hasBackload === '1') { query += ' AND atl.id IN (SELECT DISTINCT atl_id FROM backloads)'; }
    query += ' ORDER BY createdAt DESC';
    const [atls] = await pool.execute(query, params);
    const result = [];
    let totalVolume = 0, completedCount = 0, cancelledCount = 0, dispatchedCount = 0, totalActualVolume = 0;
    for (const atl of atls) {
      const [trucks] = await pool.execute('SELECT plate_no, make, total_capacity FROM trucks WHERE id = ?', [atl.truck_id]);
      const [clients] = await pool.execute('SELECT email, company_name FROM users WHERE id = ?', [atl.client_id]); const [completedBy] = await pool.execute('SELECT email FROM users WHERE id = ?', [atl.completed_by]);
      const vol = parseFloat(atl.volume) || 0; totalVolume += vol; if (atl.status === 'completed') { completedCount++; totalActualVolume += parseFloat(atl.actual_volume) || vol; } if (atl.status === 'cancelled') cancelledCount++; if (atl.status === 'dispatched') dispatchedCount++;
      result.push({ ...atl, truck: trucks[0] || null, client: clients[0] || null, completed_by_user: completedBy[0] || null });
    }
    res.json({ status: 'success', data: { records: result, summary: { total_records: atls.length, completed: completedCount, cancelled: cancelledCount, dispatched: dispatchedCount, total_volume: totalVolume, total_actual_volume: totalActualVolume, average_volume: atls.length > 0 ? Math.round(totalVolume / atls.length) : 0 } } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/reports/export', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { startDate, endDate, status } = req.query;
    let query = "SELECT * FROM authority_to_load WHERE status IN ('completed','cancelled','dispatched')";
    const params = [];
    if (startDate) { query += ' AND DATE(createdAt) >= ?'; params.push(startDate); }
    if (endDate) { query += ' AND DATE(createdAt) <= ?'; params.push(endDate); }
    const [atls] = await pool.execute(query, params);
    let csv = 'ATL Code,SO Number,Company,Plate No,Driver,Hauler,Contact Number,Volume (L),Actual Volume (L),Backload (L),SI,Status,Scheduled Date,Dispatch Date,Completed Date,Printed WC,TPS From,TPS To,Remarks,User\n';
    for (const a of atls) {
      csv += '"' + (a.atl_code||'') + '","' + (a.so_number||'') + '","' + (a.company||'') + '","' + (a.plate_no||'') + '","' + (a.driver_name||'') + '","' + (a.hauler||'') + '","' + (a.contact_number||'') + '",' + (a.volume||0) + ',' + (a.actual_volume||0) + ',' + (a.backload_volume||0) + ',"' + (a.has_si==1?'With SI':'No SI') + '","' + (a.status) + '","' + (a.scheduled_date||'') + '","' + (a.dispatch_date?new Date(a.dispatch_date).toLocaleDateString():'') + '","' + (a.completed_date?new Date(a.completed_date).toLocaleDateString():'') + '","' + (a.printed_wc||'') + '","' + (a.tps_start||'') + '","' + (a.tps_end||'') + '","' + ((a.remarks||'').replace(/"/g,'""')) + '","' + (a.completed_by_user ? a.completed_by_user.email : '') + '"\n';
    }
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=report.csv');
    res.send(csv);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/client.html', (req, res) => res.sendFile(require('path').join(__dirname, '..', 'public', 'client.html')));
app.get('/dashboard.html', (req, res) => res.sendFile(require('path').join(__dirname, '..', 'public', 'dashboard.html')));
app.get('/reports.html', (req, res) => res.sendFile(require('path').join(__dirname, '..', 'public', 'reports.html')));
app.get('/atl.html', (req, res) => res.sendFile(require('path').join(__dirname, '..', 'public', 'atl.html')));

app.put('/api/dispatch/update-si/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute('UPDATE authority_to_load SET has_si = ? WHERE id = ?', [req.body.has_si, req.params.id]);
    res.json({ status: 'success' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.put('/api/dispatch/update-tps/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute('UPDATE authority_to_load SET tps_start = ?, tps_end = ? WHERE id = ?', [req.body.tps_start, req.body.tps_end, req.params.id]);
    res.json({ status: 'success' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

// ============ CHAT ROUTES ============
// Get chat messages between current user and a specific client
app.get('/api/chat/:clientId', authenticate, async (req, res) => {
  try {
    var [messages] = await pool.execute(
      'SELECT cm.*, u.email as sender_email FROM chat_messages cm JOIN users u ON cm.sender_id = u.id WHERE (cm.sender_id = ? AND cm.receiver_id = ?) OR (cm.sender_id = ? AND cm.receiver_id = ?) ORDER BY cm.created_at ASC LIMIT 50',
      [req.user.id, req.params.clientId, req.params.clientId, req.user.id]
    );
    res.json({ status: 'success', data: messages });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// Send message to a client
app.post('/api/chat', authenticate, async (req, res) => {
  try {
    var { receiver_id, message } = req.body;
    await pool.execute('INSERT INTO chat_messages (sender_id, receiver_id, message) VALUES (?, ?, ?)',
      [req.user.id, receiver_id, message]);
    res.json({ status: 'success', message: 'Sent' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

// Get chat list (clients for admin, admin for clients)
app.get('/api/chat-list', authenticate, async (req, res) => {
  try {
    if (req.user.role === 'client') {
      // Client sees admin/dispatcher
      var [users] = await pool.execute("SELECT id, email FROM users WHERE role IN ('dispatcher','management') LIMIT 5");
    } else {
      // Admin sees clients who have chatted
      var [users] = await pool.execute("SELECT DISTINCT u.id, u.email FROM users u JOIN chat_messages cm ON (cm.sender_id = u.id OR cm.receiver_id = u.id) WHERE u.role = 'client' AND (cm.sender_id = ? OR cm.receiver_id = ?) LIMIT 20", [req.user.id, req.user.id]);
      if (users.length === 0) {
        var [users] = await pool.execute("SELECT id, email FROM users WHERE role = 'client' LIMIT 10");
      }
    }
    res.json({ status: 'success', data: users });
  } catch (error) { res.status(500).json({ error: error.message }); }
});


app.get("/api/client/atl/:id", authenticate, authorize("client"), async (req, res) => {
  try {
    var [atls] = await pool.execute("SELECT * FROM authority_to_load WHERE id = ? AND client_id = ?", [req.params.id, req.user.id]);
    if (!atls.length) return res.status(404).json({ error: "ATL not found" });
    res.json({ status: "success", data: atls[0] });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/demo-credentials', async (req, res) => {
  try {
    var [users] = await pool.execute(
      "SELECT email, role FROM users WHERE email IN (?, ?, ?)",
      ['admin@fueltrak.com', 'dispatcher@fueltrak.com', 'client1@hauler.com']
    );
    var credentials = {};
    users.forEach(function(u) {
      if (u.role === 'management') credentials.admin = u.email;
      if (u.role === 'dispatcher') credentials.dispatcher = u.email;
      if (u.role === 'client') credentials.client = u.email;
    });
    res.json({ status: 'success', data: credentials });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ BACKLOAD ROUTES ============
app.post('/api/backloads', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    var { atl_id, volume, reason } = req.body;
    await pool.execute('INSERT INTO backloads (atl_id, volume, reason, created_by) VALUES (?, ?, ?, ?)',
      [atl_id, volume, reason, req.user.id]);
    res.json({ status: 'success', message: 'Backload recorded' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.get('/api/backloads/:atlId', authenticate, async (req, res) => {
  try {
    var [backloads] = await pool.execute(
      'SELECT b.*, u.email as created_by_email FROM backloads b JOIN users u ON b.created_by = u.id WHERE b.atl_id = ? ORDER BY b.created_at DESC',
      [req.params.atlId]
    );
    res.json({ status: 'success', data: backloads });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/ttsd-checklist', (req, res) => res.sendFile(require('path').join(__dirname, '..', 'public', 'ttsd-checklist.html')));
app.get('/tutorial', (req, res) => res.sendFile(require('path').join(__dirname, '..', 'public', 'tutorial.html')));

app.get("/api/audit-logs", authenticate, authorize("dispatcher", "management"), async (req, res) => {
  try {
    var [logs] = await pool.execute("SELECT al.*, u.email FROM audit_logs al JOIN users u ON al.user_id = u.id ORDER BY al.created_at DESC LIMIT 100");
    res.json({ status: "success", data: logs });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/audit-logs', (req, res) => res.sendFile(require('path').join(__dirname, '..', 'public', 'audit-logs.html')));


app.get('/api/truck-masterlist', authenticate, async (req, res) => {
  try {
    var [rows] = await pool.execute('SELECT plate_no FROM truck_masterlist ORDER BY plate_no ASC');
    res.json({ status: 'success', data: rows });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/truck-masterlist/:plateNo', authenticate, async (req, res) => {
  try {
    var [rows] = await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no = ?', [req.params.plateNo.toUpperCase()]);
    if (rows.length) {
      res.json({ status: 'success', data: rows[0] });
    } else {
      res.json({ status: 'error', message: 'Truck not found' });
    }
  } catch (error) { res.status(500).json({ error: error.message }); }
});

module.exports = app;





