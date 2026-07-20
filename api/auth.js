// FuelTrak API v2.0 - COT Capacity Fix
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
const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT) || 587,
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});
async function sendOTP(email, mobile, otp, type) {
  // Try free SMS first
  if (mobile) {
    const smsSent = await sendFreeSMS(mobile, otp);
    if (smsSent) {
      console.log(`OTP sent via SMS to ${mobile}`);
      return;
    }
  }
  // Fallback to email
  await sendOTPEmail(email, otp, type);
}
const tokenBlacklist = new Set();
setInterval(() => { tokenBlacklist.forEach(t => { try { jwt.verify(t, process.env.JWT_SECRET ); } catch(e) { tokenBlacklist.delete(t); } }); }, 3600000);

app.set('trust proxy', 1);
app.use(express.json({ limit: "10kb" }));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(cors({ origin: ['https://fueltrak-seven.vercel.app', 'http://localhost:3000'], credentials: true }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: "Too many requests" },
  
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

// ============ INPUT VALIDATION ============
function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validateMobile(mobile) {
  return /^(09\d{9}|\+639\d{9})$/.test(mobile);
}

function sanitizeString(str, maxLength = 100) {
  if (!str) return '';
  return String(str).trim().substring(0, maxLength).replace(/[<>]/g, '');
}

// ============ ENHANCED RATE LIMITING ============
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Too many attempts. Try again later." },
  
});

// Apply strict rate limit to auth routes
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);
app.use('/api/auth/force-login', authLimiter);

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
    if (tokenBlacklist.has(token)) return res.status(401).json({ error: 'Token revoked. Please login again.' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET );
    const [rows] = await pool.execute('SELECT id, email, role, mobile, company_name, is_active FROM users WHERE id = ?', [decoded.id]);
    if (!rows.length || !rows[0].is_active) return res.status(401).json({ error: 'Invalid token' });
    req.user = rows[0];
    next();
  } catch (error) { res.status(401).json({ error: 'Invalid token' }); }
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
    await pool.execute('INSERT INTO users (email, password, mobile, company_name, role, is_verified, is_active, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())',
      [email, hashedPassword, mobile, company_name || null, 'client', false, true, NOW()]);
    const otp = generateOTP();
    otpCache.set(email, otp);
    await sendOTPEmail(email, otp, 'verification');
    res.status(201).json({ status: 'success', message: 'Registration successful. Check console for OTP.', email, otp });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

// ============ ACCOUNT LOCKOUT ============
const loginAttempts = new Map(); // In-memory store (use DB for production)

function getLoginKey(email) {
  return 'login_' + email.toLowerCase();
}

async function checkLockout(email) {
  const key = getLoginKey(email);
  const attempts = loginAttempts.get(key);
  if (attempts && attempts.count >= 5 && (Date.now() - attempts.lastAttempt) < 15 * 60 * 1000) {
    const minutesLeft = Math.ceil((15 * 60 * 1000 - (Date.now() - attempts.lastAttempt)) / 60000);
    return { locked: true, minutesLeft };
  }
  return { locked: false };
}

function recordFailedAttempt(email) {
  const key = getLoginKey(email);
  const current = loginAttempts.get(key) || { count: 0, lastAttempt: 0 };
  loginAttempts.set(key, { count: current.count + 1, lastAttempt: Date.now() });
}

function resetAttempts(email) {
  loginAttempts.delete(getLoginKey(email));
}

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
  await sendOTPEmail(email, otp, 'verification');
  res.json({ message: 'OTP resent', otp });
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    // Check lockout
    const lockout = await checkLockout(email);
    if (lockout.locked) {
      return res.status(429).json({ error: `Account locked. Try again in ${lockout.minutesLeft} minutes.` });
    }
    const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (!users.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = users[0];
    if (!user.is_verified) return res.status(401).json({ error: 'Please verify your email first' });
    if (!user.is_active) return res.status(403).json({ error: 'Account deactivated' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET , { expiresIn: '24h' });
    if (user.current_token) {
      try { jwt.verify(user.current_token, process.env.JWT_SECRET ); return res.json({ status: 'existing_session', message: 'Already logged in on another device.', user: { id: user.id, email: user.email, role: user.role } }); } catch(e) {}
    }
    await pool.execute('UPDATE users SET current_token = ?, last_login = NOW() WHERE id = ?', [token, user.id]);
    await logAudit(user.id, "LOGIN", "users", user.id, {email: user.email});
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
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET , { expiresIn: '24h' });
    await pool.execute('UPDATE users SET current_token = ?, last_login = NOW() WHERE id = ?', [token, user.id]);
    await logAudit(user.id, "LOGIN", "users", user.id, {email: user.email});
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

    
    await sendOTPEmail(email, otp, 'reset');
    res.json({ status: 'success', message: 'OTP sent. Check console.', otp });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/auth/verify-reset-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const storedOTP = otpCache.get('reset_' + email);
    if (!storedOTP || storedOTP !== otp) return res.status(400).json({ error: 'Invalid or expired OTP' });
    otpCache.del('reset_' + email);
    const resetToken = jwt.sign({ email, purpose: 'reset' }, process.env.JWT_SECRET , { expiresIn: '15m' });
    res.json({ status: 'success', message: 'OTP verified.', resetToken });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    const decoded = jwt.verify(resetToken, process.env.JWT_SECRET );
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

// ============ MASTERLIST SYNC ============
app.post('/api/sync-masterlist', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [masterlist] = await pool.execute(`SELECT tm.* FROM truck_masterlist tm WHERE tm.plate_no NOT IN (SELECT plate_no FROM trucks)`);
    let count = 0;
    let errors = [];
    for (const m of masterlist) {
      try {
        // Trim plate_no to 20 chars max
        const plateNo = (m.plate_no || '').substring(0, 20).toUpperCase();
        await pool.execute(
          'INSERT INTO trucks (plate_no, make, driver_name, hauler_name, total_capacity, is_active, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, 1, NOW(), NOW())',
          [plateNo, (m.truck_make || 'Unknown').substring(0, 50), (m.driver_name || '').replace(/"/g, '').substring(0, 100), (m.hauler_name || '').substring(0, 100), parseFloat(m.total_capacity) || 0]
        );
        count++;
      } catch (e) {
        errors.push(m.plate_no + ': ' + e.message);
      }
    }
    res.json({ status: 'success', message: `Synced ${count} trucks from masterlist`, count, errors: errors.slice(0, 5) });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

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

app.get('/api/dispatch/approved-for-loading', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [atls] = await pool.execute("SELECT * FROM authority_to_load WHERE status = 'approved' ORDER BY createdAt DESC");
    const result = [];
    for (const atl of atls) {
      const [trucks] = await pool.execute('SELECT * FROM trucks WHERE id = ?', [atl.truck_id]);
      const [clients] = await pool.execute('SELECT id, email, company_name FROM users WHERE id = ?', [atl.client_id]);
      result.push({ ...atl, truck: trucks[0] || null, client: clients[0] || null });
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
      result.push({ ...atl, truck: trucks[0] || null, client: clients[0] || null });
    }
    res.json({ status: 'success', data: result });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/dispatch/cancel-loading/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute("UPDATE authority_to_load SET status = 'pending', dispatch_date = NULL, remarks = ? WHERE id = ?",
      ['Loading cancelled: ' + (req.body.reason || 'No reason'), req.params.id]);
    res.json({ status: 'success', message: 'Cancelled' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/dispatch/handle-cancellation/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const status = req.body.action === 'approve_cancel' ? 'cancelled' : 'approved';
    await pool.execute('UPDATE authority_to_load SET status = ? WHERE id = ?', [status, req.params.id]);
    res.json({ status: 'success', message: 'Done' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.put('/api/dispatch/update-si/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute('UPDATE authority_to_load SET has_si = ? WHERE id = ?', [req.body.has_si, req.params.id]);
    res.json({ status: 'success' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.get('/api/dispatch/truck-stats', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [truckCounts] = await pool.execute('SELECT COUNT(*) as total, SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active, SUM(CASE WHEN is_active = 0 THEN 1 ELSE 0 END) as inactive, COALESCE(SUM(total_capacity), 0) as totalCapacity FROM trucks');
    const [docCounts] = await pool.execute(`
      SELECT 
        document_type,
        SUM(CASE WHEN expiry_date >= NOW() THEN 1 ELSE 0 END) as valid,
        SUM(CASE WHEN expiry_date < NOW() THEN 1 ELSE 0 END) as expired
      FROM truck_documents 
      WHERE document_type IN ('lto_registration','fire_permit','dost_calibration')
      GROUP BY document_type
    `);
    
    const docBreakdown = { lto: { valid: 0, expired: 0, missing: 0 }, fire: { valid: 0, expired: 0, missing: 0 }, dost: { valid: 0, expired: 0, missing: 0 } };
    docCounts.forEach(d => {
      const key = d.document_type === 'lto_registration' ? 'lto' : d.document_type === 'fire_permit' ? 'fire' : 'dost';
      docBreakdown[key].valid = d.valid || 0;
      docBreakdown[key].expired = d.expired || 0;
      docBreakdown[key].missing = (truckCounts[0].total * 3) - (d.valid + d.expired);
    });
    
    // Count trucks with all valid docs
    const [validTruckCount] = await pool.execute(`
      SELECT COUNT(*) as count FROM trucks t 
      WHERE t.is_active = 1 
      AND (SELECT COUNT(*) FROM truck_documents WHERE truck_id = t.id AND expiry_date >= NOW()) = 3
    `);
    
    const total = truckCounts[0].total;
    const withValidDocs = validTruckCount[0].count;
    const withExpiredDocs = total - withValidDocs;
    
    res.json({ status: 'success', data: {
      total, active: truckCounts[0].active, inactive: truckCounts[0].inactive,
      withExpiredDocs, withValidDocs, expiringSoon: 0,
      totalCapacity: truckCounts[0].totalCapacity,
      documentBreakdown: docBreakdown,
      trucksNeedingAttention: []
    }});
  } catch (error) { res.status(500).json({ error: error.message }); }
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
      if (docs.length === 0) {
        ['lto_registration','fire_permit','dost_calibration'].forEach(type => {
          docStatus[type] = { status: 'not_required', valid: true, days_remaining: 999 };
        });
      } else {
        ['lto_registration','fire_permit','dost_calibration'].forEach(type => {
          const doc = docs.find(d => d.document_type === type);
          const days = doc ? Math.ceil((new Date(doc.expiry_date) - new Date()) / 86400000) : -1;
          docStatus[type] = { status: days < 0 ? 'expired' : days <= 30 ? 'expiring_soon' : 'valid', valid: days >= 0, days_remaining: days };
          if (days < 0) allValid = false;
        });
      }
      return res.json({ status: 'success', data: { truck: { id: truck.id, plate_no: truck.plate_no, make: truck.make, driver_name: truck.driver_name, hauler_name: truck.hauler_name, total_capacity: truck.total_capacity }, documents: docStatus, can_proceed: allValid } });
    }
    const [master] = await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no = ?', [plateNo]);
    if (master.length > 0) {
      const [newTruck] = await pool.execute(
        'INSERT INTO trucks (plate_no, make, driver_name, hauler_name, total_capacity, is_active, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, 1, NOW(), NOW())',
        [master[0].plate_no, master[0].truck_make || 'Unknown', (master[0].driver_name || '').replace(/"/g, ''), master[0].hauler_name || '', master[0].total_capacity || 0]
      );
      return res.json({ status: 'success', data: { truck: { id: newTruck.insertId, plate_no: master[0].plate_no, make: master[0].truck_make, driver_name: master[0].driver_name, hauler_name: master[0].hauler_name, total_capacity: parseFloat(master[0].total_capacity) || [master[0].cot1,master[0].cot2,master[0].cot3,master[0].cot4,master[0].cot5,master[0].cot6,master[0].cot7,master[0].cot8,master[0].cot9,master[0].cot10].reduce((s,v)=>s+parseFloat(v||0),0) }, documents: { lto_registration: { status: 'not_required', valid: true, days_remaining: 999 }, fire_permit: { status: 'not_required', valid: true, days_remaining: 999 }, dost_calibration: { status: 'not_required', valid: true, days_remaining: 999 } }, can_proceed: true } });
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
      `INSERT INTO authority_to_load (atl_code, client_id, truck_id, company, so_number, volume, hauler, plate_no, driver_name, contact_number, has_si, scheduled_date, remarks, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [atlCode, req.user.id, truckId, company || req.user.company_name || '', so_number || null, volume || null, hauler || '', plateNo || '', driver || '', contact_number || null, has_si || false, scheduled_date || new Date().toISOString().split('T')[0], remarks || '', 'pending']
    );
    res.status(201).json({ status: 'success', message: 'ATL ' + atlCode + ' Submitted!', data: { atl_code: atlCode } });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/client/cancel-atl/:id', authenticate, authorize('client'), async (req, res) => {
  try {
    await pool.execute("UPDATE authority_to_load SET status = 'cancelled', remarks = ? WHERE id = ? AND client_id = ?", ['Cancellation: ' + (req.body.reason || ''), req.params.id, req.user.id]);
    await logAudit(req.user.id, "CANCEL_ATL", "authority_to_load", req.params.id, {reason: req.body.reason});
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

// ============ TRUCKS & DOCUMENTS ============
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

app.get('/api/truck-documents/:truckId', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [docs] = await pool.execute('SELECT * FROM truck_documents WHERE truck_id = ?', [req.params.truckId]);
    res.json({ status: 'success', data: docs });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/truck-documents/:truckId', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { document_type, document_number, issue_date, expiry_date } = req.body;
    const [existing] = await pool.execute('SELECT id FROM truck_documents WHERE truck_id = ? AND document_type = ?', [req.params.truckId, document_type]);
    if (existing.length) {
      await pool.execute('UPDATE truck_documents SET document_number = ?, issue_date = ?, expiry_date = ?, status = ? WHERE id = ?',
        [document_number || '', issue_date || new Date().toISOString().split('T')[0], expiry_date, new Date(expiry_date) >= new Date() ? 'valid' : 'expired', existing[0].id]);
    } else {
      await pool.execute('INSERT INTO truck_documents (truck_id, document_type, document_number, issue_date, expiry_date, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, NOW())',
        [req.params.truckId, document_type, document_number || '', issue_date || new Date().toISOString().split('T')[0], expiry_date, 'valid']);
    }
    res.json({ status: 'success', message: 'Document saved' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

// ============ TRUCK MASTERLIST ============
app.get('/api/truck-masterlist', authenticate, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT plate_no FROM truck_masterlist ORDER BY plate_no ASC');
    res.json({ status: 'success', data: rows });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/truck-masterlist/:plateNo', authenticate, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no = ?', [req.params.plateNo.toUpperCase()]);
    if (rows.length) { res.json({ status: 'success', data: rows[0] }); }
    else { res.json({ status: 'error', message: 'Truck not found' }); }
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
    const { startDate, endDate } = req.query;
    let query = "SELECT * FROM authority_to_load WHERE status IN ('completed','cancelled','dispatched')";
    const params = [];
    if (startDate) { query += ' AND (DATE(completed_date) >= ? OR DATE(createdAt) >= ?)'; params.push(startDate, startDate); }
    if (endDate) { query += ' AND (DATE(completed_date) <= ? OR DATE(createdAt) <= ?)'; params.push(endDate, endDate); }
    query += ' ORDER BY createdAt DESC';
    const [atls] = await pool.execute(query, params);
    const result = [];
    let totalVolume = 0, totalActualVolume = 0, completedCount = 0, cancelledCount = 0, dispatchedCount = 0;
    for (const atl of atls) {
      const [trucks] = await pool.execute('SELECT plate_no, make, total_capacity FROM trucks WHERE id = ?', [atl.truck_id]);
      const [clients] = await pool.execute('SELECT email, company_name FROM users WHERE id = ?', [atl.client_id]);
      const vol = parseFloat(atl.volume) || 0;
      const actualVol = parseFloat(atl.actual_volume) || vol;
      totalVolume += vol;
      totalActualVolume += actualVol;
      if (atl.status === 'completed') completedCount++;
      if (atl.status === 'cancelled') cancelledCount++;
      if (atl.status === 'dispatched') dispatchedCount++;
      result.push({ ...atl, truck: trucks[0] || null, client: clients[0] || null });
    }
    res.json({ status: 'success', data: { records: result, summary: { total_records: result.length, completed: completedCount, cancelled: cancelledCount, dispatched: dispatchedCount, total_volume: totalVolume, total_actual_volume: totalActualVolume } } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/reports/export', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    let query = "SELECT * FROM authority_to_load WHERE status IN ('completed','cancelled','dispatched')";
    const params = [];
    if (startDate) { query += ' AND DATE(createdAt) >= ?'; params.push(startDate); }
    if (endDate) { query += ' AND DATE(createdAt) <= ?'; params.push(endDate); }
    const [atls] = await pool.execute(query, params);
    let csv = 'ATL Code,Plate No,Driver,Volume,Status,Scheduled Date,Completed Date\n';
    for (const a of atls) {
      csv += `"${a.atl_code||''}","${a.plate_no||''}","${a.driver_name||''}","${a.volume||0}","${a.status}","${a.scheduled_date||''}","${a.completed_date||''}"\n`;
    }
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=report.csv');
    res.send(csv);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ============ BULK DOCUMENT SYNC ============
app.post('/api/sync-all-documents', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { batch = 0 } = req.body;
    const batchSize = 30;
    const offset = batch * batchSize;
    
    const [trucks] = await pool.execute('SELECT id FROM trucks ORDER BY id LIMIT ? OFFSET ?', [String(batchSize), String(offset)]);
    
    if (trucks.length === 0) {
      return res.json({ status: 'success', message: 'All done!', count: 0, done: true });
    }
    
    const types = ['lto_registration', 'fire_permit', 'dost_calibration'];
    const farFuture = '2030-12-31';
    let count = 0;
    
    for (const truck of trucks) {
      for (const type of types) {
        try {
          await pool.execute(
            'INSERT IGNORE INTO truck_documents (truck_id, document_type, expiry_date, status, createdAt) VALUES (?, ?, ?, ?, NOW())',
            [truck.id, type, farFuture, 'valid']
          );
          count++;
        } catch (e) { /* skip */ }
      }
    }
    
    res.json({ status: 'success', message: `Batch ${batch + 1}: ${count} docs created`, count, done: false, nextBatch: batch + 1 });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

// ============ AUDIT LOGS ============
app.get("/api/audit-logs", authenticate, authorize("dispatcher", "management"), async (req, res) => {
  try {
    const [logs] = await pool.execute("SELECT al.*, u.email FROM audit_logs al JOIN users u ON al.user_id = u.id ORDER BY al.created_at DESC LIMIT 100");
    res.json({ status: "success", data: logs });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ============ FAST DOC REPORT ============
app.get('/api/docs-report/summary', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [stats] = await pool.execute(`
      SELECT 
        COUNT(DISTINCT t.id) as totalTrucks,
        COUNT(DISTINCT CASE WHEN td.expiry_date >= NOW() THEN t.id END) as validDocs,
        COUNT(DISTINCT CASE WHEN td.expiry_date < NOW() THEN t.id END) as expiredDocs,
        COUNT(DISTINCT CASE WHEN td.id IS NULL THEN t.id END) as missingDocs
      FROM trucks t
      LEFT JOIN truck_documents td ON t.id = td.truck_id
    `);
    
    const [records] = await pool.execute(`
      SELECT t.plate_no, t.make, t.driver_name, t.hauler_name,
        MAX(CASE WHEN td.document_type = 'lto_registration' THEN td.expiry_date END) as lto_expiry,
        MAX(CASE WHEN td.document_type = 'fire_permit' THEN td.expiry_date END) as fire_expiry,
        MAX(CASE WHEN td.document_type = 'dost_calibration' THEN td.expiry_date END) as dost_expiry
      FROM trucks t
      LEFT JOIN truck_documents td ON t.id = td.truck_id
      GROUP BY t.id
      ORDER BY t.plate_no
    `);
    
    res.json({ status: 'success', data: { stats: stats[0], records } });
  } catch (error) { res.status(500).json({ error: error.message }); }
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

app.get('/api/clients/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [clients] = await pool.execute("SELECT id, email, mobile, company_name, is_active, is_verified, last_login, createdAt FROM users WHERE id = ? AND role = 'client'", [req.params.id]);
    if (!clients.length) return res.status(404).json({ error: 'Client not found' });
    res.json({ status: 'success', data: clients[0] });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/clients', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { email, password, mobile, company_name } = req.body;
    if (!email || !password || !mobile) return res.status(400).json({ error: 'Email, password, and mobile are required' });
    const [existing] = await pool.execute('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length) return res.status(400).json({ error: 'Email already registered' });
    const hashedPassword = await bcrypt.hash(password, 12);
    await pool.execute('INSERT INTO users (email, password, mobile, company_name, role, is_verified, is_active, createdAt, updatedAt) VALUES (?,?,?,?,?,1,1,NOW())',      [email, hashedPassword, mobile, company_name || null, 'client', NOW()]);
    await logAudit(req.user.id, "CREATE_CLIENT", "users", 0, {email});
    res.status(201).json({ status: 'success', message: 'Client created' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.put('/api/clients/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { email, mobile, company_name, password } = req.body;
    if (email) {
      const [dup] = await pool.execute('SELECT id FROM users WHERE email = ? AND id != ?', [email, req.params.id]);
      if (dup.length) return res.status(400).json({ error: 'Email already in use' });
    }
    let query = 'UPDATE users SET email=?, mobile=?, company_name=?';
    let params = [email, mobile, company_name];
    if (password && password.length >= 8) {
      const hashed = await bcrypt.hash(password, 12);
      query += ', password=?';
      params.push(hashed);
    }
    params.push(req.params.id);
    await pool.execute(query + ' WHERE id = ?', params);
    await logAudit(req.user.id, "UPDATE_CLIENT", "users", req.params.id, {email});
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
    await pool.execute("DELETE FROM users WHERE id = ? AND role = 'client'", [req.params.id]);
    res.json({ status: 'success', message: 'Client deleted' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

// ============ DATABASE MIGRATION ============
app.post('/api/migrate', authenticate, authorize('management'), async (req, res) => {
  const indexes = [
    { name: 'idx_atl_status', sql: 'CREATE INDEX idx_atl_status ON authority_to_load(status)' },
    { name: 'idx_atl_client_id', sql: 'CREATE INDEX idx_atl_client_id ON authority_to_load(client_id)' },
    { name: 'idx_atl_truck_id', sql: 'CREATE INDEX idx_atl_truck_id ON authority_to_load(truck_id)' },
    { name: 'idx_atl_created', sql: 'CREATE INDEX idx_atl_created ON authority_to_load(createdAt)' },
    { name: 'idx_atl_plate', sql: 'CREATE INDEX idx_atl_plate ON authority_to_load(plate_no)' },
    { name: 'idx_trucks_plate', sql: 'CREATE INDEX idx_trucks_plate ON trucks(plate_no)' },
    { name: 'idx_trucks_active', sql: 'CREATE INDEX idx_trucks_active ON trucks(is_active)' },
    { name: 'idx_docs_truck', sql: 'CREATE INDEX idx_docs_truck ON truck_documents(truck_id)' },
    { name: 'idx_docs_type', sql: 'CREATE INDEX idx_docs_type ON truck_documents(document_type)' },
    { name: 'idx_docs_expiry', sql: 'CREATE INDEX idx_docs_expiry ON truck_documents(expiry_date)' },
    { name: 'idx_users_email', sql: 'CREATE INDEX idx_users_email ON users(email)' },
    { name: 'idx_users_role', sql: 'CREATE INDEX idx_users_role ON users(role)' },
    { name: 'idx_master_plate', sql: 'CREATE INDEX idx_master_plate ON truck_masterlist(plate_no)' },
    { name: 'idx_audit_user', sql: 'CREATE INDEX idx_audit_user ON audit_logs(user_id)' },
    { name: 'idx_audit_created', sql: 'CREATE INDEX idx_audit_created ON audit_logs(created_at)' },
    { name: 'idx_chat_users', sql: 'CREATE INDEX idx_chat_users ON chat_messages(sender_id, receiver_id)' },
    { name: 'idx_chat_created', sql: 'CREATE INDEX idx_chat_created ON chat_messages(created_at)' },
    { name: 'idx_backload_atl', sql: 'CREATE INDEX idx_backload_atl ON backloads(atl_id)' },
  ];

  let created = 0, skipped = 0, failed = 0;
  const results = [];

  for (const idx of indexes) {
    try {
      await pool.execute(idx.sql);
      created++;
      results.push({ name: idx.name, status: 'created' });
    } catch (e) {
      if (e.code === 'ER_DUP_KEYNAME') {
        skipped++;
        results.push({ name: idx.name, status: 'exists' });
      } else {
        failed++;
        results.push({ name: idx.name, status: 'error', error: e.message });
      }
    }
  }

  res.json({ status: 'success', message: `Created: ${created}, Skipped: ${skipped}, Failed: ${failed}`, results });
});

// ============ LOGOUT ============
app.post('/api/auth/logout', authenticate, async (req, res) => {
  try { const t = req.header('Authorization')?.replace('Bearer ', ''); if(t){tokenBlacklist.add(t); await pool.execute('UPDATE users SET current_token = NULL WHERE id = ?',[req.user.id]);} await logAudit(req.user.id,'LOGOUT','users',req.user.id,{email:req.user.email}); res.json({status:'success',message:'Logged out'}); }
  catch(e) { res.status(400).json({error:e.message}); }
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








