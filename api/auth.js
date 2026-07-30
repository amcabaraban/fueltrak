// ============================================================
// FuelTrak API v3.0 - Main Application
// ============================================================
// A logistics management system for fuel truck dispatching
// ============================================================

// ============ DEPENDENCIES ============
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
const nodemailer = require('nodemailer');

// ============ APP INITIALIZATION ============
const app = express();

// ============ CACHE SETUP ============
const otpCache = new NodeCache({ stdTTL: 600 }); // 10 minutes for OTP
const serverCache = new NodeCache({ stdTTL: 60, checkperiod: 120 }); // 60 seconds for API responses

// ============ SECURE CONSOLE (Production) ============
if (process.env.NODE_ENV === 'production') {
  const originalConsole = {
    log: console.log,
    warn: console.warn,
    error: console.error,
    info: console.info,
    debug: console.debug
  };

  console.log = function() {};
  console.warn = function() {};
  console.info = function() {};
  console.debug = function() {};

  console.error = function(...args) {
    const sanitized = args.map(arg => {
      if (typeof arg === 'string') {
        return arg
          .replace(/password[=:]\S+/gi, 'password=***')
          .replace(/token[=:]\S+/gi, 'token=***')
          .replace(/secret[=:]\S+/gi, 'secret=***');
      }
      return arg;
    });
    originalConsole.error.apply(console, sanitized);
  };
}

// ============ LOGGER ============
const logger = {
  error: function(message, meta = {}) {
    const sanitizedMeta = { ...meta };
    delete sanitizedMeta.password;
    delete sanitizedMeta.token;
    delete sanitizedMeta.otp;
    
    if (process.env.NODE_ENV === 'production') {
      console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: 'error', message, meta: sanitizedMeta }));
    } else {
      console.error(`[${new Date().toISOString()}] ERROR:`, message, sanitizedMeta);
    }
  },

  info: function(message, meta = {}) {
    if (process.env.NODE_ENV !== 'production') {
      console.log(`[${new Date().toISOString()}] INFO:`, message, meta);
    }
  },

  warn: function(message, meta = {}) {
    if (process.env.NODE_ENV !== 'production') {
      console.warn(`[${new Date().toISOString()}] WARN:`, message, meta);
    }
  },

  audit: function(action, userId, details = {}) {
    const sanitized = { ...details };
    delete sanitized.password;
    delete sanitized.token;
    logAudit(userId, action, 'system', 0, sanitized).catch(() => {});
  }
};

// ============ EMAIL TRANSPORTER ============
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT) || 587,
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});

// ============ DATABASE CONNECTION ============
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 16287,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false },
  waitForConnections: true,
  connectionLimit: 25,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000,
  connectTimeout: 10000,
  acquireTimeout: 15000,
  timeout: 60000,
  charset: 'utf8mb4'
});

pool.on('error', (err) => logger.error('Database pool error', { error: err.message }));

// ============ MIDDLEWARE ============
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(cors({
  origin: [
    'https://fueltraksystem.vercel.app',
    'https://fueltrak-seven.vercel.app',
    'http://localhost:3000'
  ],
  credentials: true
}));

// Rate limiting
const generalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300, message: { error: 'Too many requests' } });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many attempts. Try again later.' } });

app.use('/api/', generalLimiter);
app.use('/api/chat', (req, res, next) => next()); // Skip rate limit for chat
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);

// ============ TOKEN BLACKLIST ============
const tokenBlacklist = new Set();
setInterval(() => {
  tokenBlacklist.forEach(token => {
    try { jwt.verify(token, process.env.JWT_SECRET); } catch (e) { tokenBlacklist.delete(token); }
  });
}, 3600000); // Clean every hour

// ============ CACHE HELPERS ============
function clearCache(pattern) {
  serverCache.keys().forEach(key => { if (key.includes(pattern)) serverCache.del(key); });
}

// ============ UTILITY FUNCTIONS ============
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validatePassword(password) {
  if (!password || password.length < 8) return { valid: false, error: 'Password must be at least 8 characters' };
  if (!/[A-Z]/.test(password)) return { valid: false, error: 'Password must contain an uppercase letter' };
  if (!/[a-z]/.test(password)) return { valid: false, error: 'Password must contain a lowercase letter' };
  if (!/[0-9]/.test(password)) return { valid: false, error: 'Password must contain a number' };
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) return { valid: false, error: 'Password must contain a special character' };
  return { valid: true };
}

function sanitize(str, maxLength = 100) {
  if (!str) return '';
  return String(str).trim().substring(0, maxLength).replace(/[<>]/g, '');
}

// ============ AUDIT LOGGING ============
async function logAudit(userId, action, tableName, recordId, details) {
  try {
    await pool.execute(
      'INSERT INTO audit_logs (user_id, action, table_name, record_id, details) VALUES (?, ?, ?, ?, ?)',
      [userId, action, tableName, recordId, JSON.stringify(details)]
    );
  } catch (e) { /* Silent fail - audit shouldn't break functionality */ }
}

// ============ ATL CODE GENERATOR ============
async function generateATLCode(company) {
  const prefix = (company || 'ATL').replace(/[^a-zA-Z]/g, '').substring(0, 3).toUpperCase().padEnd(3, 'X');
  const [rows] = await pool.execute('SELECT COUNT(*) as count FROM authority_to_load');
  return prefix + '-' + String(rows[0].count + 1).padStart(9, '0');
}

// ============ EMAIL/SMS FUNCTIONS ============
async function sendOTPEmail(email, mobile, otp, type) {
  if (mobile && mobile.length > 5) {
    sendFreeSMS(mobile, otp).catch(() => {});
  }

  if (!process.env.SMTP_USER) {
    logger.info('Dev OTP generated', { email: email.replace(/(.{3}).*(@.*)/, '$1***$2') });
    return;
  }

  try {
    await transporter.sendMail({
      from: `"FuelTrak" <${process.env.SMTP_USER}>`,
      to: email,
      subject: type === 'reset' ? 'FuelTrak - Password Reset OTP' : 'FuelTrak - Verify Your Email',
      html: `<div style="font-family:Arial;max-width:500px;margin:auto;padding:20px;border:1px solid #ddd;border-radius:10px">
        <h2 style="color:#1e3a5f">FuelTrak Logistics</h2>
        <p>Your OTP code is:</p>
        <h1 style="color:#1e3a5f;font-size:36px;letter-spacing:5px;text-align:center">${otp}</h1>
        <p>This code expires in 10 minutes.</p>
      </div>`
    });
    logger.info('OTP emailed', { email: email.replace(/(.{3}).*(@.*)/, '$1***$2') });
  } catch (e) {
    logger.error('Email send failed', { error: e.message });
    if (process.env.NODE_ENV !== 'production') {
      console.log('[FALLBACK] OTP generated (dev only)');
    }
  }
}

async function sendFreeSMS(mobile, otp) {
  if (!process.env.SMTP_USER) return false;

  const gateways = [
    mobile.replace('+63', '0') + '@txt.globe.com.ph',
    mobile.replace('+63', '0') + '@isms.smart.com.ph'
  ];

  for (const gw of gateways) {
    try {
      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: gw,
        subject: '',
        text: `FuelTrak OTP: ${otp}. Expires in 10 mins.`
      });
      logger.info('Free SMS sent', { mobile: mobile.replace(/(\d{3})\d{4}(\d{3})/, '$1****$2') });
      return true;
    } catch (e) { /* Try next gateway */ }
  }
  return false;
}

// ============ AUTHENTICATION MIDDLEWARE ============
const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Please authenticate' });
    if (tokenBlacklist.has(token)) return res.status(401).json({ error: 'Token revoked' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const [users] = await pool.execute(
      'SELECT id, email, role, mobile, company_name, is_active FROM users WHERE id = ?',
      [decoded.id]
    );

    if (!users.length || !users[0].is_active) return res.status(401).json({ error: 'Invalid token' });

    req.user = users[0];
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const authorize = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Access denied' });
  next();
};

// ============ ACCOUNT LOCKOUT ============
const loginAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

function getLoginKey(email) { return 'login_' + email.toLowerCase(); }

function checkLockout(email) {
  const key = getLoginKey(email);
  const attempts = loginAttempts.get(key);
  if (attempts && attempts.count >= MAX_ATTEMPTS && (Date.now() - attempts.lastAttempt) < LOCKOUT_DURATION) {
    const minutesLeft = Math.ceil((LOCKOUT_DURATION - (Date.now() - attempts.lastAttempt)) / 60000);
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

// ============================================================
// AUTH ROUTES
// ============================================================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, mobile, company_name } = req.body;

    if (!/^(09\d{9}|\+639\d{9})$/.test(mobile)) return res.status(400).json({ error: 'Invalid mobile format' });
    if (!validatePassword(password).valid) return res.status(400).json({ error: validatePassword(password).error });

    const [existing] = await pool.execute('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length) return res.status(400).json({ error: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, 12);
    await pool.execute(
      'INSERT INTO users (email, password, mobile, company_name, role, is_verified, is_active, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())',
      [email, hashedPassword, mobile, company_name || null, 'client', false, true]
    );

    const otp = generateOTP();
    otpCache.set(email, otp);
    await sendOTPEmail(email, '', otp, 'verification');

    res.status(201).json({ status: 'success', message: 'Registration successful', email, otp });
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
  await sendOTPEmail(email, '', otp, 'verification');

  res.json({ message: 'OTP resent', otp });
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!validateEmail(email)) return res.status(400).json({ error: 'Invalid email format' });

    // Check lockout
    const lockout = checkLockout(email);
    if (lockout.locked) return res.status(429).json({ error: `Account locked. Try again in ${lockout.minutesLeft} minutes.` });

    // Find user
    const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (!users.length) {
      recordFailedAttempt(email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = users[0];
    if (!user.is_verified) return res.status(401).json({ error: 'Please verify your email first' });
    if (!user.is_active) return res.status(403).json({ error: 'Account deactivated' });

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      recordFailedAttempt(email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    resetAttempts(email);

    // First login - require password change
    if (user.first_login === 1) {
      const tempToken = jwt.sign(
        { id: user.id, role: user.role, firstLogin: true },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
      );
      return res.json({ status: 'first_login', token: tempToken, message: 'First login - please set your password.' });
    }

    // Normal login
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '24h' });

    // Invalidate old token if exists
    if (user.current_token) {
      try { jwt.verify(user.current_token, process.env.JWT_SECRET); } catch (e) {}
      await pool.execute('UPDATE users SET current_token = NULL WHERE id = ?', [user.id]);
    }

    await pool.execute('UPDATE users SET current_token = ?, last_login = NOW() WHERE id = ?', [token, user.id]);
    await logAudit(user.id, 'LOGIN', 'users', user.id, { email: user.email });

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

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
    await pool.execute('UPDATE users SET current_token = ?, last_login = NOW() WHERE id = ?', [token, user.id]);
    await logAudit(user.id, 'LOGIN', 'users', user.id, { email: user.email });

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
    await sendOTPEmail(email, '', otp, 'reset');

    res.json({ status: 'success', message: 'OTP sent', otp });
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
    const resetToken = jwt.sign({ email, purpose: 'reset' }, process.env.JWT_SECRET, { expiresIn: '15m' });

    res.json({ status: 'success', message: 'OTP verified', resetToken });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;

    if (!newPassword || !validatePassword(newPassword).valid) {
      return res.status(400).json({ error: validatePassword(newPassword).error });
    }

    const decoded = jwt.verify(resetToken, process.env.JWT_SECRET);
    if (decoded.purpose !== 'reset') return res.status(400).json({ error: 'Invalid reset token' });

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    await pool.execute('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, decoded.email]);

    res.json({ status: 'success', message: 'Password reset successfully' });
  } catch (error) {
    if (error.name === 'TokenExpiredError') return res.status(400).json({ error: 'Reset token expired' });
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/auth/logout', authenticate, async (req, res) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (token) {
      tokenBlacklist.add(token);
      await pool.execute('UPDATE users SET current_token = NULL WHERE id = ?', [req.user.id]);
    }
    await logAudit(req.user.id, 'LOGOUT', 'users', req.user.id, { email: req.user.email });
    res.json({ status: 'success', message: 'Logged out' });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ============ FIRST LOGIN SETUP ============
app.post('/api/auth/first-login-setup', authenticate, async (req, res) => {
  try {
    const { password, terms_accepted } = req.body;

    if (!terms_accepted) return res.status(400).json({ error: 'You must accept the Terms & Conditions' });
    if (!validatePassword(password).valid) return res.status(400).json({ error: validatePassword(password).error });

    const hashedPassword = await bcrypt.hash(password, 12);
    await pool.execute('UPDATE users SET password = ?, terms_accepted = 1 WHERE id = ?', [hashedPassword, req.user.id]);

    const otp = generateOTP();
    otpCache.set(req.user.email, otp);
    await sendOTPEmail(req.user.email, '', otp, 'verification');

    await logAudit(req.user.id, 'FIRST_LOGIN_PASSWORD_CHANGED', 'users', req.user.id, {});

    res.json({
      status: 'otp_required',
      message: 'Password changed! Check your email for OTP.',
      email: req.user.email
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/auth/verify-first-login-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);

    if (!users.length) return res.status(404).json({ error: 'User not found' });

    const storedOTP = otpCache.get(email);
    if (!storedOTP || storedOTP !== otp) return res.status(400).json({ error: 'Invalid OTP' });

    otpCache.del(email);
    await pool.execute('UPDATE users SET is_verified = 1, first_login = 0 WHERE email = ?', [email]);

    const token = jwt.sign({ id: users[0].id, role: users[0].role }, process.env.JWT_SECRET, { expiresIn: '24h' });
    await logAudit(users[0].id, 'FIRST_LOGIN_OTP_VERIFIED', 'users', users[0].id, {});

    res.json({
      status: 'success',
      message: 'Email verified!',
      token,
      user: { id: users[0].id, email: users[0].email, role: users[0].role }
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/api/health', (req, res) => res.json({ status: 'OK', db: process.env.DB_NAME }));

// ============================================================
// DISPATCH ROUTES
// ============================================================

app.get('/api/dispatch/enhanced-stats', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const cacheKey = 'dispatch_enhanced_stats';
    const cached = serverCache.get(cacheKey);
    if (cached) return res.json(cached);

    const [stats] = await pool.execute(`
      SELECT 
        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
        SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
        SUM(CASE WHEN status = 'dispatched' THEN 1 ELSE 0 END) as loading,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
        SUM(CASE WHEN status IN ('dispatched','completed') AND DATE(dispatch_date) = CURDATE() THEN 1 ELSE 0 END) as loadedToday,
        COALESCE(SUM(CASE WHEN status IN ('dispatched','completed') THEN volume ELSE 0 END), 0) as totalVolume,
        COALESCE(SUM(CASE WHEN status IN ('dispatched','completed') AND DATE(dispatch_date) = CURDATE() THEN volume ELSE 0 END), 0) as todayVolume
      FROM authority_to_load
    `);

    const result = {
      status: 'success',
      data: {
        pending: stats[0].pending, approved: stats[0].approved,
        loading: stats[0].loading, completed: stats[0].completed,
        loadedToday: stats[0].loadedToday, totalVolume: stats[0].totalVolume,
        todayVolume: stats[0].todayVolume, totalBackload: 0, todayBackload: 0
      }
    };

    serverCache.set(cacheKey, result, 30);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/dispatch/truck-stats', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const cacheKey = 'dispatch_truck_stats';
    const cached = serverCache.get(cacheKey);
    if (cached) return res.json(cached);

    const [stats] = await pool.execute(`
      SELECT 
        COUNT(*) as total,
        SUM(is_active) as active,
        SUM(CASE WHEN is_active = 0 THEN 1 ELSE 0 END) as inactive,
        COALESCE(SUM(total_capacity), 0) as totalCapacity,
        (SELECT COUNT(DISTINCT t.id) FROM trucks t 
         INNER JOIN truck_documents td1 ON t.id = td1.truck_id AND td1.document_type = 'lto_registration' AND td1.expiry_date >= NOW()
         INNER JOIN truck_documents td2 ON t.id = td2.truck_id AND td2.document_type = 'fire_permit' AND td2.expiry_date >= NOW()
         INNER JOIN truck_documents td3 ON t.id = td3.truck_id AND td3.document_type = 'dost_calibration' AND td3.expiry_date >= NOW()
        ) as withValidDocs,
        (SELECT COUNT(DISTINCT t.id) FROM trucks t
         INNER JOIN truck_documents td ON t.id = td.truck_id AND td.expiry_date < NOW()
        ) as withExpiredDocs
      FROM trucks
    `);

    const result = {
      status: 'success',
      data: {
        total: stats[0].total, active: stats[0].active, inactive: stats[0].inactive,
        withExpiredDocs: stats[0].withExpiredDocs, withValidDocs: stats[0].withValidDocs,
        expiringSoon: 0, totalCapacity: stats[0].totalCapacity,
        documentBreakdown: { lto: {}, fire: {}, dost: {} }, trucksNeedingAttention: []
      }
    };

    serverCache.set(cacheKey, result, 60);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
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
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/dispatch/verify/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { action, remarks } = req.body;
    const status = action === 'approve' ? 'approved' : action === 'reject' ? 'rejected' : null;
    if (!status) return res.status(400).json({ error: 'Invalid action' });

    await pool.execute('UPDATE authority_to_load SET status = ?, verified_by = ?, remarks = ? WHERE id = ?',
      [status, req.user.id, remarks || null, req.params.id]);

    serverCache.del('dispatch_enhanced_stats');
    serverCache.del('dispatch_truck_stats');

    const [updated] = await pool.execute('SELECT * FROM authority_to_load WHERE id = ?', [req.params.id]);
    res.json({ status: 'success', data: updated[0] });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/dispatch/start-loading/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute("UPDATE authority_to_load SET status = 'dispatched', dispatch_date = NOW() WHERE id = ?", [req.params.id]);
    serverCache.del('dispatch_enhanced_stats');

    const [updated] = await pool.execute('SELECT * FROM authority_to_load WHERE id = ?', [req.params.id]);
    res.json({ status: 'success', message: 'Loading started', data: updated[0] });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/dispatch/complete-loading/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { actual_volume, remarks, printed_wc } = req.body;
    await pool.execute(
      "UPDATE authority_to_load SET status = 'completed', completed_date = NOW(), completed_by = ?, actual_volume = ?, remarks = ?, printed_wc = ? WHERE id = ?",
      [req.user.id, actual_volume || null, remarks || 'Loading completed', printed_wc || null, req.params.id]
    );

    serverCache.del('dispatch_enhanced_stats');
    serverCache.del('dispatch_truck_stats');

    const [updated] = await pool.execute('SELECT * FROM authority_to_load WHERE id = ?', [req.params.id]);
    res.json({ status: 'success', data: updated[0] });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
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
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
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
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/dispatch/update-wc/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute('UPDATE authority_to_load SET printed_wc = ? WHERE id = ?', [req.body.printed_wc || null, req.params.id]);
    res.json({ status: 'success', message: 'WC updated' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put('/api/dispatch/update-si/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute('UPDATE authority_to_load SET has_si = ? WHERE id = ?', [req.body.has_si, req.params.id]);
    res.json({ status: 'success' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put('/api/dispatch/update-so/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute('UPDATE authority_to_load SET so_number = ? WHERE id = ?', [req.body.so_number, req.params.id]);
    res.json({ status: 'success' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/dispatch/cancel-loading/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute("UPDATE authority_to_load SET status = 'pending', dispatch_date = NULL, remarks = ? WHERE id = ?",
      ['Loading cancelled: ' + (req.body.reason || 'No reason'), req.params.id]);
    res.json({ status: 'success', message: 'Cancelled' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============================================================
// CLIENT ROUTES
// ============================================================

app.get('/api/client/dashboard', authenticate, authorize('client'), async (req, res) => {
  try {
    const cacheKey = 'client_dashboard_' + req.user.id;
    const cached = serverCache.get(cacheKey);
    if (cached) return res.json(cached);

    const [atls] = await pool.execute(
      `SELECT atl.*, t.plate_no as truck_plate, t.make as truck_make 
       FROM authority_to_load atl LEFT JOIN trucks t ON atl.truck_id = t.id 
       WHERE atl.client_id = ? ORDER BY atl.createdAt DESC LIMIT 20`,
      [req.user.id]
    );

    const [counts] = await pool.execute(
      'SELECT status, COUNT(*) as count FROM authority_to_load WHERE client_id = ? GROUP BY status',
      [req.user.id]
    );

    const stats = { total: 0, pending: 0, approved: 0, dispatched: 0, completed: 0, cancelled: 0 };
    counts.forEach(c => {
      if (c.status === 'cancelled' || c.status === 'rejected') stats.cancelled += c.count;
      else if (stats.hasOwnProperty(c.status)) stats[c.status] = c.count;
    });
    stats.total = Object.values(stats).reduce((a, b) => a + b, 0);

    const result = { status: 'success', data: { stats, recent: atls, recentATLs: atls } };
    serverCache.set(cacheKey, result, 30);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/client/verify-truck/:plateNo', authenticate, authorize('client'), async (req, res) => {
  try {
    const plateNo = decodeURIComponent(req.params.plateNo).toUpperCase().trim();

    // Check trucks table
    const [trucks] = await pool.execute('SELECT * FROM trucks WHERE plate_no = ? AND is_active = 1', [plateNo]);

    if (trucks.length > 0) {
      const truck = trucks[0];
      const [docs] = await pool.execute('SELECT * FROM truck_documents WHERE truck_id = ?', [truck.id]);
      const [masterRefresh] = await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no = ?', [plateNo]);

      const docStatus = {};
      let allValid = true;

      ['lto_registration', 'fire_permit', 'dost_calibration'].forEach(type => {
        const doc = docs.find(d => d.document_type === type);
        if (doc) {
          const days = Math.ceil((new Date(doc.expiry_date) - new Date()) / 86400000);
          docStatus[type] = {
            status: days < 0 ? 'expired' : days <= 30 ? 'expiring_soon' : 'valid',
            valid: days >= 0, days_remaining: days
          };
          if (days < 0) allValid = false;
        } else {
          docStatus[type] = { status: 'missing', valid: true, days_remaining: -1 };
        }
      });

      return res.json({
        status: 'success',
        data: {
          truck: {
            id: truck.id, plate_no: truck.plate_no, make: truck.make || 'Unknown',
            driver_name: (masterRefresh[0]?.driver_name || truck.driver_name || '').replace(/"/g, ''),
            hauler_name: masterRefresh[0]?.hauler_name || truck.hauler_name || '',
            total_capacity: truck.total_capacity || 0
          },
          documents: docStatus,
          can_proceed: allValid
        }
      });
    }

    // Check masterlist
    const [master] = await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no = ?', [plateNo]);

    if (master.length > 0) {
      const m = master[0];
      const cotTotal = [m.cot1, m.cot2, m.cot3, m.cot4, m.cot5, m.cot6, m.cot7, m.cot8, m.cot9, m.cot10]
        .reduce((sum, val) => sum + parseFloat(val || 0), 0);
      const totalCapacity = parseFloat(m.total_capacity) || cotTotal || 0;

      const [newTruck] = await pool.execute(
        'INSERT INTO trucks (plate_no, make, driver_name, hauler_name, total_capacity, is_active, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, 1, NOW(), NOW())',
        [m.plate_no, m.truck_make || 'Unknown', (m.driver_name || '').replace(/"/g, ''), m.hauler_name || '', totalCapacity]
      );

      return res.json({
        status: 'success',
        data: {
          truck: { id: newTruck.insertId, plate_no: m.plate_no, make: m.truck_make || 'Unknown', driver_name: (m.driver_name || '').replace(/"/g, ''), hauler_name: m.hauler_name || '', total_capacity: totalCapacity },
          documents: {
            lto_registration: { status: 'not_required', valid: true, days_remaining: 999 },
            fire_permit: { status: 'not_required', valid: true, days_remaining: 999 },
            dost_calibration: { status: 'not_required', valid: true, days_remaining: 999 }
          },
          can_proceed: true
        }
      });
    }

    res.status(404).json({ status: 'error', error: 'Truck not found', can_proceed: false });
  } catch (error) {
    res.status(500).json({ status: 'error', error: error.message, can_proceed: false });
  }
});

app.post('/api/client/submit-atl', authenticate, authorize('client'), async (req, res) => {
  try {
    const { truck_id, plate_no, volume, driver_name, hauler_name, company, so_number, scheduled_date, contact_number, has_si, special_instructions } = req.body;

    let truckId = truck_id;
    let driver = driver_name;
    let hauler = hauler_name;
    let plateNo = plate_no;

    // Resolve truck
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

    // Check duplicate
    const [existing] = await pool.execute(
      "SELECT id FROM authority_to_load WHERE client_id = ? AND truck_id = ? AND status IN ('pending','approved')",
      [req.user.id, truckId]
    );
    if (existing.length) return res.status(400).json({ error: 'You already have a pending ATL for this truck' });

    // Create ATL
    const atlCode = await generateATLCode(company || req.user.company_name);
    await pool.execute(
      `INSERT INTO authority_to_load (atl_code, client_id, truck_id, company, so_number, volume, hauler, plate_no, driver_name, contact_number, has_si, scheduled_date, special_instructions, status, createdAt) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NOW())`,
      [atlCode, req.user.id, truckId, company || '', so_number, volume, hauler || '', plateNo || '', driver || '', contact_number, has_si || false, scheduled_date || new Date().toISOString().split('T')[0], special_instructions || null]
    );

    // Clear caches
    serverCache.del('dispatch_enhanced_stats');
    serverCache.del('dispatch_truck_stats');
    clearCache('client_dashboard_' + req.user.id);

    res.status(201).json({ status: 'success', message: 'ATL ' + atlCode + ' Submitted!', data: { atl_code: atlCode } });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/client/cancel-atl/:id', authenticate, authorize('client'), async (req, res) => {
  try {
    await pool.execute(
      "UPDATE authority_to_load SET status = 'cancelled', remarks = ? WHERE id = ? AND client_id = ?",
      ['Cancellation: ' + (req.body.reason || ''), req.params.id, req.user.id]
    );
    await logAudit(req.user.id, 'CANCEL_ATL', 'authority_to_load', req.params.id, { reason: req.body.reason });
    res.json({ status: 'success', message: 'Cancellation requested' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/client/atl/:id', authenticate, authorize('client'), async (req, res) => {
  try {
    const [atls] = await pool.execute('SELECT * FROM authority_to_load WHERE id = ? AND client_id = ?', [req.params.id, req.user.id]);
    if (!atls.length) return res.status(404).json({ error: 'ATL not found' });
    res.json({ status: 'success', data: atls[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// TRUCK MASTERLIST ROUTES
// ============================================================

app.get('/api/truck-masterlist', authenticate, async (req, res) => {
  try {
    const cacheKey = 'truck_masterlist_plates';
    const cached = serverCache.get(cacheKey);
    if (cached) return res.json(cached);

    const [rows] = await pool.execute('SELECT plate_no FROM truck_masterlist ORDER BY plate_no ASC');
    const result = { status: 'success', data: rows };
    serverCache.set(cacheKey, result, 300);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/truck-masterlist-all', authenticate, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM truck_masterlist ORDER BY plate_no ASC');
    res.json({ status: 'success', data: rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/truck-masterlist-add', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { plate_no, truck_make, driver_name, hauler_name, tps_count, cot1, cot2, cot3, cot4, cot5, cot6, cot7, cot8, cot9, cot10, total_capacity } = req.body;
    await pool.execute(
      'INSERT INTO truck_masterlist (plate_no, truck_make, driver_name, hauler_name, tps_count, cot1, cot2, cot3, cot4, cot5, cot6, cot7, cot8, cot9, cot10, total_capacity) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
      [plate_no.toUpperCase(), truck_make, driver_name, hauler_name, tps_count, cot1, cot2, cot3, cot4, cot5, cot6, cot7, cot8, cot9, cot10, total_capacity]
    );
    res.json({ status: 'success', message: 'Truck added to masterlist' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/truck-masterlist-bulk', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { trucks } = req.body;
    let count = 0;
    for (const t of trucks) {
      await pool.execute(
        'INSERT INTO truck_masterlist (truck_make, plate_no, driver_name, hauler_name, cot1, cot2, cot3, cot4, cot5, cot6, cot7, cot8, cot9, cot10, total_capacity, tps_count) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        [t.truck_make || '', t.plate_no || '', t.driver_name || '', t.hauler_name || '', t.cot1 || '0', t.cot2 || '0', t.cot3 || '0', t.cot4 || '0', t.cot5 || '0', t.cot6 || '0', t.cot7 || '0', t.cot8 || '0', t.cot9 || '0', t.cot10 || '0', t.total_capacity || '0', t.tps_count || 0]
      );
      count++;
    }
    res.json({ status: 'success', message: `${count} trucks uploaded` });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/truck-masterlist-clear', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute('DELETE FROM truck_masterlist');
    await pool.execute('DELETE FROM truck_documents');
    await pool.execute('DELETE FROM trucks');
    res.json({ status: 'success', message: 'All tables cleared' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============================================================
// TRUCK DOCUMENTS ROUTES
// ============================================================

app.get('/api/docs-report/summary', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [records] = await pool.execute(`
      SELECT t.plate_no, t.make, t.driver_name, t.hauler_name,
        MAX(CASE WHEN td.document_type = 'lto_registration' THEN td.expiry_date END) as lto_expiry,
        MAX(CASE WHEN td.document_type = 'fire_permit' THEN td.expiry_date END) as fire_expiry,
        MAX(CASE WHEN td.document_type = 'dost_calibration' THEN td.expiry_date END) as dost_expiry
      FROM trucks t LEFT JOIN truck_documents td ON t.id = td.truck_id
      GROUP BY t.id ORDER BY t.plate_no
    `);

    res.json({ status: 'success', data: { stats: { totalTrucks: records.length }, records } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/truck-documents/:truckId', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [docs] = await pool.execute('SELECT * FROM truck_documents WHERE truck_id = ?', [req.params.truckId]);
    res.json({ status: 'success', data: docs });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
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
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============================================================
// SALES ORDERS ROUTES
// ============================================================

// GET /api/sales-orders/clients-list (must be before /:id)
app.get('/api/sales-orders/clients-list', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [clients] = await pool.execute("SELECT id, email, company_name FROM users WHERE role = 'client' AND is_active = 1 ORDER BY company_name ASC");
    res.json({ status: 'success', data: clients });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/sales-orders/validate (must be before /:id)
app.get('/api/sales-orders/validate', authenticate, async (req, res) => {
  try {
    const { so_number, client_id } = req.query;
    if (!so_number) return res.status(400).json({ error: 'SO Number required' });

    const [orders] = await pool.execute(
      `SELECT so.*, u.company_name as client_company FROM sales_orders so JOIN users u ON so.client_id = u.id WHERE so.so_number = ? AND so.status = 'active'`,
      [so_number]
    );

    if (!orders.length) return res.json({ status: 'error', valid: false, message: 'Sales Order not found or inactive' });

    const order = orders[0];
    let belongsToClient = order.client_id == client_id;

    if (!belongsToClient && order.is_multi_client) {
      const [allocCheck] = await pool.execute('SELECT id FROM sales_order_clients WHERE sales_order_id = ? AND client_id = ?', [order.id, client_id]);
      belongsToClient = allocCheck.length > 0;
    }

    if (!belongsToClient) return res.json({ status: 'error', valid: false, message: 'SO does not belong to your account', so_owner: order.client_company });

    const [atlUsage] = await pool.execute(`SELECT COALESCE(SUM(volume), 0) as used FROM authority_to_load WHERE so_number = ? AND status NOT IN ('cancelled','rejected')`, [so_number]);

    const total = parseFloat(order.total_volume) || 0;
    const used = parseFloat(atlUsage[0].used) || 0;

    res.json({
      status: 'success', valid: true,
      data: { so_id: order.id, so_number: order.so_number, total_volume: total, used_volume: used, remaining_volume: Math.max(0, total - used), is_multi_client: order.is_multi_client, owner_company: order.client_company }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/sales-orders
app.get('/api/sales-orders', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { search, client_id, status } = req.query;
    let query = `SELECT so.*, u.company_name as client_company, u.email as client_email FROM sales_orders so JOIN users u ON so.client_id = u.id WHERE 1=1`;
    let params = [];

    if (search) { query += ' AND (so.so_number LIKE ? OR so.company_name LIKE ?)'; params.push('%' + search + '%', '%' + search + '%'); }
    if (client_id) { query += ' AND so.client_id = ?'; params.push(client_id); }
    if (status) { query += ' AND so.status = ?'; params.push(status); }

    query += ' ORDER BY so.createdAt DESC LIMIT 200';
    const [orders] = await pool.execute(query, params);
    const result = [];

    for (const order of orders) {
      const [allocations] = await pool.execute(`SELECT soc.*, u.company_name, u.email FROM sales_order_clients soc JOIN users u ON soc.client_id = u.id WHERE soc.sales_order_id = ?`, [order.id]);
      const [atlUsage] = await pool.execute(`SELECT COALESCE(SUM(volume), 0) as used FROM authority_to_load WHERE so_number = ? AND status NOT IN ('cancelled','rejected')`, [order.so_number]);
      result.push({ ...order, allocations, used_volume: parseFloat(atlUsage[0].used) });
    }

    res.json({ status: 'success', data: result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/sales-orders
app.post('/api/sales-orders', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { so_number, client_id, company_name, total_volume, is_multi_client, notes, allocations } = req.body;
    if (!so_number || !client_id) return res.status(400).json({ error: 'SO Number and Client required' });

    const [existing] = await pool.execute('SELECT id FROM sales_orders WHERE so_number = ? AND client_id = ?', [so_number, client_id]);
    if (existing.length) return res.status(400).json({ error: 'SO already exists for this client' });

    let company = company_name;
    if (!company) {
      const [c] = await pool.execute('SELECT company_name FROM users WHERE id = ?', [client_id]);
      company = c.length ? c[0].company_name : '';
    }

    const [result] = await pool.execute(
      'INSERT INTO sales_orders (so_number, client_id, company_name, total_volume, is_multi_client, notes, created_by) VALUES (?,?,?,?,?,?,?)',
      [so_number, client_id, company, total_volume || 0, is_multi_client ? 1 : 0, notes || null, req.user.id]
    );

    if (is_multi_client && allocations && allocations.length) {
      for (const alloc of allocations) {
        if (alloc.client_id && alloc.allocated_volume > 0) {
          const [ac] = await pool.execute('SELECT company_name FROM users WHERE id = ?', [alloc.client_id]);
          await pool.execute('INSERT INTO sales_order_clients (sales_order_id, client_id, company_name, allocated_volume) VALUES (?,?,?,?)',
            [result.insertId, alloc.client_id, ac.length ? ac[0].company_name : '', alloc.allocated_volume]);
        }
      }
    }

    await logAudit(req.user.id, 'CREATE_SO', 'sales_orders', result.insertId, { so_number, client_id });
    clearCache('sales_orders');
    res.status(201).json({ status: 'success', message: 'Sales Order created', data: { id: result.insertId, so_number } });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// GET /api/sales-orders/:id (must be after specific routes)
app.get('/api/sales-orders/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [orders] = await pool.execute(`SELECT so.*, u.company_name as client_company, u.email as client_email FROM sales_orders so JOIN users u ON so.client_id = u.id WHERE so.id = ?`, [req.params.id]);
    if (!orders.length) return res.status(404).json({ error: 'Not found' });

    const order = orders[0];
    const [allocations] = await pool.execute(`SELECT soc.*, u.company_name, u.email FROM sales_order_clients soc JOIN users u ON soc.client_id = u.id WHERE soc.sales_order_id = ?`, [order.id]);
    const [atls] = await pool.execute('SELECT id, atl_code, company, plate_no, volume, status, client_id, createdAt FROM authority_to_load WHERE so_number = ? ORDER BY createdAt DESC', [order.so_number]);

    res.json({ status: 'success', data: { ...order, allocations, atls } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/sales-orders/:id
app.put('/api/sales-orders/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { total_volume, is_multi_client, notes, status, allocations } = req.body;
    const [ex] = await pool.execute('SELECT * FROM sales_orders WHERE id = ?', [req.params.id]);
    if (!ex.length) return res.status(404).json({ error: 'Not found' });

    await pool.execute('UPDATE sales_orders SET total_volume=?, is_multi_client=?, notes=?, status=? WHERE id=?',
      [total_volume || ex[0].total_volume, is_multi_client !== undefined ? (is_multi_client ? 1 : 0) : ex[0].is_multi_client, notes || ex[0].notes, status || ex[0].status, req.params.id]);

    if (allocations && allocations.length) {
      await pool.execute('DELETE FROM sales_order_clients WHERE sales_order_id = ?', [req.params.id]);
      for (const alloc of allocations) {
        if (alloc.client_id && alloc.allocated_volume > 0) {
          const [ac] = await pool.execute('SELECT company_name FROM users WHERE id = ?', [alloc.client_id]);
          await pool.execute('INSERT INTO sales_order_clients (sales_order_id, client_id, company_name, allocated_volume) VALUES (?,?,?,?)',
            [req.params.id, alloc.client_id, ac.length ? ac[0].company_name : '', alloc.allocated_volume]);
        }
      }
    }

    clearCache('sales_orders');
    res.json({ status: 'success', message: 'Updated' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// DELETE /api/sales-orders/:id
app.delete('/api/sales-orders/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [ex] = await pool.execute('SELECT so_number FROM sales_orders WHERE id = ?', [req.params.id]);
    if (!ex.length) return res.status(404).json({ error: 'Not found' });

    const [atlCheck] = await pool.execute('SELECT COUNT(*) as count FROM authority_to_load WHERE so_number = ? AND status NOT IN ("cancelled","rejected")', [ex[0].so_number]);
    if (atlCheck[0].count > 0) return res.status(400).json({ error: 'Cannot delete: SO is used in ' + atlCheck[0].count + ' active ATLs' });

    await pool.execute('DELETE FROM sales_order_clients WHERE sales_order_id = ?', [req.params.id]);
    await pool.execute('DELETE FROM sales_orders WHERE id = ?', [req.params.id]);
    res.json({ status: 'success', message: 'Deleted' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// GET /api/client/sales-orders
app.get('/api/client/sales-orders', authenticate, authorize('client'), async (req, res) => {
  try {
    const [orders] = await pool.execute(`
      SELECT DISTINCT so.*, 
        COALESCE((SELECT SUM(atl.volume) FROM authority_to_load atl WHERE atl.so_number = so.so_number AND atl.client_id = ? AND atl.status NOT IN ('cancelled','rejected')), 0) as client_used_volume,
        COALESCE((SELECT SUM(atl.volume) FROM authority_to_load atl WHERE atl.so_number = so.so_number AND atl.status NOT IN ('cancelled','rejected')), 0) as total_used_volume
      FROM sales_orders so LEFT JOIN sales_order_clients soc ON so.id = soc.sales_order_id
      WHERE so.client_id = ? OR soc.client_id = ? ORDER BY so.createdAt DESC
    `, [req.user.id, req.user.id, req.user.id]);

    const result = orders.map(so => ({
      id: so.id, so_number: so.so_number,
      total_volume: parseFloat(so.total_volume) || 0,
      used_volume: so.is_multi_client ? parseFloat(so.total_used_volume) : parseFloat(so.client_used_volume),
      remaining_volume: Math.max(0, (parseFloat(so.total_volume) || 0) - (so.is_multi_client ? parseFloat(so.total_used_volume) : parseFloat(so.client_used_volume))),
      status: so.status, is_multi_client: so.is_multi_client == 1,
      company_name: so.company_name, notes: so.notes, createdAt: so.createdAt
    }));

    res.json({ status: 'success', data: result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// CHAT ROUTES
// ============================================================

app.get('/api/chat-list', authenticate, async (req, res) => {
  try {
    let users;
    if (req.user.role === 'client') {
      [users] = await pool.execute("SELECT id, email FROM users WHERE role IN ('dispatcher','management') LIMIT 5");
    } else {
      [users] = await pool.execute("SELECT id, email, company_name FROM users WHERE role = 'client' ORDER BY company_name LIMIT 50");
    }
    res.json({ status: 'success', data: users });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/chat/:clientId', authenticate, async (req, res) => {
  try {
    const [messages] = await pool.execute(
      'SELECT cm.*, u.email as sender_email FROM chat_messages cm JOIN users u ON cm.sender_id = u.id WHERE (cm.sender_id = ? AND cm.receiver_id = ?) OR (cm.sender_id = ? AND cm.receiver_id = ?) ORDER BY cm.created_at ASC LIMIT 50',
      [req.user.id, req.params.clientId, req.params.clientId, req.user.id]
    );
    res.json({ status: 'success', data: messages });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/chat', authenticate, async (req, res) => {
  try {
    await pool.execute('INSERT INTO chat_messages (sender_id, receiver_id, message) VALUES (?, ?, ?)', [req.user.id, req.body.receiver_id, req.body.message]);
    res.json({ status: 'success', message: 'Sent' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============================================================
// REPORTS ROUTES
// ============================================================

app.get('/api/reports/summary', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    let query = "SELECT * FROM authority_to_load WHERE status IN ('completed','cancelled','dispatched','rejected')";
    const params = [];

    if (startDate) { query += ' AND DATE(createdAt) >= ?'; params.push(startDate); }
    if (endDate) { query += ' AND DATE(createdAt) <= ?'; params.push(endDate); }
    query += ' ORDER BY createdAt DESC';

    const [atls] = await pool.execute(query, params);
    const result = [];

    for (const atl of atls) {
      const [trucks] = await pool.execute('SELECT plate_no, make FROM trucks WHERE id = ?', [atl.truck_id]);
      result.push({ ...atl, truck: trucks[0] || null });
    }

    res.json({ status: 'success', data: { records: result } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/atl/summary', authenticate, async (req, res) => {
  try {
    const [atls] = await pool.execute('SELECT * FROM authority_to_load WHERE client_id = ? ORDER BY createdAt DESC LIMIT 50', [req.user.id]);
    const result = [];

    for (const atl of atls) {
      const [trucks] = await pool.execute('SELECT plate_no, make FROM trucks WHERE id = ?', [atl.truck_id]);
      result.push({ ...atl, truck: trucks[0] || null });
    }

    res.json({ status: 'success', data: { recent: result } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// ADMIN ROUTES
// ============================================================

app.get('/api/admin/optimize-database', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  const indexes = [
    { name: 'idx_atl_status_client', sql: 'CREATE INDEX idx_atl_status_client ON authority_to_load(status, client_id)' },
    { name: 'idx_atl_client_created', sql: 'CREATE INDEX idx_atl_client_created ON authority_to_load(client_id, createdAt)' },
    { name: 'idx_trucks_plate_active', sql: 'CREATE INDEX idx_trucks_plate_active ON trucks(plate_no, is_active)' },
    { name: 'idx_docs_truck_type_expiry', sql: 'CREATE INDEX idx_docs_truck_type_expiry ON truck_documents(truck_id, document_type, expiry_date)' },
    { name: 'idx_so_client_status', sql: 'CREATE INDEX idx_so_client_status ON sales_orders(client_id, status)' },
    { name: 'idx_users_role_active', sql: 'CREATE INDEX idx_users_role_active ON users(role, is_active)' },
  ];

  let created = 0, skipped = 0, failed = 0;
  const results = [];

  for (const idx of indexes) {
    try {
      await pool.execute(idx.sql);
      created++;
      results.push({ name: idx.name, status: 'created' });
    } catch (e) {
      if (e.code === 'ER_DUP_KEYNAME') { skipped++; results.push({ name: idx.name, status: 'exists' }); }
      else { failed++; results.push({ name: idx.name, status: 'error', error: e.message }); }
    }
  }

  res.json({ status: 'success', message: `Created: ${created}, Skipped: ${skipped}, Failed: ${failed}`, results });
});

app.get('/api/admin/create-so-table', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute(`CREATE TABLE IF NOT EXISTS sales_orders (id INT AUTO_INCREMENT PRIMARY KEY, so_number VARCHAR(50) NOT NULL, client_id INT NOT NULL, company_name VARCHAR(100), total_volume DECIMAL(12,2) DEFAULT 0, is_multi_client TINYINT(1) DEFAULT 0, status ENUM('active','completed','cancelled') DEFAULT 'active', notes TEXT, created_by INT, createdAt DATETIME DEFAULT CURRENT_TIMESTAMP, updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, UNIQUE KEY unique_so_client (so_number, client_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
    await pool.execute(`CREATE TABLE IF NOT EXISTS sales_order_clients (id INT AUTO_INCREMENT PRIMARY KEY, sales_order_id INT NOT NULL, client_id INT NOT NULL, company_name VARCHAR(100), allocated_volume DECIMAL(12,2) DEFAULT 0, createdAt DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE KEY unique_so_allocation (sales_order_id, client_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
    res.json({ status: 'success', message: 'Sales Order tables created' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/clients', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [clients] = await pool.execute("SELECT id, email, mobile, company_name, is_active FROM users WHERE role = 'client' ORDER BY createdAt DESC");
    res.json({ status: 'success', data: clients });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/users', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [users] = await pool.execute('SELECT id, email, role, mobile, company_name, is_active FROM users ORDER BY role, email');
    res.json({ status: 'success', data: users });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// STATIC FILES & PAGE ROUTES
// ============================================================

app.use('/public', express.static(path.join(__dirname, '..', 'public'), {
  maxAge: '1h',
  setHeaders: (res, filePath) => {
    res.setHeader('Cache-Control', filePath.endsWith('.html') ? 'public, max-age=0, must-revalidate' : 'public, max-age=3600');
  }
}));

const pages = [
  '', 'dashboard', 'client', 'sales-orders', 'docs-report', 'reports',
  'trucks', 'ttsd-checklist', 'tutorial', 'users', 'adminclient',
  'audit-logs', 'first-login', 'terms'
];

pages.forEach(page => {
  const route = page ? '/' + page : '/';
  const file = page ? page + '.html' : 'index.html';
  app.get(route, (req, res) => res.sendFile(path.join(__dirname, '..', 'public', file)));
});

// ============================================================
// EXPORT
// ============================================================
module.exports = app;