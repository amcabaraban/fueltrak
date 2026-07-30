// ============================================================
// FuelTrak API v3.0 - Production-Ready Application
// ============================================================
// Logistics Management System for Fuel Truck Dispatching
// Security-hardened with rate limiting, input validation, CSP
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

// ============ CONSTANTS ============
const BCRYPT_ROUNDS = 12;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes
const JWT_EXPIRY = '1h';
const REFRESH_TOKEN_EXPIRY = '7d';
const ALLOWED_UPDATE_FIELDS = ['tps_start', 'tps_end', 'printed_wc', 'has_si', 'so_number'];

// ============ CACHE SETUP ============
const otpCache = new NodeCache({ stdTTL: 600 });
const serverCache = new NodeCache({ stdTTL: 60, checkperiod: 120 });

// ============ SECURE CONSOLE (PRODUCTION) ============
if (process.env.NODE_ENV === 'production') {
  const origConsole = {
    log: console.log, warn: console.warn, error: console.error,
    info: console.info, debug: console.debug
  };
  console.log = () => {};
  console.warn = () => {};
  console.info = () => {};
  console.debug = () => {};
  console.error = (...args) => {
    const sanitized = args.map(arg => {
      if (typeof arg === 'string') {
        return arg
          .replace(/password[=:]\S+/gi, 'password=***')
          .replace(/token[=:]\S+/gi, 'token=***')
          .replace(/secret[=:]\S+/gi, 'secret=***')
          .replace(/Bearer\s+\S+/gi, 'Bearer ***')
          .replace(/otp[=:]\S+/gi, 'otp=***')
          .replace(/\b\d{6}\b/g, '******')
          .replace(/AVNS_\S+/gi, 'AVNS_***')
          .replace(/mysql-\S+\.aivencloud\.com/gi, '***.aivencloud.com');
      }
      return arg;
    });
    origConsole.error.apply(console, sanitized);
  };
}

// ============ LOGGER ============
const logger = {
  error: (message, meta = {}) => {
    const sanitized = { ...meta };
    delete sanitized.password; delete sanitized.token; delete sanitized.otp; delete sanitized.secret;
    if (process.env.NODE_ENV === 'production') {
      console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: 'error', message, meta: sanitized }));
    } else {
      console.error(`[${new Date().toISOString()}] ERROR:`, message, sanitized);
    }
  },
  info: (message, meta = {}) => {
    if (process.env.NODE_ENV !== 'production') console.log(`[${new Date().toISOString()}] INFO:`, message, meta);
  },
  warn: (message, meta = {}) => {
    if (process.env.NODE_ENV !== 'production') console.warn(`[${new Date().toISOString()}] WARN:`, message, meta);
  },
  audit: (action, userId, details = {}) => {
    const sanitized = { ...details };
    delete sanitized.password; delete sanitized.token;
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
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  
  // Prevent caching of sensitive pages
  if (req.path === '/' || req.path === '/index.html' || req.path === '/client') {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  
  next();
});

// Helmet with CSP
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "https://cdn.tailwindcss.com",
        "https://cdnjs.cloudflare.com"
      ],
      scriptSrcAttr: [
        "'self'",
        "'unsafe-inline'",
        "'unsafe-hashes'"
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://cdnjs.cloudflare.com"
      ],
      styleSrcAttr: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: [
        "'self'",
        "https://fueltraksystem.vercel.app",
        "https://fueltrak-seven.vercel.app"
      ],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
      baseUri: ["'self'"],
      upgradeInsecureRequests: [],
      requireTrustedTypesFor: ["'script'"]
    }
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

app.use(compression());

// CORS
app.use(cors({
  origin: function(origin, callback) {
    const allowed = ['https://fueltraksystem.vercel.app', 'https://fueltrak-seven.vercel.app', 'http://localhost:3000'];
    if (!origin || allowed.includes(origin)) {
      callback(null, true);
    } else {
      logger.warn('Blocked CORS', { origin });
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400
}));

// Rate Limiters
const generalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300, message: { error: 'Too many requests' }, standardHeaders: true, legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, message: { error: 'Rate limit exceeded' }, standardHeaders: true, legacyHeaders: false });
const strictLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: { error: 'Too many attempts. Try later.' }, standardHeaders: true, legacyHeaders: false });
const otpLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 3, message: { error: 'Too many OTP requests.' }, standardHeaders: true, legacyHeaders: false });

app.use('/api/', generalLimiter);
app.use('/api/chat', (req, res, next) => next());
app.use('/api/chat-list', (req, res, next) => next());
app.use('/api/auth/login', strictLimiter);
app.use('/api/auth/register', strictLimiter);
app.use('/api/auth/forgot-password', strictLimiter);
app.use('/api/auth/force-login', strictLimiter);
app.use('/api/auth/resend-otp', otpLimiter);
app.use('/api/auth/verify-otp', otpLimiter);
app.use('/api/auth/reset-password', strictLimiter);

// ============================================================
// ANTI-SCRAPING & BOT PROTECTION
// ============================================================

// ============ BOT USER AGENTS ============
const BOT_PATTERNS = [
  'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python',
  'java/', 'node-fetch', 'axios', 'go-http', 'ruby', 'perl',
  'scrapy', 'phpcrawl', 'httpclient', 'aiohttp', 'request',
  'mechanize', 'selenium', 'headless', 'puppeteer', 'playwright',
  'bytespider', 'petalbot', 'gptbot', 'chatgpt', 'openai',
  'claude', 'anthropic', 'bard', 'gemini', 'copilot',
  'ccbot', 'commoncrawl', 'semrush', 'ahrefs', 'mj12bot',
  'dotbot', 'rogerbot', 'exabot', 'yandexbot', 'baiduspider',
  'facebookexternalhit', 'twitterbot', 'slackbot', 'discordbot',
  'googlebot', 'bingbot', 'duckduckbot', 'yahoobot'
];

const BLOCKED_ASN_RANGES = [
  // Known AI/Scraping infrastructure ranges
  // These can be expanded based on your threat analysis
];

// ============ BOT DETECTION ============
function isBotUserAgent(userAgent) {
  if (!userAgent) return true; // Empty UA is suspicious
  const ua = userAgent.toLowerCase();
  return BOT_PATTERNS.some(pattern => ua.includes(pattern));
}

function isSuspiciousRequest(req) {
  const checks = {
    noUserAgent: !req.headers['user-agent'],
    noAcceptLanguage: !req.headers['accept-language'],
    noAccept: !req.headers['accept'],
    missingHeaders: !req.headers['user-agent'] && !req.headers['accept'],
    rapidRequests: false, // Checked via rate limiting
    knownBotUA: isBotUserAgent(req.headers['user-agent']),
    suspiciousIP: false
  };
  
  // Count suspicious indicators
  const suspiciousCount = Object.values(checks).filter(Boolean).length;
  return suspiciousCount >= 2;
}

// ============ ANTI-SCRAPING MIDDLEWARE ============
app.use((req, res, next) => {
  const clientIP = req.ip || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'] || '';
  
  // 1. Block known bot user agents
  if (isBotUserAgent(userAgent) && !userAgent.includes('googlebot')) {
    logger.warn('Bot blocked', { ip: clientIP, ua: userAgent.substring(0, 100), path: req.path });
    return res.status(403).json({ error: 'Access denied', reason: 'Automated access not permitted' });
  }
  
  // 2. Block suspicious requests
  if (isSuspiciousRequest(req)) {
    logger.warn('Suspicious request blocked', { ip: clientIP, ua: userAgent.substring(0, 100), path: req.path });
    return res.status(403).json({ error: 'Access denied', reason: 'Suspicious request detected' });
  }
  
  // 3. Add honeypot headers to confuse scrapers
  res.setHeader('X-Content-Protected-By', 'FuelTrak Security');
  res.setHeader('X-Frame-Options', 'DENY');
  
  next();
});

// ============ HONEYPOT ROUTES (Trap for bots) ============
app.get('/api/admin', (req, res) => {
  logger.warn('Honeypot hit: /api/admin', { ip: req.ip, ua: req.headers['user-agent'] });
  res.status(403).json({ error: 'Forbidden' });
});

app.get('/api/v1', (req, res) => {
  logger.warn('Honeypot hit: /api/v1', { ip: req.ip, ua: req.headers['user-agent'] });
  res.status(403).json({ error: 'Forbidden' });
});

app.get('/wp-admin', (req, res) => {
  logger.warn('Honeypot hit: /wp-admin', { ip: req.ip, ua: req.headers['user-agent'] });
  res.status(403).json({ error: 'Forbidden' });
});

app.get('/.env', (req, res) => {
  logger.warn('Honeypot hit: /.env', { ip: req.ip, ua: req.headers['user-agent'] });
  res.status(403).json({ error: 'Forbidden' });
});

app.get('/admin', (req, res) => {
  logger.warn('Honeypot hit: /admin', { ip: req.ip, ua: req.headers['user-agent'] });
  res.status(403).json({ error: 'Forbidden' });
});

// ============ RATE LIMITING BY FINGERPRINT ============
const fingerprintLimiter = rateLimit({
  windowMs: 60 * 1000,        // 1 minute
  max: 30,                     // 30 requests per minute per IP
  message: { error: 'Rate limit exceeded' },
  keyGenerator: (req) => {
    // Create fingerprint from IP + User-Agent
    return req.ip + '|' + (req.headers['user-agent'] || '').substring(0, 50);
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Apply fingerprint rate limit to API
app.use('/api/', fingerprintLimiter);

// ============ SCRAPER TRAP ENDPOINTS ============
// Fake endpoints that return fake data to poison AI training
app.get('/api/public-data', (req, res) => {
  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const isKnownScraper = BOT_PATTERNS.some(p => userAgent.includes(p));
  
  if (isKnownScraper) {
    // Return fake data to poison scrapers
    logger.info('Scraper trapped: /api/public-data', { ip: req.ip });
    return res.json({
      data: Array(10).fill(null).map((_, i) => ({
        id: i + 1000,
        name: 'REDACTED_' + Math.random().toString(36).substring(7),
        value: Math.floor(Math.random() * 99999),
        status: 'fake_data_for_ai_poisoning'
      }))
    });
  }
  
  res.status(404).json({ error: 'Not found' });
});

app.get('/api/users-list', (req, res) => {
  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const isKnownScraper = BOT_PATTERNS.some(p => userAgent.includes(p));
  
  if (isKnownScraper) {
    logger.info('Scraper trapped: /api/users-list', { ip: req.ip });
    return res.json({
      users: Array(20).fill(null).map(() => ({
        email: 'fake_' + Math.random().toString(36).substring(7) + '@poisoned-data.com',
        name: 'AI Poison Data',
        role: 'scraper_target'
      }))
    });
  }
  
  res.status(404).json({ error: 'Not found' });
});

// ============ RESPONSE OBFUSCATION ============
app.use((req, res, next) => {
  const originalJson = res.json.bind(res);
  
  res.json = function(data) {
    // Add random noise to confuse scrapers trying to fingerprint the API
    if (process.env.NODE_ENV === 'production') {
      // Add random response time variation (100-500ms delay for bots)
      const userAgent = (req.headers['user-agent'] || '').toLowerCase();
      if (BOT_PATTERNS.some(p => userAgent.includes(p))) {
        const delay = 100 + Math.floor(Math.random() * 400);
        setTimeout(() => originalJson(data), delay);
        return;
      }
    }
    return originalJson(data);
  };
  
  next();
});

// ============ TOKEN BLACKLIST ============
const tokenBlacklist = new Set();
setInterval(() => {
  tokenBlacklist.forEach(t => {
    try { jwt.verify(t, process.env.JWT_SECRET); } catch (e) { tokenBlacklist.delete(t); }
  });
}, 3600000);

// ============ CACHE HELPERS ============
function clearCache(pattern) {
  serverCache.keys().forEach(key => { if (key.includes(pattern)) serverCache.del(key); });
}

// ============ UTILITY FUNCTIONS ============
function generateOTP() { return Math.floor(100000 + Math.random() * 900000).toString(); }
function validateEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function sanitize(str, max = 100) { return str ? String(str).trim().substring(0, max).replace(/[<>]/g, '') : ''; }
function maskEmail(email) { return email ? email.replace(/(.{3}).*(@.*)/, '$1***$2') : '***'; }

function validatePassword(password) {
  if (!password || password.length < 8) return { valid: false, error: 'Password must be at least 8 characters' };
  if (!/[A-Z]/.test(password)) return { valid: false, error: 'Password must contain an uppercase letter' };
  if (!/[a-z]/.test(password)) return { valid: false, error: 'Password must contain a lowercase letter' };
  if (!/[0-9]/.test(password)) return { valid: false, error: 'Password must contain a number' };
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) return { valid: false, error: 'Password must contain a special character' };
  return { valid: true };
}

function validatePasswordComplexity(password) {
  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/.test(password);
}

async function hashPassword(password) {
  return await bcrypt.hash(password, BCRYPT_ROUNDS);
}

async function logAudit(userId, action, tableName, recordId, details) {
  try {
    await pool.execute('INSERT INTO audit_logs (user_id, action, table_name, record_id, details) VALUES (?,?,?,?,?)',
      [userId, action, tableName, recordId, JSON.stringify(details)]);
  } catch (e) { /* silent */ }
}

async function generateATLCode(company) {
  const prefix = (company || 'ATL').replace(/[^a-zA-Z]/g, '').substring(0, 3).toUpperCase().padEnd(3, 'X');
  const [rows] = await pool.execute('SELECT COUNT(*) as count FROM authority_to_load');
  return prefix + '-' + String(rows[0].count + 1).padStart(9, '0');
}

// ============ INPUT VALIDATION MIDDLEWARE ============
function validateATLInput(req, res, next) {
  const { volume, plate_no, company } = req.body;
  const errors = [];
  if (volume && (isNaN(volume) || volume <= 0 || volume > 100000)) errors.push('Volume must be between 1 and 100,000 liters');
  if (plate_no && plate_no.length > 20) errors.push('Plate number too long');
  if (company && company.length > 100) errors.push('Company name too long');
  if (errors.length) return res.status(400).json({ error: errors.join('. ') });
  next();
}

// ============ EMAIL/SMS ============
async function sendOTPEmail(email, mobile, otp, type) {
  if (mobile && mobile.length > 5) sendFreeSMS(mobile, otp).catch(() => {});
  if (!process.env.SMTP_USER) {
    logger.info('Dev OTP', { email: maskEmail(email) });
    return;
  }
  try {
    await transporter.sendMail({
      from: `"FuelTrak" <${process.env.SMTP_USER}>`,
      to: email,
      subject: type === 'reset' ? 'FuelTrak - Password Reset OTP' : 'FuelTrak - Verify Your Email',
      html: `<div style="font-family:Arial;max-width:500px;margin:auto;padding:20px;border:1px solid #ddd;border-radius:10px"><h2 style="color:#1e3a5f">FuelTrak Logistics</h2><p>Your OTP code is:</p><h1 style="color:#1e3a5f;font-size:36px;letter-spacing:5px;text-align:center">${otp}</h1><p>This code expires in 10 minutes.</p></div>`
    });
    logger.info('OTP emailed', { email: maskEmail(email) });
  } catch (e) {
    logger.error('Email failed', { error: e.message });
  }
}

async function sendFreeSMS(mobile, otp) {
  if (!process.env.SMTP_USER) return false;
  const gateways = [mobile.replace('+63', '0') + '@txt.globe.com.ph', mobile.replace('+63', '0') + '@isms.smart.com.ph'];
  for (const gw of gateways) {
    try {
      await transporter.sendMail({ from: process.env.SMTP_USER, to: gw, subject: '', text: `FuelTrak OTP: ${otp}. Expires in 10 mins.` });
      logger.info('SMS sent', { mobile: mobile.replace(/(\d{3})\d{4}(\d{3})/, '$1****$2') });
      return true;
    } catch (e) {}
  }
  return false;
}

// ============ AUTH MIDDLEWARE ============
const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Please authenticate' });
    if (tokenBlacklist.has(token)) return res.status(401).json({ error: 'Token revoked' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.type === 'refresh') return res.status(401).json({ error: 'Use access token, not refresh token' });
    const [users] = await pool.execute('SELECT id, email, role, mobile, company_name, is_active FROM users WHERE id = ?', [decoded.id]);
    if (!users.length || !users[0].is_active) return res.status(401).json({ error: 'Invalid token' });
    req.user = users[0];
    next();
  } catch (error) { res.status(401).json({ error: 'Invalid token' }); }
};

const authorize = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Access denied' });
  next();
};

// ============ ACCOUNT LOCKOUT ============
const loginAttempts = new Map();

function getLoginKey(email) { return 'login_' + email.toLowerCase(); }
function checkLockout(email) {
  const a = loginAttempts.get(getLoginKey(email));
  if (a && a.count >= MAX_LOGIN_ATTEMPTS && (Date.now() - a.lastAttempt) < LOCKOUT_DURATION_MS) {
    return { locked: true, minutesLeft: Math.ceil((LOCKOUT_DURATION_MS - (Date.now() - a.lastAttempt)) / 60000) };
  }
  return { locked: false };
}
function recordFailedAttempt(email) {
  const key = getLoginKey(email);
  const c = loginAttempts.get(key) || { count: 0, lastAttempt: 0 };
  loginAttempts.set(key, { count: c.count + 1, lastAttempt: Date.now() });
}
function resetAttempts(email) { loginAttempts.delete(getLoginKey(email)); }

// ============ WEB APPLICATION FIREWALL (WAF) - TUNED ============

const WAF_PATTERNS = {
  // Only block obvious SQL injection attempts
  sqli: /(\bUNION\s+SELECT\b|\bSELECT\s+.*\s+FROM\b.*--|\bINSERT\s+INTO\b.*\bVALUES\b.*--|\bDROP\s+TABLE\b)/i,
  
  // Only block obvious XSS (script tags in query params)
  xss: /(<script[\s>]|<\/script>|javascript\s*:\s*alert)/i,
  
  // Only block path traversal attempts
  pathTraversal: /(\.\.\/\.\.\/|\/etc\/passwd|\/\.env$|\/wp-admin$)/i,
};

function detectWAFViolation(req) {
  const url = req.originalUrl || req.url || '';
  const ua = (req.headers['user-agent'] || '');
  
  // Only check GET parameters and URL path, not body
  for (const [type, pattern] of Object.entries(WAF_PATTERNS)) {
    if (pattern.test(url) || pattern.test(ua)) {
      return { blocked: true, type };
    }
  }
  
  return { blocked: false };
}

app.use((req, res, next) => {
  const result = detectWAFViolation(req);
  
  if (result.blocked) {
    logger.warn('WAF blocked', { ip: req.ip, type: result.type, path: req.path });
    return res.status(403).json({ error: 'Request blocked by WAF' });
  }
  
  next();
});

// ============================================================
// AUTH ROUTES
// ============================================================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, mobile, company_name } = req.body;
    if (!/^(09\d{9}|\+639\d{9})$/.test(mobile)) return res.status(400).json({ error: 'Invalid mobile format' });
    if (!validatePasswordComplexity(password)) return res.status(400).json({ error: 'Password must have 8+ chars, 1 uppercase, 1 lowercase, 1 number, and 1 symbol.' });
    const [existing] = await pool.execute('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length) return res.status(400).json({ error: 'Email already registered' });
    const hashed = await hashPassword(password);
    await pool.execute('INSERT INTO users (email, password, mobile, company_name, role, is_verified, is_active, createdAt, updatedAt) VALUES (?,?,?,?,?,?,?,NOW(),NOW())',
      [email, hashed, mobile, company_name || null, 'client', false, true]);
    const otp = generateOTP();
    otpCache.set(email, otp);
    await sendOTPEmail(email, '', otp, 'verification');
    res.status(201).json({ status: 'success', message: 'Registration successful. Check your email for OTP.', email: maskEmail(email) });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (!users.length) return res.status(404).json({ error: 'User not found' });
    if (users[0].is_verified) return res.json({ message: 'Already verified' });
    const stored = otpCache.get(email);
    if (!stored || stored !== otp) return res.status(400).json({ error: 'Invalid OTP' });
    otpCache.del(email);
    await pool.execute('UPDATE users SET is_verified = 1 WHERE email = ?', [email]);
    res.json({ status: 'success', message: 'Email verified' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/auth/resend-otp', async (req, res) => {
  const { email } = req.body;
  const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
  if (!users.length) return res.status(404).json({ error: 'User not found' });
  if (users[0].is_verified) return res.json({ message: 'Already verified' });
  const otp = generateOTP();
  otpCache.set(email, otp);
  await sendOTPEmail(email, '', otp, 'verification');
  res.json({ status: 'success', message: 'OTP resent to your email' });
});

app.post('/api/auth/login', async (req, res) => {
  // Use consistent timing to prevent timing attacks
  const startTime = Date.now();
  
  try {
    const { email, password } = req.body;
    
    // Validate email format first
    if (!email || !password) {
      // Simulate bcrypt delay to prevent timing attacks
      await bcrypt.compare('dummy_password', '$2a$12$dummy_hash_for_timing_attack_prevention');
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    if (!validateEmail(email)) {
      await bcrypt.compare('dummy_password', '$2a$12$dummy_hash_for_timing_attack_prevention');
      return res.status(400).json({ error: 'Invalid email format' });
    }
    
    // Check lockout before any DB query
    const lockout = checkLockout(email);
    if (lockout.locked) {
      return res.status(429).json({ 
        error: 'Too many login attempts. Please try again later.',
        retryAfter: lockout.minutesLeft * 60
      });
    }
    
    // Find user
    const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    
    // ALWAYS run bcrypt.compare even if user doesn't exist
    // This prevents timing attacks that reveal valid emails
    const dummyHash = '$2a$12$LJ3m4ys3GZqGqGqGqGqGqO'; // Dummy bcrypt hash
    const user = users.length ? users[0] : null;
    
    // Always perform the password comparison with consistent timing
    const passwordMatch = user 
      ? await bcrypt.compare(password, user.password)
      : await bcrypt.compare(password, dummyHash); // Waste time if user doesn't exist
    
    // Generic error message - never reveal what was wrong
    if (!user || !passwordMatch) {
      recordFailedAttempt(email);
      
      // Ensure minimum response time to prevent timing attacks
      const elapsed = Date.now() - startTime;
      if (elapsed < 500) {
        await new Promise(resolve => setTimeout(resolve, 500 - elapsed));
      }
      
      return res.status(401).json({ 
        error: 'Invalid email or password',
        // Don't reveal remaining attempts - prevents attacker from knowing when to stop
      });
    }
    
    // Check account status with same generic error
    if (!user.is_verified || !user.is_active) {
      // Don't reveal which check failed
      await new Promise(resolve => setTimeout(resolve, 200));
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    resetAttempts(email);
    
    // First login flow
    if (user.first_login === 1) {
      const tempToken = jwt.sign(
        { id: user.id, role: user.role, firstLogin: true, iat: Math.floor(Date.now() / 1000) },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
      );
      return res.json({ 
        status: 'first_login', 
        token: tempToken, 
        message: 'Please set your password and accept the terms.' 
      });
    }
    
    // Normal login
    const accessToken = jwt.sign(
      { id: user.id, role: user.role, iat: Math.floor(Date.now() / 1000) },
      process.env.JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );
    
    const refreshToken = jwt.sign(
      { id: user.id, type: 'refresh', iat: Math.floor(Date.now() / 1000) },
      process.env.JWT_SECRET,
      { expiresIn: REFRESH_TOKEN_EXPIRY }
    );
    
    // Invalidate old tokens
    if (user.current_token) {
      try { jwt.verify(user.current_token, process.env.JWT_SECRET); } catch (e) {}
      await pool.execute('UPDATE users SET current_token = NULL WHERE id = ?', [user.id]);
    }
    
    await pool.execute('UPDATE users SET current_token = ?, last_login = NOW() WHERE id = ?', [accessToken, user.id]);
    await logAudit(user.id, 'LOGIN', 'users', user.id, { email: user.email });
    
    // Set secure cookie with token (optional, for added security)
    res.setHeader('Set-Cookie', [
      `fueltrak_token=${accessToken}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${60 * 60}`,
      `fueltrak_refresh=${refreshToken}; HttpOnly; Secure; SameSite=Strict; Path=/api/auth/refresh; Max-Age=${7 * 24 * 60 * 60}`
    ]);
    
    res.json({
      status: 'success',
      token: accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        mobile: user.mobile ? user.mobile.replace(/(\d{3})\d{4}(\d{4})/, '$1****$3') : null,
        company_name: user.company_name
      }
    });
    
  } catch (error) {
    // Don't leak error details
    logger.error('Login error', { error: error.message });
    
    // Ensure consistent response time even on errors
    const elapsed = Date.now() - startTime;
    if (elapsed < 500) {
      await new Promise(resolve => setTimeout(resolve, 500 - elapsed));
    }
    
    res.status(500).json({ error: 'An error occurred. Please try again.' });
  }
});

app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    if (decoded.type !== 'refresh') return res.status(400).json({ error: 'Invalid token type' });
    const [users] = await pool.execute('SELECT id, role FROM users WHERE id = ? AND is_active = 1', [decoded.id]);
    if (!users.length) return res.status(401).json({ error: 'User not found' });
    const newToken = jwt.sign({ id: users[0].id, role: users[0].role }, process.env.JWT_SECRET, { expiresIn: JWT_EXPIRY });
    res.json({ status: 'success', token: newToken });
  } catch (error) { res.status(401).json({ error: 'Invalid refresh token' }); }
});

app.get('/api/auth/profile', authenticate, (req, res) => res.json({ status: 'success', user: req.user }));

app.post('/api/auth/force-login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (!users.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = users[0];
    if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
    await pool.execute('UPDATE users SET current_token = ?, last_login = NOW() WHERE id = ?', [token, user.id]);
    await logAudit(user.id, 'LOGIN', 'users', user.id, { email: user.email });
    res.json({ status: 'success', token, user: { id: user.id, email: user.email, role: user.role, mobile: user.mobile, company_name: user.company_name } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const [users] = await pool.execute('SELECT id FROM users WHERE email = ?', [email]);
    if (!users.length) return res.json({ status: 'success', message: 'If the email exists, an OTP has been sent.' });
    const otp = generateOTP();
    otpCache.set('reset_' + email, otp);
    await sendOTPEmail(email, '', otp, 'reset');
    res.json({ status: 'success', message: 'If the email exists, an OTP has been sent.' });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/auth/verify-reset-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const stored = otpCache.get('reset_' + email);
    if (!stored || stored !== otp) return res.status(400).json({ error: 'Invalid or expired OTP' });
    otpCache.del('reset_' + email);
    const resetToken = jwt.sign({ email, purpose: 'reset' }, process.env.JWT_SECRET, { expiresIn: '15m' });
    res.json({ status: 'success', message: 'OTP verified', resetToken });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    if (!newPassword || !validatePasswordComplexity(newPassword)) return res.status(400).json({ error: 'Password must have 8+ chars, 1 uppercase, 1 lowercase, 1 number, and 1 symbol.' });
    const decoded = jwt.verify(resetToken, process.env.JWT_SECRET);
    if (decoded.purpose !== 'reset') return res.status(400).json({ error: 'Invalid reset token' });
    await pool.execute('UPDATE users SET password = ? WHERE email = ?', [await hashPassword(newPassword), decoded.email]);
    res.json({ status: 'success', message: 'Password reset' });
  } catch (error) {
    if (error.name === 'TokenExpiredError') return res.status(400).json({ error: 'Reset token expired' });
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/auth/logout', authenticate, async (req, res) => {
  try {
    const t = req.header('Authorization')?.replace('Bearer ', '');
    if (t) { tokenBlacklist.add(t); await pool.execute('UPDATE users SET current_token = NULL WHERE id = ?', [req.user.id]); }
    await logAudit(req.user.id, 'LOGOUT', 'users', req.user.id, { email: req.user.email });
    res.json({ status: 'success', message: 'Logged out' });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ============ FIRST LOGIN SETUP ============
app.post('/api/auth/first-login-setup', authenticate, async (req, res) => {
  try {
    const { password, terms_accepted } = req.body;
    if (!terms_accepted) return res.status(400).json({ error: 'You must accept the Terms & Conditions' });
    if (!validatePassword(password).valid) return res.status(400).json({ error: validatePassword(password).error });
    await pool.execute('UPDATE users SET password = ?, terms_accepted = 1 WHERE id = ?', [await hashPassword(password), req.user.id]);
    const otp = generateOTP();
    otpCache.set(req.user.email, otp);
    await sendOTPEmail(req.user.email, '', otp, 'verification');
    await logAudit(req.user.id, 'FIRST_LOGIN_PASSWORD_CHANGED', 'users', req.user.id, {});
    res.json({ status: 'otp_required', message: 'Password changed! Check email for OTP.', email: maskEmail(req.user.email) });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/auth/verify-first-login-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (!users.length) return res.status(404).json({ error: 'User not found' });
    const stored = otpCache.get(email);
    if (!stored || stored !== otp) return res.status(400).json({ error: 'Invalid OTP' });
    otpCache.del(email);
    await pool.execute('UPDATE users SET is_verified = 1, first_login = 0 WHERE email = ?', [email]);
    const token = jwt.sign({ id: users[0].id, role: users[0].role }, process.env.JWT_SECRET, { expiresIn: '24h' });
    await logAudit(users[0].id, 'FIRST_LOGIN_OTP_VERIFIED', 'users', users[0].id, {});
    res.json({ status: 'success', message: 'Email verified!', token, user: { id: users[0].id, email: users[0].email, role: users[0].role } });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/api/health', (req, res) => res.json({ status: 'OK', db: process.env.DB_NAME }));

// ============================================================
// DISPATCH ROUTES
// ============================================================

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
    const cacheKey = 'dispatch_enhanced_stats';
    const cached = serverCache.get(cacheKey);
    if (cached) return res.json(cached);
    const [stats] = await pool.execute(`
      SELECT SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as pending,
             SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) as approved,
             SUM(CASE WHEN status='dispatched' THEN 1 ELSE 0 END) as loading,
             SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed,
             SUM(CASE WHEN status IN ('dispatched','completed') AND DATE(dispatch_date)=CURDATE() THEN 1 ELSE 0 END) as loadedToday,
             COALESCE(SUM(CASE WHEN status IN ('dispatched','completed') THEN volume ELSE 0 END),0) as totalVolume,
             COALESCE(SUM(CASE WHEN status IN ('dispatched','completed') AND DATE(dispatch_date)=CURDATE() THEN volume ELSE 0 END),0) as todayVolume
      FROM authority_to_load`);
    const s = stats[0];
    const result = { status: 'success', data: { pending: s.pending, approved: s.approved, loading: s.loading, completed: s.completed, loadedToday: s.loadedToday, totalVolume: s.totalVolume, todayVolume: s.todayVolume, totalBackload: 0, todayBackload: 0 } };
    serverCache.set(cacheKey, result, 30);
    res.json(result);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/dispatch/truck-stats', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const cacheKey = 'dispatch_truck_stats';
    const cached = serverCache.get(cacheKey);
    if (cached) return res.json(cached);
    const [stats] = await pool.execute(`
      SELECT COUNT(*) as total, SUM(is_active) as active, SUM(CASE WHEN is_active=0 THEN 1 ELSE 0 END) as inactive,
             COALESCE(SUM(total_capacity),0) as totalCapacity,
             (SELECT COUNT(DISTINCT t.id) FROM trucks t INNER JOIN truck_documents td1 ON t.id=td1.truck_id AND td1.document_type='lto_registration' AND td1.expiry_date>=NOW() INNER JOIN truck_documents td2 ON t.id=td2.truck_id AND td2.document_type='fire_permit' AND td2.expiry_date>=NOW() INNER JOIN truck_documents td3 ON t.id=td3.truck_id AND td3.document_type='dost_calibration' AND td3.expiry_date>=NOW()) as withValidDocs,
             (SELECT COUNT(DISTINCT t.id) FROM trucks t INNER JOIN truck_documents td ON t.id=td.truck_id AND td.expiry_date<NOW()) as withExpiredDocs
      FROM trucks`);
    const s = stats[0];
    const result = { status: 'success', data: { total: s.total, active: s.active, inactive: s.inactive, withExpiredDocs: s.withExpiredDocs, withValidDocs: s.withValidDocs, expiringSoon: 0, totalCapacity: s.totalCapacity, documentBreakdown: { lto: {}, fire: {}, dost: {} }, trucksNeedingAttention: [] } };
    serverCache.set(cacheKey, result, 60);
    res.json(result);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/dispatch/pending', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [atls] = await pool.execute("SELECT * FROM authority_to_load WHERE status IN ('pending','verified') ORDER BY createdAt DESC");
    const result = [];
    for (const a of atls) {
      const [trucks] = await pool.execute('SELECT * FROM trucks WHERE id = ?', [a.truck_id]);
      const [clients] = await pool.execute('SELECT id, email, company_name FROM users WHERE id = ?', [a.client_id]);
      result.push({ ...a, truck: trucks[0] || null, client: clients[0] || null });
    }
    res.json({ status: 'success', data: result });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/dispatch/verify/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { action, remarks } = req.body;
    const status = action === 'approve' ? 'approved' : action === 'reject' ? 'rejected' : null;
    if (!status) return res.status(400).json({ error: 'Invalid action' });
    await pool.execute('UPDATE authority_to_load SET status=?, verified_by=?, remarks=? WHERE id=?', [status, req.user.id, remarks || null, req.params.id]);
    serverCache.del('dispatch_enhanced_stats'); serverCache.del('dispatch_truck_stats');
    const [updated] = await pool.execute('SELECT * FROM authority_to_load WHERE id = ?', [req.params.id]);
    res.json({ status: 'success', data: updated[0] });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/dispatch/start-loading/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute("UPDATE authority_to_load SET status='dispatched', dispatch_date=NOW() WHERE id=?", [req.params.id]);
    serverCache.del('dispatch_enhanced_stats');
    const [updated] = await pool.execute('SELECT * FROM authority_to_load WHERE id = ?', [req.params.id]);
    res.json({ status: 'success', message: 'Loading started', data: updated[0] });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/dispatch/complete-loading/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { actual_volume, remarks, printed_wc } = req.body;
    await pool.execute("UPDATE authority_to_load SET status='completed', completed_date=NOW(), completed_by=?, actual_volume=?, remarks=?, printed_wc=? WHERE id=?",
      [req.user.id, actual_volume || null, remarks || 'Loading completed', printed_wc || null, req.params.id]);
    serverCache.del('dispatch_enhanced_stats'); serverCache.del('dispatch_truck_stats');
    const [updated] = await pool.execute('SELECT * FROM authority_to_load WHERE id = ?', [req.params.id]);
    res.json({ status: 'success', data: updated[0] });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.put('/api/dispatch/update-wc/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try { await pool.execute('UPDATE authority_to_load SET printed_wc=? WHERE id=?', [req.body.printed_wc || null, req.params.id]); res.json({ status: 'success', message: 'WC updated' }); }
  catch (error) { res.status(400).json({ error: error.message }); }
});

app.put('/api/dispatch/update-si/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try { await pool.execute('UPDATE authority_to_load SET has_si=? WHERE id=?', [req.body.has_si, req.params.id]); res.json({ status: 'success' }); }
  catch (error) { res.status(400).json({ error: error.message }); }
});

app.put('/api/dispatch/update-tps/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const updates = []; const params = [];
    for (const [key, value] of Object.entries(req.body)) {
      if (ALLOWED_UPDATE_FIELDS.includes(key)) { updates.push(`${key}=?`); params.push(value); }
    }
    if (updates.length > 0) { params.push(req.params.id); await pool.execute('UPDATE authority_to_load SET ' + updates.join(',') + ' WHERE id=?', params); }
    res.json({ status: 'success' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.put('/api/dispatch/update-so/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try { await pool.execute('UPDATE authority_to_load SET so_number=? WHERE id=?', [req.body.so_number, req.params.id]); res.json({ status: 'success' }); }
  catch (error) { res.status(400).json({ error: error.message }); }
});

app.get('/api/dispatch/approved-for-loading', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [atls] = await pool.execute("SELECT * FROM authority_to_load WHERE status='approved' ORDER BY createdAt DESC");
    const result = [];
    for (const a of atls) {
      const [trucks] = await pool.execute('SELECT * FROM trucks WHERE id=?', [a.truck_id]);
      const [clients] = await pool.execute('SELECT id, email, company_name FROM users WHERE id=?', [a.client_id]);
      result.push({ ...a, truck: trucks[0] || null, client: clients[0] || null });
    }
    res.json({ status: 'success', data: result });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/dispatch/ongoing-loading', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [atls] = await pool.execute("SELECT * FROM authority_to_load WHERE status='dispatched' ORDER BY dispatch_date DESC");
    const result = [];
    for (const a of atls) {
      const [trucks] = await pool.execute('SELECT * FROM trucks WHERE id=?', [a.truck_id]);
      const [clients] = await pool.execute('SELECT id, email, company_name FROM users WHERE id=?', [a.client_id]);
      result.push({ ...a, truck: trucks[0] || null, client: clients[0] || null });
    }
    res.json({ status: 'success', data: result });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/dispatch/cancel-loading/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute("UPDATE authority_to_load SET status='pending', dispatch_date=NULL, remarks=? WHERE id=?",
      ['Loading cancelled: ' + (req.body.reason || 'No reason'), req.params.id]);
    res.json({ status: 'success', message: 'Cancelled' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/dispatch/handle-cancellation/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const status = req.body.action === 'approve_cancel' ? 'cancelled' : 'approved';
    await pool.execute('UPDATE authority_to_load SET status=? WHERE id=?', [status, req.params.id]);
    res.json({ status: 'success', message: 'Done' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

// ============================================================
// MASTERLIST SYNC
// ============================================================
app.post('/api/sync-masterlist', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [masterlist] = await pool.execute('SELECT tm.* FROM truck_masterlist tm WHERE tm.plate_no NOT IN (SELECT plate_no FROM trucks)');
    let count = 0, errors = [];
    for (const m of masterlist) {
      try {
        await pool.execute('INSERT INTO trucks (plate_no, make, driver_name, hauler_name, total_capacity, is_active, createdAt, updatedAt) VALUES (?,?,?,?,?,1,NOW(),NOW())',
          [(m.plate_no||'').substring(0,20).toUpperCase(), (m.truck_make||'Unknown').substring(0,50), (m.driver_name||'').replace(/"/g,'').substring(0,100), (m.hauler_name||'').substring(0,100), parseFloat(m.total_capacity)||0]);
        count++;
      } catch (e) { errors.push(m.plate_no + ': ' + e.message); }
    }
    res.json({ status: 'success', message: `Synced ${count} trucks`, count, errors: errors.slice(0,5) });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

// ============================================================
// CLIENT ROUTES
// ============================================================

app.get('/api/client/dashboard', authenticate, authorize('client'), async (req, res) => {
  try {
    const cacheKey = 'client_dashboard_' + req.user.id;
    const cached = serverCache.get(cacheKey);
    if (cached) return res.json(cached);
    const [atls] = await pool.execute('SELECT atl.*, t.plate_no as truck_plate, t.make as truck_make FROM authority_to_load atl LEFT JOIN trucks t ON atl.truck_id=t.id WHERE atl.client_id=? ORDER BY atl.createdAt DESC LIMIT 20', [req.user.id]);
    const [counts] = await pool.execute('SELECT status, COUNT(*) as count FROM authority_to_load WHERE client_id=? GROUP BY status', [req.user.id]);
    const stats = { total: 0, pending: 0, approved: 0, dispatched: 0, completed: 0, cancelled: 0 };
    counts.forEach(c => {
      if (c.status === 'cancelled' || c.status === 'rejected') stats.cancelled += c.count;
      else if (stats.hasOwnProperty(c.status)) stats[c.status] = c.count;
    });
    stats.total = Object.values(stats).reduce((a, b) => a + b, 0);
    const result = { status: 'success', data: { stats, recent: atls, recentATLs: atls } };
    serverCache.set(cacheKey, result, 30);
    res.json(result);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/client/verify-truck/:plateNo', authenticate, authorize('client'), async (req, res) => {
  try {
    const plateNo = decodeURIComponent(req.params.plateNo).toUpperCase().trim();
    const [trucks] = await pool.execute('SELECT * FROM trucks WHERE plate_no=? AND is_active=1', [plateNo]);
    if (trucks.length > 0) {
      const truck = trucks[0];
      const [docs] = await pool.execute('SELECT * FROM truck_documents WHERE truck_id=?', [truck.id]);
      const [masterRefresh] = await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no=?', [plateNo]);
      const docStatus = {}; let allValid = true;
      ['lto_registration','fire_permit','dost_calibration'].forEach(type => {
        const doc = docs.find(d => d.document_type === type);
        if (doc) {
          const days = Math.ceil((new Date(doc.expiry_date) - new Date()) / 86400000);
          docStatus[type] = { status: days < 0 ? 'expired' : days <= 30 ? 'expiring_soon' : 'valid', valid: days >= 0, days_remaining: days, expiry_date: doc.expiry_date, document_number: doc.document_number || '' };
          if (days < 0) allValid = false;
        } else { docStatus[type] = { status: 'missing', valid: true, days_remaining: -1 }; }
      });
      const freshDriver = (masterRefresh.length > 0 ? masterRefresh[0].driver_name : truck.driver_name) || truck.driver_name;
      const freshHauler = (masterRefresh.length > 0 ? masterRefresh[0].hauler_name : truck.hauler_name) || truck.hauler_name;
      return res.json({ status: 'success', data: { truck: { id: truck.id, plate_no: truck.plate_no, make: truck.make || 'Unknown', driver_name: freshDriver ? freshDriver.replace(/"/g,'') : '', hauler_name: freshHauler || '', total_capacity: truck.total_capacity || 0 }, documents: docStatus, can_proceed: allValid } });
    }
    const [master] = await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no=?', [plateNo]);
    if (master.length > 0) {
      const m = master[0];
      const cotTotal = [m.cot1,m.cot2,m.cot3,m.cot4,m.cot5,m.cot6,m.cot7,m.cot8,m.cot9,m.cot10].reduce((s,v) => s + parseFloat(v||0), 0);
      const totalCapacity = parseFloat(m.total_capacity) || cotTotal || 0;
      const [newTruck] = await pool.execute('INSERT INTO trucks (plate_no, make, driver_name, hauler_name, total_capacity, is_active, createdAt, updatedAt) VALUES (?,?,?,?,?,1,NOW(),NOW())',
        [m.plate_no, m.truck_make || 'Unknown', (m.driver_name||'').replace(/"/g,''), m.hauler_name || '', totalCapacity]);
      return res.json({ status: 'success', data: { truck: { id: newTruck.insertId, plate_no: m.plate_no, make: m.truck_make || 'Unknown', driver_name: (m.driver_name||'').replace(/"/g,''), hauler_name: m.hauler_name || '', total_capacity: totalCapacity }, documents: { lto_registration: { status: 'not_required', valid: true, days_remaining: 999 }, fire_permit: { status: 'not_required', valid: true, days_remaining: 999 }, dost_calibration: { status: 'not_required', valid: true, days_remaining: 999 } }, can_proceed: true } });
    }
    res.status(404).json({ status: 'error', error: 'Truck not found', can_proceed: false });
  } catch (error) { res.status(500).json({ status: 'error', error: error.message, can_proceed: false }); }
});

app.post('/api/client/submit-atl', authenticate, authorize('client'), validateATLInput, async (req, res) => {
  try {
    const { truck_id, plate_no, volume, driver_name, hauler_name, remarks, company, so_number, scheduled_date, contact_number, has_si, special_instructions } = req.body;
    let truckId = truck_id, plateNo = plate_no, driver = driver_name, hauler = hauler_name;
    if (truckId) {
      const [trucks] = await pool.execute('SELECT * FROM trucks WHERE id=? AND is_active=1', [truckId]);
      if (!trucks.length) return res.status(404).json({ error: 'Truck not found' });
      plateNo = trucks[0].plate_no;
      if (!driver) driver = trucks[0].driver_name;
      if (!hauler) hauler = trucks[0].hauler_name;
      const [mu] = await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no=?', [plateNo.toUpperCase()]);
      if (mu.length > 0) { if (!driver) driver = mu[0].driver_name; if (!hauler) hauler = mu[0].hauler_name; }
    } else if (plateNo) {
      const [trucks] = await pool.execute('SELECT * FROM trucks WHERE plate_no=? AND is_active=1', [plateNo.toUpperCase()]);
      if (trucks.length > 0) {
        truckId = trucks[0].id; if (!driver) driver = trucks[0].driver_name; if (!hauler) hauler = trucks[0].hauler_name;
      } else {
        const [master] = await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no=?', [plateNo.toUpperCase()]);
        if (master.length > 0) {
          const [nt] = await pool.execute('INSERT INTO trucks (plate_no, make, driver_name, hauler_name, total_capacity, is_active, createdAt, updatedAt) VALUES (?,?,?,?,?,1,NOW(),NOW())',
            [master[0].plate_no, master[0].truck_make || 'Unknown', (master[0].driver_name||'').replace(/"/g,''), master[0].hauler_name || '', master[0].total_capacity || 0]);
          truckId = nt.insertId; if (!driver) driver = master[0].driver_name; if (!hauler) hauler = master[0].hauler_name;
        }
      }
    }
    if (!truckId) return res.status(400).json({ error: 'Truck not found. Please verify the plate number.' });
    const [existing] = await pool.execute("SELECT id FROM authority_to_load WHERE client_id=? AND truck_id=? AND status IN ('pending','approved')", [req.user.id, truckId]);
    if (existing.length) return res.status(400).json({ error: 'You already have a pending ATL for this truck' });
    const atlCode = await generateATLCode(company || req.user.company_name);
    await pool.execute("INSERT INTO authority_to_load (atl_code, client_id, truck_id, company, so_number, volume, hauler, plate_no, driver_name, contact_number, has_si, scheduled_date, remarks, special_instructions, status, createdAt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',NOW())",
      [atlCode, req.user.id, truckId, sanitize(company || req.user.company_name, 100), sanitize(so_number, 50), volume, sanitize(hauler, 100), sanitize(plateNo, 20), sanitize(driver, 100), sanitize(contact_number, 20), has_si || false, scheduled_date || new Date().toISOString().split('T')[0], sanitize(remarks, 200), sanitize(special_instructions, 500)]);
    serverCache.del('dispatch_enhanced_stats'); serverCache.del('dispatch_truck_stats'); clearCache('client_dashboard_' + req.user.id);
    res.status(201).json({ status: 'success', message: 'ATL ' + atlCode + ' Submitted!', data: { atl_code: atlCode } });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/client/cancel-atl/:id', authenticate, authorize('client'), async (req, res) => {
  try {
    await pool.execute("UPDATE authority_to_load SET status='cancelled', remarks=? WHERE id=? AND client_id=?", ['Cancellation: ' + (req.body.reason || ''), req.params.id, req.user.id]);
    await logAudit(req.user.id, 'CANCEL_ATL', 'authority_to_load', req.params.id, { reason: req.body.reason });
    res.json({ status: 'success', message: 'Cancellation requested' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.get('/api/client/atl/:id', authenticate, authorize('client'), async (req, res) => {
  try {
    const [atls] = await pool.execute('SELECT * FROM authority_to_load WHERE id=? AND client_id=?', [req.params.id, req.user.id]);
    if (!atls.length) return res.status(404).json({ error: 'ATL not found' });
    res.json({ status: 'success', data: atls[0] });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/client/sales-orders', authenticate, authorize('client'), async (req, res) => {
  try {
    const [orders] = await pool.execute(`SELECT DISTINCT so.*, COALESCE((SELECT SUM(atl.volume) FROM authority_to_load atl WHERE atl.so_number=so.so_number AND atl.client_id=? AND atl.status NOT IN ('cancelled','rejected')),0) as client_used_volume, COALESCE((SELECT SUM(atl.volume) FROM authority_to_load atl WHERE atl.so_number=so.so_number AND atl.status NOT IN ('cancelled','rejected')),0) as total_used_volume FROM sales_orders so LEFT JOIN sales_order_clients soc ON so.id=soc.sales_order_id WHERE so.client_id=? OR soc.client_id=? ORDER BY so.createdAt DESC`, [req.user.id, req.user.id, req.user.id]);
    const result = orders.map(so => ({ id: so.id, so_number: so.so_number, total_volume: parseFloat(so.total_volume)||0, used_volume: so.is_multi_client ? parseFloat(so.total_used_volume) : parseFloat(so.client_used_volume), remaining_volume: Math.max(0, (parseFloat(so.total_volume)||0) - (so.is_multi_client ? parseFloat(so.total_used_volume) : parseFloat(so.client_used_volume))), status: so.status, is_multi_client: so.is_multi_client == 1, company_name: so.company_name, notes: so.notes, createdAt: so.createdAt }));
    res.json({ status: 'success', data: result });
  } catch (error) { res.status(500).json({ error: error.message }); }
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
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/truck-masterlist/:plateNo', authenticate, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no=?', [req.params.plateNo.toUpperCase()]);
    if (rows.length) res.json({ status: 'success', data: rows[0] });
    else res.json({ status: 'error', message: 'Truck not found' });
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
    const allowed = ['truck_make','driver_name','hauler_name','tps_count','plate_no','cot1','cot2','cot3','cot4','cot5','cot6','cot7','cot8','cot9','cot10','total_capacity'];
    const updates = [], params = [];
    for (const key in req.body) { if (allowed.includes(key)) { updates.push(key+'=?'); params.push(req.body[key]); } }
    if (!updates.length) return res.status(400).json({ error: 'No valid fields' });
    params.push(req.params.id);
    await pool.execute('UPDATE truck_masterlist SET ' + updates.join(',') + ' WHERE id=?', params);
    res.json({ status: 'success', message: 'Updated' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/truck-masterlist-add', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { plate_no, truck_make, driver_name, hauler_name, tps_count, cot1, cot2, cot3, cot4, cot5, cot6, cot7, cot8, cot9, cot10, total_capacity } = req.body;
    await pool.execute('INSERT INTO truck_masterlist (plate_no, truck_make, driver_name, hauler_name, tps_count, cot1, cot2, cot3, cot4, cot5, cot6, cot7, cot8, cot9, cot10, total_capacity) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
      [plate_no.toUpperCase(), truck_make, driver_name, hauler_name, tps_count, cot1, cot2, cot3, cot4, cot5, cot6, cot7, cot8, cot9, cot10, total_capacity]);
    res.json({ status: 'success', message: 'Truck added' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/truck-masterlist-clear', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try { await pool.execute('DELETE FROM truck_masterlist'); await pool.execute('DELETE FROM truck_documents'); await pool.execute('DELETE FROM trucks'); res.json({ status: 'success', message: 'All tables cleared' }); }
  catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/truck-masterlist-bulk', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { trucks } = req.body; let count = 0;
    for (const t of trucks) {
      await pool.execute('INSERT INTO truck_masterlist (truck_make, plate_no, driver_name, hauler_name, cot1, cot2, cot3, cot4, cot5, cot6, cot7, cot8, cot9, cot10, total_capacity, tps_count) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        [t.truck_make||'', t.plate_no||'', t.driver_name||'', t.hauler_name||'', t.cot1||'0', t.cot2||'0', t.cot3||'0', t.cot4||'0', t.cot5||'0', t.cot6||'0', t.cot7||'0', t.cot8||'0', t.cot9||'0', t.cot10||'0', t.total_capacity||'0', t.tps_count||0]);
      count++;
    }
    res.json({ status: 'success', message: `${count} trucks uploaded` });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

// ============================================================
// TRUCKS & DOCUMENTS ROUTES
// ============================================================

app.get('/api/trucks/all', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [trucks] = await pool.execute('SELECT * FROM trucks ORDER BY plate_no ASC');
    const result = [];
    for (const t of trucks) { const [docs] = await pool.execute('SELECT * FROM truck_documents WHERE truck_id=?', [t.id]); result.push({ ...t, documents: docs }); }
    res.json({ status: 'success', data: result });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.delete('/api/trucks/delete/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [master] = await pool.execute('SELECT plate_no FROM truck_masterlist WHERE id=?', [req.params.id]);
    if (master.length > 0) {
      const pn = master[0].plate_no;
      const [truck] = await pool.execute('SELECT id FROM trucks WHERE plate_no=?', [pn]);
      if (truck.length > 0) { await pool.execute('DELETE FROM truck_documents WHERE truck_id=?', [truck[0].id]); await pool.execute('DELETE FROM trucks WHERE plate_no=?', [pn]); }
      await pool.execute('DELETE FROM truck_masterlist WHERE id=?', [req.params.id]);
      await logAudit(req.user.id, 'DELETE_TRUCK', 'trucks', req.params.id, { plate_no: pn });
      return res.json({ status: 'success', message: 'Truck deleted' });
    }
    const [truck] = await pool.execute('SELECT plate_no FROM trucks WHERE id=?', [req.params.id]);
    if (!truck.length) return res.status(404).json({ error: 'Truck not found' });
    await pool.execute('DELETE FROM truck_documents WHERE truck_id=?', [req.params.id]);
    await pool.execute('DELETE FROM trucks WHERE id=?', [req.params.id]);
    await pool.execute('DELETE FROM truck_masterlist WHERE plate_no=?', [truck[0].plate_no]);
    await logAudit(req.user.id, 'DELETE_TRUCK', 'trucks', req.params.id, { plate_no: truck[0].plate_no });
    res.json({ status: 'success', message: 'Truck deleted' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.get('/api/truck-documents/:truckId', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try { const [docs] = await pool.execute('SELECT * FROM truck_documents WHERE truck_id=?', [req.params.truckId]); res.json({ status: 'success', data: docs }); }
  catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/truck-documents/:truckId', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { document_type, document_number, issue_date, expiry_date } = req.body;
    const [existing] = await pool.execute('SELECT id FROM truck_documents WHERE truck_id=? AND document_type=?', [req.params.truckId, document_type]);
    if (existing.length) {
      await pool.execute('UPDATE truck_documents SET document_number=?, issue_date=?, expiry_date=?, status=? WHERE id=?',
        [document_number||'', issue_date||new Date().toISOString().split('T')[0], expiry_date, new Date(expiry_date)>=new Date()?'valid':'expired', existing[0].id]);
    } else {
      await pool.execute('INSERT INTO truck_documents (truck_id, document_type, document_number, issue_date, expiry_date, status, createdAt) VALUES (?,?,?,?,?,?,NOW())',
        [req.params.truckId, document_type, document_number||'', issue_date||new Date().toISOString().split('T')[0], expiry_date, 'valid']);
    }
    res.json({ status: 'success', message: 'Document saved' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.get('/api/docs-report/summary', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [stats] = await pool.execute(`SELECT COUNT(DISTINCT t.id) as totalTrucks, COUNT(DISTINCT CASE WHEN td.expiry_date>=NOW() THEN t.id END) as validDocs, COUNT(DISTINCT CASE WHEN td.expiry_date<NOW() THEN t.id END) as expiredDocs, COUNT(DISTINCT CASE WHEN td.id IS NULL THEN t.id END) as missingDocs FROM trucks t LEFT JOIN truck_documents td ON t.id=td.truck_id`);
    const [records] = await pool.execute(`SELECT t.plate_no, t.make, t.driver_name, t.hauler_name, MAX(CASE WHEN td.document_type='lto_registration' THEN td.expiry_date END) as lto_expiry, MAX(CASE WHEN td.document_type='fire_permit' THEN td.expiry_date END) as fire_expiry, MAX(CASE WHEN td.document_type='dost_calibration' THEN td.expiry_date END) as dost_expiry FROM trucks t LEFT JOIN truck_documents td ON t.id=td.truck_id GROUP BY t.id ORDER BY t.plate_no`);
    res.json({ status: 'success', data: { stats: stats[0], records } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ============================================================
// SALES ORDERS ROUTES
// ============================================================

app.get('/api/sales-orders/clients-list', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try { const [clients] = await pool.execute("SELECT id, email, company_name FROM users WHERE role='client' AND is_active=1 ORDER BY company_name ASC"); res.json({ status: 'success', data: clients }); }
  catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/sales-orders/validate', authenticate, async (req, res) => {
  try {
    const { so_number, client_id } = req.query;
    if (!so_number) return res.status(400).json({ error: 'SO Number required' });
    const [orders] = await pool.execute("SELECT so.*, u.company_name as client_company FROM sales_orders so JOIN users u ON so.client_id=u.id WHERE so.so_number=? AND so.status='active'", [so_number]);
    if (!orders.length) return res.json({ status: 'error', valid: false, message: 'Sales Order not found or inactive' });
    const order = orders[0];
    let belongs = order.client_id == client_id;
    if (!belongs && order.is_multi_client) {
      const [ac] = await pool.execute('SELECT id FROM sales_order_clients WHERE sales_order_id=? AND client_id=?', [order.id, client_id]);
      belongs = ac.length > 0;
    }
    if (!belongs) return res.json({ status: 'error', valid: false, message: 'SO does not belong to your account', so_owner: order.client_company });
    const [usage] = await pool.execute("SELECT COALESCE(SUM(volume),0) as used FROM authority_to_load WHERE so_number=? AND status NOT IN ('cancelled','rejected')", [so_number]);
    const total = parseFloat(order.total_volume) || 0, used = parseFloat(usage[0].used) || 0;
    res.json({ status: 'success', valid: true, data: { so_id: order.id, so_number: order.so_number, total_volume: total, used_volume: used, remaining_volume: Math.max(0, total - used), is_multi_client: order.is_multi_client, owner_company: order.client_company } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.put('/api/sales-orders/sync-company-names', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute("UPDATE sales_orders so JOIN users u ON so.client_id=u.id SET so.company_name=u.company_name WHERE u.company_name IS NOT NULL AND u.company_name!=''");
    await pool.execute("UPDATE sales_order_clients soc JOIN users u ON soc.client_id=u.id SET soc.company_name=u.company_name WHERE u.company_name IS NOT NULL AND u.company_name!=''");
    res.json({ status: 'success', message: 'Company names synced' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.get('/api/sales-orders', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { search, client_id, status } = req.query;
    let query = 'SELECT so.*, u.company_name as client_company, u.email as client_email FROM sales_orders so JOIN users u ON so.client_id=u.id WHERE 1=1';
    const params = [];
    if (search) { query += ' AND (so.so_number LIKE ? OR so.company_name LIKE ?)'; params.push('%'+search+'%', '%'+search+'%'); }
    if (client_id) { query += ' AND so.client_id=?'; params.push(client_id); }
    if (status) { query += ' AND so.status=?'; params.push(status); }
    query += ' ORDER BY so.createdAt DESC LIMIT 200';
    const [orders] = await pool.execute(query, params);
    const result = [];
    for (const o of orders) {
      const [allocations] = await pool.execute('SELECT soc.*, u.company_name, u.email FROM sales_order_clients soc JOIN users u ON soc.client_id=u.id WHERE soc.sales_order_id=?', [o.id]);
      const [usage] = await pool.execute("SELECT COALESCE(SUM(volume),0) as used FROM authority_to_load WHERE so_number=? AND status NOT IN ('cancelled','rejected')", [o.so_number]);
      result.push({ ...o, allocations, used_volume: parseFloat(usage[0].used) });
    }
    res.json({ status: 'success', data: result });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/sales-orders', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { so_number, client_id, company_name, total_volume, is_multi_client, notes, allocations } = req.body;
    if (!so_number || !client_id) return res.status(400).json({ error: 'SO Number and Client required' });
    const [existing] = await pool.execute('SELECT id FROM sales_orders WHERE so_number=? AND client_id=?', [so_number, client_id]);
    if (existing.length) return res.status(400).json({ error: 'SO already exists for this client' });
    let company = company_name;
    if (!company) { const [c] = await pool.execute('SELECT company_name FROM users WHERE id=?', [client_id]); company = c.length ? c[0].company_name : ''; }
    const [result] = await pool.execute('INSERT INTO sales_orders (so_number, client_id, company_name, total_volume, is_multi_client, notes, created_by) VALUES (?,?,?,?,?,?,?)',
      [so_number, client_id, company, total_volume||0, is_multi_client?1:0, notes||null, req.user.id]);
    if (is_multi_client && allocations && allocations.length) {
      for (const a of allocations) {
        if (a.client_id && a.allocated_volume > 0) {
          const [ac] = await pool.execute('SELECT company_name FROM users WHERE id=?', [a.client_id]);
          await pool.execute('INSERT INTO sales_order_clients (sales_order_id, client_id, company_name, allocated_volume) VALUES (?,?,?,?)',
            [result.insertId, a.client_id, ac.length?ac[0].company_name:'', a.allocated_volume]);
        }
      }
    }
    await logAudit(req.user.id, 'CREATE_SO', 'sales_orders', result.insertId, { so_number, client_id });
    clearCache('sales_orders');
    res.status(201).json({ status: 'success', message: 'Sales Order created', data: { id: result.insertId, so_number } });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.get('/api/sales-orders/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [orders] = await pool.execute('SELECT so.*, u.company_name as client_company, u.email as client_email FROM sales_orders so JOIN users u ON so.client_id=u.id WHERE so.id=?', [req.params.id]);
    if (!orders.length) return res.status(404).json({ error: 'Not found' });
    const o = orders[0];
    const [allocations] = await pool.execute('SELECT soc.*, u.company_name, u.email FROM sales_order_clients soc JOIN users u ON soc.client_id=u.id WHERE soc.sales_order_id=?', [o.id]);
    const [atls] = await pool.execute('SELECT id, atl_code, company, plate_no, volume, status, client_id, createdAt FROM authority_to_load WHERE so_number=? ORDER BY createdAt DESC', [o.so_number]);
    res.json({ status: 'success', data: { ...o, allocations, atls } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.put('/api/sales-orders/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { total_volume, is_multi_client, notes, status, allocations } = req.body;
    const [ex] = await pool.execute('SELECT * FROM sales_orders WHERE id=?', [req.params.id]);
    if (!ex.length) return res.status(404).json({ error: 'Not found' });
    await pool.execute('UPDATE sales_orders SET total_volume=?, is_multi_client=?, notes=?, status=? WHERE id=?',
      [total_volume||ex[0].total_volume, is_multi_client!==undefined?(is_multi_client?1:0):ex[0].is_multi_client, notes||ex[0].notes, status||ex[0].status, req.params.id]);
    if (allocations && allocations.length) {
      await pool.execute('DELETE FROM sales_order_clients WHERE sales_order_id=?', [req.params.id]);
      for (const a of allocations) {
        if (a.client_id && a.allocated_volume > 0) {
          const [ac] = await pool.execute('SELECT company_name FROM users WHERE id=?', [a.client_id]);
          await pool.execute('INSERT INTO sales_order_clients (sales_order_id, client_id, company_name, allocated_volume) VALUES (?,?,?,?)',
            [req.params.id, a.client_id, ac.length?ac[0].company_name:'', a.allocated_volume]);
        }
      }
    }
    clearCache('sales_orders');
    res.json({ status: 'success', message: 'Updated' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.delete('/api/sales-orders/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [ex] = await pool.execute('SELECT so_number FROM sales_orders WHERE id=?', [req.params.id]);
    if (!ex.length) return res.status(404).json({ error: 'Not found' });
    const [check] = await pool.execute("SELECT COUNT(*) as count FROM authority_to_load WHERE so_number=? AND status NOT IN ('cancelled','rejected')", [ex[0].so_number]);
    if (check[0].count > 0) return res.status(400).json({ error: 'Cannot delete: SO used in ' + check[0].count + ' active ATLs' });
    await pool.execute('DELETE FROM sales_order_clients WHERE sales_order_id=?', [req.params.id]);
    await pool.execute('DELETE FROM sales_orders WHERE id=?', [req.params.id]);
    res.json({ status: 'success', message: 'Deleted' });
  } catch (error) { res.status(400).json({ error: error.message }); }
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
      [users] = await pool.execute("SELECT id, email FROM users WHERE role='client' ORDER BY company_name LIMIT 50");
      if (!users.length) [users] = await pool.execute("SELECT id, email FROM users WHERE role='client' LIMIT 50");
    }
    res.json({ status: 'success', data: users });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/chat/:clientId', authenticate, async (req, res) => {
  try {
    const [messages] = await pool.execute('SELECT cm.*, u.email as sender_email FROM chat_messages cm JOIN users u ON cm.sender_id=u.id WHERE (cm.sender_id=? AND cm.receiver_id=?) OR (cm.sender_id=? AND cm.receiver_id=?) ORDER BY cm.created_at ASC LIMIT 50',
      [req.user.id, req.params.clientId, req.params.clientId, req.user.id]);
    res.json({ status: 'success', data: messages });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/chat', authenticate, async (req, res) => {
  try { await pool.execute('INSERT INTO chat_messages (sender_id, receiver_id, message) VALUES (?,?,?)', [req.user.id, req.body.receiver_id, req.body.message]); res.json({ status: 'success', message: 'Sent' }); }
  catch (error) { res.status(400).json({ error: error.message }); }
});

app.get('/api/chat/unread', authenticate, async (req, res) => {
  try {
    const [result] = await pool.execute("SELECT COUNT(*) as unread FROM chat_messages WHERE receiver_id=? AND created_at > COALESCE((SELECT last_read FROM chat_reads WHERE user_id=?), '1970-01-01')", [req.user.id, req.user.id]);
    res.json({ status: 'success', unread: result[0].unread });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ============================================================
// REPORTS ROUTES
// ============================================================

app.get('/api/reports/filters', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [clients] = await pool.execute("SELECT id, email, company_name FROM users WHERE role='client'");
    const [trucks] = await pool.execute('SELECT id, plate_no, make FROM trucks');
    res.json({ status: 'success', data: { clients: clients.map(c => ({ id: c.id, label: (c.company_name||c.email)+' ('+c.email+')' })), trucks: trucks.map(t => ({ id: t.id, label: t.plate_no+' - '+t.make })) } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/reports/summary', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    let query = "SELECT * FROM authority_to_load WHERE status IN ('completed','cancelled','dispatched','rejected')";
    const params = [];
    if (startDate) { query += ' AND (DATE(completed_date)>=? OR DATE(createdAt)>=? OR DATE(scheduled_date)>=?)'; params.push(startDate, startDate, startDate); }
    if (endDate) { query += ' AND (DATE(completed_date)<=? OR DATE(createdAt)<=? OR DATE(scheduled_date)<=?)'; params.push(endDate, endDate, endDate); }
    query += ' ORDER BY createdAt DESC';
    const [atls] = await pool.execute(query, params);
    const result = [];
    let totalVolume = 0, totalActualVolume = 0, completedCount = 0, cancelledCount = 0, dispatchedCount = 0;
    for (const a of atls) {
      const [trucks] = await pool.execute('SELECT plate_no, make, total_capacity FROM trucks WHERE id=?', [a.truck_id]);
      const [clients] = await pool.execute('SELECT email, company_name FROM users WHERE id=?', [a.client_id]);
      const vol = parseFloat(a.volume) || 0;
      const actualVol = parseFloat(a.actual_volume) || vol;
      totalVolume += vol;
      totalActualVolume += actualVol;
      if (a.status === 'completed') completedCount++;
      if (a.status === 'cancelled') cancelledCount++;
      if (a.status === 'dispatched') dispatchedCount++;
      result.push({ ...a, truck: trucks[0] || null, client: clients[0] || null });
    }
    res.json({
      status: 'success',
      data: {
        records: result,
        summary: {
          total_records: result.length,
          completed: completedCount,
          cancelled: cancelledCount,
          dispatched: dispatchedCount,
          total_volume: totalVolume,
          total_actual_volume: totalActualVolume
        }
      }
    });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/reports/export', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    let query = "SELECT * FROM authority_to_load WHERE status IN ('completed','cancelled','dispatched','rejected')";
    const params = [];
    if (startDate) { query += ' AND DATE(createdAt)>=?'; params.push(startDate); }
    if (endDate) { query += ' AND DATE(createdAt)<=?'; params.push(endDate); }
    const [atls] = await pool.execute(query, params);
    let csv = 'ATL Code,SO Number,Company,Plate No,Driver,Hauler,Contact,Volume (L),Actual Volume (L),SI,Status,Scheduled Date,Dispatch Date,Completed Date,Printed WC,TPS From,TPS To,Remarks\n';
    for (const a of atls) {
      csv += `"${a.atl_code||''}","${a.so_number||''}","${a.company||''}","${a.plate_no||''}","${a.driver_name||''}","${a.hauler||''}","${a.contact_number||''}","${a.volume||0}","${a.actual_volume||0}","${a.has_si==1?'With SI':'No SI'}","${a.status}","${a.scheduled_date||''}","${a.dispatch_date||''}","${a.completed_date||''}","${a.printed_wc||''}","${a.tps_start||''}","${a.tps_end||''}","${(a.remarks||'').replace(/"/g,'""')}"\n`;
    }
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=report.csv');
    res.send(csv);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/atl/summary', authenticate, async (req, res) => {
  try {
    const [atls] = await pool.execute('SELECT * FROM authority_to_load WHERE client_id=? ORDER BY createdAt DESC LIMIT 50', [req.user.id]);
    const result = [];
    for (const a of atls) { const [trucks] = await pool.execute('SELECT plate_no, make FROM trucks WHERE id=?', [a.truck_id]); result.push({ ...a, truck: trucks[0] || null }); }
    res.json({ status: 'success', data: { recent: result } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ============================================================
// BULK DOCUMENT SYNC
// ============================================================
app.post('/api/sync-all-documents', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { batch = 0 } = req.body;
    const [trucks] = await pool.execute('SELECT id FROM trucks ORDER BY id LIMIT 30 OFFSET ?', [String(batch * 30)]);
    if (!trucks.length) return res.json({ status: 'success', message: 'All done!', done: true });
    let count = 0;
    for (const t of trucks) {
      for (const type of ['lto_registration','fire_permit','dost_calibration']) {
        try { await pool.execute("INSERT IGNORE INTO truck_documents (truck_id, document_type, expiry_date, status, createdAt) VALUES (?,?,?,'valid',NOW())", [t.id, type, '2030-12-31']); count++; } catch (e) {}
      }
    }
    res.json({ status: 'success', message: `Batch ${batch+1}: ${count} docs`, count, done: false, nextBatch: batch + 1 });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

// ============================================================
// ADMIN ROUTES
// ============================================================

app.get('/api/admin/optimize-database', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  const indexes = [
    'CREATE INDEX idx_atl_status_client ON authority_to_load(status, client_id)',
    'CREATE INDEX idx_atl_client_created ON authority_to_load(client_id, createdAt)',
    'CREATE INDEX idx_atl_truck_status ON authority_to_load(truck_id, status)',
    'CREATE INDEX idx_atl_so_status ON authority_to_load(so_number, status)',
    'CREATE INDEX idx_trucks_plate_active ON trucks(plate_no, is_active)',
    'CREATE INDEX idx_docs_truck_type_expiry ON truck_documents(truck_id, document_type, expiry_date)',
    'CREATE INDEX idx_so_client_status ON sales_orders(client_id, status)',
    'CREATE INDEX idx_soc_so_client ON sales_order_clients(sales_order_id, client_id)',
    'CREATE INDEX idx_chat_receiver_created ON chat_messages(receiver_id, created_at)',
    'CREATE INDEX idx_users_role_active ON users(role, is_active)',
  ];
  let created = 0, skipped = 0, failed = 0;
  for (const sql of indexes) {
    try { await pool.execute(sql); created++; }
    catch (e) { if (e.code === 'ER_DUP_KEYNAME') skipped++; else failed++; }
  }
  res.json({ status: 'success', message: `Created: ${created}, Skipped: ${skipped}, Failed: ${failed}` });
});

app.get('/api/admin/create-so-table', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    await pool.execute(`CREATE TABLE IF NOT EXISTS sales_orders (id INT AUTO_INCREMENT PRIMARY KEY, so_number VARCHAR(50) NOT NULL, client_id INT NOT NULL, company_name VARCHAR(100), total_volume DECIMAL(12,2) DEFAULT 0, used_volume DECIMAL(12,2) DEFAULT 0, is_multi_client TINYINT(1) DEFAULT 0, status ENUM('active','completed','cancelled') DEFAULT 'active', notes TEXT, created_by INT, createdAt DATETIME DEFAULT CURRENT_TIMESTAMP, updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, UNIQUE KEY unique_so_client (so_number, client_id), INDEX idx_so_number (so_number), INDEX idx_client_id (client_id), INDEX idx_status (status), FOREIGN KEY (client_id) REFERENCES users(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
    await pool.execute(`CREATE TABLE IF NOT EXISTS sales_order_clients (id INT AUTO_INCREMENT PRIMARY KEY, sales_order_id INT NOT NULL, client_id INT NOT NULL, company_name VARCHAR(100), allocated_volume DECIMAL(12,2) DEFAULT 0, used_volume DECIMAL(12,2) DEFAULT 0, createdAt DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (sales_order_id) REFERENCES sales_orders(id) ON DELETE CASCADE, FOREIGN KEY (client_id) REFERENCES users(id) ON DELETE CASCADE, UNIQUE KEY unique_so_allocation (sales_order_id, client_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
    try { await pool.execute('CREATE INDEX idx_atl_so_number ON authority_to_load(so_number)'); } catch (e) {}
    res.json({ status: 'success', message: 'Tables created' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/admin/verify-user', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try { await pool.execute('UPDATE users SET is_verified=1 WHERE email=?', [req.body.email]); res.json({ status: 'success', message: 'User verified' }); }
  catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/admin/cleanup-loading', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try { await pool.execute('DELETE FROM authority_to_load'); res.json({ status: 'success', message: 'Cleared' }); }
  catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/admin/add-first-login-column', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try { await pool.execute('ALTER TABLE authority_to_load ADD COLUMN special_instructions TEXT'); res.json({ status: 'success' }); }
  catch (error) { if (error.code === 'ER_DUP_FIELDNAME') res.json({ status: 'success', message: 'Already exists' }); else res.status(400).json({ error: error.message }); }
});

// ============================================================
// CLIENTS & USERS MANAGEMENT
// ============================================================

app.get('/api/clients', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [clients] = await pool.execute("SELECT id, email, mobile, company_name, is_active, is_verified, last_login, createdAt FROM users WHERE role='client' ORDER BY createdAt DESC");
    const result = [];
    for (const c of clients) { const [atls] = await pool.execute('SELECT COUNT(*) as total FROM authority_to_load WHERE client_id=?', [c.id]); result.push({ ...c, total_atls: atls[0].total }); }
    res.json({ status: 'success', data: result, total: result.length });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/clients/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [clients] = await pool.execute("SELECT id, email, mobile, company_name, is_active, is_verified, last_login, createdAt FROM users WHERE id=? AND role='client'", [req.params.id]);
    if (!clients.length) return res.status(404).json({ error: 'Client not found' });
    res.json({ status: 'success', data: clients[0] });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/clients', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { email, password, mobile, company_name } = req.body;
    if (!email || !password || !mobile) return res.status(400).json({ error: 'Email, password, and mobile required' });
    const [existing] = await pool.execute('SELECT id FROM users WHERE email=?', [email]);
    if (existing.length) return res.status(400).json({ error: 'Email already registered' });
    await pool.execute('INSERT INTO users (email, password, mobile, company_name, role, is_verified, is_active, first_login, createdAt, updatedAt) VALUES (?,?,?,?,?,1,1,1,NOW(),NOW())',
      [email, await hashPassword(password), mobile, company_name || null, 'client']);
    await logAudit(req.user.id, 'CREATE_CLIENT', 'users', 0, { email });
    res.status(201).json({ status: 'success', message: 'Client created' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.put('/api/clients/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { email, mobile, company_name, password } = req.body;
    if (email) { const [dup] = await pool.execute('SELECT id FROM users WHERE email=? AND id!=?', [email, req.params.id]); if (dup.length) return res.status(400).json({ error: 'Email already in use' }); }
    let query = 'UPDATE users SET email=?, mobile=?, company_name=?';
    let params = [email, mobile, company_name];
    if (password && password.length >= 8) { query += ', password=?'; params.push(await hashPassword(password)); }
    params.push(req.params.id);
    await pool.execute(query + ' WHERE id=?', params);
    await logAudit(req.user.id, 'UPDATE_CLIENT', 'users', req.params.id, { email });
    res.json({ status: 'success', message: 'Client updated' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.patch('/api/clients/:id/toggle-status', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [clients] = await pool.execute("SELECT is_active FROM users WHERE id=? AND role='client'", [req.params.id]);
    if (!clients.length) return res.status(404).json({ error: 'Client not found' });
    const ns = clients[0].is_active ? 0 : 1;
    await pool.execute('UPDATE users SET is_active=? WHERE id=?', [ns, req.params.id]);
    res.json({ status: 'success', message: 'Client ' + (ns ? 'activated' : 'deactivated') });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.delete('/api/clients/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try { await pool.execute("DELETE FROM users WHERE id=? AND role='client'", [req.params.id]); res.json({ status: 'success', message: 'Client deleted' }); }
  catch (error) { res.status(400).json({ error: error.message }); }
});

app.get('/api/users', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try { const [users] = await pool.execute('SELECT id, email, role, mobile, company_name, is_active, is_verified, last_login, createdAt FROM users ORDER BY role, email'); res.json({ status: 'success', data: users }); }
  catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/users', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { email, password, mobile, company_name, role } = req.body;
    if (!email || !password || !role) return res.status(400).json({ error: 'Email, password, and role required' });
    if (!validatePassword(password).valid) return res.status(400).json({ error: validatePassword(password).error });
    const [existing] = await pool.execute('SELECT id FROM users WHERE email=?', [email]);
    if (existing.length) return res.status(400).json({ error: 'Email already registered' });
    await pool.execute('INSERT INTO users (email, password, mobile, company_name, role, is_verified, is_active, createdAt, updatedAt) VALUES (?,?,?,?,?,1,1,NOW(),NOW())',
      [email, await hashPassword(password), mobile || null, company_name || null, role]);
    res.status(201).json({ status: 'success', message: 'User created' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.put('/api/users/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { email, mobile, company_name, role, password, is_active } = req.body;
    let query = 'UPDATE users SET email=?, mobile=?, company_name=?, role=?, is_active=?';
    let params = [email, mobile || null, company_name || null, role, is_active !== undefined ? is_active : 1];
    if (password) { query += ', password=?'; params.push(await hashPassword(password)); }
    params.push(req.params.id);
    await pool.execute(query + ' WHERE id=?', params);
    res.json({ status: 'success', message: 'User updated' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.delete('/api/users/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try { await pool.execute('DELETE FROM users WHERE id=?', [req.params.id]); res.json({ status: 'success', message: 'User deleted' }); }
  catch (error) { res.status(400).json({ error: error.message }); }
});

// ============================================================
// AUDIT LOGS
// ============================================================
app.get('/api/audit-logs', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [logs] = await pool.execute('SELECT al.*, u.email FROM audit_logs al JOIN users u ON al.user_id=u.id ORDER BY al.created_at DESC LIMIT 500');
    res.json({ status: 'success', data: logs });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ============================================================
// DATABASE MIGRATION
// ============================================================
app.post('/api/migrate', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  const indexes = [
    'CREATE INDEX idx_atl_status ON authority_to_load(status)',
    'CREATE INDEX idx_atl_client_id ON authority_to_load(client_id)',
    'CREATE INDEX idx_atl_truck_id ON authority_to_load(truck_id)',
    'CREATE INDEX idx_atl_created ON authority_to_load(createdAt)',
    'CREATE INDEX idx_atl_plate ON authority_to_load(plate_no)',
    'CREATE INDEX idx_trucks_plate ON trucks(plate_no)',
    'CREATE INDEX idx_trucks_active ON trucks(is_active)',
    'CREATE INDEX idx_docs_truck ON truck_documents(truck_id)',
    'CREATE INDEX idx_docs_type ON truck_documents(document_type)',
    'CREATE INDEX idx_docs_expiry ON truck_documents(expiry_date)',
    'CREATE INDEX idx_users_email ON users(email)',
    'CREATE INDEX idx_users_role ON users(role)',
    'CREATE INDEX idx_master_plate ON truck_masterlist(plate_no)',
    'CREATE INDEX idx_audit_user ON audit_logs(user_id)',
    'CREATE INDEX idx_audit_created ON audit_logs(created_at)',
    'CREATE INDEX idx_chat_users ON chat_messages(sender_id, receiver_id)',
    'CREATE INDEX idx_chat_created ON chat_messages(created_at)',
  ];
  let created = 0, skipped = 0, failed = 0;
  for (const sql of indexes) {
    try { await pool.execute(sql); created++; }
    catch (e) { if (e.code === 'ER_DUP_KEYNAME') skipped++; else failed++; }
  }
  res.json({ status: 'success', message: `Created: ${created}, Skipped: ${skipped}, Failed: ${failed}` });
});

app.post('/api/sync-truck-capacities', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { batch = 0 } = req.body;
    const [trucks] = await pool.execute('SELECT id, plate_no FROM trucks WHERE total_capacity=0 OR total_capacity IS NULL ORDER BY id LIMIT 50 OFFSET ?', [String(batch * 50)]);
    if (!trucks.length) return res.json({ status: 'success', message: 'All done!', done: true });
    let count = 0;
    for (const t of trucks) {
      const [master] = await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no=?', [t.plate_no]);
      if (master.length > 0) {
        const cap = [master[0].cot1,master[0].cot2,master[0].cot3,master[0].cot4,master[0].cot5,master[0].cot6,master[0].cot7,master[0].cot8,master[0].cot9,master[0].cot10].reduce((s,v) => s + parseFloat(v||0), 0);
        if (cap > 0) { await pool.execute('UPDATE trucks SET total_capacity=? WHERE id=?', [cap, t.id]); count++; }
      }
    }
    res.json({ status: 'success', message: `Batch ${batch+1}: ${count} updated`, count, done: false, nextBatch: batch + 1 });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

// ============================================================
// STATIC FILES & PAGE ROUTES
// ============================================================

app.use('/public', express.static(path.join(__dirname, '..', 'public'), {
  maxAge: '1h',
  setHeaders: (res, fp) => res.setHeader('Cache-Control', fp.endsWith('.html') ? 'public, max-age=0, must-revalidate' : 'public, max-age=3600')
}));

const pageRoutes = {
  '/': 'index.html',
  '/dashboard': 'dashboard.html',
  '/dashboard.html': 'dashboard.html',
  '/client': 'client.html',
  '/client.html': 'client.html',
  '/sales-orders': 'sales-orders.html',
  '/docs-report': 'docs-report.html',
  '/reports': 'reports.html',
  '/reports.html': 'reports.html',
  '/atl.html': 'atl.html',
  '/trucks': 'trucks.html',
  '/ttsd-checklist': 'ttsd-checklist.html',
  '/tutorial': 'tutorial.html',
  '/users': 'users.html',
  '/adminclient': 'adminclient.html',
  '/audit-logs': 'audit-logs.html',
  '/first-login': 'first-login.html',
  '/terms': 'terms.html'
};

Object.entries(pageRoutes).forEach(([route, file]) => {
  app.get(route, (req, res) => res.sendFile(path.join(__dirname, '..', 'public', file)));
});

// ============================================================
// EXPORT
// ============================================================
module.exports = app;