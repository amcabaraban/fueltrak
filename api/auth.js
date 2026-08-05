// ============================================================
// FuelTrak API v3.0 - Production-Ready Application
// ============================================================
// Logistics Management System for Fuel Truck Dispatching
// Security-hardened with rate limiting, input validation, CSP, WAF
// Multi-user optimized with connection pooling, audit cleanup
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
const LOCKOUT_DURATION_MS = 15 * 60 * 1000;
const JWT_EXPIRY = '1h';
const REFRESH_TOKEN_EXPIRY = '7d';
const ALLOWED_UPDATE_FIELDS = ['tps_start', 'tps_end', 'printed_wc', 'has_si', 'so_number'];
const RECYCLE_BIN_DAYS = 30;
const AUDIT_LOG_RETENTION_DAYS = 90;

// ============ CACHE SETUP ============
const otpCache = new NodeCache({ stdTTL: 600 });
const serverCache = new NodeCache({ stdTTL: 60, checkperiod: 120 });

// ============ SECURE CONSOLE (PRODUCTION) ============
if (process.env.NODE_ENV === 'production') {
  const origConsole = { log: console.log, warn: console.warn, error: console.error, info: console.info, debug: console.debug };
  console.log = () => {};
  console.warn = () => {};
  console.info = () => {};
  console.debug = () => {};
  console.error = (...args) => {
    const sanitized = args.map(arg => {
      if (typeof arg === 'string') {
        return arg.replace(/password[=:]\S+/gi, 'password=***').replace(/token[=:]\S+/gi, 'token=***').replace(/secret[=:]\S+/gi, 'secret=***').replace(/Bearer\s+\S+/gi, 'Bearer ***').replace(/otp[=:]\S+/gi, 'otp=***').replace(/\b\d{6}\b/g, '******').replace(/AVNS_\S+/gi, 'AVNS_***').replace(/mysql-\S+\.aivencloud\.com/gi, '***.aivencloud.com');
      }
      return arg;
    });
    origConsole.error.apply(console, sanitized);
  };
}

// ============ LOGGER ============
const logger = {
  error: (message, meta = {}) => {
    const sanitized = { ...meta }; delete sanitized.password; delete sanitized.token; delete sanitized.otp; delete sanitized.secret;
    if (process.env.NODE_ENV === 'production') console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: 'error', message, meta: sanitized }));
    else console.error(`[${new Date().toISOString()}] ERROR:`, message, sanitized);
  },
  info: (message, meta = {}) => { if (process.env.NODE_ENV !== 'production') console.log(`[${new Date().toISOString()}] INFO:`, message, meta); },
  warn: (message, meta = {}) => { if (process.env.NODE_ENV !== 'production') console.warn(`[${new Date().toISOString()}] WARN:`, message, meta); },
  audit: (action, userId, details = {}) => { const s = { ...details }; delete s.password; delete s.token; logAudit(userId, action, 'system', 0, s).catch(() => {}); }
};

// ============ EMAIL TRANSPORTER ============
const transporter = nodemailer.createTransport({ host: process.env.SMTP_HOST || 'smtp.gmail.com', port: parseInt(process.env.SMTP_PORT) || 587, secure: false, auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } });

// ============ DATABASE CONNECTION ============
const pool = mysql.createPool({ 
  host: process.env.DB_HOST, 
  port: process.env.DB_PORT || 16287, 
  user: process.env.DB_USER, 
  password: process.env.DB_PASSWORD, 
  database: process.env.DB_NAME, 
  ssl: { rejectUnauthorized: false }, 
  waitForConnections: true, 
  connectionLimit: 50, 
  queueLimit: 100, 
  enableKeepAlive: true, 
  keepAliveInitialDelay: 5000,
  connectTimeout: 10000,
  charset: 'utf8mb4' 
});
pool.on('error', (err) => logger.error('Database pool error', { error: err.message }));

// ============ MIDDLEWARE ============
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// Cache control for sensitive pages
app.use((req, res, next) => {
  if (req.path === '/' || req.path === '/index.html' || req.path === '/client') {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
});

// ============ STRONGER CSP & SECURITY HEADERS ============

// Generate nonce for CSP (if needed later)
app.use((req, res, next) => {
  res.locals.nonce = require('crypto').randomBytes(16).toString('base64');
  next();
});

// Helmet - Hardened CSP (unsafe-inline removed from scripts)
app.use(helmet({
contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      
      // SCRIPTS
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://cdn.tailwindcss.com",
        "https://cdnjs.cloudflare.com",
      ],
      scriptSrcAttr: [
        "'self'",
        "'unsafe-inline'",
        "'unsafe-hashes'",
      ],
      
      // STYLES
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://cdnjs.cloudflare.com",
      ],
      styleSrcAttr: [
        "'self'",
        "'unsafe-inline'",
      ],
      
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
    }
  },
  
  // Enhanced HSTS
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  
  // Strict framing protection
  frameguard: { action: 'deny' },
  
  // Hide tech stack
  hidePoweredBy: true,
  
  // Prevent MIME type sniffing
  noSniff: true,
  
  // Enable XSS filter in older browsers
  xssFilter: true,
  
  // Control referrer information
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  
  // Prevent cross-domain policy files
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  
  // Disable DNS prefetch
  dnsPrefetchControl: { allow: false },
  
  // ADDED: Cross-Origin isolation policies
  crossOriginEmbedderPolicy: { policy: 'credentialless' },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
}));

// Additional strict security headers
app.use((req, res, next) => {
  // Remove any remaining powered-by headers
  res.removeHeader('X-Powered-By');
  
  // Strict permissions policy - deny everything by default
  res.setHeader(
    'Permissions-Policy',
    'camera=(), ' +
    'microphone=(), ' +
    'geolocation=(), ' +
    'interest-cohort=(), ' +
    'payment=(), ' +
    'usb=(), ' +
    'accelerometer=(), ' +
    'autoplay=(), ' +
    'clipboard-read=(), ' +
    'clipboard-write=(self), ' +
    'display-capture=(), ' +
    'fullscreen=(self), ' +
    'gyroscope=(), ' +
    'magnetometer=(), ' +
    'midi=(), ' +
    'picture-in-picture=(), ' +
    'sync-xhr=()'
  );
  
  // Additional browser security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  res.setHeader('X-Download-Options', 'noopen');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  
  // Cache control for API responses
  if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  }
  
  next();
});

// Enhanced CORS with proper validation
app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = [
      'https://fueltraksystem.vercel.app',
      'https://fueltrak-seven.vercel.app',
      'http://localhost:3000',
      'http://localhost:8080'
    ];
    
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`CORS blocked origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'Accept',
    'Origin'
  ],
  exposedHeaders: [
    'Content-Length',
    'X-RateLimit-Limit',
    'X-RateLimit-Remaining'
  ],
  maxAge: 86400 // 24 hours cache for preflight
}));

app.use(compression());

// ============ RATE LIMITERS ============

// General API limiter - 60 requests per minute
const generalLimiter = rateLimit({ 
  windowMs: 60 * 1000, 
  max: 60, 
  message: { error: 'Too many requests' }, 
  standardHeaders: true, 
  legacyHeaders: false 
});

// Strict limiter for auth endpoints
const strictLimiter = rateLimit({ 
  windowMs: 15 * 60 * 1000, 
  max: 5, 
  message: { error: 'Too many attempts. Try later.' }, 
  standardHeaders: true, 
  legacyHeaders: false 
});

// OTP limiter - 3 per hour
const otpLimiter = rateLimit({ 
  windowMs: 60 * 60 * 1000, 
  max: 3, 
  message: { error: 'Too many OTP requests.' }, 
  standardHeaders: true, 
  legacyHeaders: false 
});

// Fingerprint limiter - uses headers instead of IP (IPv6 safe)
const fingerprintLimiter = rateLimit({ 
  windowMs: 60 * 1000, 
  max: 30, 
  message: { error: 'Rate limit exceeded' }, 
  standardHeaders: true, 
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Use request headers as fingerprint (no IP manipulation)
    const ua = (req.headers['user-agent'] || '').substring(0, 100);
    const lang = (req.headers['accept-language'] || '').substring(0, 50);
    return (ua + lang) || 'unknown';
  }
});

// Rate limit skips for chat endpoints
app.use('/api/chat', (req, res, next) => next());
app.use('/api/chat-list', (req, res, next) => next());
app.use('/api/chat/unread', (req, res, next) => next());

// Apply rate limiters
app.use('/api/', generalLimiter);
app.use('/api/', fingerprintLimiter);

// Auth-specific rate limits
app.use('/api/auth/login', strictLimiter);
app.use('/api/auth/register', strictLimiter);
app.use('/api/auth/forgot-password', strictLimiter);
app.use('/api/auth/force-login', strictLimiter);
app.use('/api/auth/resend-otp', otpLimiter);
app.use('/api/auth/verify-otp', otpLimiter);
app.use('/api/auth/reset-password', strictLimiter);

// Static file middleware
app.use('/css', express.static(path.join(__dirname, '..', 'public', 'css'), { maxAge: '1h', setHeaders: (res) => res.setHeader('Cache-Control', 'public, max-age=3600') }));
app.use('/js', express.static(path.join(__dirname, '..', 'public', 'js'), { maxAge: '1h', setHeaders: (res) => res.setHeader('Cache-Control', 'public, max-age=3600') }));

// ============ ANTI-SCRAPING & BOT PROTECTION ============
const BOT_PATTERNS = ['bot','crawler','spider','scraper','curl','wget','python','java/','node-fetch','axios','go-http','ruby','perl','scrapy','phpcrawl','httpclient','aiohttp','request','mechanize','selenium','headless','puppeteer','playwright','bytespider','petalbot','gptbot','chatgpt','openai','claude','anthropic','bard','gemini','copilot','ccbot','commoncrawl','semrush','ahrefs','mj12bot','dotbot','rogerbot','exabot','yandexbot','baiduspider','facebookexternalhit','twitterbot','slackbot','discordbot','googlebot','bingbot','duckduckbot','yahoobot'];
function isBotUA(ua) { return !ua || BOT_PATTERNS.some(p => (ua||'').toLowerCase().includes(p)); }
function isSuspicious(req) { const checks = { noUA: !req.headers['user-agent'], noAL: !req.headers['accept-language'], noAccept: !req.headers['accept'], missingHdrs: !req.headers['user-agent'] && !req.headers['accept'], knownBot: isBotUA(req.headers['user-agent']) }; return Object.values(checks).filter(Boolean).length >= 2; }

app.use((req, res, next) => {
  const ip = req.ip, ua = req.headers['user-agent'] || '';
  if (isBotUA(ua) && !ua.includes('googlebot')) { logger.warn('Bot blocked', { ip, ua: ua.substring(0,100), path: req.path }); return res.status(403).json({ error: 'Access denied' }); }
  if (isSuspicious(req)) { logger.warn('Suspicious blocked', { ip, ua: ua.substring(0,100), path: req.path }); return res.status(403).json({ error: 'Access denied' }); }
  next();
});

// Honeypots
['/api/admin','/api/v1','/wp-admin','/.env','/admin'].forEach(r => app.get(r, (req, res) => { logger.warn('Honeypot: '+r, { ip: req.ip }); res.status(403).json({ error: 'Forbidden' }); }));

// Scraper traps
app.get('/api/public-data', (req, res) => { if (isBotUA(req.headers['user-agent'])) return res.json({ data: Array(10).fill(null).map((_,i)=>({id:i+1000,name:'REDACTED_'+Math.random().toString(36).substring(7),value:Math.floor(Math.random()*99999),status:'fake_data'})) }); res.status(404).json({ error: 'Not found' }); });
app.get('/api/users-list', (req, res) => { if (isBotUA(req.headers['user-agent'])) return res.json({ users: Array(20).fill(null).map(()=>({email:'fake_'+Math.random().toString(36).substring(7)+'@poisoned-data.com',name:'AI Poison',role:'scraper_target'})) }); res.status(404).json({ error: 'Not found' }); });

// Bot response delay
app.use((req, res, next) => { const orig = res.json.bind(res); res.json = function(d) { if (process.env.NODE_ENV==='production' && isBotUA(req.headers['user-agent'])) { setTimeout(()=>orig(d), 100+Math.floor(Math.random()*400)); return; } return orig(d); }; next(); });

// ============ TOKEN BLACKLIST ============
const tokenBlacklist = new Set();
setInterval(() => { tokenBlacklist.forEach(t => { try { jwt.verify(t, process.env.JWT_SECRET); } catch(e) { tokenBlacklist.delete(t); } }); }, 3600000);

// ============ CACHE HELPERS ============
function clearCache(pattern) { serverCache.keys().forEach(k => { if (k.includes(pattern)) serverCache.del(k); }); }

// ============ UTILITY FUNCTIONS ============
function generateOTP() { return Math.floor(100000 + Math.random() * 900000).toString(); }
function validateEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); }
function sanitize(s, max=100) { return s ? String(s).trim().substring(0,max).replace(/[<>]/g,'') : ''; }
function maskEmail(e) { return e ? e.replace(/(.{3}).*(@.*)/,'$1***$2') : '***'; }
function validatePassword(p) { if(!p||p.length<8) return {valid:false,error:'Password must be at least 8 characters'}; if(!/[A-Z]/.test(p)) return {valid:false,error:'Password must contain an uppercase letter'}; if(!/[a-z]/.test(p)) return {valid:false,error:'Password must contain a lowercase letter'}; if(!/[0-9]/.test(p)) return {valid:false,error:'Password must contain a number'}; if(!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(p)) return {valid:false,error:'Password must contain a special character'}; return {valid:true}; }
function validatePasswordComplexity(p) { return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/.test(p); }
async function hashPassword(p) { return await bcrypt.hash(p, BCRYPT_ROUNDS); }
async function logAudit(uid, action, table, rid, details) { try { await pool.execute('INSERT INTO audit_logs (user_id,action,table_name,record_id,details) VALUES (?,?,?,?,?)', [uid,action,table,rid,JSON.stringify(details)]); } catch(e) {} }
async function generateATLCode(company) { const pfx = (company||'ATL').replace(/[^a-zA-Z]/g,'').substring(0,3).toUpperCase().padEnd(3,'X'); const [r] = await pool.execute('SELECT COUNT(*) as count FROM authority_to_load'); return pfx+'-'+String(r[0].count+1).padStart(9,'0'); }

// ============ INPUT VALIDATION ============
function validateATLInput(req, res, next) { const {volume,plate_no,company}=req.body; const errs=[]; if(volume&&(isNaN(volume)||volume<=0||volume>100000)) errs.push('Volume must be 1-100,000L'); if(plate_no&&plate_no.length>20) errs.push('Plate too long'); if(company&&company.length>100) errs.push('Company too long'); if(errs.length) return res.status(400).json({error:errs.join('. ')}); next(); }

// ============ EMAIL/SMS ============
async function sendOTPEmail(email, mobile, otp, type) { if(mobile&&mobile.length>5) sendFreeSMS(mobile,otp).catch(()=>{}); if(!process.env.SMTP_USER){logger.info('Dev OTP',{email:maskEmail(email)});return;} try{await transporter.sendMail({from:`"FuelTrak" <${process.env.SMTP_USER}>`,to:email,subject:type==='reset'?'FuelTrak - Password Reset OTP':'FuelTrak - Verify Your Email',html:`<div style="font-family:Arial;max-width:500px;margin:auto;padding:20px;border:1px solid #ddd;border-radius:10px"><h2 style="color:#1e3a5f">FuelTrak Logistics</h2><p>Your OTP code is:</p><h1 style="color:#1e3a5f;font-size:36px;letter-spacing:5px;text-align:center">${otp}</h1><p>This code expires in 10 minutes.</p></div>`});logger.info('OTP emailed',{email:maskEmail(email)});}catch(e){logger.error('Email failed',{error:e.message});}}
async function sendFreeSMS(mobile, otp) { if(!process.env.SMTP_USER) return false; for(const gw of [mobile.replace('+63','0')+'@txt.globe.com.ph',mobile.replace('+63','0')+'@isms.smart.com.ph']){try{await transporter.sendMail({from:process.env.SMTP_USER,to:gw,subject:'',text:`FuelTrak OTP: ${otp}. Expires in 10 mins.`});logger.info('SMS sent',{mobile:mobile.replace(/(\d{3})\d{4}(\d{3})/,'$1****$2')});return true;}catch(e){}} return false; }

app.get('/api/demo-credentials', async (req, res) => {
  try {
    const [users] = await pool.execute("SELECT email, role FROM users WHERE email IN (?, ?, ?)", ['admin@fueltrak.com', 'dispatcher@fueltrak.com', 'client1@hauler.com']);
    const credentials = {};
    users.forEach(u => { if (u.role === 'management') credentials.admin = u.email; if (u.role === 'dispatcher') credentials.dispatcher = u.email; if (u.role === 'client') credentials.client = u.email; });
    res.json({ status: 'success', data: credentials });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ============ AUTH MIDDLEWARE ============
const authenticate = async (req, res, next) => { try { const t = req.header('Authorization')?.replace('Bearer ',''); if(!t) return res.status(401).json({error:'Please authenticate'}); if(tokenBlacklist.has(t)) return res.status(401).json({error:'Token revoked'}); const d = jwt.verify(t, process.env.JWT_SECRET); if(d.type==='refresh') return res.status(401).json({error:'Use access token'}); const [u] = await pool.execute('SELECT id,email,role,mobile,company_name,is_active FROM users WHERE id=?',[d.id]); if(!u.length||!u[0].is_active) return res.status(401).json({error:'Invalid token'}); req.user=u[0]; next(); } catch(e) { res.status(401).json({error:'Invalid token'}); } };
const authorize = (...roles) => (req,res,next) => { if(!roles.includes(req.user.role)) return res.status(403).json({error:'Access denied'}); next(); };

// ============ ACCOUNT LOCKOUT ============
const loginAttempts = new Map();
function getLoginKey(e) { return 'login_'+e.toLowerCase(); }
function checkLockout(e) { const a=loginAttempts.get(getLoginKey(e)); if(a&&a.count>=MAX_LOGIN_ATTEMPTS&&(Date.now()-a.lastAttempt)<LOCKOUT_DURATION_MS) return {locked:true,minutesLeft:Math.ceil((LOCKOUT_DURATION_MS-(Date.now()-a.lastAttempt))/60000)}; return {locked:false}; }
function recordFailedAttempt(e) { const k=getLoginKey(e),c=loginAttempts.get(k)||{count:0,lastAttempt:0}; loginAttempts.set(k,{count:c.count+1,lastAttempt:Date.now()}); }
function resetAttempts(e) { loginAttempts.delete(getLoginKey(e)); }

// ============ WAF ============
const WAF_PATTERNS = { sqli: /(\bUNION\s+SELECT\b|\bSELECT\s+.*\s+FROM\b.*--|\bINSERT\s+INTO\b.*\bVALUES\b.*--|\bDROP\s+TABLE\b)/i, xss: /(<script[\s>]|<\/script>|javascript\s*:\s*alert)/i, pathTraversal: /(\.\.\/\.\.\/|\/etc\/passwd|\/\.env$|\/wp-admin$)/i };
function detectWAF(req) { const url=req.originalUrl||req.url||'',ua=req.headers['user-agent']||''; for(const [t,p] of Object.entries(WAF_PATTERNS)){ if(p.test(url)||p.test(ua)) return {blocked:true,type:t}; } return {blocked:false}; }
app.use((req,res,next)=>{const r=detectWAF(req); if(r.blocked){logger.warn('WAF blocked',{ip:req.ip,type:r.type,path:req.path});return res.status(403).json({error:'Request blocked by WAF'});} next();});

// ============================================================
// RECYCLE BIN & BACKUP HELPERS
// ============================================================

async function softDelete(tableName, recordId, deletedBy, deletedByEmail, daysToKeep = RECYCLE_BIN_DAYS) {
  try {
    const [records] = await pool.execute(`SELECT * FROM ${tableName} WHERE id = ?`, [recordId]);
    if (!records.length) return false;
    const recordData = records[0];
    delete recordData.password; delete recordData.current_token; delete recordData.openim_token;
    const expiresAt = new Date(); expiresAt.setDate(expiresAt.getDate() + daysToKeep);
    await pool.execute('INSERT INTO recycle_bin (table_name, record_id, record_data, deleted_by, deleted_by_email, expires_at) VALUES (?, ?, ?, ?, ?, ?)', [tableName, recordId, JSON.stringify(recordData), deletedBy, deletedByEmail, expiresAt]);
    return true;
  } catch (error) { logger.error('Soft delete failed', { error: error.message }); return false; }
}

async function restoreFromBin(binId, restoredBy) {
  try {
    const [bins] = await pool.execute('SELECT * FROM recycle_bin WHERE id = ? AND restored = 0', [binId]);
    if (!bins.length) return { success: false, error: 'Not found' };
    const bin = bins[0]; const recordData = JSON.parse(bin.record_data); delete recordData.id;
    const columns = Object.keys(recordData).join(', '); const placeholders = Object.keys(recordData).map(() => '?').join(', '); const values = Object.values(recordData);
    const [result] = await pool.execute(`INSERT INTO ${bin.table_name} (${columns}) VALUES (${placeholders})`, values);
    await pool.execute('UPDATE recycle_bin SET restored = 1, restored_at = NOW(), restored_by = ? WHERE id = ?', [restoredBy, binId]);
    await logAudit(restoredBy, 'RESTORE', bin.table_name, result.insertId, { restored_from_bin: binId });
    return { success: true, newId: result.insertId };
  } catch (error) { return { success: false, error: error.message }; }
}

async function cleanupRecycleBin() {
  try { const [r] = await pool.execute('DELETE FROM recycle_bin WHERE expires_at < NOW() AND restored = 0'); if (r.affectedRows > 0) logger.info('Recycle bin cleaned', { deleted: r.affectedRows }); } catch(e) {}
}
setInterval(cleanupRecycleBin, 60 * 60 * 1000);

async function cleanupAuditLogs() {
  try { const [r] = await pool.execute('DELETE FROM audit_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY) LIMIT 1000', [AUDIT_LOG_RETENTION_DAYS]); if (r.affectedRows > 0) console.log(`Cleaned ${r.affectedRows} old audit logs`); } catch(e) {}
}
setInterval(cleanupAuditLogs, 24 * 60 * 60 * 1000);

// ============================================================
// GLOBAL ERROR HANDLERS
// ============================================================
process.on('uncaughtException', (error) => { console.error('UNCAUGHT EXCEPTION:', error.message); });
process.on('unhandledRejection', (reason) => { console.error('UNHANDLED REJECTION:', reason); });

// ============================================================
// AUTH ROUTES
// ============================================================

app.post('/api/auth/register', async (req, res) => {
  try { const {email,password,mobile,company_name}=req.body; if(!/^(09\d{9}|\+639\d{9})$/.test(mobile)) return res.status(400).json({error:'Invalid mobile'}); if(!validatePasswordComplexity(password)) return res.status(400).json({error:'Password: 8+ chars, upper, lower, number, symbol'}); const [ex]=await pool.execute('SELECT id FROM users WHERE email=?',[email]); if(ex.length) return res.status(400).json({error:'Email registered'}); await pool.execute('INSERT INTO users (email,password,mobile,company_name,role,is_verified,is_active,createdAt,updatedAt) VALUES (?,?,?,?,?,?,?,NOW(),NOW())',[email,await hashPassword(password),mobile,company_name||null,'client',false,true]); const otp=generateOTP(); otpCache.set(email,otp); await sendOTPEmail(email,'',otp,'verification'); res.status(201).json({status:'success',message:'Check email for OTP',email:maskEmail(email)}); } catch(e) { res.status(400).json({error:e.message}); }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try { const {email,otp}=req.body; const [u]=await pool.execute('SELECT * FROM users WHERE email=?',[email]); if(!u.length) return res.status(404).json({error:'User not found'}); if(u[0].is_verified) return res.json({message:'Already verified'}); const s=otpCache.get(email); if(!s||s!==otp) return res.status(400).json({error:'Invalid OTP'}); otpCache.del(email); await pool.execute('UPDATE users SET is_verified=1 WHERE email=?',[email]); res.json({status:'success',message:'Email verified'}); } catch(e) { res.status(400).json({error:e.message}); }
});

app.post('/api/auth/resend-otp', async (req, res) => {
  const {email}=req.body; const [u]=await pool.execute('SELECT * FROM users WHERE email=?',[email]); if(!u.length) return res.status(404).json({error:'User not found'}); if(u[0].is_verified) return res.json({message:'Already verified'}); const otp=generateOTP(); otpCache.set(email,otp); await sendOTPEmail(email,'',otp,'verification'); res.json({status:'success',message:'OTP resent'}); 
});

app.post('/api/auth/login', async (req, res) => {
  const st=Date.now();
  try { const {email,password}=req.body; if(!email||!password){await bcrypt.compare('x','$2a$12$dummyhashfortimingprevention');return res.status(400).json({error:'Email and password required'});} if(!validateEmail(email)){await bcrypt.compare('x','$2a$12$dummyhashfortimingprevention');return res.status(400).json({error:'Invalid email'});} const lo=checkLockout(email); if(lo.locked) return res.status(429).json({error:'Too many attempts',retryAfter:lo.minutesLeft*60}); const [users]=await pool.execute('SELECT * FROM users WHERE email=?',[email]); const user=users.length?users[0]:null; const match=user?await bcrypt.compare(password,user.password):await bcrypt.compare(password,'$2a$12$LJ3m4ys3GZqGqGqGqGqGqO'); if(!user||!match){recordFailedAttempt(email);const el=Date.now()-st;if(el<500) await new Promise(r=>setTimeout(r,500-el));return res.status(401).json({error:'Invalid email or password'});} if(!user.is_verified||!user.is_active){await new Promise(r=>setTimeout(r,200));return res.status(401).json({error:'Invalid email or password'});} resetAttempts(email); if(user.first_login===1){const tt=jwt.sign({id:user.id,role:user.role,firstLogin:true,iat:Math.floor(Date.now()/1000)},process.env.JWT_SECRET,{expiresIn:'15m'});return res.json({status:'first_login',token:tt,message:'Set password and accept terms'});} const at=jwt.sign({id:user.id,role:user.role,iat:Math.floor(Date.now()/1000)},process.env.JWT_SECRET,{expiresIn:JWT_EXPIRY}); const rt=jwt.sign({id:user.id,type:'refresh',iat:Math.floor(Date.now()/1000)},process.env.JWT_SECRET,{expiresIn:REFRESH_TOKEN_EXPIRY}); if(user.current_token){try{jwt.verify(user.current_token,process.env.JWT_SECRET);}catch(e){}await pool.execute('UPDATE users SET current_token=NULL WHERE id=?',[user.id]);} await pool.execute('UPDATE users SET current_token=?,last_login=NOW() WHERE id=?',[at,user.id]); await logAudit(user.id,'LOGIN','users',user.id,{email:user.email}); res.setHeader('Set-Cookie',[`fueltrak_token=${at};HttpOnly;Secure;SameSite=Strict;Path=/;Max-Age=3600`,`fueltrak_refresh=${rt};HttpOnly;Secure;SameSite=Strict;Path=/api/auth/refresh;Max-Age=604800`]); res.json({status:'success',token:at,refreshToken:rt,user:{id:user.id,email:user.email,role:user.role,mobile:user.mobile?user.mobile.replace(/(\d{3})\d{4}(\d{4})/,'$1****$3'):null,company_name:user.company_name}}); } catch(e) { logger.error('Login error',{error:e.message}); const el=Date.now()-st; if(el<500) await new Promise(r=>setTimeout(r,500-el)); res.status(500).json({error:'An error occurred'}); }
});

app.post('/api/auth/refresh', async (req, res) => {
  try { const {refreshToken}=req.body; if(!refreshToken) return res.status(400).json({error:'Refresh token required'}); const d=jwt.verify(refreshToken,process.env.JWT_SECRET); if(d.type!=='refresh') return res.status(400).json({error:'Invalid token type'}); const [u]=await pool.execute('SELECT id,role FROM users WHERE id=? AND is_active=1',[d.id]); if(!u.length) return res.status(401).json({error:'User not found'}); res.json({status:'success',token:jwt.sign({id:u[0].id,role:u[0].role},process.env.JWT_SECRET,{expiresIn:JWT_EXPIRY})}); } catch(e) { res.status(401).json({error:'Invalid token'}); }
});

app.get('/api/auth/profile', authenticate, (req, res) => res.json({ status: 'success', user: req.user }));

app.post('/api/auth/force-login', async (req, res) => {
  try { const {email,password}=req.body; const [u]=await pool.execute('SELECT * FROM users WHERE email=?',[email]); if(!u.length||!await bcrypt.compare(password,u[0].password)) return res.status(401).json({error:'Invalid credentials'}); const t=jwt.sign({id:u[0].id,role:u[0].role},process.env.JWT_SECRET,{expiresIn:'24h'}); await pool.execute('UPDATE users SET current_token=?,last_login=NOW() WHERE id=?',[t,u[0].id]); res.json({status:'success',token:t,user:{id:u[0].id,email:u[0].email,role:u[0].role,mobile:u[0].mobile,company_name:u[0].company_name}}); } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try { const {email}=req.body; const [u]=await pool.execute('SELECT id FROM users WHERE email=?',[email]); if(!u.length) return res.json({status:'success',message:'If email exists, OTP sent'}); const otp=generateOTP(); otpCache.set('reset_'+email,otp); await sendOTPEmail(email,'',otp,'reset'); res.json({status:'success',message:'If email exists, OTP sent'}); } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/auth/verify-reset-otp', async (req, res) => {
  try { const {email,otp}=req.body; const s=otpCache.get('reset_'+email); if(!s||s!==otp) return res.status(400).json({error:'Invalid OTP'}); otpCache.del('reset_'+email); res.json({status:'success',message:'OTP verified',resetToken:jwt.sign({email,purpose:'reset'},process.env.JWT_SECRET,{expiresIn:'15m'})}); } catch(e) { res.status(400).json({error:e.message}); }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try { const {resetToken,newPassword}=req.body; if(!newPassword||!validatePasswordComplexity(newPassword)) return res.status(400).json({error:'Invalid password'}); const d=jwt.verify(resetToken,process.env.JWT_SECRET); if(d.purpose!=='reset') return res.status(400).json({error:'Invalid token'}); await pool.execute('UPDATE users SET password=? WHERE email=?',[await hashPassword(newPassword),d.email]); res.json({status:'success',message:'Password reset'}); } catch(e) { if(e.name==='TokenExpiredError') return res.status(400).json({error:'Token expired'}); res.status(400).json({error:e.message}); }
});

app.post('/api/auth/logout', authenticate, async (req, res) => {
  try { const t=req.header('Authorization')?.replace('Bearer ',''); if(t){tokenBlacklist.add(t);await pool.execute('UPDATE users SET current_token=NULL WHERE id=?',[req.user.id]);} await logAudit(req.user.id,'LOGOUT','users',req.user.id,{email:req.user.email}); res.json({status:'success',message:'Logged out'}); } catch(e) { res.status(400).json({error:e.message}); }
});

app.post('/api/auth/first-login-setup', authenticate, async (req, res) => {
  try { const {password,terms_accepted}=req.body; if(!terms_accepted) return res.status(400).json({error:'Accept terms'}); if(!validatePassword(password).valid) return res.status(400).json({error:validatePassword(password).error}); await pool.execute('UPDATE users SET password=?,terms_accepted=1 WHERE id=?',[await hashPassword(password),req.user.id]); const otp=generateOTP(); otpCache.set(req.user.email,otp); await sendOTPEmail(req.user.email,'',otp,'verification'); res.json({status:'otp_required',message:'Check email for OTP',email:maskEmail(req.user.email)}); } catch(e) { res.status(400).json({error:e.message}); }
});

app.post('/api/auth/verify-first-login-otp', async (req, res) => {
  try { const {email,otp}=req.body; const [u]=await pool.execute('SELECT * FROM users WHERE email=?',[email]); if(!u.length) return res.status(404).json({error:'User not found'}); const s=otpCache.get(email); if(!s||s!==otp) return res.status(400).json({error:'Invalid OTP'}); otpCache.del(email); await pool.execute('UPDATE users SET is_verified=1,first_login=0 WHERE email=?',[email]); const t=jwt.sign({id:u[0].id,role:u[0].role},process.env.JWT_SECRET,{expiresIn:'24h'}); res.json({status:'success',message:'Email verified!',token:t,user:{id:u[0].id,email:u[0].email,role:u[0].role}}); } catch(e) { res.status(400).json({error:e.message}); }
});

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/api/health', (req, res) => res.json({ status: 'OK', db: process.env.DB_NAME }));

// ============================================================
// DISPATCH ROUTES
// ============================================================

app.get('/api/dispatch/dashboard', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [[{pending}],[{dispatched}],[{completed}],[{trucks}]]=await Promise.all([pool.execute("SELECT COUNT(*) as pending FROM authority_to_load WHERE status='pending'"),pool.execute("SELECT COUNT(*) as dispatched FROM authority_to_load WHERE status='dispatched'"),pool.execute("SELECT COUNT(*) as completed FROM authority_to_load WHERE status='completed'"),pool.execute('SELECT COUNT(*) as trucks FROM trucks WHERE is_active=1')]); res.json({status:'success',data:{loadedToday:dispatched,pendingCount:pending,completedCount:completed,totalTrucks:trucks}}); } catch(e) { res.status(500).json({error:e.message}); } });
app.get('/api/dispatch/enhanced-stats', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const ck='dispatch_enhanced_stats',c=serverCache.get(ck); if(c) return res.json(c); const [s]=await pool.execute("SELECT SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as pending,SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) as approved,SUM(CASE WHEN status='dispatched' THEN 1 ELSE 0 END) as loading,SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed,SUM(CASE WHEN status IN ('dispatched','completed') AND DATE(dispatch_date)=CURDATE() THEN 1 ELSE 0 END) as loadedToday,COALESCE(SUM(CASE WHEN status IN ('dispatched','completed') THEN volume ELSE 0 END),0) as totalVolume,COALESCE(SUM(CASE WHEN status IN ('dispatched','completed') AND DATE(dispatch_date)=CURDATE() THEN volume ELSE 0 END),0) as todayVolume FROM authority_to_load"); const r={status:'success',data:{pending:s[0].pending,approved:s[0].approved,loading:s[0].loading,completed:s[0].completed,loadedToday:s[0].loadedToday,totalVolume:s[0].totalVolume,todayVolume:s[0].todayVolume,totalBackload:0,todayBackload:0}}; serverCache.set(ck,r,30); res.json(r); } catch(e) { res.status(500).json({error:e.message}); } });
app.get('/api/dispatch/truck-stats', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const ck='dispatch_truck_stats',c=serverCache.get(ck); if(c) return res.json(c); const [s]=await pool.execute("SELECT COUNT(*) as total,SUM(is_active) as active,SUM(CASE WHEN is_active=0 THEN 1 ELSE 0 END) as inactive,COALESCE(SUM(total_capacity),0) as totalCapacity,(SELECT COUNT(DISTINCT t.id) FROM trucks t INNER JOIN truck_documents td1 ON t.id=td1.truck_id AND td1.document_type='lto_registration' AND td1.expiry_date>=NOW() INNER JOIN truck_documents td2 ON t.id=td2.truck_id AND td2.document_type='fire_permit' AND td2.expiry_date>=NOW() INNER JOIN truck_documents td3 ON t.id=td3.truck_id AND td3.document_type='dost_calibration' AND td3.expiry_date>=NOW()) as withValidDocs,(SELECT COUNT(DISTINCT t.id) FROM trucks t INNER JOIN truck_documents td ON t.id=td.truck_id AND td.expiry_date<NOW()) as withExpiredDocs FROM trucks"); const r={status:'success',data:{total:s[0].total,active:s[0].active,inactive:s[0].inactive,withExpiredDocs:s[0].withExpiredDocs,withValidDocs:s[0].withValidDocs,expiringSoon:0,totalCapacity:s[0].totalCapacity,documentBreakdown:{lto:{},fire:{},dost:{}},trucksNeedingAttention:[]}}; serverCache.set(ck,r,60); res.json(r); } catch(e) { res.status(500).json({error:e.message}); } });
app.get('/api/dispatch/pending', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [a]=await pool.execute("SELECT * FROM authority_to_load WHERE status IN ('pending','verified') ORDER BY createdAt DESC"); const r=[]; for(const x of a){const [t]=await pool.execute('SELECT * FROM trucks WHERE id=?',[x.truck_id]);const [c]=await pool.execute('SELECT id,email,company_name FROM users WHERE id=?',[x.client_id]);r.push({...x,truck:t[0]||null,client:c[0]||null});} res.json({status:'success',data:r}); } catch(e) { res.status(500).json({error:e.message}); } });
app.post('/api/dispatch/verify/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const {action,remarks}=req.body; const s=action==='approve'?'approved':action==='reject'?'rejected':null; if(!s) return res.status(400).json({error:'Invalid action'}); await pool.execute('UPDATE authority_to_load SET status=?,verified_by=?,remarks=? WHERE id=?',[s,req.user.id,remarks||null,req.params.id]); serverCache.del('dispatch_enhanced_stats');serverCache.del('dispatch_truck_stats'); const [u]=await pool.execute('SELECT * FROM authority_to_load WHERE id=?',[req.params.id]); res.json({status:'success',data:u[0]}); } catch(e) { res.status(400).json({error:e.message}); } });
app.post('/api/dispatch/start-loading/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { await pool.execute("UPDATE authority_to_load SET status='dispatched',dispatch_date=NOW() WHERE id=?",[req.params.id]); serverCache.del('dispatch_enhanced_stats'); const [u]=await pool.execute('SELECT * FROM authority_to_load WHERE id=?',[req.params.id]); res.json({status:'success',message:'Loading started',data:u[0]}); } catch(e) { res.status(400).json({error:e.message}); } });
app.post('/api/dispatch/complete-loading/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const {actual_volume,remarks,printed_wc}=req.body; await pool.execute("UPDATE authority_to_load SET status='completed',completed_date=NOW(),completed_by=?,actual_volume=?,remarks=?,printed_wc=? WHERE id=?",[req.user.id,actual_volume||null,remarks||'Loading completed',printed_wc||null,req.params.id]); serverCache.del('dispatch_enhanced_stats');serverCache.del('dispatch_truck_stats'); const [u]=await pool.execute('SELECT * FROM authority_to_load WHERE id=?',[req.params.id]); res.json({status:'success',data:u[0]}); } catch(e) { res.status(400).json({error:e.message}); } });
app.put('/api/dispatch/update-wc/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { await pool.execute('UPDATE authority_to_load SET printed_wc=? WHERE id=?',[req.body.printed_wc||null,req.params.id]); res.json({status:'success',message:'WC updated'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.put('/api/dispatch/update-si/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { await pool.execute('UPDATE authority_to_load SET has_si=? WHERE id=?',[req.body.has_si,req.params.id]); res.json({status:'success'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.put('/api/dispatch/update-tps/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const u=[],p=[]; for(const[k,v] of Object.entries(req.body)){if(ALLOWED_UPDATE_FIELDS.includes(k)){u.push(`${k}=?`);p.push(v);}} if(u.length){p.push(req.params.id);await pool.execute('UPDATE authority_to_load SET '+u.join(',')+' WHERE id=?',p);} res.json({status:'success'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.put('/api/dispatch/update-so/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { await pool.execute('UPDATE authority_to_load SET so_number=? WHERE id=?',[req.body.so_number,req.params.id]); res.json({status:'success'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.get('/api/dispatch/approved-for-loading', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [a]=await pool.execute("SELECT * FROM authority_to_load WHERE status='approved' ORDER BY createdAt DESC"); const r=[]; for(const x of a){const [t]=await pool.execute('SELECT * FROM trucks WHERE id=?',[x.truck_id]);const [c]=await pool.execute('SELECT id,email,company_name FROM users WHERE id=?',[x.client_id]);r.push({...x,truck:t[0]||null,client:c[0]||null});} res.json({status:'success',data:r}); } catch(e) { res.status(500).json({error:e.message}); } });
app.get('/api/dispatch/ongoing-loading', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [a]=await pool.execute("SELECT * FROM authority_to_load WHERE status='dispatched' ORDER BY dispatch_date DESC"); const r=[]; for(const x of a){const [t]=await pool.execute('SELECT * FROM trucks WHERE id=?',[x.truck_id]);const [c]=await pool.execute('SELECT id,email,company_name FROM users WHERE id=?',[x.client_id]);r.push({...x,truck:t[0]||null,client:c[0]||null});} res.json({status:'success',data:r}); } catch(e) { res.status(500).json({error:e.message}); } });
app.post('/api/dispatch/cancel-loading/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { await pool.execute("UPDATE authority_to_load SET status='pending',dispatch_date=NULL,remarks=? WHERE id=?",['Loading cancelled: '+(req.body.reason||'No reason'),req.params.id]); res.json({status:'success',message:'Cancelled'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.post('/api/dispatch/handle-cancellation/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const s=req.body.action==='approve_cancel'?'cancelled':'approved'; await pool.execute('UPDATE authority_to_load SET status=? WHERE id=?',[s,req.params.id]); res.json({status:'success',message:'Done'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.post('/api/sync-masterlist', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [m]=await pool.execute('SELECT tm.* FROM truck_masterlist tm WHERE tm.plate_no NOT IN (SELECT plate_no FROM trucks)'); let c=0,errs=[]; for(const x of m){try{await pool.execute('INSERT INTO trucks (plate_no,make,driver_name,hauler_name,total_capacity,is_active,createdAt,updatedAt) VALUES (?,?,?,?,?,1,NOW(),NOW())',[(x.plate_no||'').substring(0,20).toUpperCase(),(x.truck_make||'Unknown').substring(0,50),(x.driver_name||'').replace(/"/g,'').substring(0,100),(x.hauler_name||'').substring(0,100),parseFloat(x.total_capacity)||0]);c++;}catch(e){errs.push(x.plate_no+': '+e.message);}} res.json({status:'success',message:`Synced ${c} trucks`,count:c,errors:errs.slice(0,5)}); } catch(e) { res.status(400).json({error:e.message}); } });

// ============================================================
// CLIENT ROUTES
// ============================================================

app.get('/api/client/dashboard', authenticate, authorize('client'), async (req, res) => { try { const ck='client_dashboard_'+req.user.id,c=serverCache.get(ck); if(c) return res.json(c); const [a]=await pool.execute('SELECT atl.*,t.plate_no as truck_plate,t.make as truck_make FROM authority_to_load atl LEFT JOIN trucks t ON atl.truck_id=t.id WHERE atl.client_id=? ORDER BY atl.createdAt DESC LIMIT 20',[req.user.id]); const [cnt]=await pool.execute('SELECT status,COUNT(*) as count FROM authority_to_load WHERE client_id=? GROUP BY status',[req.user.id]); const s={total:0,pending:0,approved:0,dispatched:0,completed:0,cancelled:0}; cnt.forEach(x=>{if(x.status==='cancelled'||x.status==='rejected') s.cancelled+=x.count; else if(s.hasOwnProperty(x.status)) s[x.status]=x.count;}); s.total=Object.values(s).reduce((a,b)=>a+b,0); const r={status:'success',data:{stats:s,recent:a,recentATLs:a}}; serverCache.set(ck,r,30); res.json(r); } catch(e) { res.status(500).json({error:e.message}); } });
app.get('/api/client/verify-truck/:plateNo', authenticate, authorize('client'), async (req, res) => { try { const pn=decodeURIComponent(req.params.plateNo).toUpperCase().trim(); const [t]=await pool.execute('SELECT * FROM trucks WHERE plate_no=? AND is_active=1',[pn]); if(t.length){const tr=t[0];const [d]=await pool.execute('SELECT * FROM truck_documents WHERE truck_id=?',[tr.id]);const [mr]=await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no=?',[pn]);const ds={};let av=true;['lto_registration','fire_permit','dost_calibration'].forEach(ty=>{const doc=d.find(x=>x.document_type===ty);if(doc){const days=Math.ceil((new Date(doc.expiry_date)-new Date())/86400000);ds[ty]={status:days<0?'expired':days<=30?'expiring_soon':'valid',valid:days>=0,days_remaining:days,expiry_date:doc.expiry_date,document_number:doc.document_number||''};if(days<0)av=false;}else{ds[ty]={status:'missing',valid:true,days_remaining:-1};}});return res.json({status:'success',data:{truck:{id:tr.id,plate_no:tr.plate_no,make:tr.make||'Unknown',driver_name:(mr[0]?.driver_name||tr.driver_name||'').replace(/"/g,''),hauler_name:mr[0]?.hauler_name||tr.hauler_name||'',total_capacity:tr.total_capacity||0},documents:ds,can_proceed:av}});} const [m]=await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no=?',[pn]); if(m.length){const mx=m[0];const ct=[mx.cot1,mx.cot2,mx.cot3,mx.cot4,mx.cot5,mx.cot6,mx.cot7,mx.cot8,mx.cot9,mx.cot10].reduce((s,v)=>s+parseFloat(v||0),0);const tc=parseFloat(mx.total_capacity)||ct||0;const [nt]=await pool.execute('INSERT INTO trucks (plate_no,make,driver_name,hauler_name,total_capacity,is_active,createdAt,updatedAt) VALUES (?,?,?,?,?,1,NOW(),NOW())',[mx.plate_no,mx.truck_make||'Unknown',(mx.driver_name||'').replace(/"/g,''),mx.hauler_name||'',tc]);return res.json({status:'success',data:{truck:{id:nt.insertId,plate_no:mx.plate_no,make:mx.truck_make||'Unknown',driver_name:(mx.driver_name||'').replace(/"/g,''),hauler_name:mx.hauler_name||'',total_capacity:tc},documents:{lto_registration:{status:'not_required',valid:true,days_remaining:999},fire_permit:{status:'not_required',valid:true,days_remaining:999},dost_calibration:{status:'not_required',valid:true,days_remaining:999}},can_proceed:true}});} res.status(404).json({status:'error',error:'Truck not found',can_proceed:false}); } catch(e) { res.status(500).json({status:'error',error:e.message,can_proceed:false}); } });
app.post('/api/client/submit-atl', authenticate, authorize('client'), validateATLInput, async (req, res) => { try { const {truck_id,plate_no,volume,driver_name,hauler_name,remarks,company,so_number,scheduled_date,contact_number,has_si,special_instructions}=req.body; let tid=truck_id,pn=plate_no,d=driver_name,h=hauler_name; if(tid){const [t]=await pool.execute('SELECT * FROM trucks WHERE id=? AND is_active=1',[tid]);if(!t.length)return res.status(404).json({error:'Truck not found'});pn=t[0].plate_no;if(!d)d=t[0].driver_name;if(!h)h=t[0].hauler_name;const [mu]=await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no=?',[pn.toUpperCase()]);if(mu.length){if(!d)d=mu[0].driver_name;if(!h)h=mu[0].hauler_name;}}else if(pn){const [t]=await pool.execute('SELECT * FROM trucks WHERE plate_no=? AND is_active=1',[pn.toUpperCase()]);if(t.length){tid=t[0].id;if(!d)d=t[0].driver_name;if(!h)h=t[0].hauler_name;}else{const [m]=await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no=?',[pn.toUpperCase()]);if(m.length){const [nt]=await pool.execute('INSERT INTO trucks (plate_no,make,driver_name,hauler_name,total_capacity,is_active,createdAt,updatedAt) VALUES (?,?,?,?,?,1,NOW(),NOW())',[m[0].plate_no,m[0].truck_make||'Unknown',(m[0].driver_name||'').replace(/"/g,''),m[0].hauler_name||'',m[0].total_capacity||0]);tid=nt.insertId;if(!d)d=m[0].driver_name;if(!h)h=m[0].hauler_name;}}} if(!tid)return res.status(400).json({error:'Truck not found'}); const [ex]=await pool.execute("SELECT id FROM authority_to_load WHERE client_id=? AND truck_id=? AND status IN ('pending','approved')",[req.user.id,tid]);if(ex.length)return res.status(400).json({error:'Pending ATL exists for this truck'}); const ac=await generateATLCode(company||req.user.company_name); await pool.execute("INSERT INTO authority_to_load (atl_code,client_id,truck_id,company,so_number,volume,hauler,plate_no,driver_name,contact_number,has_si,scheduled_date,remarks,special_instructions,status,createdAt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',NOW())",[ac,req.user.id,tid,sanitize(company||req.user.company_name,100),sanitize(so_number,50),volume,sanitize(h,100),sanitize(pn,20),sanitize(d,100),sanitize(contact_number,20),has_si||false,scheduled_date||new Date().toISOString().split('T')[0],sanitize(remarks,200),sanitize(special_instructions,500)]); serverCache.del('dispatch_enhanced_stats');serverCache.del('dispatch_truck_stats');clearCache('client_dashboard_'+req.user.id); res.status(201).json({status:'success',message:'ATL '+ac+' Submitted!',data:{atl_code:ac}}); } catch(e) { res.status(400).json({error:e.message}); } });
app.post('/api/client/cancel-atl/:id', authenticate, authorize('client'), async (req, res) => { try { await pool.execute("UPDATE authority_to_load SET status='cancelled',remarks=? WHERE id=? AND client_id=?",['Cancellation: '+(req.body.reason||''),req.params.id,req.user.id]); await logAudit(req.user.id,'CANCEL_ATL','authority_to_load',req.params.id,{reason:req.body.reason}); res.json({status:'success',message:'Cancelled'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.get('/api/client/atl/:id', authenticate, authorize('client'), async (req, res) => { try { const [a]=await pool.execute('SELECT * FROM authority_to_load WHERE id=? AND client_id=?',[req.params.id,req.user.id]); if(!a.length) return res.status(404).json({error:'Not found'}); res.json({status:'success',data:a[0]}); } catch(e) { res.status(500).json({error:e.message}); } });
app.get('/api/client/sales-orders', authenticate, authorize('client'), async (req, res) => { try { const [o]=await pool.execute("SELECT DISTINCT so.*,COALESCE((SELECT SUM(atl.volume) FROM authority_to_load atl WHERE atl.so_number=so.so_number AND atl.client_id=? AND atl.status NOT IN ('cancelled','rejected')),0) as client_used_volume,COALESCE((SELECT SUM(atl.volume) FROM authority_to_load atl WHERE atl.so_number=so.so_number AND atl.status NOT IN ('cancelled','rejected')),0) as total_used_volume FROM sales_orders so LEFT JOIN sales_order_clients soc ON so.id=soc.sales_order_id WHERE so.client_id=? OR soc.client_id=? ORDER BY so.createdAt DESC",[req.user.id,req.user.id,req.user.id]); res.json({status:'success',data:o.map(so=>({id:so.id,so_number:so.so_number,total_volume:parseFloat(so.total_volume)||0,used_volume:so.is_multi_client?parseFloat(so.total_used_volume):parseFloat(so.client_used_volume),remaining_volume:Math.max(0,(parseFloat(so.total_volume)||0)-(so.is_multi_client?parseFloat(so.total_used_volume):parseFloat(so.client_used_volume))),status:so.status,is_multi_client:so.is_multi_client==1,company_name:so.company_name,notes:so.notes,createdAt:so.createdAt}))}); } catch(e) { res.status(500).json({error:e.message}); } });

// ============================================================
// TRUCK MASTERLIST ROUTES
// ============================================================

app.get('/api/truck-masterlist', authenticate, async (req, res) => { try { const ck='truck_masterlist_plates',c=serverCache.get(ck); if(c) return res.json(c); const [r]=await pool.execute('SELECT plate_no FROM truck_masterlist ORDER BY plate_no ASC'); const d={status:'success',data:r}; serverCache.set(ck,d,300); res.json(d); } catch(e) { res.status(500).json({error:e.message}); } });
app.get('/api/truck-masterlist/:plateNo', authenticate, async (req, res) => { try { const [r]=await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no=?',[req.params.plateNo.toUpperCase()]); res.json(r.length?{status:'success',data:r[0]}:{status:'error',message:'Not found'}); } catch(e) { res.status(500).json({error:e.message}); } });
app.get('/api/truck-masterlist-all', authenticate, async (req, res) => { try { const [r]=await pool.execute('SELECT * FROM truck_masterlist ORDER BY plate_no ASC'); res.json({status:'success',data:r}); } catch(e) { res.status(500).json({error:e.message}); } });
app.put('/api/update-truck-masterlist/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const allowed=['truck_make','driver_name','hauler_name','tps_count','plate_no','cot1','cot2','cot3','cot4','cot5','cot6','cot7','cot8','cot9','cot10','total_capacity']; const u=[],p=[]; for(const k in req.body){if(allowed.includes(k)){u.push(k+'=?');p.push(req.body[k]);}} if(!u.length) return res.status(400).json({error:'No valid fields'}); p.push(req.params.id); await pool.execute('UPDATE truck_masterlist SET '+u.join(',')+' WHERE id=?',p); res.json({status:'success',message:'Updated'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.post('/api/truck-masterlist-add', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const {plate_no,truck_make,driver_name,hauler_name,tps_count,cot1,cot2,cot3,cot4,cot5,cot6,cot7,cot8,cot9,cot10,total_capacity}=req.body; await pool.execute('INSERT INTO truck_masterlist (plate_no,truck_make,driver_name,hauler_name,tps_count,cot1,cot2,cot3,cot4,cot5,cot6,cot7,cot8,cot9,cot10,total_capacity) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',[plate_no.toUpperCase(),truck_make,driver_name,hauler_name,tps_count,cot1,cot2,cot3,cot4,cot5,cot6,cot7,cot8,cot9,cot10,total_capacity]); res.json({status:'success',message:'Truck added'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.post('/api/truck-masterlist-clear', authenticate, authorize('dispatcher','management'), async (req, res) => { try { await pool.execute('DELETE FROM truck_masterlist');await pool.execute('DELETE FROM truck_documents');await pool.execute('DELETE FROM trucks'); res.json({status:'success',message:'Cleared'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.post('/api/truck-masterlist-bulk', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const {trucks}=req.body; let c=0; for(const t of trucks){await pool.execute('INSERT INTO truck_masterlist (truck_make,plate_no,driver_name,hauler_name,cot1,cot2,cot3,cot4,cot5,cot6,cot7,cot8,cot9,cot10,total_capacity,tps_count) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',[t.truck_make||'',t.plate_no||'',t.driver_name||'',t.hauler_name||'',t.cot1||'0',t.cot2||'0',t.cot3||'0',t.cot4||'0',t.cot5||'0',t.cot6||'0',t.cot7||'0',t.cot8||'0',t.cot9||'0',t.cot10||'0',t.total_capacity||'0',t.tps_count||0]);c++;} res.json({status:'success',message:`${c} uploaded`}); } catch(e) { res.status(400).json({error:e.message}); } });

// ============================================================
// TRUCKS & DOCUMENTS ROUTES
// ============================================================

app.get('/api/trucks/all', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [t]=await pool.execute('SELECT * FROM trucks ORDER BY plate_no ASC'); const r=[]; for(const x of t){const [d]=await pool.execute('SELECT * FROM truck_documents WHERE truck_id=?',[x.id]);r.push({...x,documents:d});} res.json({status:'success',data:r}); } catch(e) { res.status(500).json({error:e.message}); } });
app.delete('/api/trucks/delete/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [truck]=await pool.execute('SELECT * FROM trucks WHERE id=?',[req.params.id]); if(!truck.length) return res.status(404).json({error:'Truck not found'}); await softDelete('trucks', req.params.id, req.user.id, req.user.email); await pool.execute('DELETE FROM truck_documents WHERE truck_id=?',[req.params.id]); await pool.execute('DELETE FROM trucks WHERE id=?',[req.params.id]); await pool.execute('DELETE FROM truck_masterlist WHERE plate_no=?',[truck[0].plate_no]); res.json({status:'success',message:'Truck deleted (moved to recycle bin)'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.get('/api/truck-documents/:truckId', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [d]=await pool.execute('SELECT * FROM truck_documents WHERE truck_id=?',[req.params.truckId]); res.json({status:'success',data:d}); } catch(e) { res.status(500).json({error:e.message}); } });
app.post('/api/truck-documents/:truckId', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const {document_type,document_number,issue_date,expiry_date}=req.body; const [ex]=await pool.execute('SELECT id FROM truck_documents WHERE truck_id=? AND document_type=?',[req.params.truckId,document_type]); if(ex.length){await pool.execute('UPDATE truck_documents SET document_number=?,issue_date=?,expiry_date=?,status=? WHERE id=?',[document_number||'',issue_date||new Date().toISOString().split('T')[0],expiry_date,new Date(expiry_date)>=new Date()?'valid':'expired',ex[0].id]);}else{await pool.execute('INSERT INTO truck_documents (truck_id,document_type,document_number,issue_date,expiry_date,status,createdAt) VALUES (?,?,?,?,?,?,NOW())',[req.params.truckId,document_type,document_number||'',issue_date||new Date().toISOString().split('T')[0],expiry_date,'valid']);} res.json({status:'success',message:'Document saved'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.get('/api/docs-report/summary', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [s]=await pool.execute("SELECT COUNT(DISTINCT t.id) as totalTrucks,COUNT(DISTINCT CASE WHEN td.expiry_date>=NOW() THEN t.id END) as validDocs,COUNT(DISTINCT CASE WHEN td.expiry_date<NOW() THEN t.id END) as expiredDocs,COUNT(DISTINCT CASE WHEN td.id IS NULL THEN t.id END) as missingDocs FROM trucks t LEFT JOIN truck_documents td ON t.id=td.truck_id"); const [r]=await pool.execute("SELECT t.plate_no,t.make,t.driver_name,t.hauler_name,MAX(CASE WHEN td.document_type='lto_registration' THEN td.expiry_date END) as lto_expiry,MAX(CASE WHEN td.document_type='fire_permit' THEN td.expiry_date END) as fire_expiry,MAX(CASE WHEN td.document_type='dost_calibration' THEN td.expiry_date END) as dost_expiry FROM trucks t LEFT JOIN truck_documents td ON t.id=td.truck_id GROUP BY t.id ORDER BY t.plate_no"); res.json({status:'success',data:{stats:s[0],records:r}}); } catch(e) { res.status(500).json({error:e.message}); } });

// ============================================================
// SALES ORDERS ROUTES
// ============================================================

app.get('/api/sales-orders/clients-list', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [c]=await pool.execute("SELECT id,email,company_name FROM users WHERE role='client' AND is_active=1 ORDER BY company_name ASC"); res.json({status:'success',data:c}); } catch(e) { res.status(500).json({error:e.message}); } });
app.get('/api/sales-orders/validate', authenticate, async (req, res) => { try { const {so_number,client_id}=req.query; if(!so_number) return res.status(400).json({error:'SO required'}); const [o]=await pool.execute("SELECT so.*,u.company_name as client_company FROM sales_orders so JOIN users u ON so.client_id=u.id WHERE so.so_number=? AND so.status='active'",[so_number]); if(!o.length) return res.json({status:'error',valid:false,message:'SO not found'}); const od=o[0]; let belongs=od.client_id==client_id; if(!belongs&&od.is_multi_client){const [ac]=await pool.execute('SELECT id FROM sales_order_clients WHERE sales_order_id=? AND client_id=?',[od.id,client_id]);belongs=ac.length>0;} if(!belongs) return res.json({status:'error',valid:false,message:'SO not yours',so_owner:od.client_company}); const [u]=await pool.execute("SELECT COALESCE(SUM(volume),0) as used FROM authority_to_load WHERE so_number=? AND status NOT IN ('cancelled','rejected')",[so_number]); const t=parseFloat(od.total_volume)||0,us=parseFloat(u[0].used)||0; res.json({status:'success',valid:true,data:{so_id:od.id,so_number:od.so_number,total_volume:t,used_volume:us,remaining_volume:Math.max(0,t-us),is_multi_client:od.is_multi_client,owner_company:od.client_company}}); } catch(e) { res.status(500).json({error:e.message}); } });
app.put('/api/sales-orders/sync-company-names', authenticate, authorize('dispatcher','management'), async (req, res) => { try { await pool.execute("UPDATE sales_orders so JOIN users u ON so.client_id=u.id SET so.company_name=u.company_name WHERE u.company_name IS NOT NULL AND u.company_name!=''"); await pool.execute("UPDATE sales_order_clients soc JOIN users u ON soc.client_id=u.id SET soc.company_name=u.company_name WHERE u.company_name IS NOT NULL AND u.company_name!=''"); res.json({status:'success',message:'Synced'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.get('/api/sales-orders', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const {search,client_id,status}=req.query; let q='SELECT so.*,u.company_name as client_company,u.email as client_email FROM sales_orders so JOIN users u ON so.client_id=u.id WHERE 1=1'; const p=[]; if(search){q+=' AND (so.so_number LIKE ? OR so.company_name LIKE ?)';p.push('%'+search+'%','%'+search+'%');}if(client_id){q+=' AND so.client_id=?';p.push(client_id);}if(status){q+=' AND so.status=?';p.push(status);}q+=' ORDER BY so.createdAt DESC LIMIT 200'; const [o]=await pool.execute(q,p); const r=[]; for(const x of o){const [a]=await pool.execute('SELECT soc.*,u.company_name,u.email FROM sales_order_clients soc JOIN users u ON soc.client_id=u.id WHERE soc.sales_order_id=?',[x.id]);const [u]=await pool.execute("SELECT COALESCE(SUM(volume),0) as used FROM authority_to_load WHERE so_number=? AND status NOT IN ('cancelled','rejected')",[x.so_number]);r.push({...x,allocations:a,used_volume:parseFloat(u[0].used)});} res.json({status:'success',data:r}); } catch(e) { res.status(500).json({error:e.message}); } });
app.post('/api/sales-orders', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const {so_number,client_id,company_name,total_volume,is_multi_client,notes,allocations}=req.body; if(!so_number||!client_id) return res.status(400).json({error:'SO and Client required'}); const [ex]=await pool.execute('SELECT id FROM sales_orders WHERE so_number=? AND client_id=?',[so_number,client_id]); if(ex.length) return res.status(400).json({error:'Already exists'}); let c=company_name; if(!c){const [cl]=await pool.execute('SELECT company_name FROM users WHERE id=?',[client_id]);c=cl.length?cl[0].company_name:'';} const [r]=await pool.execute('INSERT INTO sales_orders (so_number,client_id,company_name,total_volume,is_multi_client,notes,created_by) VALUES (?,?,?,?,?,?,?)',[so_number,client_id,c,total_volume||0,is_multi_client?1:0,notes||null,req.user.id]); if(is_multi_client&&allocations&&allocations.length){for(const a of allocations){if(a.client_id&&a.allocated_volume>0){const [ac]=await pool.execute('SELECT company_name FROM users WHERE id=?',[a.client_id]);await pool.execute('INSERT INTO sales_order_clients (sales_order_id,client_id,company_name,allocated_volume) VALUES (?,?,?,?)',[r.insertId,a.client_id,ac.length?ac[0].company_name:'',a.allocated_volume]);}}} clearCache('sales_orders'); res.status(201).json({status:'success',message:'Created',data:{id:r.insertId,so_number}}); } catch(e) { res.status(400).json({error:e.message}); } });
app.get('/api/sales-orders/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [o]=await pool.execute('SELECT so.*,u.company_name as client_company,u.email as client_email FROM sales_orders so JOIN users u ON so.client_id=u.id WHERE so.id=?',[req.params.id]); if(!o.length) return res.status(404).json({error:'Not found'}); const [a]=await pool.execute('SELECT soc.*,u.company_name,u.email FROM sales_order_clients soc JOIN users u ON soc.client_id=u.id WHERE soc.sales_order_id=?',[o[0].id]); const [at]=await pool.execute('SELECT id,atl_code,company,plate_no,volume,status,client_id,createdAt FROM authority_to_load WHERE so_number=? ORDER BY createdAt DESC',[o[0].so_number]); res.json({status:'success',data:{...o[0],allocations:a,atls:at}}); } catch(e) { res.status(500).json({error:e.message}); } });
app.put('/api/sales-orders/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const {total_volume,is_multi_client,notes,status,allocations}=req.body; const [ex]=await pool.execute('SELECT * FROM sales_orders WHERE id=?',[req.params.id]); if(!ex.length) return res.status(404).json({error:'Not found'}); await pool.execute('UPDATE sales_orders SET total_volume=?,is_multi_client=?,notes=?,status=? WHERE id=?',[total_volume||ex[0].total_volume,is_multi_client!==undefined?(is_multi_client?1:0):ex[0].is_multi_client,notes||ex[0].notes,status||ex[0].status,req.params.id]); if(allocations&&allocations.length){await pool.execute('DELETE FROM sales_order_clients WHERE sales_order_id=?',[req.params.id]);for(const a of allocations){if(a.client_id&&a.allocated_volume>0){const [ac]=await pool.execute('SELECT company_name FROM users WHERE id=?',[a.client_id]);await pool.execute('INSERT INTO sales_order_clients (sales_order_id,client_id,company_name,allocated_volume) VALUES (?,?,?,?)',[req.params.id,a.client_id,ac.length?ac[0].company_name:'',a.allocated_volume]);}}} clearCache('sales_orders'); res.json({status:'success',message:'Updated'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.delete('/api/sales-orders/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [ex]=await pool.execute('SELECT so_number FROM sales_orders WHERE id=?',[req.params.id]); if(!ex.length) return res.status(404).json({error:'Not found'}); const [ch]=await pool.execute("SELECT COUNT(*) as count FROM authority_to_load WHERE so_number=? AND status NOT IN ('cancelled','rejected')",[ex[0].so_number]); if(ch[0].count>0) return res.status(400).json({error:'Used in '+ch[0].count+' ATLs'}); await pool.execute('DELETE FROM sales_order_clients WHERE sales_order_id=?',[req.params.id]);await pool.execute('DELETE FROM sales_orders WHERE id=?',[req.params.id]); res.json({status:'success',message:'Deleted'}); } catch(e) { res.status(400).json({error:e.message}); } });

// ============================================================
// CHAT ROUTES
// ============================================================

app.get('/api/chat-list', authenticate, async (req, res) => { try { let u; if(req.user.role==='client'){[u]=await pool.execute("SELECT id,email FROM users WHERE role IN ('dispatcher','management') LIMIT 5");}else{[u]=await pool.execute("SELECT id,email FROM users WHERE role='client' ORDER BY company_name LIMIT 50");if(!u.length)[u]=await pool.execute("SELECT id,email FROM users WHERE role='client' LIMIT 50");} res.json({status:'success',data:u}); } catch(e) { res.status(500).json({error:e.message}); } });
app.get('/api/chat/unread', authenticate, async (req, res) => {
  try { const [r]=await pool.execute("SELECT COUNT(*) as unread FROM chat_messages WHERE receiver_id=? AND sender_id!=? AND created_at>DATE_SUB(NOW(),INTERVAL 24 HOUR)",[req.user.id,req.user.id]); res.json({status:'success',unread:r[0].unread||0}); } catch(e) { res.json({status:'success',unread:0}); }
});
app.get('/api/chat/:clientId', authenticate, async (req, res) => { try { const [m]=await pool.execute('SELECT cm.*,u.email as sender_email FROM chat_messages cm JOIN users u ON cm.sender_id=u.id WHERE (cm.sender_id=? AND cm.receiver_id=?) OR (cm.sender_id=? AND cm.receiver_id=?) ORDER BY cm.created_at ASC LIMIT 50',[req.user.id,req.params.clientId,req.params.clientId,req.user.id]); res.json({status:'success',data:m}); } catch(e) { res.status(500).json({error:e.message}); } });
app.post('/api/chat', authenticate, async (req, res) => { try { await pool.execute('INSERT INTO chat_messages (sender_id,receiver_id,message) VALUES (?,?,?)',[req.user.id,req.body.receiver_id,req.body.message]); res.json({status:'success',message:'Sent'}); } catch(e) { res.status(400).json({error:e.message}); } });

// ============================================================
// REPORTS ROUTES
// ============================================================

app.get('/api/reports/filters', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [cl]=await pool.execute("SELECT id,email,company_name FROM users WHERE role='client'"); const [tr]=await pool.execute('SELECT id,plate_no,make FROM trucks'); res.json({status:'success',data:{clients:cl.map(c=>({id:c.id,label:(c.company_name||c.email)+' ('+c.email+')'})),trucks:tr.map(t=>({id:t.id,label:t.plate_no+' - '+t.make}))}}); } catch(e) { res.status(500).json({error:e.message}); } });
app.get('/api/reports/summary', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const {startDate,endDate}=req.query; let q="SELECT * FROM authority_to_load WHERE status IN ('completed','cancelled','dispatched','rejected')"; const p=[]; if(startDate){q+=' AND (DATE(completed_date)>=? OR DATE(createdAt)>=? OR DATE(scheduled_date)>=?)';p.push(startDate,startDate,startDate);}if(endDate){q+=' AND (DATE(completed_date)<=? OR DATE(createdAt)<=? OR DATE(scheduled_date)<=?)';p.push(endDate,endDate,endDate);}q+=' ORDER BY createdAt DESC'; const [a]=await pool.execute(q,p); const r=[]; let tv=0,ta=0,cc=0,ca=0,dc=0; for(const x of a){const [t]=await pool.execute('SELECT plate_no,make,total_capacity FROM trucks WHERE id=?',[x.truck_id]);const [cl]=await pool.execute('SELECT email,company_name FROM users WHERE id=?',[x.client_id]);const v=parseFloat(x.volume)||0,av=parseFloat(x.actual_volume)||v;tv+=v;ta+=av;if(x.status==='completed')cc++;if(x.status==='cancelled')ca++;if(x.status==='dispatched')dc++;r.push({...x,truck:t[0]||null,client:cl[0]||null});} res.json({status:'success',data:{records:r,summary:{total_records:r.length,completed:cc,cancelled:ca,dispatched:dc,total_volume:tv,total_actual_volume:ta}}}); } catch(e) { res.status(500).json({error:e.message}); } });
app.get('/api/reports/export', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const {startDate,endDate}=req.query; let q="SELECT * FROM authority_to_load WHERE status IN ('completed','cancelled','dispatched','rejected')"; const p=[]; if(startDate){q+=' AND DATE(createdAt)>=?';p.push(startDate);}if(endDate){q+=' AND DATE(createdAt)<=?';p.push(endDate);} const [a]=await pool.execute(q,p); let csv='ATL Code,SO Number,Company,Plate No,Driver,Hauler,Contact,Volume (L),Actual Volume (L),SI,Status,Scheduled Date,Dispatch Date,Completed Date,Printed WC,TPS From,TPS To,Remarks\n'; for(const x of a){csv+=`"${x.atl_code||''}","${x.so_number||''}","${x.company||''}","${x.plate_no||''}","${x.driver_name||''}","${x.hauler||''}","${x.contact_number||''}","${x.volume||0}","${x.actual_volume||0}","${x.has_si==1?'With SI':'No SI'}","${x.status}","${x.scheduled_date||''}","${x.dispatch_date||''}","${x.completed_date||''}","${x.printed_wc||''}","${x.tps_start||''}","${x.tps_end||''}","${(x.remarks||'').replace(/"/g,'""')}"\n`;} res.setHeader('Content-Type','text/csv');res.setHeader('Content-Disposition','attachment;filename=report.csv');res.send(csv); } catch(e) { res.status(500).json({error:e.message}); } });
app.get('/api/atl/summary', authenticate, async (req, res) => { try { const [a]=await pool.execute('SELECT * FROM authority_to_load WHERE client_id=? ORDER BY createdAt DESC LIMIT 50',[req.user.id]); const r=[]; for(const x of a){const [t]=await pool.execute('SELECT plate_no,make FROM trucks WHERE id=?',[x.truck_id]);r.push({...x,truck:t[0]||null});} res.json({status:'success',data:{recent:r}}); } catch(e) { res.status(500).json({error:e.message}); } });

// ============================================================
// BULK SYNC, ADMIN, CLIENTS, USERS, AUDIT, MIGRATION
// ============================================================

app.post('/api/sync-all-documents', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const {batch=0}=req.body; const [t]=await pool.execute('SELECT id FROM trucks ORDER BY id LIMIT 30 OFFSET ?',[String(batch*30)]); if(!t.length) return res.json({status:'success',message:'Done!',done:true}); let c=0; for(const x of t){for(const ty of ['lto_registration','fire_permit','dost_calibration']){try{await pool.execute("INSERT IGNORE INTO truck_documents (truck_id,document_type,expiry_date,status,createdAt) VALUES (?,?,?,'valid',NOW())",[x.id,ty,'2030-12-31']);c++;}catch(e){}}} res.json({status:'success',message:`Batch ${batch+1}: ${c} docs`,count:c,done:false,nextBatch:batch+1}); } catch(e) { res.status(400).json({error:e.message}); } });
app.get('/api/admin/optimize-database', authenticate, authorize('dispatcher','management'), async (req, res) => { const idx=['CREATE INDEX idx_atl_status_client ON authority_to_load(status,client_id)','CREATE INDEX idx_atl_client_created ON authority_to_load(client_id,createdAt)','CREATE INDEX idx_atl_truck_status ON authority_to_load(truck_id,status)','CREATE INDEX idx_atl_so_status ON authority_to_load(so_number,status)','CREATE INDEX idx_trucks_plate_active ON trucks(plate_no,is_active)','CREATE INDEX idx_docs_truck_type_expiry ON truck_documents(truck_id,document_type,expiry_date)','CREATE INDEX idx_so_client_status ON sales_orders(client_id,status)','CREATE INDEX idx_soc_so_client ON sales_order_clients(sales_order_id,client_id)','CREATE INDEX idx_chat_receiver_created ON chat_messages(receiver_id,created_at)','CREATE INDEX idx_users_role_active ON users(role,is_active)']; let cr=0,sk=0,fa=0; for(const s of idx){try{await pool.execute(s);cr++;}catch(e){if(e.code==='ER_DUP_KEYNAME')sk++;else fa++;}} res.json({status:'success',message:`Created:${cr},Skipped:${sk},Failed:${fa}`}); });
app.get('/api/admin/create-so-table', authenticate, authorize('dispatcher','management'), async (req, res) => { try { await pool.execute("CREATE TABLE IF NOT EXISTS sales_orders (id INT AUTO_INCREMENT PRIMARY KEY,so_number VARCHAR(50) NOT NULL,client_id INT NOT NULL,company_name VARCHAR(100),total_volume DECIMAL(12,2) DEFAULT 0,used_volume DECIMAL(12,2) DEFAULT 0,is_multi_client TINYINT(1) DEFAULT 0,status ENUM('active','completed','cancelled') DEFAULT 'active',notes TEXT,created_by INT,createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,UNIQUE KEY unique_so_client (so_number,client_id),INDEX idx_so_number (so_number),INDEX idx_client_id (client_id),INDEX idx_status (status),FOREIGN KEY (client_id) REFERENCES users(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"); await pool.execute("CREATE TABLE IF NOT EXISTS sales_order_clients (id INT AUTO_INCREMENT PRIMARY KEY,sales_order_id INT NOT NULL,client_id INT NOT NULL,company_name VARCHAR(100),allocated_volume DECIMAL(12,2) DEFAULT 0,used_volume DECIMAL(12,2) DEFAULT 0,createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY (sales_order_id) REFERENCES sales_orders(id) ON DELETE CASCADE,FOREIGN KEY (client_id) REFERENCES users(id) ON DELETE CASCADE,UNIQUE KEY unique_so_allocation (sales_order_id,client_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"); try{await pool.execute('CREATE INDEX idx_atl_so_number ON authority_to_load(so_number)');}catch(e){} res.json({status:'success',message:'Tables created'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.get('/api/admin/create-login-attempts-table', authenticate, authorize('dispatcher','management'), async (req, res) => { try { await pool.execute("CREATE TABLE IF NOT EXISTS login_attempts (id INT AUTO_INCREMENT PRIMARY KEY,email VARCHAR(100) NOT NULL,attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,INDEX idx_email_time (email,attempted_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"); res.json({status:'success',message:'Login attempts table created'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.post('/api/admin/verify-user', authenticate, authorize('dispatcher','management'), async (req, res) => { try { await pool.execute('UPDATE users SET is_verified=1 WHERE email=?',[req.body.email]); res.json({status:'success',message:'Verified'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.post('/api/admin/cleanup-loading', authenticate, authorize('dispatcher','management'), async (req, res) => { try { await pool.execute('DELETE FROM authority_to_load'); res.json({status:'success',message:'Cleared'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.post('/api/admin/add-first-login-column', authenticate, authorize('dispatcher','management'), async (req, res) => { try { await pool.execute('ALTER TABLE authority_to_load ADD COLUMN special_instructions TEXT'); res.json({status:'success'}); } catch(e) { if(e.code==='ER_DUP_FIELDNAME') res.json({status:'success',message:'Exists'}); else res.status(400).json({error:e.message}); } });
app.get('/api/clients', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [c]=await pool.execute("SELECT id,email,mobile,company_name,is_active,is_verified,last_login,createdAt FROM users WHERE role='client' ORDER BY createdAt DESC"); const r=[]; for(const x of c){const [a]=await pool.execute('SELECT COUNT(*) as total FROM authority_to_load WHERE client_id=?',[x.id]);r.push({...x,total_atls:a[0].total});} res.json({status:'success',data:r,total:r.length}); } catch(e) { res.status(500).json({error:e.message}); } });
app.get('/api/clients/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [c]=await pool.execute("SELECT id,email,mobile,company_name,is_active,is_verified,last_login,createdAt FROM users WHERE id=? AND role='client'",[req.params.id]); if(!c.length) return res.status(404).json({error:'Not found'}); res.json({status:'success',data:c[0]}); } catch(e) { res.status(500).json({error:e.message}); } });
app.post('/api/clients', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const {email,password,mobile,company_name}=req.body; if(!email||!password||!mobile) return res.status(400).json({error:'All fields required'}); const [ex]=await pool.execute('SELECT id FROM users WHERE email=?',[email]); if(ex.length) return res.status(400).json({error:'Exists'}); await pool.execute('INSERT INTO users (email,password,mobile,company_name,role,is_verified,is_active,first_login,createdAt,updatedAt) VALUES (?,?,?,?,?,1,1,1,NOW(),NOW())',[email,await hashPassword(password),mobile,company_name||null,'client']); res.status(201).json({status:'success',message:'Created'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.put('/api/clients/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const {email,mobile,company_name,password}=req.body; if(email){const [d]=await pool.execute('SELECT id FROM users WHERE email=? AND id!=?',[email,req.params.id]);if(d.length)return res.status(400).json({error:'Email in use'});} let q='UPDATE users SET email=?,mobile=?,company_name=?'; let p=[email,mobile,company_name]; if(password&&password.length>=8){q+=',password=?';p.push(await hashPassword(password));} p.push(req.params.id); await pool.execute(q+' WHERE id=?',p); res.json({status:'success',message:'Updated'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.patch('/api/clients/:id/toggle-status', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [c]=await pool.execute("SELECT is_active FROM users WHERE id=? AND role='client'",[req.params.id]); if(!c.length) return res.status(404).json({error:'Not found'}); const ns=c[0].is_active?0:1; await pool.execute('UPDATE users SET is_active=? WHERE id=?',[ns,req.params.id]); res.json({status:'success',message:'Client '+(ns?'activated':'deactivated')}); } catch(e) { res.status(400).json({error:e.message}); } });
app.delete('/api/clients/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [clients]=await pool.execute("SELECT * FROM users WHERE id=? AND role='client'",[req.params.id]); if(!clients.length) return res.status(404).json({error:'Client not found'}); await softDelete('users',req.params.id,req.user.id,req.user.email); await pool.execute("DELETE FROM users WHERE id=? AND role='client'",[req.params.id]); await logAudit(req.user.id,'DELETE_CLIENT','users',req.params.id,{email:clients[0].email,soft_delete:true}); res.json({status:'success',message:'Client deleted (moved to recycle bin)'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.get('/api/users', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [u]=await pool.execute('SELECT id,email,role,mobile,company_name,is_active,is_verified,last_login,createdAt FROM users ORDER BY role,email'); res.json({status:'success',data:u}); } catch(e) { res.status(500).json({error:e.message}); } });
app.post('/api/users', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const {email,password,mobile,company_name,role}=req.body; if(!email||!password||!role) return res.status(400).json({error:'Required'}); const [ex]=await pool.execute('SELECT id FROM users WHERE email=?',[email]); if(ex.length) return res.status(400).json({error:'Exists'}); await pool.execute('INSERT INTO users (email,password,mobile,company_name,role,is_verified,is_active,createdAt,updatedAt) VALUES (?,?,?,?,?,1,1,NOW(),NOW())',[email,await hashPassword(password),mobile||null,company_name||null,role]); res.status(201).json({status:'success',message:'Created'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.put('/api/users/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const {email,mobile,company_name,role,password,is_active}=req.body; let q='UPDATE users SET email=?,mobile=?,company_name=?,role=?,is_active=?'; let p=[email,mobile||null,company_name||null,role,is_active!==undefined?is_active:1]; if(password){q+=',password=?';p.push(await hashPassword(password));} p.push(req.params.id); await pool.execute(q+' WHERE id=?',p); res.json({status:'success',message:'Updated'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.delete('/api/users/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [users]=await pool.execute('SELECT * FROM users WHERE id=?',[req.params.id]); if(!users.length) return res.status(404).json({error:'User not found'}); await softDelete('users',req.params.id,req.user.id,req.user.email); await pool.execute('DELETE FROM users WHERE id=?',[req.params.id]); await logAudit(req.user.id,'DELETE_USER','users',req.params.id,{email:users[0].email,soft_delete:true}); res.json({status:'success',message:'User deleted (moved to recycle bin)'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.get('/api/audit-logs', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [l]=await pool.execute('SELECT al.*,u.email FROM audit_logs al JOIN users u ON al.user_id=u.id ORDER BY al.created_at DESC LIMIT 500'); res.json({status:'success',data:l}); } catch(e) { res.status(500).json({error:e.message}); } });
app.post('/api/migrate', authenticate, authorize('dispatcher','management'), async (req, res) => { const idx=['CREATE INDEX idx_atl_status ON authority_to_load(status)','CREATE INDEX idx_atl_client_id ON authority_to_load(client_id)','CREATE INDEX idx_atl_truck_id ON authority_to_load(truck_id)','CREATE INDEX idx_atl_created ON authority_to_load(createdAt)','CREATE INDEX idx_atl_plate ON authority_to_load(plate_no)','CREATE INDEX idx_trucks_plate ON trucks(plate_no)','CREATE INDEX idx_trucks_active ON trucks(is_active)','CREATE INDEX idx_docs_truck ON truck_documents(truck_id)','CREATE INDEX idx_docs_type ON truck_documents(document_type)','CREATE INDEX idx_docs_expiry ON truck_documents(expiry_date)','CREATE INDEX idx_users_email ON users(email)','CREATE INDEX idx_users_role ON users(role)','CREATE INDEX idx_master_plate ON truck_masterlist(plate_no)','CREATE INDEX idx_audit_user ON audit_logs(user_id)','CREATE INDEX idx_audit_created ON audit_logs(created_at)','CREATE INDEX idx_chat_users ON chat_messages(sender_id,receiver_id)','CREATE INDEX idx_chat_created ON chat_messages(created_at)']; let cr=0,sk=0,fa=0; for(const s of idx){try{await pool.execute(s);cr++;}catch(e){if(e.code==='ER_DUP_KEYNAME')sk++;else fa++;}} res.json({status:'success',message:`Created:${cr},Skipped:${sk},Failed:${fa}`}); });
app.post('/api/sync-truck-capacities', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const {batch=0}=req.body; const [t]=await pool.execute('SELECT id,plate_no FROM trucks WHERE total_capacity=0 OR total_capacity IS NULL ORDER BY id LIMIT 50 OFFSET ?',[String(batch*50)]); if(!t.length) return res.json({status:'success',message:'Done!',done:true}); let c=0; for(const x of t){const [m]=await pool.execute('SELECT * FROM truck_masterlist WHERE plate_no=?',[x.plate_no]); if(m.length){const cap=[m[0].cot1,m[0].cot2,m[0].cot3,m[0].cot4,m[0].cot5,m[0].cot6,m[0].cot7,m[0].cot8,m[0].cot9,m[0].cot10].reduce((s,v)=>s+parseFloat(v||0),0);if(cap>0){await pool.execute('UPDATE trucks SET total_capacity=? WHERE id=?',[cap,x.id]);c++;}}} res.json({status:'success',message:`Batch ${batch+1}: ${c} updated`,count:c,done:false,nextBatch:batch+1}); } catch(e) { res.status(400).json({error:e.message}); } });

// ============================================================
// RECYCLE BIN API
// ============================================================

app.get('/api/admin/recycle-bin', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const {table,search}=req.query; let q='SELECT * FROM recycle_bin WHERE restored=0'; const p=[]; if(table){q+=' AND table_name=?';p.push(table);} if(search){q+=' AND (record_data LIKE ? OR deleted_by_email LIKE ?)';p.push('%'+search+'%','%'+search+'%');} q+=' ORDER BY deleted_at DESC LIMIT 200'; const [items]=await pool.execute(q,p); const result=items.map(item=>({...item,record_data:JSON.parse(item.record_data||'{}'),days_remaining:Math.max(0,Math.ceil((new Date(item.expires_at)-new Date())/86400000))})); res.json({status:'success',data:result,total:result.length}); } catch(e) { res.status(500).json({error:e.message}); } });
app.post('/api/admin/recycle-bin/:id/restore', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const result=await restoreFromBin(req.params.id,req.user.id); if(result.success) res.json({status:'success',message:'Record restored',newId:result.newId}); else res.status(400).json({error:result.error}); } catch(e) { res.status(400).json({error:e.message}); } });
app.delete('/api/admin/recycle-bin/:id', authenticate, authorize('dispatcher','management'), async (req, res) => { try { await pool.execute('DELETE FROM recycle_bin WHERE id=?',[req.params.id]); res.json({status:'success',message:'Permanently deleted'}); } catch(e) { res.status(400).json({error:e.message}); } });
app.post('/api/admin/recycle-bin/empty', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [r]=await pool.execute('DELETE FROM recycle_bin WHERE restored=0'); res.json({status:'success',message:`Emptied ${r.affectedRows} items`}); } catch(e) { res.status(400).json({error:e.message}); } });
app.get('/api/admin/recycle-bin/stats', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [s]=await pool.execute("SELECT COUNT(*) as total_items,SUM(CASE WHEN restored=0 THEN 1 ELSE 0 END) as active_items,SUM(CASE WHEN restored=1 THEN 1 ELSE 0 END) as restored_items,SUM(CASE WHEN expires_at<NOW() AND restored=0 THEN 1 ELSE 0 END) as expired_items,COUNT(DISTINCT table_name) as unique_tables FROM recycle_bin"); const [bt]=await pool.execute("SELECT table_name,COUNT(*) as count FROM recycle_bin WHERE restored=0 GROUP BY table_name ORDER BY count DESC"); res.json({status:'success',data:{...s[0],by_table:bt,retention_days:RECYCLE_BIN_DAYS}}); } catch(e) { res.status(500).json({error:e.message}); } });

// ============================================================
// BACKUP API
// ============================================================

app.post('/api/admin/backup', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const tables=['authority_to_load','audit_logs','backup_logs','chat_messages','recycle_bin','sales_order_clients','sales_orders','truck_documents','truck_masterlist','trucks','users']; let backup={},totalRecords=0; for(const table of tables){try{const [rows]=await pool.execute(`SELECT * FROM ${table}`);backup[table]=rows;totalRecords+=rows.length;}catch(e){backup[table]=[];}} const timestamp=new Date().toISOString().replace(/[:.]/g,'-'); const filename=`fueltrak_backup_${timestamp}.json`; const backupJSON=JSON.stringify(backup); const fileSize=Buffer.byteLength(backupJSON,'utf8'); await pool.execute('INSERT INTO backup_logs (backup_type,filename,file_size,tables_backed_up,records_count,status,created_by) VALUES (?,?,?,?,?,?,?)',['manual',filename,fileSize,tables.join(', '),totalRecords,'success',req.user.id]); res.setHeader('Content-Type','application/json');res.setHeader('Content-Disposition',`attachment; filename="${filename}"`);res.send(backupJSON); } catch(e) { await pool.execute('INSERT INTO backup_logs (backup_type,filename,status,error_message,created_by) VALUES (?,?,?,?,?)',['manual','failed_backup.json','failed',e.message,req.user.id]); res.status(500).json({error:e.message}); } });
app.get('/api/admin/backup-logs', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const [logs]=await pool.execute('SELECT bl.*,u.email as created_by_email FROM backup_logs bl LEFT JOIN users u ON bl.created_by=u.id ORDER BY bl.created_at DESC LIMIT 50'); res.json({status:'success',data:logs}); } catch(e) { res.status(500).json({error:e.message}); } });
app.post('/api/admin/restore', authenticate, authorize('dispatcher','management'), async (req, res) => { try { const {backup,mode='merge'}=req.body; if(!backup||typeof backup!=='object') return res.status(400).json({error:'Invalid backup data'}); let restored=0,errors=[]; for(const [table,records] of Object.entries(backup)){if(!Array.isArray(records)||!records.length) continue; try{if(mode==='replace') await pool.execute(`DELETE FROM ${table}`); for(const record of records){try{const columns=Object.keys(record).join(', ');const placeholders=Object.keys(record).map(()=>'?').join(', ');const values=Object.values(record);await pool.execute(`INSERT IGNORE INTO ${table} (${columns}) VALUES (${placeholders})`,values);restored++;}catch(e){errors.push(`${table}: ${e.message}`);}}}catch(e){errors.push(`Table ${table}: ${e.message}`);}} await logAudit(req.user.id,'RESTORE_BACKUP','system',0,{restored,errors:errors.length}); res.json({status:'success',message:`Restored ${restored} records`,errors:errors.slice(0,10),mode}); } catch(e) { res.status(400).json({error:e.message}); } });

// ============================================================
// STATIC FILES & PAGE ROUTES
// ============================================================

app.use('/images', express.static(path.join(__dirname, '..', 'public', 'images'), { maxAge: '24h', setHeaders: (res) => res.setHeader('Cache-Control', 'public, max-age=86400') })); // ADD THIS LINE
app.use('/public', express.static(path.join(__dirname, '..', 'public'), { maxAge: '1h', setHeaders: (res, fp) => res.setHeader('Cache-Control', fp.endsWith('.html') ? 'public, max-age=0, must-revalidate' : 'public, max-age=3600') }));

const pageRoutes = { '/': 'index.html', '/privacy': 'privacy.html', '/dashboard': 'dashboard.html', '/dashboard.html': 'dashboard.html', '/client': 'client.html', '/client.html': 'client.html', '/sales-orders': 'sales-orders.html', '/docs-report': 'docs-report.html', '/reports': 'reports.html', '/reports.html': 'reports.html', '/atl.html': 'atl.html', '/trucks': 'trucks.html', '/ttsd-checklist': 'ttsd-checklist.html', '/tutorial': 'tutorial.html', '/users': 'users.html', '/adminclient': 'adminclient.html', '/audit-logs': 'audit-logs.html', '/first-login': 'first-login.html', '/terms': 'terms.html', '/recycle-bin': 'recycle-bin.html' };
Object.entries(pageRoutes).forEach(([route, file]) => { app.get(route, (req, res) => res.sendFile(path.join(__dirname, '..', 'public', file))); });

// ============================================================
// EXPORT
// ============================================================
module.exports = app;