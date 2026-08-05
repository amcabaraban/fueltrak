const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const NodeCache = require('node-cache');
const pool = require('../config/database');
const { authenticate, authorize, tokenBlacklist } = require('../middleware/auth');
const { generateOTP, validateEmail, maskEmail, validatePassword, validatePasswordComplexity, hashPassword } = require('../services/utilities');
const { sendOTPEmail } = require('../services/emailService');
const { logAudit } = require('../services/auditService');
const { JWT_EXPIRY, REFRESH_TOKEN_EXPIRY, MAX_LOGIN_ATTEMPTS, LOCKOUT_DURATION_MS } = require('../constants');
const logger = require('../services/logger');

const otpCache = new NodeCache({ stdTTL: 600 });
const loginAttempts = new Map();

function getLoginKey(e) { return 'login_'+e.toLowerCase(); }
function checkLockout(e) { const a=loginAttempts.get(getLoginKey(e)); if(a&&a.count>=MAX_LOGIN_ATTEMPTS&&(Date.now()-a.lastAttempt)<LOCKOUT_DURATION_MS) return {locked:true,minutesLeft:Math.ceil((LOCKOUT_DURATION_MS-(Date.now()-a.lastAttempt))/60000)}; return {locked:false}; }
function recordFailedAttempt(e) { const k=getLoginKey(e),c=loginAttempts.get(k)||{count:0,lastAttempt:0}; loginAttempts.set(k,{count:c.count+1,lastAttempt:Date.now()}); }
function resetAttempts(e) { loginAttempts.delete(getLoginKey(e)); }

function setupAuthRoutes(app) {
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
        try { const {email,password}=req.body; if(!email||!password){await bcrypt.compare('x','$2a$12$dummyhashfortimingprevention');return res.status(400).json({error:'Email and password required'});} if(!validateEmail(email)){await bcrypt.compare('x','$2a$12$dummyhashfortimingprevention');return res.status(400).json({error:'Invalid email'});} const lo=checkLockout(email); if(lo.locked) return res.status(429).json({error:'Too many attempts',retryAfter:lo.minutesLeft*60}); const [users]=await pool.execute('SELECT * FROM users WHERE email=?',[email]); const user=users.length?users[0]:null; const match=user?await bcrypt.compare(password,user.password):await bcrypt.compare(password,'$2a$12$LJ3m4ys3GZqGqGqGqGqGqO'); if(!user||!match){recordFailedAttempt(email);const el=Date.now()-st;if(el<500) await new Promise(r=>setTimeout(r,500-el));return res.status(401).json({error:'Invalid email or password'});} if(!user.is_verified||!user.is_active){await new Promise(r=>setTimeout(r,200));return res.status(401).json({error:'Invalid email or password'});} resetAttempts(email); if(user.first_login===1){const tt=jwt.sign({id:user.id,role:user.role,firstLogin:true,iat:Math.floor(Date.now()/1000)},process.env.JWT_SECRET,{expiresIn:'15m'});return res.json({status:'first_login',token:tt,message:'Set password and accept terms'});} const at=jwt.sign({id:user.id,role:user.role,iat:Math.floor(Date.now()/1000)},process.env.JWT_SECRET,{expiresIn:JWT_EXPIRY}); const rt=jwt.sign({id:user.id,type:'refresh',iat:Math.floor(Date.now()/1000)},process.env.JWT_SECRET,{expiresIn:REFRESH_TOKEN_EXPIRY}); if(user.current_token){try{jwt.verify(user.current_token,process.env.JWT_SECRET);}catch(e){}await pool.execute('UPDATE users SET current_token=NULL WHERE id=?',[user.id]);} await pool.execute('UPDATE users SET current_token=?,last_login=NOW() WHERE id=?',[at,user.id]); await logAudit(user.id,'LOGIN','users',user.id,{email:user.email}); res.setHeader('Set-Cookie',['fueltrak_token='+at+';HttpOnly;Secure;SameSite=Strict;Path=/;Max-Age=3600','fueltrak_refresh='+rt+';HttpOnly;Secure;SameSite=Strict;Path=/api/auth/refresh;Max-Age=604800']); res.json({status:'success',token:at,refreshToken:rt,user:{id:user.id,email:user.email,role:user.role,mobile:user.mobile?user.mobile.replace(/(\d{3})\d{4}(\d{4})/,'$1****$3'):null,company_name:user.company_name}}); } catch(e) { logger.error('Login error',{error:e.message}); const el=Date.now()-st; if(el<500) await new Promise(r=>setTimeout(r,500-el)); res.status(500).json({error:'An error occurred'}); }
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
}

module.exports = { setupAuthRoutes };