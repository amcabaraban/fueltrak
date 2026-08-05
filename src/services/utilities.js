const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../config/database');
const { BCRYPT_ROUNDS } = require('../constants');

function generateOTP() { return Math.floor(100000 + Math.random() * 900000).toString(); }
function validateEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); }
function sanitize(s, max=100) { return s ? String(s).trim().substring(0,max).replace(/[<>]/g,'') : ''; }
function maskEmail(e) { return e ? e.replace(/(.{3}).*(@.*)/,'$1***$2') : '***'; }
function validatePassword(p) { if(!p||p.length<8) return {valid:false,error:'Password must be at least 8 characters'}; if(!/[A-Z]/.test(p)) return {valid:false,error:'Password must contain an uppercase letter'}; if(!/[a-z]/.test(p)) return {valid:false,error:'Password must contain a lowercase letter'}; if(!/[0-9]/.test(p)) return {valid:false,error:'Password must contain a number'}; if(!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(p)) return {valid:false,error:'Password must contain a special character'}; return {valid:true}; }
function validatePasswordComplexity(p) { return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/.test(p); }
async function hashPassword(p) { return await bcrypt.hash(p, BCRYPT_ROUNDS); }
async function generateATLCode(company) { const pfx = (company||'ATL').replace(/[^a-zA-Z]/g,'').substring(0,3).toUpperCase().padEnd(3,'X'); const [r] = await pool.execute('SELECT COUNT(*) as count FROM authority_to_load'); return pfx+'-'+String(r[0].count+1).padStart(9,'0'); }
function validateATLInput(req, res, next) { const {volume,plate_no,company}=req.body; const errs=[]; if(volume&&(isNaN(volume)||volume<=0||volume>100000)) errs.push('Volume must be 1-100,000L'); if(plate_no&&plate_no.length>20) errs.push('Plate too long'); if(company&&company.length>100) errs.push('Company too long'); if(errs.length) return res.status(400).json({error:errs.join('. ')}); next(); }

module.exports = { generateOTP, validateEmail, sanitize, maskEmail, validatePassword, validatePasswordComplexity, hashPassword, generateATLCode, validateATLInput };