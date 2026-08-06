const nodemailer = require('nodemailer');
const { maskEmail } = require('./utilities');
const logger = require('./logger');

const transporter = nodemailer.createTransport({ host: process.env.SMTP_HOST || 'smtp.gmail.com', port: parseInt(process.env.SMTP_PORT) || 587, secure: false, auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } });

async function sendFreeSMS(mobile, otp) { if(!process.env.SMTP_USER) return false; for(const gw of [mobile.replace('+63','0')+'@txt.globe.com.ph',mobile.replace('+63','0')+'@isms.smart.com.ph']){try{await transporter.sendMail({from:process.env.SMTP_USER,to:gw,subject:'',text:'FuelTrak OTP: '+otp+'. Expires in 10 mins.'});logger.info('SMS sent',{mobile:mobile.replace(/(\d{3})\d{4}(\d{3})/,'$1****$2')});return true;}catch(e){}} return false; }

async function sendOTPEmail(email, mobile, otp, type) { if(mobile&&mobile.length>5) sendFreeSMS(mobile,otp).catch(()=>{}); if(!process.env.SMTP_USER){logger.info('Dev OTP',{email:maskEmail(email)});return;} try{await transporter.sendMail({from:'"FuelTrak" <'+process.env.SMTP_USER+'>',to:email,subject:type==='reset'?'FuelTrak - Password Reset OTP':'FuelTrak - Verify Your Email',html:'<div style="font-family:Arial;max-width:500px;margin:auto;padding:20px;border:1px solid #ddd;border-radius:10px"><h2 style="color:#1e3a5f">FuelTrak Logistics</h2><p>Your OTP code is:</p><h1 style="color:#1e3a5f;font-size:36px;letter-spacing:5px;text-align:center">'+otp+'</h1><p>This code expires in 10 minutes.</p></div>'});logger.info('OTP emailed',{email:maskEmail(email)});}catch(e){logger.error('Email failed',{error:e.message});}}

module.exports = { sendOTPEmail, sendFreeSMS, transporter };