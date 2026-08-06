const rateLimit = require('express-rate-limit');

function setupRateLimiters(app) {
    const generalLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, message: { error: 'Too many requests' }, standardHeaders: true, legacyHeaders: false });
    const strictLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: { error: 'Too many attempts. Try later.' }, standardHeaders: true, legacyHeaders: false });
    const otpLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 3, message: { error: 'Too many OTP requests.' }, standardHeaders: true, legacyHeaders: false });
    const fingerprintLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, message: { error: 'Rate limit exceeded' }, standardHeaders: true, legacyHeaders: false, keyGenerator: (req) => { const ua = (req.headers['user-agent'] || '').substring(0, 100); const lang = (req.headers['accept-language'] || '').substring(0, 50); return (ua + lang) || 'unknown'; } });
    
    app.use('/api/chat', (req, res, next) => next());
    app.use('/api/chat-list', (req, res, next) => next());
    app.use('/api/chat/unread', (req, res, next) => next());
    app.use('/api/', generalLimiter);
    app.use('/api/', fingerprintLimiter);
    app.use('/api/auth/login', strictLimiter);
    app.use('/api/auth/register', strictLimiter);
    app.use('/api/auth/forgot-password', strictLimiter);
    app.use('/api/auth/force-login', strictLimiter);
    app.use('/api/auth/resend-otp', otpLimiter);
    app.use('/api/auth/verify-otp', otpLimiter);
    app.use('/api/auth/reset-password', strictLimiter);
}

module.exports = { setupRateLimiters };