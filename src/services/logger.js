const { logAudit } = require('./auditService');

if (process.env.NODE_ENV === 'production') {
    const origConsole = { log: console.log, warn: console.warn, error: console.error, info: console.info, debug: console.debug };
    console.log = () => {};
    console.warn = () => {};
    console.info = () => {};
    console.debug = () => {};
    console.error = (...args) => {
        const sanitized = args.map(arg => {
            if (typeof arg === 'string') return arg.replace(/password[=:]\S+/gi, 'password=***').replace(/token[=:]\S+/gi, 'token=***').replace(/secret[=:]\S+/gi, 'secret=***').replace(/Bearer\s+\S+/gi, 'Bearer ***').replace(/otp[=:]\S+/gi, 'otp=***').replace(/\b\d{6}\b/g, '******').replace(/AVNS_\S+/gi, 'AVNS_***').replace(/mysql-\S+\.aivencloud\.com/gi, '***.aivencloud.com');
            return arg;
        });
        origConsole.error.apply(console, sanitized);
    };
}

const logger = {
    error: (message, meta = {}) => {
        const sanitized = { ...meta }; delete sanitized.password; delete sanitized.token; delete sanitized.otp; delete sanitized.secret;
        if (process.env.NODE_ENV === 'production') console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: 'error', message, meta: sanitized }));
        else console.error('[' + new Date().toISOString() + '] ERROR:', message, sanitized);
    },
    info: (message, meta = {}) => { if (process.env.NODE_ENV !== 'production') console.log('[' + new Date().toISOString() + '] INFO:', message, meta); },
    warn: (message, meta = {}) => { if (process.env.NODE_ENV !== 'production') console.warn('[' + new Date().toISOString() + '] WARN:', message, meta); },
    audit: (action, userId, details = {}) => { const s = { ...details }; delete s.password; delete s.token; logAudit(userId, action, 'system', 0, s).catch(() => {}); }
};

module.exports = logger;