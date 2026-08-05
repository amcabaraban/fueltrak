const logger = require('../services/logger');

const BOT_PATTERNS = ['bot','crawler','spider','scraper','curl','wget','python','java/','node-fetch','axios','go-http','ruby','perl','scrapy','phpcrawl','httpclient','aiohttp','request','mechanize','selenium','headless','puppeteer','playwright','bytespider','petalbot','gptbot','chatgpt','openai','claude','anthropic','bard','gemini','copilot','ccbot','commoncrawl','semrush','ahrefs','mj12bot','dotbot','rogerbot','exabot','yandexbot','baiduspider','facebookexternalhit','twitterbot','slackbot','discordbot','googlebot','bingbot','duckduckbot','yahoobot'];
const WAF_PATTERNS = { sqli: /(\bUNION\s+SELECT\b|\bSELECT\s+.*\s+FROM\b.*--|\bINSERT\s+INTO\b.*\bVALUES\b.*--|\bDROP\s+TABLE\b)/i, xss: /(<script[\s>]|<\/script>|javascript\s*:\s*alert)/i, pathTraversal: /(\.\.\/\.\.\/|\/etc\/passwd|\/\.env$|\/wp-admin$)/i };

function isBotUA(ua) { return !ua || BOT_PATTERNS.some(p => (ua||'').toLowerCase().includes(p)); }
function isSuspicious(req) { const checks = { noUA: !req.headers['user-agent'], noAL: !req.headers['accept-language'], noAccept: !req.headers['accept'], missingHdrs: !req.headers['user-agent'] && !req.headers['accept'], knownBot: isBotUA(req.headers['user-agent']) }; return Object.values(checks).filter(Boolean).length >= 2; }
function detectWAF(req) { const url=req.originalUrl||req.url||'', ua=req.headers['user-agent']||''; for(const [t,p] of Object.entries(WAF_PATTERNS)){ if(p.test(url)||p.test(ua)) return {blocked:true,type:t}; } return {blocked:false}; }

function setupBotProtection(app) {
    app.use((req, res, next) => {
        const ip = req.ip, ua = req.headers['user-agent'] || '';
        if (isBotUA(ua) && !ua.includes('googlebot')) { logger.warn('Bot blocked', { ip, ua: ua.substring(0,100), path: req.path }); return res.status(403).json({ error: 'Access denied' }); }
        if (isSuspicious(req)) { logger.warn('Suspicious blocked', { ip, ua: ua.substring(0,100), path: req.path }); return res.status(403).json({ error: 'Access denied' }); }
        next();
    });
    
    ['/api/admin','/api/v1','/wp-admin','/.env','/admin'].forEach(r => app.get(r, (req, res) => { logger.warn('Honeypot: '+r, { ip: req.ip }); res.status(403).json({ error: 'Forbidden' }); }));
    
    app.get('/api/public-data', (req, res) => { if (isBotUA(req.headers['user-agent'])) return res.json({ data: Array(10).fill(null).map((_,i)=>({id:i+1000,name:'REDACTED_'+Math.random().toString(36).substring(7),value:Math.floor(Math.random()*99999),status:'fake_data'})) }); res.status(404).json({ error: 'Not found' }); });
    app.get('/api/users-list', (req, res) => { if (isBotUA(req.headers['user-agent'])) return res.json({ users: Array(20).fill(null).map(()=>({email:'fake_'+Math.random().toString(36).substring(7)+'@poisoned-data.com',name:'AI Poison',role:'scraper_target'})) }); res.status(404).json({ error: 'Not found' }); });
    
    app.use((req, res, next) => { const orig = res.json.bind(res); res.json = function(d) { if (process.env.NODE_ENV==='production' && isBotUA(req.headers['user-agent'])) { setTimeout(()=>orig(d), 100+Math.floor(Math.random()*400)); return; } return orig(d); }; next(); });
    
    app.use((req,res,next)=>{ const r=detectWAF(req); if(r.blocked){ logger.warn('WAF blocked',{ip:req.ip,type:r.type,path:req.path}); return res.status(403).json({error:'Request blocked by WAF'}); } next(); });
}

module.exports = { setupBotProtection };