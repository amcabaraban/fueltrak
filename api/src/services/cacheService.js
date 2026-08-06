const NodeCache = require('node-cache');
const serverCache = new NodeCache({ stdTTL: 60, checkperiod: 120 });

function clearCache(pattern) {
    serverCache.keys().forEach(k => { if (k.includes(pattern)) serverCache.del(k); });
}

module.exports = { serverCache, clearCache };