const mysql = require('mysql2/promise');
const pool = mysql.createPool({
    host: process.env.DB_HOST, port: process.env.DB_PORT || 16287,
    user: process.env.DB_USER, password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME, ssl: { rejectUnauthorized: false },
    waitForConnections: true, connectionLimit: 50, queueLimit: 100,
    enableKeepAlive: true, keepAliveInitialDelay: 5000,
    connectTimeout: 10000, charset: 'utf8mb4'
});
pool.on('error', (err) => console.error('Database pool error:', err.message));
module.exports = pool;