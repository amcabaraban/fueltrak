require('dotenv').config();
const express = require('express');
const { setupSecurity } = require('./src/middleware/security');
const { setupRateLimiters } = require('./src/middleware/rateLimiter');
const { setupBotProtection } = require('./src/middleware/botProtection');
const { setupAuthRoutes } = require('./src/controllers/authController');
const { setupDispatchRoutes } = require('./src/controllers/dispatchController');
const { setupClientRoutes } = require('./src/controllers/clientController');
const { setupTruckRoutes } = require('./src/controllers/truckController');
const { setupSalesRoutes } = require('./src/controllers/salesController');
const { setupChatRoutes } = require('./src/controllers/chatController');
const { setupReportRoutes } = require('./src/controllers/reportController');
const { setupAdminRoutes } = require('./src/controllers/adminController');
const { setupPageRoutes } = require('./src/routes/pageRoutes');
const { cleanupRecycleBin, cleanupAuditLogs } = require('./src/services/recycleBin');

const app = express();

setupSecurity(app);
setupRateLimiters(app);
setupBotProtection(app);
setupAuthRoutes(app);
setupDispatchRoutes(app);
setupClientRoutes(app);
setupTruckRoutes(app);
setupSalesRoutes(app);
setupChatRoutes(app);
setupReportRoutes(app);
setupAdminRoutes(app);
setupPageRoutes(app);

setInterval(() => { cleanupRecycleBin().catch(() => {}); }, 60 * 60 * 1000);
setInterval(() => { cleanupAuditLogs().catch(() => {}); }, 24 * 60 * 60 * 1000);
process.on('uncaughtException', (error) => { console.error('UNCAUGHT EXCEPTION:', error.message); });
process.on('unhandledRejection', (reason) => { console.error('UNHANDLED REJECTION:', reason); });

module.exports = app;