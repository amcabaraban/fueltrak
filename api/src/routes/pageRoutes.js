const path = require('path');

function setupPageRoutes(app) {
    const publicPath = path.join(__dirname, '..', '..', '..', 'public');
    
    app.get('/api/health', (req, res) => res.json({ status: 'OK', db: process.env.DB_NAME }));
    
    const pageRoutes = {
        '/': 'index.html',
        '/privacy': 'privacy.html',
        '/dashboard': 'dashboard.html',
        '/dashboard.html': 'dashboard.html',
        '/client': 'client.html',
        '/client.html': 'client.html',
        '/sales-orders': 'sales-orders.html',
        '/docs-report': 'docs-report.html',
        '/reports': 'reports.html',
        '/reports.html': 'reports.html',
        '/atl.html': 'atl.html',
        '/trucks': 'trucks.html',
        '/ttsd-checklist': 'ttsd-checklist.html',
        '/tutorial': 'tutorial.html',
        '/users': 'users.html',
        '/adminclient': 'adminclient.html',
        '/audit-logs': 'audit-logs.html',
        '/first-login': 'first-login.html',
        '/terms': 'terms.html',
        '/settings': 'settings.html',
        '/announcements': 'announcements.html',
        '/announcements-manage': 'announcements-manage.html',
    };
    
    Object.entries(pageRoutes).forEach(([route, file]) => {
        app.get(route, (req, res) => res.sendFile(path.join(publicPath, file)));
    });
    
    app.use((req, res) => {
        if (req.path.startsWith('/api/')) {
            return res.status(404).json({ error: 'Endpoint not found' });
        }
        res.status(404).sendFile(path.join(publicPath, 'index.html'));
    });
}

module.exports = { setupPageRoutes };