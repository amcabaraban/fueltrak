require('dotenv').config();
const pool = require('./api/src/config/database');

(async () => {
    try {
        // Create announcements table
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS announcements (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(200) NOT NULL,
                message TEXT NOT NULL,
                priority ENUM('normal','important','urgent') DEFAULT 'normal',
                created_by INT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NULL,
                is_active TINYINT(1) DEFAULT 1,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        `);
        console.log('✅ announcements table created');
    } catch(e) {
        if(e.code === 'ER_TABLE_EXISTS_ERROR' || e.errno === 1050) {
            console.log('⚠️ announcements table already exists');
        } else {
            console.error('❌ Error creating announcements:', e.message);
        }
    }
    
    try {
        // Create announcement_reads table
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS announcement_reads (
                id INT AUTO_INCREMENT PRIMARY KEY,
                announcement_id INT NOT NULL,
                user_id INT NOT NULL,
                read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY unique_read (announcement_id, user_id),
                FOREIGN KEY (announcement_id) REFERENCES announcements(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        `);
        console.log('✅ announcement_reads table created');
    } catch(e) {
        if(e.code === 'ER_TABLE_EXISTS_ERROR' || e.errno === 1050) {
            console.log('⚠️ announcement_reads table already exists');
        } else {
            console.error('❌ Error creating announcement_reads:', e.message);
        }
    }
    
    await pool.end();
    process.exit(0);
})();