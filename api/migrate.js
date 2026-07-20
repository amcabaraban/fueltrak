const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 16287,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false },
  waitForConnections: true,
  connectionLimit: 10
});

async function migrate() {
  console.log('Starting migration...');
  
  const indexes = [
    // ATL table - most queried
    `CREATE INDEX IF NOT EXISTS idx_atl_status ON authority_to_load(status)`,
    `CREATE INDEX IF NOT EXISTS idx_atl_client_id ON authority_to_load(client_id)`,
    `CREATE INDEX IF NOT EXISTS idx_atl_truck_id ON authority_to_load(truck_id)`,
    `CREATE INDEX IF NOT EXISTS idx_atl_created ON authority_to_load(createdAt)`,
    `CREATE INDEX IF NOT EXISTS idx_atl_plate ON authority_to_load(plate_no)`,
    
    // Trucks table
    `CREATE INDEX IF NOT EXISTS idx_trucks_plate ON trucks(plate_no)`,
    `CREATE INDEX IF NOT EXISTS idx_trucks_active ON trucks(is_active)`,
    
    // Documents
    `CREATE INDEX IF NOT EXISTS idx_docs_truck ON truck_documents(truck_id)`,
    `CREATE INDEX IF NOT EXISTS idx_docs_type ON truck_documents(document_type)`,
    `CREATE INDEX IF NOT EXISTS idx_docs_expiry ON truck_documents(expiry_date)`,
    
    // Users
    `CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`,
    `CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)`,
    
    // Masterlist
    `CREATE INDEX IF NOT EXISTS idx_master_plate ON truck_masterlist(plate_no)`,
    
    // Audit logs
    `CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at)`,
    
    // Chat
    `CREATE INDEX IF NOT EXISTS idx_chat_users ON chat_messages(sender_id, receiver_id)`,
    `CREATE INDEX IF NOT EXISTS idx_chat_created ON chat_messages(created_at)`,
    
    // Backloads
    `CREATE INDEX IF NOT EXISTS idx_backload_atl ON backloads(atl_id)`,
  ];

  let success = 0;
  let errors = 0;
  
  for (const idx of indexes) {
    try {
      await pool.execute(idx);
      success++;
      console.log(`✅ ${idx.substring(0, 60)}...`);
    } catch (e) {
      // MySQL doesn't support IF NOT EXISTS for indexes
      // Try alternative: just create and ignore duplicates
      try {
        await pool.execute(idx.replace('IF NOT EXISTS ', ''));
        success++;
        console.log(`✅ ${idx.substring(0, 60)}...`);
      } catch (e2) {
        if (e2.code === 'ER_DUP_KEYNAME') {
          console.log(`⏭️  Already exists: ${idx.match(/idx_\w+/)[0]}`);
          success++;
        } else {
          errors++;
          console.log(`❌ ${e2.message.substring(0, 80)}`);
        }
      }
    }
  }
  
  console.log(`\nMigration complete: ${success} indexes, ${errors} errors`);
  process.exit(0);
}

migrate().catch(e => { console.error(e); process.exit(1); });