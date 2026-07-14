const m = require('mysql2/promise');
(async () => {
  const c = await m.createConnection({
    host: 'mysql-35c3780e-payrollsystem.d.aivencloud.com',
    port: 16287,
    user: 'avnadmin',
    password: 'AVNS_bb-714cmxraxxZ7lG22',
    database: 'fueltrak',
    ssl: { rejectUnauthorized: false }
  });
  await c.execute("ALTER TABLE authority_to_load ADD COLUMN printed_wc VARCHAR(12) NULL AFTER remarks");
  console.log('Column added');
  await c.end();
})();
