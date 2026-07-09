const mysql = require('mysql2');
require('dotenv').config();

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: ''
});

connection.connect((err) => {
  if (err) {
    console.error('Connection failed:', err.message);
    process.exit(1);
  }
  console.log('Connected to MySQL');
  connection.query('CREATE DATABASE IF NOT EXISTS fueltrak_node', (err) => {
    if (err) throw err;
    console.log('Database ready');
    connection.end();
  });
});