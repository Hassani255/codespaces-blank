const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'mtaa.sqlite');
const shouldInit = !fs.existsSync(DB_PATH);
const db = new Database(DB_PATH);

if (shouldInit) {
  const migrations = fs.readFileSync(path.join(__dirname, 'migrations.sql'), 'utf8');
  db.exec(migrations);
  console.log('Database created and initialized.');
}

module.exports = db;
