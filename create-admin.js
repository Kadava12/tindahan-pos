
require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const ask = (question) => new Promise(resolve => {
  rl.question(question, resolve);
});

async function main() {
  let connection;
  try {
    const username = (await ask('Admin username: ')).trim();
    const fullName = (await ask('Admin full name: ')).trim();
    const password = await ask('Admin password (minimum 12 characters): ');

    if (!username || !fullName || password.length < 12) {
      throw new Error('Enter a username, full name, and password of at least 12 characters.');
    }

    connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      port: Number(process.env.DB_PORT || 3306),
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME
    });

    const hash = await bcrypt.hash(password, 12);

    await connection.execute(
      `INSERT INTO users (username, password_hash, full_name, role)
       VALUES (?, ?, ?, 'admin')
       ON DUPLICATE KEY UPDATE
       password_hash = VALUES(password_hash),
       full_name = VALUES(full_name),
       role = 'admin',
       active = 1`,
      [username, hash, fullName]
    );

    console.log('Administrator account created or updated successfully.');
  } catch (error) {
    console.error('Setup failed:', error.message);
    process.exitCode = 1;
  } finally {
    if (connection) await connection.end();
    rl.close();
  }
}

main();
