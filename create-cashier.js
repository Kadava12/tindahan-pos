
require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});
const ask = q => new Promise(resolve => rl.question(q, resolve));

async function main() {
  let db;
  try {
    const username = (await ask('Cashier username: ')).trim();
    const fullName = (await ask('Cashier full name: ')).trim();
    const password = await ask('Cashier password (minimum 12 characters): ');

    if (!username || !fullName || password.length < 12) {
      throw new Error('Enter a username, full name, and password of at least 12 characters.');
    }

    db = await mysql.createConnection({
      host: process.env.DB_HOST,
      port: Number(process.env.DB_PORT || 3306),
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME
    });

    const hash = await bcrypt.hash(password, 12);
    await db.execute(
      `INSERT INTO users (username, password_hash, full_name, role)
       VALUES (?, ?, ?, 'cashier')`,
      [username, hash, fullName]
    );

    console.log('Cashier account created successfully.');
  } catch (err) {
    console.error('Could not create cashier:', err.message);
    process.exitCode = 1;
  } finally {
    if (db) await db.end();
    rl.close();
  }
}

main();
