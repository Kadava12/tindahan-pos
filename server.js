
require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);


if (!process.env.SESSION_SECRET ||
    process.env.SESSION_SECRET.length < 32) {
  throw new Error(
    'Set SESSION_SECRET to a random secret of at least 32 characters in .env'
  );
}

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'tindahan_pos',
  waitForConnections: true,
  connectionLimit: 10,
  decimalNumbers: true
});

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));

app.use(session({
  name: 'tindahan.sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: false,
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const asyncRoute = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Please log in.' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (req.session.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required.' });
  }
  next();
}

function requireSameOrigin(req, res, next) {
  const origin = req.get('origin');

  if (origin && origin !== `${req.protocol}://${req.get('host')}`) {
    return res.status(403).json({ error: 'Invalid request origin.' });
  }

  next();
}

app.use('/api', requireSameOrigin);

// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------

app.get('/api/health', asyncRoute(async (req, res) => {
  await pool.query('SELECT 1');
  res.json({ ok: true, database: 'connected' });
}));

// --------------------------------------------------
// LOGIN
// --------------------------------------------------

app.post('/api/login', asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};

  if (
    typeof username !== 'string' ||
    typeof password !== 'string' ||
    username.length > 50 ||
    password.length > 200
  ) {
    return res.status(400).json({
      error: 'Enter your username and password.'
    });
  }

  const [rows] = await pool.execute(
    `SELECT id, username, password_hash, full_name, role, active
     FROM users
     WHERE username = ?
     LIMIT 1`,
    [username.trim()]
  );

  const user = rows[0];
  const valid = user && user.active &&
    await bcrypt.compare(password, user.password_hash);

  if (!valid) {
    return res.status(401).json({
      error: 'Invalid username or password.'
    });
  }

  await new Promise((resolve, reject) => {
    req.session.regenerate(err =>
      err ? reject(err) : resolve()
    );
  });

  req.session.user = {
    id: user.id,
    username: user.username,
    fullName: user.full_name,
    role: user.role
  };

  res.json({ user: req.session.user });
}));

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.session.user });
});

app.post('/api/logout', requireAuth, (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed.' });
    }

    res.clearCookie('tindahan.sid');
    res.json({ ok: true });
  });
});

// --------------------------------------------------
// PRODUCTS / INVENTORY
// --------------------------------------------------

app.get('/api/products', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT id, sku, name, category, unit, cost_price,
            selling_price, stock, low_stock_threshold
     FROM products
     WHERE active = 1
     ORDER BY name`
  );

  res.json(rows);
}));

app.post(
  '/api/products',
  requireAuth,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const b = req.body || {};

    const sku = String(b.sku || '').trim();
    const name = String(b.name || '').trim();
    const category = String(b.category || 'General').trim();
    const unit = String(b.unit || 'pcs').trim();

    const cost = Number(b.cost_price);
    const price = Number(b.selling_price);
    const stock = Number(b.stock);
    const threshold = Number(b.low_stock_threshold ?? 5);

    if (
      !sku || !name ||
      sku.length > 50 || name.length > 150 ||
      !category || category.length > 80 ||
      !unit || unit.length > 30 ||
      ![cost, price, stock, threshold].every(Number.isFinite) ||
      cost < 0 || price < 0 || stock < 0 || threshold < 0 ||
      cost > 999999999 || price > 999999999 ||
      stock > 999999999 || threshold > 999999999
    ) {
      return res.status(400).json({
        error: 'Check product details and amounts.'
      });
    }

    const conn = await pool.getConnection();

    try {
      await conn.beginTransaction();

      const [result] = await conn.execute(
        `INSERT INTO products
         (sku, name, category, unit, cost_price, selling_price,
          stock, low_stock_threshold)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [sku, name, category, unit, cost, price, stock, threshold]
      );

      if (stock > 0) {
        await conn.execute(
          `INSERT INTO inventory_movements
           (product_id, user_id, movement_type, quantity_change, note)
           VALUES (?, ?, 'opening', ?, 'Initial stock')`,
          [result.insertId, req.session.user.id, stock]
        );
      }

      await conn.commit();
      res.status(201).json({ id: result.insertId });
    } catch (e) {
      await conn.rollback();

      if (e.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({
          error: 'That SKU already exists.'
        });
      }

      throw e;
    } finally {
      conn.release();
    }
  })
);

app.post(
  '/api/products/:id/restock',
  requireAuth,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const id = Number(req.params.id);
    const qty = Number(req.body?.quantity);
    const note = String(
      req.body?.note || 'Stock replenishment'
    ).trim();

    if (
      !Number.isSafeInteger(id) || id < 1 ||
      !Number.isFinite(qty) || qty <= 0 || qty > 999999999 ||
      note.length > 255
    ) {
      return res.status(400).json({
        error: 'Enter a valid restock quantity.'
      });
    }

    const conn = await pool.getConnection();

    try {
      await conn.beginTransaction();

      const [rows] = await conn.execute(
        'SELECT id FROM products WHERE id = ? AND active = 1 FOR UPDATE',
        [id]
      );

      if (!rows.length) {
        await conn.rollback();
        return res.status(404).json({
          error: 'Product not found.'
        });
      }

      await conn.execute(
        'UPDATE products SET stock = stock + ? WHERE id = ?',
        [qty, id]
      );

      await conn.execute(
        `INSERT INTO inventory_movements
         (product_id, user_id, movement_type, quantity_change, note)
         VALUES (?, ?, 'restock', ?, ?)`,
        [id, req.session.user.id, qty, note || 'Stock replenishment']
      );

      await conn.commit();
      res.json({ ok: true });
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }
  })
);

// --------------------------------------------------
// CHECKOUT / SALES
// --------------------------------------------------

app.post('/api/sales', requireAuth, asyncRoute(async (req, res) => {
  const items = req.body?.items;
  const discount = Number(req.body?.discount || 0);
  const paid = Number(req.body?.amount_paid);

  if (
    !Array.isArray(items) ||
    items.length < 1 ||
    items.length > 100 ||
    !Number.isFinite(discount) ||
    discount < 0 ||
    !Number.isFinite(paid) ||
    paid < 0
  ) {
    return res.status(400).json({
      error: 'Invalid checkout details.'
    });
  }

  const quantities = new Map();

  for (const item of items) {
    const id = Number(item.product_id);
    const qty = Number(item.quantity);

    if (
      !Number.isSafeInteger(id) || id < 1 ||
      !Number.isFinite(qty) || qty <= 0 || qty > 999999
    ) {
      return res.status(400).json({
        error: 'Check product quantities.'
      });
    }

    quantities.set(id, (quantities.get(id) || 0) + qty);
  }

  const conn = await pool.getConnection();

  try {
    await conn.beginTransaction();

    const ids = [...quantities.keys()].sort((a, b) => a - b);
    const locked = [];

    for (const id of ids) {
      const [rows] = await conn.execute(
        `SELECT id, name, cost_price, selling_price, stock
         FROM products
         WHERE id = ? AND active = 1
         FOR UPDATE`,
        [id]
      );

      if (!rows.length) {
        throw new Error('A product is unavailable.');
      }

      const p = rows[0];
      const qty = quantities.get(id);

      if (qty > p.stock) {
        throw new Error(`Not enough stock for ${p.name}.`);
      }

      locked.push({ ...p, quantity: qty });
    }

    const subtotal = Math.round(
      locked.reduce(
        (sum, p) => sum + p.selling_price * p.quantity,
        0
      ) * 100
    ) / 100;

    const total = Math.round((subtotal - discount) * 100) / 100;

    if (
      discount > subtotal ||
      total < 0 ||
      total > 999999999 ||
      paid < total
    ) {
      throw new Error('Discount or payment amount is invalid.');
    }

    const change = Math.round((paid - total) * 100) / 100;

    const receiptNo =
      `TD-${Date.now()}-${crypto.randomBytes(3)
        .toString('hex').toUpperCase()}`;

    const [sale] = await conn.execute(
      `INSERT INTO sales
       (receipt_no, user_id, subtotal, discount, total,
        amount_paid, change_amount)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        receiptNo,
        req.session.user.id,
        subtotal,
        discount,
        total,
        paid,
        change
      ]
    );

    for (const p of locked) {
      const lineTotal = Math.round(
        p.selling_price * p.quantity * 100
      ) / 100;

      await conn.execute(
        `INSERT INTO sale_items
         (sale_id, product_id, product_name, quantity,
          unit_cost, unit_price, line_total)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          sale.insertId,
          p.id,
          p.name,
          p.quantity,
          p.cost_price,
          p.selling_price,
          lineTotal
        ]
      );

      await conn.execute(
        'UPDATE products SET stock = stock - ? WHERE id = ?',
        [p.quantity, p.id]
      );

      await conn.execute(
        `INSERT INTO inventory_movements
         (product_id, user_id, movement_type, quantity_change, note)
         VALUES (?, ?, 'sale', ?, ?)`,
        [p.id, req.session.user.id, -p.quantity, receiptNo]
      );
    }

    await conn.commit();

    res.status(201).json({
      id: sale.insertId,
      receipt_no: receiptNo,
      subtotal,
      discount,
      total,
      amount_paid: paid,
      change_amount: change,
      items: locked.map(p => ({
        name: p.name,
        quantity: p.quantity,
        unit_price: p.selling_price,
        line_total: Math.round(
          p.selling_price * p.quantity * 100
        ) / 100
      }))
    });
  } catch (e) {
    await conn.rollback();

    if (
      e.message.includes('stock') ||
      e.message.includes('unavailable') ||
      e.message.includes('Discount') ||
      e.message.includes('payment')
    ) {
      return res.status(400).json({ error: e.message });
    }

    throw e;
  } finally {
    conn.release();
  }
}));

// --------------------------------------------------
// SALES REPORTS
// --------------------------------------------------

app.get(
  '/api/sales',
  requireAuth,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const from = /^\d{4}-\d{2}-\d{2}$/.test(req.query.from || '')
      ? req.query.from
      : new Date().toISOString().slice(0, 10);

    const to = /^\d{4}-\d{2}-\d{2}$/.test(req.query.to || '')
      ? req.query.to
      : from;

    if (from > to) {
      return res.status(400).json({
        error: 'Start date must not be after end date.'
      });
    }

    const [rows] = await pool.execute(
      `SELECT
         s.id,
         s.receipt_no,
         s.subtotal,
         s.discount,
         s.total,
         s.amount_paid,
         s.change_amount,
         s.created_at,
         u.full_name,
         COALESCE(
           SUM(si.quantity * si.unit_cost), 0
         ) AS cost_total,
         s.total - COALESCE(
           SUM(si.quantity * si.unit_cost), 0
         ) AS estimated_profit
       FROM sales s
       JOIN users u ON u.id = s.user_id
       LEFT JOIN sale_items si ON si.sale_id = s.id
       WHERE s.created_at >= ?
         AND s.created_at < DATE_ADD(?, INTERVAL 1 DAY)
       GROUP BY s.id
       ORDER BY s.created_at DESC
       LIMIT 1000`,
      [from, to]
    );

    res.json({
      sales: rows,
      totals: rows.reduce((a, s) => ({
        sales: a.sales + Number(s.total),
        profit: a.profit + Number(s.estimated_profit),
        count: a.count + 1
      }), { sales: 0, profit: 0, count: 0 })
    });
  })
);

// --------------------------------------------------
// STORE OVERVIEW / DASHBOARD
// --------------------------------------------------

app.get(
  '/api/dashboard',
  requireAuth,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const [[todayStats]] = await pool.query(`
      SELECT
        COALESCE(SUM(total), 0) AS todaySales,
        COUNT(*) AS totalTransactions
      FROM sales
      WHERE created_at >= CURDATE()
        AND created_at < CURDATE() + INTERVAL 1 DAY
    `);

    const [[inventoryStats]] = await pool.query(`
      SELECT
        COUNT(*) AS totalProducts,
        COALESCE(SUM(stock * cost_price), 0) AS inventoryValue,
        COALESCE(SUM(
          CASE
            WHEN stock <= low_stock_threshold THEN 1
            ELSE 0
          END
        ), 0) AS lowStock
      FROM products
      WHERE active = 1
    `);

    const [[profitStats]] = await pool.query(`
      SELECT
        COALESCE(
          SUM(si.line_total - si.quantity * si.unit_cost), 0
        ) AS estimatedProfit
      FROM sales s
      JOIN sale_items si ON si.sale_id = s.id
      WHERE s.created_at >= CURDATE()
        AND s.created_at < CURDATE() + INTERVAL 1 DAY
    `);

    const [recentSales] = await pool.query(`
      SELECT
        s.id,
        s.receipt_no,
        s.total,
        s.created_at,
        u.full_name AS cashier
      FROM sales s
      LEFT JOIN users u ON u.id = s.user_id
      ORDER BY s.created_at DESC
      LIMIT 5
    `);

    const [lowStockProducts] = await pool.query(`
      SELECT
        id,
        sku,
        name,
        stock,
        unit,
        low_stock_threshold
      FROM products
      WHERE active = 1
        AND stock <= low_stock_threshold
      ORDER BY stock ASC, name ASC
      LIMIT 10
    `);

    res.json({
      todaySales: Number(todayStats.todaySales),
      totalTransactions: Number(todayStats.totalTransactions),
      totalProducts: Number(inventoryStats.totalProducts),
      inventoryValue: Number(inventoryStats.inventoryValue),
      lowStock: Number(inventoryStats.lowStock),
      estimatedProfit: Number(profitStats.estimatedProfit),
      recentSales,
      lowStockProducts
    });
  })
);

// --------------------------------------------------
// FRONTEND
// --------------------------------------------------

app.use(express.static(path.join(__dirname, 'public')));

// --------------------------------------------------
// ERROR HANDLER
// --------------------------------------------------

app.use((err, req, res, next) => {
  console.error(err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    error: 'Server error. Check the terminal for details.'
  });
});

// --------------------------------------------------
// START SERVER
// --------------------------------------------------

async function start() {
  await pool.query('SELECT 1');

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Tindahan POS running at http://localhost:${PORT}`);
    console.log('Database connected successfully.');
    console.log('Keep this terminal open while using the POS.');
  });
}

start().catch(err => {
  console.error(
    'Cannot start POS. Check MySQL and your .env settings:',
    err.message
  );
  process.exit(1);
});
