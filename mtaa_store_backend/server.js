require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const db = require('./db');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';

// ---------- Helpers ----------
const run = (sql, params = []) => db.prepare(sql).run(...params);
const get = (sql, params = []) => db.prepare(sql).get(...params);
const all = (sql, params = []) => db.prepare(sql).all(...params);

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  const token = auth.replace(/^Bearer\s+/, '');
  try { const data = jwt.verify(token, JWT_SECRET); req.user = data; next(); } catch (e) { return res.status(401).json({ error: 'Invalid token' }); }
}

// ---------- Admin bootstrap (create default admin if none) ----------
(function initAdmin(){
  const existing = get('SELECT * FROM admins LIMIT 1');
  if (!existing) {
    const username = process.env.ADMIN_USER || 'admin';
    const password = process.env.ADMIN_PASS || 'admin123';
    const hash = bcrypt.hashSync(password, 10);
    run('INSERT INTO admins (id, username, password_hash) VALUES (?, ?, ?)', [uuidv4(), username, hash]);
    console.log('Default admin created:', username);
  }
})();

// ---------- Public APIs ----------
app.get('/api/products', (req, res) => {
  const rows = all('SELECT * FROM products ORDER BY created_at DESC');
  res.json(rows);
});

app.get('/api/banners', (req, res) => {
  const rows = all('SELECT * FROM banners ORDER BY created_at DESC');
  res.json(rows);
});

// Create order (frontend will call this before initiating payment)
app.post('/api/orders', (req, res) => {
  const { items, amount, customer_phone, provider } = req.body;
  if (!items || !amount) return res.status(400).json({ error: 'Missing items or amount' });
  const id = uuidv4();
  run('INSERT INTO orders (id, amount, items, customer_phone, provider, status) VALUES (?, ?, ?, ?, ?, ?)', [id, amount, JSON.stringify(items), customer_phone || null, provider || null, 'pending']);
  res.json({ ok: true, orderId: id });
});

// ---------- Admin APIs (protected) ----------
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const admin = get('SELECT * FROM admins WHERE username = ? LIMIT 1', [username]);
  if (!admin) return res.status(401).json({ error: 'Invalid' });
  const ok = await bcrypt.compare(password, admin.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid' });
  const token = jwt.sign({ id: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});

// Save products (replace all)
app.post('/api/save/products', authMiddleware, (req, res) => {
  const items = req.body;
  if (!Array.isArray(items)) return res.status(400).json({ error: 'Array required' });
  // simplistic approach: clear table and insert
  run('DELETE FROM products');
  const stmt = db.prepare('INSERT INTO products (id, title, price, description, image) VALUES (?, ?, ?, ?, ?)');
  for (const p of items) {
    stmt.run(p.id || uuidv4(), p.title, p.price, p.desc || p.description || null, p.image || null);
  }
  res.json({ ok: true });
});

// Save banners
app.post('/api/save/banners', authMiddleware, (req, res) => {
  const items = req.body;
  if (!Array.isArray(items)) return res.status(400).json({ error: 'Array required' });
  run('DELETE FROM banners');
  const stmt = db.prepare('INSERT INTO banners (id, url, alt) VALUES (?, ?, ?)');
  for (const b of items) stmt.run(b.id || uuidv4(), b.url, b.alt || null);
  res.json({ ok: true });
});

// Orders list
app.get('/api/admin/orders', authMiddleware, (req, res) => {
  const rows = all('SELECT * FROM orders ORDER BY created_at DESC');
  res.json(rows.map(r => ({ ...r, items: JSON.parse(r.items) })));
});

// ---------- Payments ----------
// M-Pesa (Safaricom Daraja) STK Push flow example
app.post('/api/pay/mpesa', async (req, res) => {
  // Expecting: orderId, phone
  const { orderId, phone } = req.body;
  const order = get('SELECT * FROM orders WHERE id = ? LIMIT 1', [orderId]);
  if (!order) return res.status(404).json({ error: 'Order not found' });

  // For Daraja you need consumer key/secret, shortcode and passkey
  const consumerKey = process.env.MPESA_CONSUMER_KEY;
  const consumerSecret = process.env.MPESA_CONSUMER_SECRET;
  const shortcode = process.env.MPESA_SHORTCODE;
  const passkey = process.env.MPESA_PASSKEY;
  const callbackUrl = process.env.MPESA_CALLBACK_URL; // public URL that Safaricom can reach

  if (!consumerKey || !consumerSecret || !shortcode || !passkey || !callbackUrl) return res.status(500).json({ error: 'MPESA credentials not configured' });

  try {
    // 1) Get access token
    const tokenResp = await axios.get('https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials', {
      auth: { username: consumerKey, password: consumerSecret }
    });
    const accessToken = tokenResp.data.access_token;

    // 2) build timestamp & password
    const timestamp = new Date().toISOString().replace(/[-:TZ.]/g,'').slice(0,14);
    const password = Buffer.from(shortcode + passkey + timestamp).toString('base64');

    // 3) Call STK Push
    const payload = {
      BusinessShortCode: shortcode,
      Password: password,
      Timestamp: timestamp,
      TransactionType: 'CustomerPayBillOnline',
      Amount: Math.round(order.amount),
      PartyA: phone, // customer MSISDN
      PartyB: shortcode,
      PhoneNumber: phone,
      CallBackURL: callbackUrl,
      AccountReference: orderId,
      TransactionDesc: `Order ${orderId}`
    };

    const resp = await axios.post('https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest', payload, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    // Store external reference if provided by response
    // This is a sandbox flow; production domain is https://api.safaricom.co.ke
    res.json({ ok: true, resp: resp.data });
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to initiate STK Push', details: err.response?.data || err.message });
  }
});

// MPESA callback endpoint (Daraja will POST here to confirm transaction result)
app.post('/api/callback/mpesa', (req, res) => {
  // Daraja will send the transaction details here. Save whatever you need.
  // For demo we'll log and mark order as paid if successful.
  const body = req.body;
  console.log('MPESA callback', JSON.stringify(body));

  // A real implementation must parse the body to get checkoutRequestID, resultCode, etc.
  // Example: if resultCode === 0 => success. Use AccountReference as our orderId.

  try {
    const callback = req.body.Body.stkCallback;
    const resultCode = callback.ResultCode;
    const accountRef = callback.CallbackMetadata ? callback.CallbackMetadata.Item.find(i => i.Name === 'AccountReference') : null;
    const orderId = accountRef ? accountRef.Value : null;

    if (resultCode === 0 && orderId) {
      run('UPDATE orders SET status = ?, external_reference = ? WHERE id = ?', ['paid', callback.CheckoutRequestID || null, orderId]);
    }
  } catch (e) { console.warn('Could not process mpesa payload', e.message); }
  res.json({ Received: true });
});

// Airtel / Tigo stubs — many providers require partnerships or aggregator
app.post('/api/pay/airtel', (req, res) => {
  // Implement using Airtel Africa documentation or via aggregator
  res.json({ ok: true, message: 'Airtel payment endpoint: integrate with Airtel APIs or aggregator' });
});
app.post('/api/pay/tigo', (req, res) => {
  res.json({ ok: true, message: 'TigoPesa payment endpoint: integrate with Tigo partner APIs or aggregator' });
});

// Webhook endpoints for Airtel/Tigo would be implemented similarly.

// ---------- Start server ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server started on', PORT));
