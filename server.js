require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'quicktopup123';

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
if (!fs.existsSync(ORDERS_FILE)) fs.writeFileSync(ORDERS_FILE, '[]');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function readJSON(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf-8') || '[]'); }
  catch { return []; }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'Login koro' });
  try {
    req.user = jwt.verify(h.split(' ')[1], SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: 'Sob field dao' });

    const users = readJSON(USERS_FILE);
    if (users.find(u => u.email === email))
      return res.status(400).json({ error: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 10);
    const user = { id: Date.now().toString(), name, email, password: hashed };
    users.push(user);
    writeJSON(USERS_FILE, users);

    const token = jwt.sign({ id: user.id, email }, SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name, email } });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.email === email);
    if (!user) return res.status(400).json({ error: 'User pai nai' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: 'Password vul' });

    const token = jwt.sign({ id: user.id, email }, SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name: user.name, email } });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/order', auth, (req, res) => {
  const { freeFireId, packageName, price } = req.body;
  if (!freeFireId || !packageName)
    return res.status(400).json({ error: 'Info missing' });

  const orders = readJSON(ORDERS_FILE);
  const order = {
    _id: 'ORD' + Date.now(),
    userId: req.user.id,
    freeFireId,
    packageName,
    price,
    status: 'pending',
    createdAt: new Date().toISOString()
  };
  orders.push(order);
  writeJSON(ORDERS_FILE, orders);
  res.json({ success: true, order });
});

app.get('/api/order', auth, (req, res) => {
  const orders = readJSON(ORDERS_FILE).filter(o => o.userId === req.user.id);
  res.json(orders);
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log('Server running: http://localhost:' + PORT);

});
