const { Router } = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('../db');
const { generateToken, authMiddleware } = require('../auth');

const router = Router();

// Register
router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be 6+ characters' });
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) return res.status(409).json({ error: 'Email already registered' });
    const id = crypto.randomUUID();
    const hash = await bcrypt.hash(password, 10);
    const apiKey = 'fb_' + crypto.randomBytes(24).toString('hex');
    db.prepare('INSERT INTO users (id, email, password_hash, api_key) VALUES (?, ?, ?, ?)').run(id, email, hash, apiKey);
    const token = generateToken({ id, email });
    res.status(201).json({ token, user: { id, email, plan: 'free', api_key: apiKey } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = generateToken(user);
    res.json({ token, user: { id: user.id, email: user.email, plan: user.plan, api_key: user.api_key } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Get profile
router.get('/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, email, plan, api_key, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const formCount = db.prepare('SELECT COUNT(*) as c FROM forms WHERE user_id = ?').get(req.user.id).c;
  const totalSubs = db.prepare(`SELECT COUNT(*) as c FROM submissions s JOIN forms f ON s.form_id = f.id WHERE f.user_id = ?`).get(req.user.id).c;
  res.json({ ...user, form_count: formCount, total_submissions: totalSubs });
});

// Regenerate API key
router.post('/me/regenerate-key', authMiddleware, (req, res) => {
  const apiKey = 'fb_' + crypto.randomBytes(24).toString('hex');
  db.prepare('UPDATE users SET api_key = ? WHERE id = ?').run(apiKey, req.user.id);
  res.json({ api_key: apiKey });
});

module.exports = router;
