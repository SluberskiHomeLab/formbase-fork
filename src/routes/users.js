const { Router } = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('../db');
const { generateToken, authMiddleware } = require('../auth');
const { limitAuth, clearAuthAttempts } = require('../lib/rate-limit');

const router = Router();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_EMAIL = 254;
const MIN_PASSWORD = 6;
// bcrypt only considers the first 72 bytes; accepting longer silently
// truncates, so reject instead of pretending the extra characters counted.
const MAX_PASSWORD = 72;

// Cost-matched dummy hash. Compared against when the account does not exist so
// the "no such user" path takes the same time as a wrong password -- otherwise
// response latency alone reveals which addresses are registered.
const DUMMY_HASH = bcrypt.hashSync('formbase-timing-equalizer', 10);

function validateCredentials(email, password) {
  if (!email || !password) return 'Email and password required';
  if (typeof email !== 'string' || typeof password !== 'string') return 'Email and password required';
  if (email.length > MAX_EMAIL) return 'Email is too long';
  if (!EMAIL_RE.test(email)) return 'Invalid email address';
  if (password.length < MIN_PASSWORD) return `Password must be ${MIN_PASSWORD}+ characters`;
  if (Buffer.byteLength(password, 'utf8') > MAX_PASSWORD) {
    return `Password must be at most ${MAX_PASSWORD} bytes`;
  }
  return null;
}

// Register
router.post('/register', limitAuth(), async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    const invalid = validateCredentials(email, password);
    if (invalid) return res.status(400).json({ error: invalid });

    const normalized = email.trim().toLowerCase();
    // COLLATE NOCASE so an address cannot be re-registered under different
    // casing, and so rows written before emails were normalised still match.
    const existing = db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE').get(normalized);
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const id = crypto.randomUUID();
    const hash = await bcrypt.hash(password, 10);
    const apiKey = 'fb_' + crypto.randomBytes(24).toString('hex');
    db.prepare('INSERT INTO users (id, email, password_hash, api_key) VALUES (?, ?, ?, ?)')
      .run(id, normalized, hash, apiKey);
    await clearAuthAttempts(req);
    const token = generateToken({ id, email: normalized });
    res.status(201).json({ token, user: { id, email: normalized, plan: 'free', api_key: apiKey } });
  } catch (e) {
    next(e);
  }
});

// Login
router.post('/login', limitAuth(), async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string' || !email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    const normalized = email.trim().toLowerCase();
    // NOCASE keeps accounts created before normalisation (which stored the
    // address verbatim) able to log in after an upgrade.
    const user = db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE').get(normalized);

    // Always run a compare, even with no user, to keep timing flat.
    const valid = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
    if (!user || !valid) return res.status(401).json({ error: 'Invalid credentials' });

    await clearAuthAttempts(req);
    const token = generateToken(user);
    res.json({ token, user: { id: user.id, email: user.email, plan: user.plan, api_key: user.api_key } });
  } catch (e) {
    next(e);
  }
});

// Get profile
router.get('/me', authMiddleware, (req, res, next) => {
  try {
    const user = db.prepare('SELECT id, email, plan, api_key, created_at FROM users WHERE id = ?').get(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const formCount = db.prepare('SELECT COUNT(*) as c FROM forms WHERE user_id = ?').get(req.user.id).c;
    const totalSubs = db.prepare(`SELECT COUNT(*) as c FROM submissions s JOIN forms f ON s.form_id = f.id WHERE f.user_id = ?`).get(req.user.id).c;
    res.json({ ...user, form_count: formCount, total_submissions: totalSubs });
  } catch (e) {
    next(e);
  }
});

// Regenerate API key
router.post('/me/regenerate-key', authMiddleware, (req, res, next) => {
  try {
    const apiKey = 'fb_' + crypto.randomBytes(24).toString('hex');
    db.prepare('UPDATE users SET api_key = ? WHERE id = ?').run(apiKey, req.user.id);
    res.json({ api_key: apiKey });
  } catch (e) {
    next(e);
  }
});

module.exports = router;
