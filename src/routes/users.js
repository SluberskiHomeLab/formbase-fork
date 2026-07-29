const { Router } = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db');
const { generateToken, authMiddleware } = require('../auth');
const { limitAuth, clearAuthAttempts } = require('../lib/rate-limit');
const users = require('../lib/users');

const router = Router();

// Cost-matched dummy hash. Compared against when the account does not exist so
// the "no such user" path takes the same time as a wrong password -- otherwise
// response latency alone reveals which addresses are registered.
const DUMMY_HASH = bcrypt.hashSync('formbase-timing-equalizer', 10);

// Public instance configuration. The dashboard reads this before drawing the
// auth page so it can hide the sign-up form rather than offering a button that
// only ever returns 403. Carries no data that is not already observable by
// POSTing to /register once.
router.get('/config', (req, res) => {
  res.json({ registration_enabled: !users.registrationDisabled() });
});

// Register
router.post('/register', limitAuth(), async (req, res, next) => {
  try {
    // Checked before anything else, and before any write, so the switch is a
    // single unconditional gate rather than a condition threaded through the
    // creation logic. Admin-created accounts go through /api/admin/users and
    // are unaffected.
    if (users.registrationDisabled()) {
      return res.status(403).json({ error: 'Registration is disabled on this instance' });
    }

    const { email, password } = req.body || {};
    // createUser applies the same validation, uniqueness check, and
    // first-account-is-admin rule that the admin creation path uses.
    const user = await users.createUser({ email, password });
    await clearAuthAttempts(req);
    const token = generateToken(user);
    res.status(201).json({
      token,
      user: {
        id: user.id, email: user.email, plan: user.plan,
        role: user.role, is_active: !!user.is_active, api_key: user.api_key
      }
    });
  } catch (e) {
    if (e instanceof users.UserError) return res.status(e.status).json({ error: e.message });
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
    // findByEmail matches COLLATE NOCASE, which keeps accounts created before
    // normalisation (which stored the address verbatim) able to log in.
    const user = users.findByEmail(email);

    // Always run a compare, even with no user, to keep timing flat.
    const valid = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
    if (!user || !valid) return res.status(401).json({ error: 'Invalid credentials' });

    // Reported only after the password has verified, so this cannot be used to
    // enumerate which addresses hold disabled accounts.
    if (!user.is_active) {
      return res.status(403).json({ error: 'Account is disabled. Contact an administrator.' });
    }

    await clearAuthAttempts(req);
    const token = generateToken(user);
    res.json({
      token,
      user: {
        id: user.id, email: user.email, plan: user.plan,
        role: user.role, is_active: !!user.is_active, api_key: user.api_key
      }
    });
  } catch (e) {
    next(e);
  }
});

// Get profile
router.get('/me', authMiddleware, (req, res, next) => {
  try {
    const user = users.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.is_active = !!user.is_active;
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
    const apiKey = users.newApiKey();
    db.prepare('UPDATE users SET api_key = ? WHERE id = ?').run(apiKey, req.user.id);
    res.json({ api_key: apiKey });
  } catch (e) {
    next(e);
  }
});

// Change own password.
//
// With signup closed, accounts arrive with a password an admin picked and sent
// over some other channel, so the account holder needs a way to replace it
// without asking that admin to do it for them. Rate limited like the other
// credential endpoints, and the current password is required so a borrowed
// session cannot lock the real owner out.
router.post('/me/password', authMiddleware, limitAuth(), async (req, res, next) => {
  try {
    const { current_password, new_password } = req.body || {};
    if (typeof current_password !== 'string' || !current_password) {
      return res.status(400).json({ error: 'Current password required' });
    }
    const invalid = users.validatePassword(new_password);
    if (invalid) return res.status(400).json({ error: invalid });

    const row = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.id);
    if (!row) return res.status(404).json({ error: 'User not found' });
    if (!(await bcrypt.compare(current_password, row.password_hash))) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    await users.setPassword(req.user.id, new_password);
    await clearAuthAttempts(req);
    res.json({ updated: true });
  } catch (e) {
    if (e instanceof users.UserError) return res.status(e.status).json({ error: e.message });
    next(e);
  }
});

module.exports = router;
