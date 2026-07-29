// Admin user management. Mounted at /api/admin behind authMiddleware +
// requireAdmin, so every route below is admin-only.
//
// This is the account-creation path that stays open when DISABLE_REGISTRATION
// closes public signup: an admin invites people rather than anyone signing
// themselves up.

const { Router } = require('express');
const db = require('../db');
const { authMiddleware, requireAdmin } = require('../auth');
const users = require('../lib/users');

const router = Router();
router.use(authMiddleware, requireAdmin);

// Deliberately JWT-only. An API key is a long-lived bearer credential kept in
// scripts and CI, and every account has one; letting it manage other people's
// accounts would widen its blast radius far past what it is handed out for.

// Counts alongside each account so an admin can see what deleting one destroys.
const USER_SELECT = `
  SELECT u.id, u.email, u.plan, u.role, u.is_active, u.created_at,
         (SELECT COUNT(*) FROM forms f WHERE f.user_id = u.id) AS form_count,
         (SELECT COUNT(*) FROM submissions s
            JOIN forms f ON s.form_id = f.id
           WHERE f.user_id = u.id) AS submission_count
    FROM users u
`;

const listUsers = db.prepare(`${USER_SELECT} ORDER BY u.created_at ASC, u.rowid ASC`);
const selectUser = db.prepare(`${USER_SELECT} WHERE u.id = ?`);

function getUser(id) {
  return selectUser.get(id);
}

// Keeping at least one active admin alive is what stops an instance with
// signup closed from becoming unopenable. The three self-guards below are
// sufficient on their own: reaching any route here requires being an active
// admin, so demoting, disabling, or deleting SOMEONE ELSE always leaves the
// actor behind as an admin, and the actor cannot do any of the three to
// themselves. No separate last-admin check is needed.
//
// If an account is nonetheless lost outside the app -- a row deleted straight
// out of SQLite -- ensureAdminExists() promotes the oldest account at the next
// boot rather than leaving the instance stranded.

// List users
router.get('/users', (req, res, next) => {
  try {
    res.json({ users: listUsers.all(), registration_enabled: !users.registrationDisabled() });
  } catch (e) { next(e); }
});

// Get one user
router.get('/users/:id', (req, res, next) => {
  try {
    const user = getUser(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (e) { next(e); }
});

// Create user
router.post('/users', async (req, res, next) => {
  try {
    const { email, password, role, plan, is_active } = req.body || {};
    const user = await users.createUser({
      email,
      password,
      // Explicit default: an admin-created account is a plain user unless the
      // admin says otherwise. Without this, createUser's first-account rule
      // would apply and the field would be silently ignored.
      role: role === undefined ? 'user' : role,
      plan: plan === undefined ? 'free' : plan,
      is_active: is_active === undefined ? true : !!is_active
    });
    res.status(201).json(getUser(user.id));
  } catch (e) {
    if (e instanceof users.UserError) return res.status(e.status).json({ error: e.message });
    next(e);
  }
});

// Update user: email, password, plan, role, active status
router.patch('/users/:id', async (req, res, next) => {
  try {
    const target = getUser(req.params.id);
    if (!target) return res.status(404).json({ error: 'User not found' });

    const body = req.body || {};
    const { email, password, plan, role } = body;
    const isActive = body.is_active === undefined ? undefined : !!body.is_active;

    if (role !== undefined && !users.ROLES.includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    if (plan !== undefined && !users.PLANS.includes(plan)) {
      return res.status(400).json({ error: 'Invalid plan' });
    }

    // Self-inflicted lockout is the likeliest mistake in this UI, and unlike
    // the others it cannot be undone from inside the app.
    if (target.id === req.user.id) {
      if (role !== undefined && role !== target.role) {
        return res.status(400).json({ error: 'You cannot change your own role' });
      }
      if (isActive === false) {
        return res.status(400).json({ error: 'You cannot deactivate your own account' });
      }
    }

    const updates = [];
    const values = [];

    if (email !== undefined) {
      const invalid = users.validateEmail(email);
      if (invalid) return res.status(400).json({ error: invalid });
      const normalized = users.normalizeEmail(email);
      const clash = db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE AND id != ?')
        .get(normalized, target.id);
      if (clash) return res.status(409).json({ error: 'Email already registered' });
      updates.push('email = ?'); values.push(normalized);
    }
    if (plan !== undefined) { updates.push('plan = ?'); values.push(plan); }
    if (role !== undefined) { updates.push('role = ?'); values.push(role); }
    if (isActive !== undefined) { updates.push('is_active = ?'); values.push(isActive ? 1 : 0); }

    if (password !== undefined) {
      const invalid = users.validatePassword(password);
      if (invalid) return res.status(400).json({ error: invalid });
    }
    if (updates.length === 0 && password === undefined) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    if (updates.length) {
      values.push(target.id);
      db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...values);
    }
    // Hashing is async, so it happens outside the synchronous UPDATE above
    // rather than being folded into it.
    if (password !== undefined) await users.setPassword(target.id, password);

    res.json(getUser(target.id));
  } catch (e) {
    if (e instanceof users.UserError) return res.status(e.status).json({ error: e.message });
    next(e);
  }
});

// Regenerate a user's API key -- the way to cut off a leaked key for someone
// who cannot get into the dashboard to do it themselves.
router.post('/users/:id/regenerate-key', (req, res, next) => {
  try {
    const target = getUser(req.params.id);
    if (!target) return res.status(404).json({ error: 'User not found' });
    const apiKey = users.newApiKey();
    db.prepare('UPDATE users SET api_key = ? WHERE id = ?').run(apiKey, target.id);
    res.json({ id: target.id, api_key: apiKey });
  } catch (e) { next(e); }
});

// Delete user. forms/submissions cascade via the schema's ON DELETE CASCADE.
router.delete('/users/:id', (req, res, next) => {
  try {
    const target = getUser(req.params.id);
    if (!target) return res.status(404).json({ error: 'User not found' });
    if (target.id === req.user.id) {
      return res.status(400).json({ error: 'You cannot delete your own account' });
    }

    db.prepare('DELETE FROM users WHERE id = ?').run(target.id);
    res.json({ deleted: true, forms_removed: target.form_count, submissions_removed: target.submission_count });
  } catch (e) { next(e); }
});

module.exports = router;
