const { Router } = require('express');
const { randomUUID } = require('crypto');
const db = require('../db');
const { authAnyMiddleware } = require('../auth');
const { validateHttpUrl } = require('../lib/safe-url');
const { csvCell, contentDisposition } = require('../lib/escape');

const router = Router();
router.use(authAnyMiddleware);

const PLAN_LIMITS = { free: 3, pro: 50, unlimited: 9999 };
const MAX_NAME = 200;

// webhook_url is fetched server-side and redirect_url is handed to the
// browser, so both need their scheme constrained before they are stored.
function validateUrlFields(body) {
  for (const [field, label] of [['webhook_url', 'Webhook URL'], ['redirect_url', 'Redirect URL']]) {
    const value = body[field];
    if (value === undefined || value === null || value === '') continue;
    try {
      body[field] = validateHttpUrl(value, label);
    } catch (e) {
      return e.message;
    }
  }
  return null;
}

// List forms
router.get('/', (req, res, next) => {
  try {
    const forms = db.prepare('SELECT * FROM forms WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
    res.json(forms);
  } catch (e) { next(e); }
});

// Create form
router.post('/', (req, res, next) => {
  try {
    const count = db.prepare('SELECT COUNT(*) as c FROM forms WHERE user_id = ?').get(req.user.id).c;
    const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(req.user.id);
    const limit = PLAN_LIMITS[user.plan] || 3;
    if (count >= limit) return res.status(403).json({ error: `Form limit reached (${limit} on ${user.plan} plan)` });

    const body = { ...(req.body || {}) };
    const { name, notify_email, honeypot_field, allowed_origins, auto_response_subject, auto_response_body } = body;
    if (!name || typeof name !== 'string') return res.status(400).json({ error: 'Form name required' });
    if (name.length > MAX_NAME) return res.status(400).json({ error: 'Form name is too long' });

    const urlError = validateUrlFields(body);
    if (urlError) return res.status(400).json({ error: urlError });

    const id = randomUUID();
    db.prepare(`INSERT INTO forms (id, user_id, name, notify_email, redirect_url, honeypot_field, allowed_origins, webhook_url, auto_response_subject, auto_response_body)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id, req.user.id, name, notify_email || null, body.redirect_url || null, honeypot_field || '_gotcha', allowed_origins || null, body.webhook_url || null, auto_response_subject || null, auto_response_body || null);
    const form = db.prepare('SELECT * FROM forms WHERE id = ?').get(id);
    res.status(201).json(form);
  } catch (e) { next(e); }
});

// Get form
router.get('/:id', (req, res, next) => {
  try {
    const form = db.prepare('SELECT * FROM forms WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
    if (!form) return res.status(404).json({ error: 'Form not found' });
    res.json(form);
  } catch (e) { next(e); }
});

// Update form
router.patch('/:id', (req, res, next) => {
  try {
    const form = db.prepare('SELECT * FROM forms WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
    if (!form) return res.status(404).json({ error: 'Form not found' });

    const body = { ...(req.body || {}) };
    const urlError = validateUrlFields(body);
    if (urlError) return res.status(400).json({ error: urlError });
    if (body.name !== undefined && (typeof body.name !== 'string' || !body.name || body.name.length > MAX_NAME)) {
      return res.status(400).json({ error: 'Invalid form name' });
    }

    const fields = ['name', 'notify_email', 'redirect_url', 'honeypot_field', 'allowed_origins', 'webhook_url', 'auto_response_subject', 'auto_response_body'];
    const updates = [];
    const values = [];
    for (const f of fields) {
      if (body[f] !== undefined) { updates.push(`${f} = ?`); values.push(body[f]); }
    }
    if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });
    values.push(req.params.id);
    db.prepare(`UPDATE forms SET ${updates.join(', ')} WHERE id = ?`).run(...values);
    res.json(db.prepare('SELECT * FROM forms WHERE id = ?').get(req.params.id));
  } catch (e) { next(e); }
});

// Delete form
router.delete('/:id', (req, res, next) => {
  try {
    const form = db.prepare('SELECT * FROM forms WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
    if (!form) return res.status(404).json({ error: 'Form not found' });
    db.prepare('DELETE FROM forms WHERE id = ?').run(req.params.id);
    res.json({ deleted: true });
  } catch (e) { next(e); }
});

// Get submissions
router.get('/:id/submissions', (req, res, next) => {
  try {
    const form = db.prepare('SELECT * FROM forms WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
    if (!form) return res.status(404).json({ error: 'Form not found' });
    // Coerce defensively: a non-numeric or negative page reached the driver as
    // a float and surfaced a raw SqliteError to the client.
    const page = Math.max(1, Math.floor(Number(req.query.page)) || 1);
    const limit = Math.min(Math.max(1, Math.floor(Number(req.query.limit)) || 50), 200);
    const offset = (page - 1) * limit;
    const total = db.prepare('SELECT COUNT(*) as c FROM submissions WHERE form_id = ?').get(req.params.id).c;
    const submissions = db.prepare('SELECT * FROM submissions WHERE form_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?').all(req.params.id, limit, offset);
    submissions.forEach(s => { try { s.data = JSON.parse(s.data); } catch {} });
    res.json({ submissions, total, page, pages: Math.ceil(total / limit) });
  } catch (e) { next(e); }
});

// Export submissions as CSV
router.get('/:id/export', (req, res, next) => {
  try {
    const form = db.prepare('SELECT * FROM forms WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
    if (!form) return res.status(404).json({ error: 'Form not found' });
    const subs = db.prepare('SELECT * FROM submissions WHERE form_id = ? AND is_spam = 0 ORDER BY created_at DESC').all(req.params.id);
    if (subs.length === 0) return res.status(200).send('No submissions');
    const allKeys = new Set();
    const parsed = subs.map(s => { const d = JSON.parse(s.data); Object.keys(d).forEach(k => allKeys.add(k)); return { ...d, _submitted_at: s.created_at, _ip: s.ip }; });
    allKeys.add('_submitted_at'); allKeys.add('_ip');
    const keys = [...allKeys];
    // csvCell also neutralises leading =,+,-,@ so a submitted value cannot
    // execute as a formula when the owner opens the export.
    const csv = [keys.map(csvCell).join(','), ...parsed.map(r => keys.map(k => csvCell(r[k])).join(','))].join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', contentDisposition(`${form.name}-submissions.csv`));
    res.send(csv);
  } catch (e) { next(e); }
});

// Delete submission
router.delete('/:formId/submissions/:subId', (req, res, next) => {
  try {
    const form = db.prepare('SELECT * FROM forms WHERE id = ? AND user_id = ?').get(req.params.formId, req.user.id);
    if (!form) return res.status(404).json({ error: 'Form not found' });
    db.prepare('DELETE FROM submissions WHERE id = ? AND form_id = ?').run(req.params.subId, req.params.formId);
    res.json({ deleted: true });
  } catch (e) { next(e); }
});

module.exports = router;
