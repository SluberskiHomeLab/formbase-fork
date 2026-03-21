const { Router } = require('express');
const { v4: uuid } = require('uuid');
const db = require('../db');
const { authMiddleware } = require('../auth');

const router = Router();
router.use(authMiddleware);

const PLAN_LIMITS = { free: 3, pro: 50, unlimited: 9999 };

// List forms
router.get('/', (req, res) => {
  const forms = db.prepare('SELECT * FROM forms WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
  res.json(forms);
});

// Create form
router.post('/', (req, res) => {
  const count = db.prepare('SELECT COUNT(*) as c FROM forms WHERE user_id = ?').get(req.user.id).c;
  const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(req.user.id);
  const limit = PLAN_LIMITS[user.plan] || 3;
  if (count >= limit) return res.status(403).json({ error: `Form limit reached (${limit} on ${user.plan} plan)` });
  const id = uuid();
  const { name, notify_email, redirect_url, honeypot_field, allowed_origins, webhook_url, auto_response_subject, auto_response_body } = req.body;
  if (!name) return res.status(400).json({ error: 'Form name required' });
  db.prepare(`INSERT INTO forms (id, user_id, name, notify_email, redirect_url, honeypot_field, allowed_origins, webhook_url, auto_response_subject, auto_response_body)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id, req.user.id, name, notify_email || null, redirect_url || null, honeypot_field || '_gotcha', allowed_origins || null, webhook_url || null, auto_response_subject || null, auto_response_body || null);
  const form = db.prepare('SELECT * FROM forms WHERE id = ?').get(id);
  res.status(201).json(form);
});

// Get form
router.get('/:id', (req, res) => {
  const form = db.prepare('SELECT * FROM forms WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!form) return res.status(404).json({ error: 'Form not found' });
  res.json(form);
});

// Update form
router.patch('/:id', (req, res) => {
  const form = db.prepare('SELECT * FROM forms WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!form) return res.status(404).json({ error: 'Form not found' });
  const fields = ['name', 'notify_email', 'redirect_url', 'honeypot_field', 'allowed_origins', 'webhook_url', 'auto_response_subject', 'auto_response_body'];
  const updates = [];
  const values = [];
  for (const f of fields) {
    if (req.body[f] !== undefined) { updates.push(`${f} = ?`); values.push(req.body[f]); }
  }
  if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });
  values.push(req.params.id);
  db.prepare(`UPDATE forms SET ${updates.join(', ')} WHERE id = ?`).run(...values);
  res.json(db.prepare('SELECT * FROM forms WHERE id = ?').get(req.params.id));
});

// Delete form
router.delete('/:id', (req, res) => {
  const form = db.prepare('SELECT * FROM forms WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!form) return res.status(404).json({ error: 'Form not found' });
  db.prepare('DELETE FROM forms WHERE id = ?').run(req.params.id);
  res.json({ deleted: true });
});

// Get submissions
router.get('/:id/submissions', (req, res) => {
  const form = db.prepare('SELECT * FROM forms WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!form) return res.status(404).json({ error: 'Form not found' });
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = (page - 1) * limit;
  const total = db.prepare('SELECT COUNT(*) as c FROM submissions WHERE form_id = ?').get(req.params.id).c;
  const submissions = db.prepare('SELECT * FROM submissions WHERE form_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?').all(req.params.id, limit, offset);
  submissions.forEach(s => { try { s.data = JSON.parse(s.data); } catch {} });
  res.json({ submissions, total, page, pages: Math.ceil(total / limit) });
});

// Export submissions as CSV
router.get('/:id/export', (req, res) => {
  const form = db.prepare('SELECT * FROM forms WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!form) return res.status(404).json({ error: 'Form not found' });
  const subs = db.prepare('SELECT * FROM submissions WHERE form_id = ? AND is_spam = 0 ORDER BY created_at DESC').all(req.params.id);
  if (subs.length === 0) return res.status(200).send('No submissions');
  const allKeys = new Set();
  const parsed = subs.map(s => { const d = JSON.parse(s.data); Object.keys(d).forEach(k => allKeys.add(k)); return { ...d, _submitted_at: s.created_at, _ip: s.ip }; });
  allKeys.add('_submitted_at'); allKeys.add('_ip');
  const keys = [...allKeys];
  const escape = v => `"${String(v || '').replace(/"/g, '""')}"`;
  const csv = [keys.map(escape).join(','), ...parsed.map(r => keys.map(k => escape(r[k])).join(','))].join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="${form.name}-submissions.csv"`);
  res.send(csv);
});

// Delete submission
router.delete('/:formId/submissions/:subId', (req, res) => {
  const form = db.prepare('SELECT * FROM forms WHERE id = ? AND user_id = ?').get(req.params.formId, req.user.id);
  if (!form) return res.status(404).json({ error: 'Form not found' });
  db.prepare('DELETE FROM submissions WHERE id = ? AND form_id = ?').run(req.params.subId, req.params.formId);
  res.json({ deleted: true });
});

module.exports = router;
