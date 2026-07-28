const { Router } = require('express');
const { randomUUID } = require('crypto');
const db = require('../db');

const router = Router();

// Main submission endpoint — HTML forms POST here
router.post('/:formId', async (req, res) => {
  try {
    const form = db.prepare('SELECT * FROM forms WHERE id = ?').get(req.params.formId);
    if (!form) return res.status(404).json({ error: 'Form not found' });

    // Origin check
    if (form.allowed_origins) {
      const origins = form.allowed_origins.split(',').map(s => s.trim());
      const origin = req.headers.origin || req.headers.referer || '';
      if (origins.length > 0 && origins[0] !== '*' && !origins.some(o => origin.includes(o))) {
        return res.status(403).json({ error: 'Origin not allowed' });
      }
    }

    // Honeypot check
    const honeypot = form.honeypot_field || '_gotcha';
    if (req.body[honeypot]) {
      // Silent spam trap — accept but flag
      const id = randomUUID();
      const data = { ...req.body };
      delete data[honeypot];
      db.prepare('INSERT INTO submissions (id, form_id, data, ip, user_agent, is_spam) VALUES (?, ?, ?, ?, ?, 1)')
        .run(id, form.id, JSON.stringify(data), req.ip, req.headers['user-agent']);
      db.prepare('UPDATE forms SET spam_count = spam_count + 1 WHERE id = ?').run(form.id);
      return handleSuccess(req, res, form);
    }

    // Strip honeypot field from data
    const data = { ...req.body };
    delete data[honeypot];

    // Check submission limits (free = 100/form/month)
    const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(form.user_id);
    const monthLimit = user.plan === 'free' ? 100 : user.plan === 'pro' ? 10000 : 999999;
    const monthCount = db.prepare(`SELECT COUNT(*) as c FROM submissions WHERE form_id = ? AND created_at > datetime('now', '-30 days')`).get(form.id).c;
    if (monthCount >= monthLimit) {
      return res.status(429).json({ error: 'Monthly submission limit reached' });
    }

    const id = randomUUID();
    db.prepare('INSERT INTO submissions (id, form_id, data, ip, user_agent) VALUES (?, ?, ?, ?, ?)')
      .run(id, form.id, JSON.stringify(data), req.ip, req.headers['user-agent']);
    db.prepare('UPDATE forms SET submission_count = submission_count + 1 WHERE id = ?').run(form.id);

    // Webhook
    if (form.webhook_url) {
      fetch(form.webhook_url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ form_id: form.id, form_name: form.name, submission_id: id, data, submitted_at: new Date().toISOString() })
      }).catch(() => {});
    }

    // Email notification (logged, actual sending requires SMTP config)
    if (form.notify_email) {
      console.log(`[NOTIFY] New submission on "${form.name}" → ${form.notify_email}`);
      try {
        const nodemailer = require('nodemailer');
        if (process.env.SMTP_HOST) {
          const transport = nodemailer.createTransport({
            host: process.env.SMTP_HOST, port: process.env.SMTP_PORT || 587,
            auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
          });
          const fields = Object.entries(data).map(([k, v]) => `<b>${k}:</b> ${v}`).join('<br>');
          await transport.sendMail({
            from: process.env.SMTP_FROM || 'noreply@formbase.dev',
            to: form.notify_email,
            subject: `New submission: ${form.name}`,
            html: `<h2>New submission on "${form.name}"</h2><p>${fields}</p><hr><small>Sent by FormBase</small>`
          });
        }
      } catch (e) { console.error('Email error:', e.message); }
    }

    return handleSuccess(req, res, form);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

function handleSuccess(req, res, form) {
  const isAjax = req.headers.accept?.includes('application/json') || req.headers['x-requested-with'] === 'XMLHttpRequest';
  if (isAjax) return res.json({ success: true });
  if (form.redirect_url) return res.redirect(form.redirect_url);
  res.send(`<!DOCTYPE html><html><body style="font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f8fafc"><div style="text-align:center"><h1>✅ Thank you!</h1><p>Your submission has been received.</p></div></body></html>`);
}

module.exports = router;
