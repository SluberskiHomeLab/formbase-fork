const { Router } = require('express');
const { randomUUID } = require('crypto');
const net = require('net');
const db = require('../db');
const { resolveSafeUrl, validateHttpUrl } = require('../lib/safe-url');
const { escapeHtml } = require('../lib/escape');
const { limitSubmit } = require('../lib/rate-limit');

const router = Router();

const WEBHOOK_TIMEOUT_MS = 5000;

// Compares a request Origin against a form's allowlist by parsed host.
// The original substring test meant an allowlist of "trusted.com" also
// accepted "trusted.com.evil.example".
function originAllowed(allowList, originHeader) {
  const entries = allowList.split(',').map(s => s.trim()).filter(Boolean);
  if (entries.length === 0 || entries.includes('*')) return true;
  if (!originHeader) return false;

  let host;
  try {
    host = new URL(originHeader).host.toLowerCase();
  } catch {
    return false; // unparseable Origin/Referer -> refuse rather than fall through
  }

  return entries.some(entry => {
    let allowed = entry.toLowerCase();
    if (allowed === '*') return true;
    // Accept bare hosts as well as full origins in the stored list.
    try { if (/^https?:\/\//.test(allowed)) allowed = new URL(allowed).host.toLowerCase(); } catch { return false; }
    if (allowed.startsWith('*.')) {
      const suffix = allowed.slice(1); // ".example.com"
      return host === allowed.slice(2) || host.endsWith(suffix);
    }
    return host === allowed;
  });
}

// req.ip is only meaningful once TRUST_PROXY is configured; until then a
// spoofed X-Forwarded-For could otherwise be stored and rendered in the
// owner's dashboard.
function clientIp(req) {
  const ip = req.ip || req.socket?.remoteAddress || '';
  const bare = ip.replace(/^::ffff:/, '');
  return net.isIP(bare) ? bare : null;
}

async function deliverWebhook(form, payload) {
  try {
    // Re-validate at send time: a hostname that looked fine when saved can
    // resolve to a private address later.
    const url = await resolveSafeUrl(form.webhook_url, 'Webhook URL');
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      redirect: 'manual', // a 302 to 169.254.169.254 would bypass the check
      signal: AbortSignal.timeout(WEBHOOK_TIMEOUT_MS)
    });
  } catch (e) {
    console.warn(`[webhook] form=${form.id} not delivered: ${e.message}`);
  }
}

// Main submission endpoint — HTML forms POST here
router.post('/:formId', limitSubmit(), async (req, res, next) => {
  try {
    const form = db.prepare('SELECT * FROM forms WHERE id = ?').get(req.params.formId);
    if (!form) return res.status(404).json({ error: 'Form not found' });

    // Origin check
    if (form.allowed_origins) {
      const origin = req.headers.origin || req.headers.referer || '';
      if (!originAllowed(form.allowed_origins, origin)) {
        return res.status(403).json({ error: 'Origin not allowed' });
      }
    }

    const ip = clientIp(req);
    const userAgent = String(req.headers['user-agent'] || '').slice(0, 512);

    // Honeypot check
    const honeypot = form.honeypot_field || '_gotcha';
    if (req.body[honeypot]) {
      // Silent spam trap — accept but flag
      const id = randomUUID();
      const data = { ...req.body };
      delete data[honeypot];
      db.prepare('INSERT INTO submissions (id, form_id, data, ip, user_agent, is_spam) VALUES (?, ?, ?, ?, ?, 1)')
        .run(id, form.id, JSON.stringify(data), ip, userAgent);
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
      .run(id, form.id, JSON.stringify(data), ip, userAgent);
    db.prepare('UPDATE forms SET submission_count = submission_count + 1 WHERE id = ?').run(form.id);

    // Webhook
    if (form.webhook_url) {
      deliverWebhook(form, {
        form_id: form.id, form_name: form.name, submission_id: id,
        data, submitted_at: new Date().toISOString()
      });
    }

    // Email notification (logged, actual sending requires SMTP config)
    if (form.notify_email) {
      console.log(`[NOTIFY] New submission on "${form.name}" → ${form.notify_email}`);
      try {
        const nodemailer = require('nodemailer');
        if (process.env.SMTP_HOST) {
          const transport = nodemailer.createTransport({
            host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT) || 587,
            auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
          });
          // Keys and values come from an unauthenticated stranger; escape both
          // before they land in an HTML email.
          const fields = Object.entries(data)
            .map(([k, v]) => `<b>${escapeHtml(k)}:</b> ${escapeHtml(v)}`)
            .join('<br>');
          await transport.sendMail({
            from: process.env.SMTP_FROM || 'noreply@formbase.dev',
            to: form.notify_email,
            subject: `New submission: ${form.name}`,
            html: `<h2>New submission on "${escapeHtml(form.name)}"</h2><p>${fields}</p><hr><small>Sent by FormBase</small>`
          });
        }
      } catch (e) { console.error('Email error:', e.message); }
    }

    return handleSuccess(req, res, form);
  } catch (e) {
    next(e);
  }
});

function handleSuccess(req, res, form) {
  const isAjax = req.headers.accept?.includes('application/json') || req.headers['x-requested-with'] === 'XMLHttpRequest';
  if (isAjax) return res.json({ success: true });
  if (form.redirect_url) {
    // Re-check before handing the value to the browser, in case a row predates
    // validation or was written out of band.
    try {
      return res.redirect(validateHttpUrl(form.redirect_url, 'Redirect URL'));
    } catch {
      console.warn(`[submit] form=${form.id} has an unsafe redirect_url; ignoring`);
    }
  }
  res.send(`<!DOCTYPE html><html><body style="font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f8fafc"><div style="text-align:center"><h1>✅ Thank you!</h1><p>Your submission has been received.</p></div></body></html>`);
}

module.exports = router;
