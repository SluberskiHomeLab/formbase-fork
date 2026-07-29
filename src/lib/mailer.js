// Email notifications.
//
// This was previously built inline in routes/submit.js, where three separate
// problems made a correctly-configured relay reject or refuse every message:
//
//   * The From address fell back to a hardcoded `noreply@formbase.dev`. No real
//     relay is authoritative for that domain, so it answers
//     `553 Sender is not allowed to relay emails` and the notification is lost.
//   * `auth` was passed even when SMTP_USER/SMTP_PASS were unset, which makes
//     nodemailer fail with `Missing credentials for "PLAIN"` instead of
//     connecting anonymously to a relay that wants no authentication.
//   * `secure` was never set, so port 465 -- implicit TLS, and a very common
//     choice -- could not work at all.
//
// All three only ever surfaced as one line in the container log at submission
// time, long after whoever configured the instance had stopped looking. The
// config is now checked once at boot instead.

const { escapeHtml } = require('./escape');

const SEND_TIMEOUT_MS = 15000;

function env(name) {
  const value = process.env[name];
  // Compose passes an unset variable through as an empty string, which must
  // read as "not configured" rather than "configured to nothing".
  return value === undefined || value.trim() === '' ? null : value.trim();
}

// Resolves the envelope sender.
//
// SMTP_FROM wins. Falling back to SMTP_USER is right for essentially every
// authenticated relay, since the address you authenticate as is the address you
// are permitted to send as -- and it rescues an instance that set credentials
// but no From. There is deliberately no constant fallback: a literal default
// domain is what produced the 553 in the first place.
function resolveFrom() {
  const from = env('SMTP_FROM');
  if (from) return from;
  const user = env('SMTP_USER');
  if (user && user.includes('@')) return user;
  return null;
}

function buildConfig() {
  const host = env('SMTP_HOST');
  if (!host) return { configured: false };

  const port = Number(env('SMTP_PORT')) || 587;
  const user = env('SMTP_USER');
  const pass = env('SMTP_PASS');
  const from = resolveFrom();

  const secureVar = env('SMTP_SECURE');
  // Port 465 is implicit TLS; 587 and 25 are STARTTLS-upgraded. Inferring from
  // the port gets it right without another variable to set, and SMTP_SECURE
  // overrides for the unusual case.
  const secure = secureVar === null ? port === 465 : ['1', 'true', 'yes', 'on'].includes(secureVar.toLowerCase());

  const problems = [];
  if (!from) {
    problems.push(
      'SMTP_FROM is not set and SMTP_USER is not an email address, so there is no ' +
      'address to send from. Set SMTP_FROM to an address your relay is allowed to ' +
      'send as -- usually the same address as SMTP_USER, on your own domain.'
    );
  }
  // Authenticating needs both halves; one without the other is a typo, and
  // silently connecting anonymously would look like a relay problem later.
  if (user && !pass) problems.push('SMTP_USER is set but SMTP_PASS is not.');
  if (pass && !user) problems.push('SMTP_PASS is set but SMTP_USER is not.');

  return { configured: true, host, port, secure, user, pass, from, problems };
}

const config = buildConfig();
let transport = null;

function getTransport() {
  if (transport) return transport;
  const nodemailer = require('nodemailer');
  transport = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    // Omitted entirely when there are no credentials. Passing an auth object
    // with undefined fields makes nodemailer attempt PLAIN and fail.
    ...(config.user && config.pass ? { auth: { user: config.user, pass: config.pass } } : {}),
    connectionTimeout: SEND_TIMEOUT_MS,
    greetingTimeout: SEND_TIMEOUT_MS,
    socketTimeout: SEND_TIMEOUT_MS
  });
  return transport;
}

// Turns the common SMTP rejections into the thing to actually go and change,
// rather than leaving a bare status code in the log.
function explain(error) {
  const text = `${error?.message || ''} ${error?.response || ''}`;
  if (/\b553\b|not allowed to relay|sender.*(denied|rejected|not allowed)/i.test(text)) {
    return `The relay refused the From address (${config.from}). It must be an address ` +
      'the relay is allowed to send as -- normally one on your own domain, and usually ' +
      'the same address as SMTP_USER. Set SMTP_FROM.';
  }
  if (/\b535\b|authentication|credentials/i.test(text)) {
    return 'The relay rejected the credentials. Check SMTP_USER and SMTP_PASS -- many ' +
      'providers require an app-specific password rather than the account password.';
  }
  if (/\b550\b|\b551\b|recipient/i.test(text)) {
    return "The relay refused the recipient. Check the form's notification email address.";
  }
  if (/wrong version number|SSL|TLS/i.test(text)) {
    return `TLS negotiation failed. Port ${config.port} is being used with secure=${config.secure}; ` +
      'port 465 needs implicit TLS and 587 needs STARTTLS. Override with SMTP_SECURE if needed.';
  }
  if (/ETIMEDOUT|ECONNREFUSED|EHOSTUNREACH|ENOTFOUND|timeout/i.test(text)) {
    return `Could not reach ${config.host}:${config.port} from inside the container.`;
  }
  return null;
}

// Checked at boot so a misconfigured instance says so on startup instead of
// silently dropping the first real enquiry. Never throws -- email is not worth
// refusing to start over.
async function verify() {
  if (!config.configured) {
    console.log('[mail] SMTP_HOST is not set; submission notifications will be logged, not sent.');
    return false;
  }
  for (const problem of config.problems) console.error(`[mail] ${problem}`);
  if (config.problems.length) {
    console.error('[mail] notifications are DISABLED until the above is fixed.');
    return false;
  }
  try {
    await getTransport().verify();
    console.log(
      `[mail] ready: ${config.host}:${config.port} ` +
      `(${config.secure ? 'implicit TLS' : 'STARTTLS'}, ${config.user ? `auth as ${config.user}` : 'no auth'}) ` +
      `sending as ${config.from}`
    );
    return true;
  } catch (e) {
    console.error(`[mail] SMTP check failed: ${e.message}`);
    const hint = explain(e);
    if (hint) console.error(`[mail] ${hint}`);
    console.error('[mail] notifications will keep being attempted, but expect them to fail.');
    return false;
  }
}

function isEnabled() {
  return config.configured && config.problems.length === 0;
}

/**
 * Sends one submission notification. Never throws and never rejects: the
 * visitor's HTTP response must not wait on, or be failed by, a mail server.
 */
async function sendSubmissionNotification(form, data) {
  if (!isEnabled()) return false;
  try {
    // Keys and values come from an unauthenticated stranger; escape both
    // before they land in an HTML email.
    const fields = Object.entries(data)
      .map(([k, v]) => `<b>${escapeHtml(k)}:</b> ${escapeHtml(v)}`)
      .join('<br>');
    await getTransport().sendMail({
      from: config.from,
      to: form.notify_email,
      subject: `New submission: ${form.name}`,
      html: `<h2>New submission on "${escapeHtml(form.name)}"</h2><p>${fields}</p><hr><small>Sent by FormBase</small>`
    });
    return true;
  } catch (e) {
    console.error(`[mail] form=${form.id} notification to ${form.notify_email} failed: ${e.message}`);
    const hint = explain(e);
    if (hint) console.error(`[mail] ${hint}`);
    return false;
  }
}

module.exports = { verify, isEnabled, sendSubmissionNotification, config };
