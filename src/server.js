const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const crypto = require('crypto');

require('dotenv').config({ quiet: true });
require('./db'); // init database

const { authMiddleware } = require('./auth');
const { limit } = require('./lib/rate-limit');

const app = express();

// Rate limiting keys off req.ip. Behind a proxy that is the proxy's address
// unless this is set -- but enabling it unconditionally would let anyone spoof
// X-Forwarded-For and slip the limiter, so it stays opt-in.
if (process.env.TRUST_PROXY) {
  const value = process.env.TRUST_PROXY;
  app.set('trust proxy', /^\d+$/.test(value) ? Number(value) : value);
}

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      // The dashboard's JS lives in public/app.js precisely so this can be
      // 'self' rather than 'unsafe-inline'.
      scriptSrc: ["'self'"],
      // Inline style="..." attributes are used throughout the markup. Far
      // lower risk than inline script, so this concession stays.
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"]
    }
  },
  crossOriginResourcePolicy: { policy: 'same-site' }
}));

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// /f is a public submission endpoint that must work from any site, so it keeps
// permissive CORS -- cross-origin abuse there is governed per form by
// allowed_origins. /api is a private control plane and is same-origin only
// unless CORS_ORIGIN names something explicitly.
const apiCors = process.env.CORS_ORIGIN
  ? cors({ origin: process.env.CORS_ORIGIN.split(',').map(s => s.trim()), credentials: false })
  : (req, res, next) => next();

app.use('/f', cors(), require('./routes/submit'));
app.use('/api/auth', apiCors, require('./routes/users'));
app.use('/api/forms', apiCors, limit('api'), require('./routes/forms'));

// Health check. The public probe deliberately carries no instance statistics;
// counts moved behind auth.
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

app.get('/api/health/stats', apiCors, authMiddleware, (req, res) => {
  const db = require('./db');
  const users = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const forms = db.prepare('SELECT COUNT(*) as c FROM forms').get().c;
  const subs = db.prepare('SELECT COUNT(*) as c FROM submissions').get().c;
  res.json({ status: 'ok', users, forms, submissions: subs, uptime: process.uptime() });
});

// Dashboard SPA
app.use(express.static(path.join(__dirname, '..', 'public')));
app.get('/dashboard{/*splat}', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'index.html')));

// Unknown API routes answer in JSON rather than falling through to HTML.
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

// Central error handler. Route handlers used to return `e.message` straight to
// the caller, leaking SQLite and driver internals; detail now stays in the log
// and the client gets a reference to quote.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err?.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request body too large' });
  }
  if (err instanceof SyntaxError && 'body' in err) {
    return res.status(400).json({ error: 'Malformed request body' });
  }
  const ref = crypto.randomBytes(6).toString('hex');
  console.error(`[error] ref=${ref} ${req.method} ${req.originalUrl}`, err);
  res.status(500).json({ error: 'Internal server error', ref });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 FormBase running on http://localhost:${PORT}`));
