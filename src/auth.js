const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { resolveSecret } = require('./lib/secret');

const DATA_DIR = process.env.DATA_DIR || require('path').join(__dirname, '..', 'data');
const SECRET = resolveSecret(DATA_DIR);
const EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

function generateToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: EXPIRES_IN });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token provided' });
  const token = header.startsWith('Bearer ') ? header.slice(7) : header;
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Compares two API keys without leaking their contents through timing.
function safeKeyEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function apiKeyMiddleware(req, res, next) {
  const db = require('./db');
  const key = req.headers['x-api-key'];
  if (!key) return res.status(401).json({ error: 'API key required' });
  // Look the row up by key, then re-compare in constant time so the lookup
  // itself is not the only gate.
  const user = db.prepare('SELECT id, email, plan, api_key FROM users WHERE api_key = ?').get(key);
  if (!user || !safeKeyEqual(key, user.api_key)) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
  req.user = { id: user.id, email: user.email, plan: user.plan };
  next();
}

// The readme documents X-API-Key access, but apiKeyMiddleware was exported and
// never mounted, so that path did not exist. Accept either credential.
function authAnyMiddleware(req, res, next) {
  if (req.headers['x-api-key']) return apiKeyMiddleware(req, res, next);
  return authMiddleware(req, res, next);
}

module.exports = {
  generateToken, authMiddleware, apiKeyMiddleware, authAnyMiddleware, safeKeyEqual, SECRET
};
