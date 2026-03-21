const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET || 'formbase-dev-secret-change-in-production';

function generateToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '30d' });
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

function apiKeyMiddleware(req, res, next) {
  const db = require('./db');
  const key = req.headers['x-api-key'];
  if (!key) return res.status(401).json({ error: 'API key required' });
  const user = db.prepare('SELECT id, email, plan FROM users WHERE api_key = ?').get(key);
  if (!user) return res.status(401).json({ error: 'Invalid API key' });
  req.user = user;
  next();
}

module.exports = { generateToken, authMiddleware, apiKeyMiddleware, SECRET };
