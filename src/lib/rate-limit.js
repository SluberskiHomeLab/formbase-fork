// Rate limiting. `rate-limiter-flexible` was already a declared dependency of
// this project but was never imported anywhere -- brute-forcing a password was
// unthrottled. These limiters wire it up.

const { RateLimiterMemory } = require('rate-limiter-flexible');

// Budgets are env-tunable so an instance behind an office NAT (where many
// users share one source IP) can be loosened without editing code.
const num = (name, fallback) => Number(process.env[name]) || fallback;

const limiters = {
  // Failed-credential attempts, keyed by client IP.
  authIp: new RateLimiterMemory({
    points: num('RATE_LIMIT_AUTH_IP', 10), duration: 900, blockDuration: 900
  }),
  // ...and by account, so a distributed attack on one inbox is still capped.
  authAccount: new RateLimiterMemory({
    points: num('RATE_LIMIT_AUTH_ACCOUNT', 5), duration: 900, blockDuration: 900
  }),
  // Public submission endpoint, per IP per form.
  submit: new RateLimiterMemory({
    points: num('RATE_LIMIT_SUBMIT', 30), duration: 60, blockDuration: 60
  }),
  // Everything else under /api.
  api: new RateLimiterMemory({ points: num('RATE_LIMIT_API', 300), duration: 60 })
};

function clientKey(req) {
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

function reject(res, rejection) {
  const seconds = Math.max(1, Math.ceil((rejection?.msBeforeNext || 1000) / 1000));
  res.set('Retry-After', String(seconds));
  return res.status(429).json({ error: 'Too many requests, please try again later' });
}

// Generic per-IP limiter for a whole router.
function limit(name) {
  return async (req, res, next) => {
    try {
      await limiters[name].consume(clientKey(req));
      next();
    } catch (rejection) {
      if (rejection instanceof Error) return next(rejection);
      reject(res, rejection);
    }
  };
}

// Submissions are keyed per form as well as per IP so one busy form cannot
// exhaust another form's budget.
function limitSubmit() {
  return async (req, res, next) => {
    try {
      await limiters.submit.consume(`${clientKey(req)}:${req.params.formId}`);
      next();
    } catch (rejection) {
      if (rejection instanceof Error) return next(rejection);
      reject(res, rejection);
    }
  };
}

// Auth endpoints consume from both buckets up front. A successful login
// refunds the account bucket via clearAuthAttempts().
function limitAuth() {
  return async (req, res, next) => {
    const account = String(req.body?.email || '').toLowerCase().slice(0, 254);
    try {
      await limiters.authIp.consume(clientKey(req));
      if (account) await limiters.authAccount.consume(account);
      next();
    } catch (rejection) {
      if (rejection instanceof Error) return next(rejection);
      reject(res, rejection);
    }
  };
}

async function clearAuthAttempts(req) {
  const account = String(req.body?.email || '').toLowerCase().slice(0, 254);
  try {
    await limiters.authIp.delete(clientKey(req));
    if (account) await limiters.authAccount.delete(account);
  } catch { /* best effort */ }
}

module.exports = { limit, limitAuth, limitSubmit, clearAuthAttempts, limiters };
