// Resolves the JWT signing secret.
//
// The original code fell back to a literal published in the repository, so any
// instance that did not set JWT_SECRET could have its tokens forged by anyone
// who had read the source. There is no fallback constant here by design.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Shipped in the upstream source; refuse it outright so an inherited .env that
// still carries it fails loudly instead of staying quietly vulnerable.
const KNOWN_BAD = new Set([
  'formbase-dev-secret-change-in-production',
  'change-me',
  'secret'
]);

const MIN_LENGTH = 32;

function resolveSecret(dataDir) {
  const fromEnv = process.env.JWT_SECRET;

  if (fromEnv) {
    if (KNOWN_BAD.has(fromEnv)) {
      throw new Error(
        'JWT_SECRET is set to a well-known default value that is published in the ' +
        'FormBase source. Tokens signed with it can be forged by anyone. Set a ' +
        'unique random value, e.g. `openssl rand -hex 32`.'
      );
    }
    if (fromEnv.length < MIN_LENGTH) {
      throw new Error(`JWT_SECRET must be at least ${MIN_LENGTH} characters (got ${fromEnv.length}).`);
    }
    return fromEnv;
  }

  // No env var: keep a persistent random secret alongside the database so
  // tokens survive restarts without anyone having to configure anything.
  fs.mkdirSync(dataDir, { recursive: true });
  const secretPath = path.join(dataDir, '.jwt-secret');
  try {
    const existing = fs.readFileSync(secretPath, 'utf8').trim();
    if (existing.length >= MIN_LENGTH) return existing;
  } catch { /* not created yet */ }

  const generated = crypto.randomBytes(48).toString('hex');
  fs.writeFileSync(secretPath, generated, { mode: 0o600 });
  console.warn(
    `[formbase] JWT_SECRET was not set; generated a random one at ${secretPath}. ` +
    'Set JWT_SECRET explicitly if you run more than one instance, otherwise each ' +
    'will issue tokens the others reject.'
  );
  return generated;
}

module.exports = { resolveSecret, KNOWN_BAD, MIN_LENGTH };
