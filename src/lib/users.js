// User creation, roles, and the registration switch.
//
// Everything that writes a row into `users` goes through here -- public
// self-registration, admin-created accounts, and the env-seeded bootstrap
// admin -- so the "first account is an admin" rule and the credential rules
// cannot drift between those three paths.

const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('../db');

const ROLES = ['admin', 'user'];
const PLANS = ['free', 'pro', 'unlimited'];

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_EMAIL = 254;
const MIN_PASSWORD = 6;
// bcrypt only considers the first 72 bytes; accepting longer silently
// truncates, so reject instead of pretending the extra characters counted.
const MAX_PASSWORD = 72;

const BCRYPT_ROUNDS = 10;

// --- Validation --------------------------------------------------------------

function validateEmail(email) {
  if (typeof email !== 'string' || !email) return 'Email required';
  if (email.length > MAX_EMAIL) return 'Email is too long';
  if (!EMAIL_RE.test(email)) return 'Invalid email address';
  return null;
}

function validatePassword(password) {
  if (typeof password !== 'string' || !password) return 'Password required';
  if (password.length < MIN_PASSWORD) return `Password must be ${MIN_PASSWORD}+ characters`;
  if (Buffer.byteLength(password, 'utf8') > MAX_PASSWORD) {
    return `Password must be at most ${MAX_PASSWORD} bytes`;
  }
  return null;
}

function validateCredentials(email, password) {
  if (!email || !password) return 'Email and password required';
  if (typeof email !== 'string' || typeof password !== 'string') return 'Email and password required';
  return validateEmail(email) || validatePassword(password);
}

function normalizeEmail(email) {
  return String(email).trim().toLowerCase();
}

// --- Registration switch -----------------------------------------------------

// DISABLE_REGISTRATION shuts the public /api/auth/register endpoint outright.
// It is deliberately a hard block with no "unless there are no users yet"
// escape hatch: the whole point of the switch is that the endpoint cannot
// create an account while it is on. Bootstrapping a first admin on a locked
// instance is handled by seedAdminFromEnv() instead.
//
// Any of 1/true/yes/on enables it, so a truthy-looking value in a .env behaves
// the way the person who typed it expected. An unset or empty variable -- what
// docker-compose passes through for anything not in .env -- leaves it off.
function registrationDisabled() {
  const value = String(process.env.DISABLE_REGISTRATION || '').trim().toLowerCase();
  return ['1', 'true', 'yes', 'on'].includes(value);
}

// --- Queries -----------------------------------------------------------------

const PUBLIC_COLUMNS = 'id, email, plan, role, is_active, api_key, created_at';

function findByEmail(email) {
  // COLLATE NOCASE so an address cannot be re-registered under different
  // casing, and so rows written before emails were normalised still match.
  return db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE').get(normalizeEmail(email));
}

function findById(id) {
  return db.prepare(`SELECT ${PUBLIC_COLUMNS} FROM users WHERE id = ?`).get(id);
}

function countUsers() {
  return db.prepare('SELECT COUNT(*) as c FROM users').get().c;
}

function newApiKey() {
  return 'fb_' + crypto.randomBytes(24).toString('hex');
}

// --- Creation ----------------------------------------------------------------

class UserError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

/**
 * Creates a user. Throws UserError with a `status` for the caller to return.
 *
 * `role` is honoured only when the caller passes one (an admin creating an
 * account). Otherwise the first account on a fresh instance becomes the admin
 * and every later one is a plain user.
 */
async function createUser({ email, password, role, plan = 'free', is_active = true }) {
  const invalid = validateCredentials(email, password);
  if (invalid) throw new UserError(invalid, 400);
  if (role !== undefined && !ROLES.includes(role)) throw new UserError('Invalid role', 400);
  if (plan !== undefined && !PLANS.includes(plan)) throw new UserError('Invalid plan', 400);

  const normalized = normalizeEmail(email);
  const id = crypto.randomUUID();
  // Hashing is the slow part and must not happen inside the transaction, so it
  // runs first and the transaction below stays a short synchronous write.
  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const apiKey = newApiKey();

  // The uniqueness check and the insert have to be atomic, otherwise two
  // simultaneous registrations on an empty database both see zero users and
  // both claim admin. better-sqlite3 transactions are synchronous, so nothing
  // can interleave between the count and the insert.
  const insert = db.transaction(() => {
    if (db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE').get(normalized)) {
      throw new UserError('Email already registered', 409);
    }
    const effectiveRole = role !== undefined
      ? role
      : (countUsers() === 0 ? 'admin' : 'user');
    db.prepare(
      'INSERT INTO users (id, email, password_hash, api_key, role, plan, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(id, normalized, hash, apiKey, effectiveRole, plan, is_active ? 1 : 0);
    return effectiveRole;
  });

  insert();
  return findById(id);
}

async function setPassword(id, password) {
  const invalid = validatePassword(password);
  if (invalid) throw new UserError(invalid, 400);
  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, id);
}

// --- Bootstrap ---------------------------------------------------------------

// An instance upgraded from a version without roles has users but no admin.
// Promote the oldest account -- the one that would have been the admin had the
// rule existed when it registered.
function ensureAdminExists() {
  const admins = db.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'admin'").get().c;
  if (admins > 0 || countUsers() === 0) return null;
  const oldest = db.prepare('SELECT id, email FROM users ORDER BY created_at ASC, rowid ASC LIMIT 1').get();
  db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(oldest.id);
  console.warn(`[formbase] no admin account existed; promoted the oldest account (${oldest.email}) to admin.`);
  return oldest;
}

// Seeds an admin from ADMIN_EMAIL / ADMIN_PASSWORD.
//
// This exists because DISABLE_REGISTRATION on a brand-new instance would
// otherwise be unopenable: registration is blocked, and creating accounts
// requires an admin that does not exist yet. It runs ONLY when the users table
// is empty, so it can never overwrite or resurrect an account on an instance
// that is already in use.
async function seedAdminFromEnv() {
  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;
  if (!email && !password) return null;
  if (!email || !password) {
    console.warn('[formbase] ADMIN_EMAIL and ADMIN_PASSWORD must both be set to seed an admin; skipping.');
    return null;
  }
  if (countUsers() > 0) return null;

  try {
    const user = await createUser({ email, password, role: 'admin' });
    console.warn(
      `[formbase] seeded admin account ${user.email} from ADMIN_EMAIL/ADMIN_PASSWORD. ` +
      'Change the password after first login and remove ADMIN_PASSWORD from the environment.'
    );
    return user;
  } catch (e) {
    console.error(`[formbase] could not seed admin account: ${e.message}`);
    return null;
  }
}

// Called once at boot. Warns rather than throws when a locked instance has no
// way in, so an operator who set DISABLE_REGISTRATION before creating an
// account sees why the login page will not let them in.
async function initUsers() {
  ensureAdminExists();
  await seedAdminFromEnv();
  if (registrationDisabled() && countUsers() === 0) {
    console.warn(
      '[formbase] DISABLE_REGISTRATION is on and there are no accounts yet, so nobody ' +
      'can sign in. Set ADMIN_EMAIL and ADMIN_PASSWORD to seed the first admin, or start ' +
      'once with registration enabled and create it yourself.'
    );
  }
}

module.exports = {
  ROLES, PLANS, MIN_PASSWORD, MAX_PASSWORD, MAX_EMAIL, PUBLIC_COLUMNS,
  UserError,
  validateEmail, validatePassword, validateCredentials, normalizeEmail,
  registrationDisabled,
  findByEmail, findById, countUsers, newApiKey,
  createUser, setPassword,
  ensureAdminExists, seedAdminFromEnv, initUsers
};
