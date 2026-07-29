const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'formbase.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    plan TEXT DEFAULT 'free',
    created_at TEXT DEFAULT (datetime('now')),
    api_key TEXT UNIQUE,
    role TEXT NOT NULL DEFAULT 'user',
    is_active INTEGER NOT NULL DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS forms (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    notify_email TEXT,
    redirect_url TEXT,
    honeypot_field TEXT DEFAULT '_gotcha',
    recaptcha_secret TEXT,
    allowed_origins TEXT,
    webhook_url TEXT,
    auto_response_subject TEXT,
    auto_response_body TEXT,
    submission_count INTEGER DEFAULT 0,
    spam_count INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS submissions (
    id TEXT PRIMARY KEY,
    form_id TEXT NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
    data TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    is_spam INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_submissions_form ON submissions(form_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_forms_user ON forms(user_id);
`);

// --- Migrations --------------------------------------------------------------
// CREATE TABLE IF NOT EXISTS is a no-op on a database that already has the
// table, so columns added after the fact need an explicit ALTER. Each is
// applied only when absent, which makes running this on every boot idempotent.
function addColumn(table, column, definition) {
  const present = db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === column);
  if (!present) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}

// role: 'admin' can manage every account; 'user' can only manage its own forms.
addColumn('users', 'role', "TEXT NOT NULL DEFAULT 'user'");
// is_active: 0 blocks login and invalidates already-issued tokens, without
// destroying the account's forms and submissions the way a delete would.
addColumn('users', 'is_active', 'INTEGER NOT NULL DEFAULT 1');

module.exports = db;
