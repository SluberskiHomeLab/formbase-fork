/**
 * Registration control and user management suite.
 *
 * Unlike test/security.js this one needs instances in specific states, so it
 * starts its own servers on throwaway data directories rather than probing a
 * running one:
 *
 *   node test/users.js
 *
 * Exits non-zero if any test fails.
 */
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SERVER = path.join(ROOT, 'src', 'server.js');

const results = [];
function record(id, title, ok, detail = '') {
  results.push({ id, title, ok, detail });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${id}  ${title}${detail ? `\n          ${detail}` : ''}`);
}

// --- Harness -----------------------------------------------------------------

let nextPort = 3210;
const running = [];

// Each instance gets its own DATA_DIR so "first user becomes admin" can be
// tested repeatedly -- it only ever fires on an empty database.
function startServer(env = {}) {
  const port = nextPort++;
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'formbase-test-'));
  const child = spawn(process.execPath, [SERVER], {
    env: { ...process.env, ...env, PORT: String(port), DATA_DIR: dataDir },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  const logs = [];
  child.stdout.on('data', d => logs.push(String(d)));
  child.stderr.on('data', d => logs.push(String(d)));

  const base = `http://127.0.0.1:${port}`;
  const instance = { child, base, dataDir, logs, port };
  running.push(instance);

  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 20000;
    (async function poll() {
      if (child.exitCode !== null) {
        return reject(new Error(`server exited (${child.exitCode}):\n${logs.join('')}`));
      }
      try {
        const r = await fetch(`${base}/api/health`);
        if (r.ok) return resolve(instance);
      } catch { /* not up yet */ }
      if (Date.now() > deadline) return reject(new Error(`server never came up:\n${logs.join('')}`));
      setTimeout(poll, 150);
    })();
  });
}

function stopAll() {
  for (const i of running) {
    try { i.child.kill(); } catch { /* already gone */ }
    try { fs.rmSync(i.dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
}

function client(base) {
  return async function req(method, pathname, body, token) {
    const res = await fetch(base + pathname, {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {})
      },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    let data;
    try { data = await res.json(); } catch { data = {}; }
    return { status: res.status, body: data };
  };
}

// --- R1: registration switch -------------------------------------------------

async function r1_registrationDisabled() {
  const open = await startServer();
  const oq = client(open.base);
  const first = await oq('POST', '/api/auth/register', { email: 'a@example.com', password: 'secret123' });
  record('R1a', 'registration works when the switch is off', first.status === 201, `HTTP ${first.status}`);

  const closed = await startServer({ DISABLE_REGISTRATION: '1' });
  const cq = client(closed.base);

  const blocked = await cq('POST', '/api/auth/register', { email: 'b@example.com', password: 'secret123' });
  record('R1b', 'registration is refused when the switch is on',
    blocked.status === 403, `HTTP ${blocked.status} ${blocked.body.error || ''}`);

  // The block must not be an "only when users already exist" rule -- this
  // instance's database is empty and it must still refuse.
  record('R1c', 'refused even on a completely empty instance',
    blocked.status === 403 && (await cq('GET', '/api/admin/users')).status === 401,
    'no account was created by the blocked attempt');

  const config = await cq('GET', '/api/auth/config');
  record('R1d', '/api/auth/config advertises the switch to the dashboard',
    config.status === 200 && config.body.registration_enabled === false,
    JSON.stringify(config.body));

  const openConfig = await oq('GET', '/api/auth/config');
  record('R1e', '...and reports open when it is off',
    openConfig.body.registration_enabled === true, JSON.stringify(openConfig.body));

  // Truthy spellings a person might reasonably put in a .env.
  for (const value of ['true', 'yes', 'on']) {
    const s = await startServer({ DISABLE_REGISTRATION: value });
    const r = await client(s.base)('POST', '/api/auth/register', { email: 'c@example.com', password: 'secret123' });
    record(`R1f:${value}`, `DISABLE_REGISTRATION=${value} also closes it`, r.status === 403, `HTTP ${r.status}`);
  }

  // An unset variable arrives from docker-compose as an empty string and must
  // read as "not configured", not as "set to something".
  const empty = await startServer({ DISABLE_REGISTRATION: '' });
  const er = await client(empty.base)('POST', '/api/auth/register', { email: 'd@example.com', password: 'secret123' });
  record('R1g', 'an empty DISABLE_REGISTRATION leaves registration open', er.status === 201, `HTTP ${er.status}`);

  // Accounts that already exist keep working after the switch goes on.
  const closedWithUser = await startServer({ DISABLE_REGISTRATION: '1', ADMIN_EMAIL: 'boss@example.com', ADMIN_PASSWORD: 'bootstrap123' });
  const cwq = client(closedWithUser.base);
  const login = await cwq('POST', '/api/auth/login', { email: 'boss@example.com', password: 'bootstrap123' });
  record('R1h', 'existing accounts can still log in with registration closed',
    login.status === 200, `HTTP ${login.status}`);

  return { closedWithUser, token: login.body.token, user: login.body.user };
}

// --- R2: first user is admin -------------------------------------------------

async function r2_firstUserIsAdmin() {
  const s = await startServer();
  const q = client(s.base);

  const first = await q('POST', '/api/auth/register', { email: 'one@example.com', password: 'secret123' });
  record('R2a', 'the first registered account is an admin',
    first.body.user?.role === 'admin', `role=${first.body.user?.role}`);

  const second = await q('POST', '/api/auth/register', { email: 'two@example.com', password: 'secret123' });
  record('R2b', 'the second is a plain user',
    second.body.user?.role === 'user', `role=${second.body.user?.role}`);

  const third = await q('POST', '/api/auth/register', { email: 'three@example.com', password: 'secret123' });
  record('R2c', 'and so is every one after that',
    third.body.user?.role === 'user', `role=${third.body.user?.role}`);

  const admins = await q('GET', '/api/admin/users', undefined, first.body.token);
  record('R2d', 'a non-admin cannot reach the admin API',
    (await q('GET', '/api/admin/users', undefined, second.body.token)).status === 403,
    'plain user got 403');
  record('R2e', 'the admin can',
    admins.status === 200 && admins.body.users.length === 3, `HTTP ${admins.status}`);

  return { s, q, admin: first.body, plain: second.body, spare: third.body };
}

// --- R3: env-seeded bootstrap admin ------------------------------------------

async function r3_seededAdmin() {
  const s = await startServer({
    DISABLE_REGISTRATION: '1',
    ADMIN_EMAIL: 'seed@example.com',
    ADMIN_PASSWORD: 'bootstrap123'
  });
  const q = client(s.base);
  const login = await q('POST', '/api/auth/login', { email: 'seed@example.com', password: 'bootstrap123' });
  record('R3a', 'ADMIN_EMAIL/ADMIN_PASSWORD seed an admin on an empty instance',
    login.status === 200 && login.body.user?.role === 'admin',
    `HTTP ${login.status} role=${login.body.user?.role}`);

  // Reusing the same data directory with DIFFERENT credentials must not create
  // a second account or change the first -- otherwise anyone who can set env
  // vars could mint themselves an admin on a live instance.
  s.child.kill();
  await new Promise(r => s.child.on('exit', r));
  const restarted = spawn(process.execPath, [SERVER], {
    env: {
      ...process.env, PORT: String(s.port), DATA_DIR: s.dataDir,
      DISABLE_REGISTRATION: '1', ADMIN_EMAIL: 'intruder@example.com', ADMIN_PASSWORD: 'bootstrap123'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  running.push({ child: restarted, dataDir: s.dataDir });
  await new Promise(resolve => {
    const deadline = Date.now() + 20000;
    (async function poll() {
      try { if ((await fetch(`${s.base}/api/health`)).ok) return resolve(); } catch { /* not up */ }
      if (Date.now() > deadline) return resolve();
      setTimeout(poll, 150);
    })();
  });

  const intruder = await q('POST', '/api/auth/login', { email: 'intruder@example.com', password: 'bootstrap123' });
  record('R3b', 'seeding is ignored once the instance has any user',
    intruder.status === 401, `HTTP ${intruder.status}`);

  const stillWorks = await q('POST', '/api/auth/login', { email: 'seed@example.com', password: 'bootstrap123' });
  record('R3c', 'the original seeded admin is untouched by the restart',
    stillWorks.status === 200, `HTTP ${stillWorks.status}`);
}

// --- R4: admin user management ----------------------------------------------

async function r4_userManagement(ctx) {
  const { q, admin, plain } = ctx;
  const T = admin.token;

  const created = await q('POST', '/api/admin/users',
    { email: 'made@example.com', password: 'secret123', plan: 'pro' }, T);
  record('R4a', 'an admin can create an account',
    created.status === 201 && created.body.email === 'made@example.com', `HTTP ${created.status}`);
  record('R4b', 'an admin-created account defaults to the user role',
    created.body.role === 'user' && created.body.plan === 'pro',
    `role=${created.body.role} plan=${created.body.plan}`);

  const madeLogin = await q('POST', '/api/auth/login', { email: 'made@example.com', password: 'secret123' });
  record('R4c', 'the created account can log in',
    madeLogin.status === 200, `HTTP ${madeLogin.status}`);

  const dupe = await q('POST', '/api/admin/users', { email: 'MADE@example.com', password: 'secret123' }, T);
  record('R4d', 'duplicate email is refused regardless of casing',
    dupe.status === 409, `HTTP ${dupe.status}`);

  const weak = await q('POST', '/api/admin/users', { email: 'x@example.com', password: 'abc' }, T);
  record('R4e', 'admin-created accounts are held to the same password rules',
    weak.status === 400, `HTTP ${weak.status} ${weak.body.error || ''}`);

  const badRole = await q('POST', '/api/admin/users', { email: 'y@example.com', password: 'secret123', role: 'superuser' }, T);
  record('R4f', 'an unknown role is rejected', badRole.status === 400, `HTTP ${badRole.status}`);

  const promoted = await q('PATCH', `/api/admin/users/${plain.user.id}`, { role: 'admin' }, T);
  record('R4g', 'an admin can promote someone',
    promoted.status === 200 && promoted.body.role === 'admin', `role=${promoted.body.role}`);
  const promotedList = await q('GET', '/api/admin/users', undefined, plain.token);
  record('R4h', 'the promotion takes effect on their EXISTING token',
    promotedList.status === 200, `HTTP ${promotedList.status}`);

  const demoted = await q('PATCH', `/api/admin/users/${plain.user.id}`, { role: 'user' }, T);
  record('R4i', 'and can demote them again',
    demoted.body.role === 'user', `role=${demoted.body.role}`);
  record('R4j', 'the demotion also takes effect on the existing token',
    (await q('GET', '/api/admin/users', undefined, plain.token)).status === 403,
    'demoted user got 403');

  const repwd = await q('PATCH', `/api/admin/users/${plain.user.id}`, { password: 'resetpass99' }, T);
  record('R4k', 'an admin can reset a password', repwd.status === 200, `HTTP ${repwd.status}`);
  record('R4l', 'the new password works and the old one does not',
    (await q('POST', '/api/auth/login', { email: plain.user.email, password: 'resetpass99' })).status === 200 &&
    (await q('POST', '/api/auth/login', { email: plain.user.email, password: 'secret123' })).status === 401);

  const key = await q('POST', `/api/admin/users/${plain.user.id}/regenerate-key`, undefined, T);
  record('R4m', "an admin can regenerate a user's API key",
    key.status === 200 && /^fb_[0-9a-f]{48}$/.test(key.body.api_key || ''), `HTTP ${key.status}`);

  const missing = await q('PATCH', '/api/admin/users/no-such-id', { plan: 'pro' }, T);
  record('R4n', 'an unknown user id is a 404', missing.status === 404, `HTTP ${missing.status}`);
}

// --- R5: deactivation --------------------------------------------------------

async function r5_deactivation(ctx) {
  const { q, admin, spare } = ctx;
  const T = admin.token;

  const off = await q('PATCH', `/api/admin/users/${spare.user.id}`, { is_active: false }, T);
  record('R5a', 'an admin can disable an account',
    off.status === 200 && off.body.is_active === 0, `is_active=${off.body.is_active}`);

  record('R5b', "a disabled account's existing token stops working",
    (await q('GET', '/api/auth/me', undefined, spare.token)).status === 403, 'got 403');

  const login = await q('POST', '/api/auth/login', { email: spare.user.email, password: 'secret123' });
  record('R5c', 'a disabled account cannot log in even with the right password',
    login.status === 403, `HTTP ${login.status}`);

  // The API key is a second credential and must be cut off too.
  const viaKey = await fetch(`${ctx.s.base}/api/forms`, { headers: { 'X-API-Key': spare.user.api_key } });
  record('R5d', "a disabled account's API key stops working too",
    viaKey.status === 403, `HTTP ${viaKey.status}`);

  const on = await q('PATCH', `/api/admin/users/${spare.user.id}`, { is_active: true }, T);
  record('R5e', 're-enabling restores access',
    on.body.is_active === 1 &&
    (await q('POST', '/api/auth/login', { email: spare.user.email, password: 'secret123' })).status === 200);
}

// --- R6: lockout guardrails --------------------------------------------------

async function r6_guardrails(ctx) {
  const { q, admin, plain } = ctx;
  const T = admin.token;
  const me = admin.user.id;

  record('R6a', 'an admin cannot demote themselves',
    (await q('PATCH', `/api/admin/users/${me}`, { role: 'user' }, T)).status === 400);
  record('R6b', 'an admin cannot deactivate themselves',
    (await q('PATCH', `/api/admin/users/${me}`, { is_active: false }, T)).status === 400);
  record('R6c', 'an admin cannot delete themselves',
    (await q('DELETE', `/api/admin/users/${me}`, undefined, T)).status === 400);

  // Every route needs an active admin, so acting on someone else always leaves
  // the actor behind -- the instance can never end up with zero admins.
  const list = await q('GET', '/api/admin/users', undefined, T);
  record('R6d', 'at least one active admin always remains',
    list.body.users.some(u => u.role === 'admin' && u.is_active),
    `${list.body.users.filter(u => u.role === 'admin' && u.is_active).length} active admin(s)`);

  // Deleting cascades. Give the user a form first so there is something to lose.
  const plainLogin = await q('POST', '/api/auth/login', { email: plain.user.email, password: 'resetpass99' });
  await q('POST', '/api/forms', { name: 'doomed' }, plainLogin.body.token);
  const del = await q('DELETE', `/api/admin/users/${plain.user.id}`, undefined, T);
  record('R6e', 'deleting a user reports what it cascaded to',
    del.status === 200 && del.body.forms_removed === 1, JSON.stringify(del.body));
  record('R6f', 'the deleted account can no longer log in',
    (await q('POST', '/api/auth/login', { email: plain.user.email, password: 'resetpass99' })).status === 401);
  record('R6g', "the deleted account's token is dead",
    (await q('GET', '/api/auth/me', undefined, plainLogin.body.token)).status === 401);
}

// --- R7: admin API is not reachable by API key -------------------------------

async function r7_apiKeyScope(ctx) {
  const viaKey = await fetch(`${ctx.s.base}/api/admin/users`, {
    headers: { 'X-API-Key': ctx.admin.user.api_key }
  });
  record('R7a', "an admin's API key cannot manage users (JWT only)",
    viaKey.status === 401, `HTTP ${viaKey.status}`);
}

// --- R8: self-service password change ----------------------------------------

async function r8_selfPassword(ctx) {
  const { q, admin } = ctx;
  const wrong = await q('POST', '/api/auth/me/password',
    { current_password: 'not-it', new_password: 'brandnew123' }, admin.token);
  record('R8a', 'changing your password requires the current one',
    wrong.status === 401, `HTTP ${wrong.status}`);

  const ok = await q('POST', '/api/auth/me/password',
    { current_password: 'secret123', new_password: 'brandnew123' }, admin.token);
  record('R8b', 'a correct current password lets it through', ok.status === 200, `HTTP ${ok.status}`);
  record('R8c', 'the new password works and the old one does not',
    (await q('POST', '/api/auth/login', { email: admin.user.email, password: 'brandnew123' })).status === 200 &&
    (await q('POST', '/api/auth/login', { email: admin.user.email, password: 'secret123' })).status === 401);

  const short = await q('POST', '/api/auth/me/password',
    { current_password: 'brandnew123', new_password: 'abc' }, admin.token);
  record('R8d', 'the new password is held to the length rules', short.status === 400, `HTTP ${short.status}`);
}

// --- R9: migration of a pre-roles database -----------------------------------

async function r9_migration() {
  // Build a database in the OLD shape -- no role, no is_active -- and confirm
  // an upgraded server both migrates it and finds an admin in it.
  const Database = require('better-sqlite3');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'formbase-legacy-'));
  const legacy = new Database(path.join(dir, 'formbase.db'));
  legacy.exec(`
    CREATE TABLE users (
      id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
      plan TEXT DEFAULT 'free', created_at TEXT DEFAULT (datetime('now')), api_key TEXT UNIQUE
    );
  `);
  const hash = require('bcryptjs').hashSync('secret123', 10);
  legacy.prepare('INSERT INTO users (id, email, password_hash, api_key, created_at) VALUES (?,?,?,?,?)')
    .run('old-1', 'oldest@example.com', hash, 'fb_legacy_one', '2020-01-01 00:00:00');
  legacy.prepare('INSERT INTO users (id, email, password_hash, api_key, created_at) VALUES (?,?,?,?,?)')
    .run('old-2', 'newer@example.com', hash, 'fb_legacy_two', '2021-01-01 00:00:00');
  legacy.close();

  const port = nextPort++;
  const child = spawn(process.execPath, [SERVER], {
    env: { ...process.env, PORT: String(port), DATA_DIR: dir, DISABLE_REGISTRATION: '1' },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  running.push({ child, dataDir: dir });
  const base = `http://127.0.0.1:${port}`;
  await new Promise((resolve, reject) => {
    const deadline = Date.now() + 20000;
    (async function poll() {
      try { if ((await fetch(`${base}/api/health`)).ok) return resolve(); } catch { /* not up */ }
      if (Date.now() > deadline) return reject(new Error('legacy server never came up'));
      setTimeout(poll, 150);
    })();
  });

  const q = client(base);
  const oldest = await q('POST', '/api/auth/login', { email: 'oldest@example.com', password: 'secret123' });
  record('R9a', 'a pre-roles database still logs in after migration',
    oldest.status === 200, `HTTP ${oldest.status}`);
  record('R9b', 'the oldest existing account is promoted to admin',
    oldest.body.user?.role === 'admin', `role=${oldest.body.user?.role}`);

  const newer = await q('POST', '/api/auth/login', { email: 'newer@example.com', password: 'secret123' });
  record('R9c', 'later accounts stay plain users',
    newer.body.user?.role === 'user', `role=${newer.body.user?.role}`);
  record('R9d', 'migrated accounts default to active',
    newer.body.user?.is_active === true, `is_active=${newer.body.user?.is_active}`);
}

// -----------------------------------------------------------------------------
(async () => {
  console.log('\nRegistration control & user management suite\n');
  try {
    console.log('R1  registration switch');
    await r1_registrationDisabled();

    console.log('\nR2  first user is admin');
    const ctx = await r2_firstUserIsAdmin();

    console.log('\nR3  seeded bootstrap admin');
    await r3_seededAdmin();

    console.log('\nR4  admin user management');
    await r4_userManagement(ctx);

    console.log('\nR5  deactivation');
    await r5_deactivation(ctx);

    console.log('\nR6  lockout guardrails');
    await r6_guardrails(ctx);

    console.log('\nR7  API key scope');
    await r7_apiKeyScope(ctx);

    console.log('\nR8  self-service password change');
    await r8_selfPassword(ctx);

    console.log('\nR9  pre-roles database migration');
    await r9_migration();
  } catch (e) {
    record('SUITE', `threw: ${e.message}`, false, e.stack?.split('\n').slice(1, 3).join('\n'));
  } finally {
    stopAll();
  }

  const passed = results.filter(r => r.ok).length;
  const failed = results.filter(r => !r.ok);
  console.log(`\n${'='.repeat(70)}`);
  console.log(`${passed} passed, ${failed.length} failed, ${results.length} total`);
  if (failed.length) {
    console.log('\nFailing:');
    for (const f of failed) console.log(`  ${f.id}  ${f.title}${f.detail ? ` -- ${f.detail}` : ''}`);
  }
  process.exit(failed.length === 0 ? 0 : 1);
})();
