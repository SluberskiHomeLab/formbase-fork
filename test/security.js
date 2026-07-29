/**
 * Security regression suite.
 *
 * One test per finding from the security review. Each asserts that a
 * previously-exploitable behaviour is gone. Run against a live instance:
 *
 *   node test/security.js http://localhost:3030
 *
 * Exits non-zero if any test fails.
 */
const http = require('http');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');

// BASE runs with loosened auth budgets so the suite itself is not throttled
// while probing everything else. STRICT runs the shipped default limits, and
// is what the S3 rate-limiting tests are pointed at.
const BASE = process.argv[2] || 'http://localhost:3030';
const STRICT = process.argv[3] || BASE;
const ROOT = path.join(__dirname, '..');
const OLD_DEFAULT_SECRET = 'formbase-dev-secret-change-in-production';

const results = [];
function record(id, title, ok, detail = '') {
  results.push({ id, title, ok, detail });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${id}  ${title}${detail ? `\n          ${detail}` : ''}`);
}

let TOKEN, USER, AUTH;

async function registerUser(tag) {
  const email = `${tag}${Date.now()}${Math.floor(Math.random() * 1e6)}@example.com`;
  const r = await fetch(`${BASE}/api/auth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: 'secret123' })
  });
  return { status: r.status, body: await r.json(), email };
}

// The free plan caps forms at 3, so each suite gets its own account rather
// than exhausting a shared one and failing for the wrong reason.
async function ctx(tag) {
  const reg = await registerUser(tag);
  if (reg.status !== 201) throw new Error(`register failed: ${reg.status} ${JSON.stringify(reg.body)}`);
  return {
    user: reg.body.user,
    token: reg.body.token,
    auth: { Authorization: `Bearer ${reg.body.token}`, 'Content-Type': 'application/json' }
  };
}

async function makeForm(fields, auth = AUTH) {
  const r = await fetch(`${BASE}/api/forms`, {
    method: 'POST', headers: auth, body: JSON.stringify(fields)
  });
  const text = await r.text();
  let body; try { body = JSON.parse(text); } catch { body = { raw: text.slice(0, 120) }; }
  return { status: r.status, body };
}

async function jsonOf(res) {
  const text = await res.text();
  try { return JSON.parse(text); } catch { return { raw: text.slice(0, 160) }; }
}

// ---------------------------------------------------------------- S1
async function s1_jwtSecret() {
  const forged = jwt.sign({ id: USER.id, email: USER.email }, OLD_DEFAULT_SECRET, { expiresIn: '30d' });
  const r = await fetch(`${BASE}/api/auth/me`, { headers: { Authorization: `Bearer ${forged}` } });
  record('S1', 'forged token using old default secret is rejected',
    r.status === 401, `got HTTP ${r.status}`);

  const r2 = await fetch(`${BASE}/api/auth/me`, { headers: { Authorization: `Bearer ${TOKEN}` } });
  record('S1b', 'legitimately issued token still works', r2.status === 200, `got HTTP ${r2.status}`);
}

// ---------------------------------------------------------------- S2
async function s2_ssrf() {
  const hits = [];
  const listener = http.createServer((req, res) => { hits.push(req.url); res.end('ok'); });
  await new Promise(res => listener.listen(3121, '127.0.0.1', res));

  const a = await ctx('ssrfa');
  const created = await makeForm({ name: 'SSRF', webhook_url: 'http://127.0.0.1:3121/internal' }, a.auth);
  record('S2a', 'loopback webhook_url rejected on create',
    created.status === 400, `got HTTP ${created.status} ${JSON.stringify(created.body).slice(0, 100)}`);

  const meta = await makeForm({ name: 'SSRF2', webhook_url: 'http://169.254.169.254/latest/meta-data/' }, a.auth);
  record('S2b', 'link-local (cloud metadata) webhook_url rejected',
    meta.status === 400, `got HTTP ${meta.status}`);

  const scheme = await makeForm({ name: 'SSRF3', webhook_url: 'file:///etc/passwd' }, a.auth);
  record('S2c', 'non-http webhook scheme rejected', scheme.status === 400, `got HTTP ${scheme.status}`);

  // Defence in depth: even if a private URL reaches the table by some other
  // path, the fetch-time guard must refuse it. Write one straight into the DB.
  const b = await ctx('ssrfb');
  const ok = await makeForm({ name: 'SSRFok' }, b.auth);
  let injected = false;
  const dataDir = process.env.FORMBASE_DATA_DIR;
  if (ok.status === 201 && dataDir) {
    try {
      const Database = require('better-sqlite3');
      const db = new Database(path.join(dataDir, 'formbase.db'));
      db.prepare('UPDATE forms SET webhook_url = ? WHERE id = ?')
        .run('http://127.0.0.1:3121/internal-injected', ok.body.id);
      db.close();
      injected = true;
    } catch (e) { /* reported below */ }
  }
  if (ok.status === 201) {
    await fetch(`${BASE}/f/${ok.body.id}`, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ a: '1' })
    });
  }
  await new Promise(r => setTimeout(r, 1200));
  // Only meaningful when the DB is reachable from the test process (host runs).
  // Against a container the listener is unreachable anyway, so it is skipped.
  record('S2d', 'private webhook already in the DB is still not fetched',
    !injected || hits.length === 0,
    injected ? `observed ${hits.length} hit(s): ${hits.join(',')}`
             : 'SKIPPED - set FORMBASE_DATA_DIR to a locally-readable data dir');
  listener.close();
}

// ---------------------------------------------------------------- S4
async function s4_origin() {
  const c = await ctx('origin');
  const f = await makeForm({ name: 'OriginTest', allowed_origins: 'trusted.com' }, c.auth);
  const bypass = await fetch(`${BASE}/f/${f.body.id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: 'https://trusted.com.evil.example' },
    body: new URLSearchParams({ a: '1' })
  });
  record('S4a', 'substring-matching origin is blocked',
    bypass.status === 403, `got HTTP ${bypass.status}`);

  const legit = await fetch(`${BASE}/f/${f.body.id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: 'https://trusted.com' },
    body: new URLSearchParams({ a: '1' })
  });
  record('S4b', 'exact-host origin still allowed', legit.status === 200, `got HTTP ${legit.status}`);
}

// ---------------------------------------------------------------- S5 / S6
async function s5s6_csv() {
  const c = await ctx('csv');
  const f = await makeForm({ name: 'evil"; drop=1; x="' }, c.auth);
  record('S6a', 'form name with quotes accepted (sanitised at output, not input)',
    f.status === 201, `got HTTP ${f.status}`);

  await fetch(`${BASE}/f/${f.body.id}`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ payload: '=cmd|\' /C calc\'!A0', minus: '-2+3', at: '@SUM(1)' })
  });

  const r = await fetch(`${BASE}/api/forms/${f.body.id}/export`, { headers: c.auth });
  const csv = await r.text();
  const cd = r.headers.get('content-disposition') || '';

  record('S5', 'CSV formula payloads are neutralised',
    !/"[=+@]/.test(csv) && !/"-2\+3/.test(csv) && csv.includes('=cmd'),
    `cells: ${(csv.split('\n')[1] || '').slice(0, 90)}`);

  const params = cd.split(';').map(s => s.trim()).filter(Boolean);
  const injected = params.some(p => /^drop=/.test(p));
  record('S6b', 'Content-Disposition cannot be broken out of',
    !injected && cd.startsWith('attachment'), `header: ${cd.slice(0, 120)}`);
}

// ---------------------------------------------------------------- S7 / S8
async function s7s8_escaping() {
  const esc = require(path.join(ROOT, 'src', 'lib', 'escape.js'));
  record('S7', 'escapeHtml neutralises tags and quotes',
    esc.escapeHtml('<img src=x onerror="alert(1)">') === '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;',
    esc.escapeHtml('<img src=x onerror="alert(1)">'));

  // dashboard: no raw interpolation of user-controlled fields
  const appJs = fs.readFileSync(path.join(ROOT, 'public', 'app.js'), 'utf8');
  const rawSinks = ['${f.notify_email', '${f.redirect_url', '${f.webhook_url',
    '${f.allowed_origins', '${f.honeypot_field', '${s.ip', '${state.user?.email',
    '${state.user.email'];
  const found = rawSinks.filter(s => appJs.includes(s));
  record('S8a', 'dashboard has no unescaped user-controlled interpolations',
    found.length === 0, found.length ? `unescaped: ${found.join(', ')}` : '');

  // Property assignment (el.onclick = fn) is CSP-safe; what must not appear is
  // an inline handler *attribute* baked into the rendered markup.
  record('S8b', 'dashboard emits no inline event handler attributes',
    !/\son\w+\s*=\s*["']/.test(appJs), 'inline on*="..." attribute found in app.js');

  // spoofed XFF must not be stored as the submission IP
  const c = await ctx('xff');
  const f = await makeForm({ name: 'XFFTest' }, c.auth);
  await fetch(`${BASE}/f/${f.body.id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Forwarded-For': '<img src=x onerror=alert(1)>' },
    body: new URLSearchParams({ a: '1' })
  });
  const subs = await jsonOf(await fetch(`${BASE}/api/forms/${f.body.id}/submissions`, { headers: c.auth }));
  const ip = subs.submissions?.[0]?.ip || '';
  record('S8c', 'spoofed X-Forwarded-For is not stored verbatim',
    !ip.includes('<img'), `stored ip: ${JSON.stringify(ip)}`);
}

// ---------------------------------------------------------------- S9
async function s9_csp() {
  const r = await fetch(`${BASE}/dashboard`);
  const csp = r.headers.get('content-security-policy') || '';
  record('S9a', 'CSP header is present', csp.length > 0, `header: ${csp.slice(0, 120)}`);
  record('S9b', "script-src is 'self' without 'unsafe-inline'",
    /script-src[^;]*'self'/.test(csp) && !/script-src[^;]*'unsafe-inline'/.test(csp),
    `script-src directive: ${(csp.match(/script-src[^;]*/) || [''])[0]}`);
  record('S9c', "object-src 'none' and frame-ancestors 'none' set",
    /object-src[^;]*'none'/.test(csp) && /frame-ancestors[^;]*'none'/.test(csp));

  const html = await (await fetch(`${BASE}/`)).text();
  record('S9d', 'index.html carries no inline <script> body',
    !/<script(?![^>]*\bsrc=)[^>]*>[\s\S]*?\S[\s\S]*?<\/script>/.test(html));

  // Regression: upgrade-insecure-requests breaks every non-localhost address
  // on a plain-HTTP deployment -- the browser fetches /app.js over https, gets
  // no TLS listener, and the dashboard renders blank. It must stay off unless
  // FORCE_HTTPS=1 is set.
  const forceHttps = process.env.FORCE_HTTPS === '1';
  record('S9e', forceHttps
    ? 'upgrade-insecure-requests present when FORCE_HTTPS=1'
    : 'upgrade-insecure-requests absent on plain HTTP (LAN/IP access works)',
    /upgrade-insecure-requests/.test(csp) === forceHttps,
    `FORCE_HTTPS=${forceHttps ? '1' : 'unset'}, directive ${/upgrade-insecure-requests/.test(csp) ? 'present' : 'absent'}`);

  const hsts = r.headers.get('strict-transport-security');
  record('S9f', forceHttps
    ? 'HSTS sent when FORCE_HTTPS=1'
    : 'HSTS not sent on plain HTTP',
    !!hsts === forceHttps, `Strict-Transport-Security: ${hsts}`);
}

// ---------------------------------------------------------------- S10
async function s10_cors() {
  const r = await fetch(`${BASE}/api/health`, { headers: { Origin: 'https://evil.example' } });
  const acao = r.headers.get('access-control-allow-origin');
  record('S10a', '/api does not reflect an arbitrary Origin',
    acao !== 'https://evil.example' && acao !== '*', `ACAO: ${acao}`);

  // public submission endpoint must stay cross-origin usable
  const c = await ctx('cors');
  const f = await makeForm({ name: 'CorsTest' }, c.auth);
  const sub = await fetch(`${BASE}/f/${f.body.id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: 'https://anywhere.example' },
    body: new URLSearchParams({ a: '1' })
  });
  record('S10b', '/f remains cross-origin submittable', sub.status === 200, `got HTTP ${sub.status}`);
}

// ---------------------------------------------------------------- S11
async function s11_errors() {
  // force a driver-level error: oversized/invalid pagination
  const c = await ctx('err');
  const f = await makeForm({ name: 'ErrTest' }, c.auth);
  const r = await fetch(`${BASE}/api/forms/${f.body.id}/submissions?limit=notanumber&page=-99999999999999999999`, { headers: c.auth });
  const text = await r.text();
  const leaks = /SQLITE|sqlite3|better-sqlite|at Object\.|at Module\.|\.js:\d+|node_modules/i.test(text);
  record('S11a', 'error responses leak no internals', !leaks, text.slice(0, 140));

  const bad = await fetch(`${BASE}/f/${f.body.id}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"a":'
  });
  const badText = await bad.text();
  record('S11b', 'malformed JSON returns clean JSON error, no stack',
    !/SyntaxError|at \w+|<pre>/.test(badText), badText.slice(0, 140));
}

// ---------------------------------------------------------------- S12
async function s12_health() {
  const r = await fetch(`${BASE}/api/health`);
  const body = await jsonOf(r);
  record('S12a', 'public health exposes no instance counts',
    body.users === undefined && body.forms === undefined && body.submissions === undefined,
    JSON.stringify(body));
  record('S12b', 'public health still reports status', body.status === 'ok');

  const unauth = await fetch(`${BASE}/api/health/stats`);
  record('S12c', 'detailed stats require auth', unauth.status === 401, `got HTTP ${unauth.status}`);

  const authed = await fetch(`${BASE}/api/health/stats`, { headers: AUTH });
  const stats = await jsonOf(authed);
  record('S12d', 'authenticated stats still available',
    authed.status === 200 && typeof stats.users === 'number', JSON.stringify(stats).slice(0, 80));
}

// ---------------------------------------------------------------- S13
async function s13_redirect() {
  const c = await ctx('redir');
  const js = await makeForm({ name: 'RedirJS', redirect_url: 'javascript:alert(1)' }, c.auth);
  record('S13a', 'javascript: redirect_url rejected', js.status === 400, `got HTTP ${js.status}`);

  const data = await makeForm({ name: 'RedirData', redirect_url: 'data:text/html,<script>alert(1)</script>' }, c.auth);
  record('S13b', 'data: redirect_url rejected', data.status === 400, `got HTTP ${data.status}`);

  const ok = await makeForm({ name: 'RedirOK', redirect_url: 'https://example.com/thanks' }, c.auth);
  record('S13c', 'https redirect_url still accepted', ok.status === 201, `got HTTP ${ok.status}`);
}

// ---------------------------------------------------------------- S14
async function s14_timing() {
  const known = USER.email;
  const unknown = `definitely-not-a-user-${Date.now()}@example.com`;
  const time = async email => {
    const runs = [];
    for (let i = 0; i < 6; i++) {
      const t = process.hrtime.bigint();
      await fetch(`${BASE}/api/auth/login`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: 'wrongpassword' })
      });
      runs.push(Number(process.hrtime.bigint() - t) / 1e6);
    }
    return runs.sort((a, b) => a - b)[Math.floor(runs.length / 2)];
  };
  const tKnown = await time(known);
  const tUnknown = await time(unknown);
  const ratio = tKnown > tUnknown ? tKnown / tUnknown : tUnknown / tKnown;
  record('S14', 'login timing does not distinguish known vs unknown account',
    ratio < 3, `known ${tKnown.toFixed(1)}ms vs unknown ${tUnknown.toFixed(1)}ms (ratio ${ratio.toFixed(2)})`);
}

// ---------------------------------------------------------------- S15
async function s15_validation() {
  const bad = await fetch(`${BASE}/api/auth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: `not-an-email-${Date.now()}`, password: 'secret123' })
  });
  record('S15a', 'malformed email rejected server-side', bad.status === 400, `got HTTP ${bad.status}`);

  const long = await fetch(`${BASE}/api/auth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: `x${Date.now()}@example.com`, password: 'a'.repeat(200) })
  });
  record('S15b', 'over-long password rejected rather than silently truncated',
    long.status === 400, `got HTTP ${long.status}`);

  const huge = await fetch(`${BASE}/api/auth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: `y${Date.now()}@example.com`, password: 'secret123', junk: 'z'.repeat(200000) })
  });
  record('S15c', 'oversized request body rejected', huge.status === 413, `got HTTP ${huge.status}`);
}

// ---------------------------------------------------------------- S16
async function s16_expiry() {
  const decoded = jwt.decode(TOKEN);
  const days = (decoded.exp - decoded.iat) / 86400;
  record('S16', 'JWT lifetime reduced to <= 7 days', days <= 7, `lifetime ${days.toFixed(1)} days`);
}

// ---------------------------------------------------------------- S19
async function s19_apiKey() {
  const r = await fetch(`${BASE}/api/forms`, { headers: { 'X-API-Key': USER.api_key } });
  record('S19a', 'X-API-Key authenticates the documented API', r.status === 200, `got HTTP ${r.status}`);

  const bad = await fetch(`${BASE}/api/forms`, { headers: { 'X-API-Key': 'fb_' + '0'.repeat(48) } });
  record('S19b', 'invalid API key rejected', bad.status === 401, `got HTTP ${bad.status}`);
}

// ---------------------------------------------------------------- S3 (runs last; burns quota)
async function s3_rateLimit() {
  // Against the strict instance, using its shipped default budgets.
  const email = `rl${Date.now()}@example.com`;
  const reg = await fetch(`${STRICT}/api/auth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: 'secret123' })
  });
  const regBody = await jsonOf(reg);
  if (reg.status !== 201) {
    record('S3', `could not seed strict instance (HTTP ${reg.status})`, false, JSON.stringify(regBody).slice(0, 120));
    return;
  }
  const auth = { Authorization: `Bearer ${regBody.token}`, 'Content-Type': 'application/json' };

  // Create the form BEFORE burning the auth budget, or this request 429s too.
  const fr = await fetch(`${STRICT}/api/forms`, {
    method: 'POST', headers: auth, body: JSON.stringify({ name: 'FloodTest' })
  });
  const form = await jsonOf(fr);

  const attempts = [];
  let retryAfter = null;
  for (let i = 0; i < 40; i++) {
    const r = await fetch(`${STRICT}/api/auth/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'wrong' })
    });
    attempts.push(r.status);
    if (r.status === 429) { retryAfter = r.headers.get('retry-after'); break; }
  }
  record('S3a', 'repeated failed logins are throttled',
    attempts.includes(429), `throttled after ${attempts.length} attempts`);
  record('S3c', '429 response carries Retry-After',
    !!retryAfter, `Retry-After: ${retryAfter}`);

  const subs = [];
  if (fr.status === 201) {
    for (let i = 0; i < 60; i++) {
      const r = await fetch(`${STRICT}/f/${form.id}`, {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ i: String(i) })
      });
      subs.push(r.status);
      if (r.status === 429) break;
    }
  }
  record('S3b', 'submission flooding is throttled',
    subs.includes(429), `throttled after ${subs.length} submissions`);
}

// ---------------------------------------------------------------------------
(async () => {
  console.log(`\nSecurity regression suite -> ${BASE}\n`);
  const reg = await registerUser('sec');
  if (reg.status !== 201) {
    console.error('Could not register a test user:', reg.status, JSON.stringify(reg.body));
    process.exit(1);
  }
  TOKEN = reg.body.token;
  USER = reg.body.user;
  AUTH = { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' };

  const suites = [
    ['S1  JWT secret', s1_jwtSecret],
    ['S2  webhook SSRF', s2_ssrf],
    ['S4  origin allowlist', s4_origin],
    ['S5/S6 CSV export', s5s6_csv],
    ['S7/S8 output escaping', s7s8_escaping],
    ['S9  CSP', s9_csp],
    ['S10 CORS', s10_cors],
    ['S11 error leakage', s11_errors],
    ['S12 health disclosure', s12_health],
    ['S13 open redirect', s13_redirect],
    ['S15 input validation', s15_validation],
    ['S16 JWT expiry', s16_expiry],
    ['S19 API key auth', s19_apiKey],
    // These two spend auth budget, so they go last.
    ['S14 login timing', s14_timing],
    ['S3  rate limiting', s3_rateLimit]
  ];

  for (const [label, fn] of suites) {
    console.log(`\n${label}`);
    try { await fn(); }
    catch (e) { record(label.split(' ')[0], `suite threw: ${e.message}`, false); }
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
