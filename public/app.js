/*
 * Dashboard SPA.
 *
 * Lives in its own file rather than an inline <script> so the app can ship a
 * real `script-src 'self'` CSP. For the same reason there are no inline
 * onclick= attributes: every handler is bound here, keyed off data-* hooks.
 */
const API = '/api';
let state = {
  user: null, token: localStorage.getItem('fb_token'), view: 'home',
  forms: [], selectedForm: null, submissions: [], formModal: false,
  // User management. `registrationEnabled` mirrors the server's
  // DISABLE_REGISTRATION switch so the sign-up form is hidden rather than
  // offered and then rejected. `userModal` is null, 'create', or the user
  // object being edited.
  registrationEnabled: true, users: [], userModal: null
};

const isAdmin = () => state.user?.role === 'admin';

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}) };
  const res = await fetch(API + path, { ...opts, headers: { ...headers, ...opts.headers } });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

function toast(msg, type = 'success') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

async function init() {
  // Whether signup is open decides what the auth page renders, so it is read
  // before the first paint. A failure here is not fatal -- the form still
  // works, the server just refuses it.
  try {
    const config = await api('/auth/config');
    state.registrationEnabled = config.registration_enabled !== false;
  } catch { /* leave the default */ }

  if (state.token) {
    try { state.user = await api('/auth/me'); state.view = 'dashboard'; } catch { logout(); }
  }
  render();
}

function logout() { state.token = null; state.user = null; state.view = 'home'; localStorage.removeItem('fb_token'); render(); }
function navigate(view) { state.view = view; render(); }

async function loadForms() {
  state.forms = await api('/forms');
  render();
}

async function loadSubmissions(formId) {
  const res = await api(`/forms/${formId}/submissions`);
  state.submissions = res.submissions;
  render();
}

async function loadUsers() {
  const res = await api('/admin/users');
  state.users = res.users;
  state.registrationEnabled = res.registration_enabled !== false;
  render();
}

function render() {
  const app = document.getElementById('app');
  switch (state.view) {
    case 'home': app.innerHTML = renderHome(); break;
    case 'auth': app.innerHTML = renderAuth(); break;
    case 'dashboard': app.innerHTML = renderNav() + renderDashboard(); break;
    case 'form-detail': app.innerHTML = renderNav() + renderFormDetail(); break;
    case 'users': app.innerHTML = renderNav() + renderUsers(); break;
    case 'account': app.innerHTML = renderNav() + renderAccount(); break;
    default: app.innerHTML = renderHome();
  }
  bindEvents();
}

function renderHome() {
  return `
    <nav><div class="logo">⬡ Form<span>Base</span></div><div class="nav-actions">
      <button class="btn btn-outline" data-nav="auth">Login</button>
      <button class="btn btn-primary" data-nav="auth">Get Started</button>
    </div></nav>
    <div class="hero">
      <h1>Form backend for <span>developers</span></h1>
      <p>Collect form submissions without writing server code. Spam protection, email notifications, webhooks, CSV export — all self-hosted and open source.</p>
      <div class="actions">
        <button class="btn btn-primary" data-nav="auth" style="padding:12px 28px;font-size:1em">Start Free →</button>
        <a href="https://github.com/kszongic/formbase" class="btn btn-outline" style="padding:12px 28px;font-size:1em">GitHub ↗</a>
      </div>
    </div>
    <div class="features">
      <div class="feature"><h3>🛡️ Spam Protection</h3><p>Built-in honeypot fields catch bots silently. No CAPTCHAs needed for basic protection.</p></div>
      <div class="feature"><h3>📧 Email Alerts</h3><p>Get notified instantly when forms are submitted. Configure per-form notification emails.</p></div>
      <div class="feature"><h3>🔗 Webhooks</h3><p>Forward submissions to Slack, Discord, Zapier, or any HTTP endpoint in real-time.</p></div>
      <div class="feature"><h3>📊 CSV Export</h3><p>Download all submissions as CSV with one click. Perfect for spreadsheet workflows.</p></div>
      <div class="feature"><h3>🔑 API Access</h3><p>Full REST API with API key auth. Integrate FormBase into your existing tools.</p></div>
      <div class="feature"><h3>🏠 Self-Hosted</h3><p>Your data stays on your server. No vendor lock-in. Deploy anywhere with Node.js.</p></div>
    </div>
    <div style="text-align:center;padding:20px 0 40px"><div class="code copy-wrap" style="max-width:700px;margin:0 auto;text-align:left">&lt;form action="https://yourserver.com/f/FORM_ID" method="POST"&gt;
  &lt;input type="email" name="email" required&gt;
  &lt;textarea name="message"&gt;&lt;/textarea&gt;
  &lt;input type="text" name="_gotcha" style="display:none"&gt;
  &lt;button type="submit"&gt;Send&lt;/button&gt;
&lt;/form&gt;</div></div>`;
}

function renderAuth() {
  // With registration disabled there is only one thing this page can do, so it
  // opens on Log In and drops the toggle entirely rather than showing a sign-up
  // form the server will refuse.
  const open = state.registrationEnabled;
  return `<nav><div class="logo" style="cursor:pointer" data-nav="home">⬡ Form<span>Base</span></div></nav>
    <div class="auth-page"><div class="auth-box">
      <h2 id="auth-title">${open ? 'Sign Up' : 'Log In'}</h2>
      <form id="auth-form">
        <div class="field"><label>Email</label><input type="email" id="auth-email" required></div>
        <div class="field"><label>Password</label><input type="password" id="auth-password" required minlength="6"></div>
        <button type="submit" class="btn btn-primary" style="width:100%" id="auth-submit">${open ? 'Create Account' : 'Log In'}</button>
      </form>
      ${open
        ? `<div class="auth-toggle"><span id="auth-mode-text">Already have an account?</span> <a href="#" id="auth-toggle">Log in</a></div>`
        : `<div class="auth-toggle">Registration is closed on this instance. Ask an administrator for an account.</div>`}
    </div></div>`;
}

function renderNav() {
  return `<nav><div class="logo" style="cursor:pointer" data-nav="dashboard">⬡ Form<span>Base</span></div>
    <div class="nav-actions">
    <button class="btn btn-outline btn-sm" data-nav="dashboard">Forms</button>
    ${isAdmin() ? '<button class="btn btn-outline btn-sm" data-action="users">Users</button>' : ''}
    <button class="btn btn-outline btn-sm" data-nav="account">Account</button>
    <span class="user-email">${esc(state.user?.email || '')}${isAdmin() ? ' <span class="badge badge-admin">admin</span>' : ''}</span>
    <button class="btn btn-outline btn-sm" data-action="logout">Logout</button></div></nav>`;
}

function renderDashboard() {
  const total = state.forms.reduce((s, f) => s + f.submission_count, 0);
  const spam = state.forms.reduce((s, f) => s + f.spam_count, 0);
  return `<div class="container">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
      <h2>Dashboard</h2><button class="btn btn-primary" id="new-form-btn">+ New Form</button>
    </div>
    <div class="stats">
      <div class="stat"><div class="num">${state.forms.length}</div><div class="label">Forms</div></div>
      <div class="stat"><div class="num">${total}</div><div class="label">Submissions</div></div>
      <div class="stat"><div class="num">${spam}</div><div class="label">Spam Blocked</div></div>
      <div class="stat"><div class="num">${esc(state.user?.plan || 'free')}</div><div class="label">Plan</div></div>
    </div>
    ${state.forms.length === 0 ? '<div class="empty"><p>No forms yet. Create your first form to start collecting submissions!</p></div>' :
    state.forms.map(f => `<div class="card" style="cursor:pointer" data-form-id="${esc(f.id)}">
      <div style="display:flex;justify-content:space-between;align-items:start">
        <div><h3>${esc(f.name)}</h3><div class="meta">${f.submission_count} submissions · ${f.spam_count} spam blocked · Created ${new Date(f.created_at).toLocaleDateString()}</div></div>
        <div style="display:flex;gap:8px"><button class="btn btn-outline btn-sm copy-endpoint" data-id="${esc(f.id)}">Copy URL</button><button class="btn btn-danger btn-sm delete-form" data-id="${esc(f.id)}">Delete</button></div>
      </div>
    </div>`).join('')}
    ${state.formModal ? renderFormModal() : ''}
  </div>`;
}

function renderFormModal() {
  return `<div class="modal-overlay" id="modal-overlay"><div class="modal">
    <h2>Create Form</h2>
    <form id="create-form-form">
      <div class="field"><label>Form Name *</label><input id="cf-name" required placeholder="Contact Form"></div>
      <div class="field"><label>Notification Email</label><input id="cf-email" type="email" placeholder="you@example.com"></div>
      <div class="field"><label>Redirect URL (after submit)</label><input id="cf-redirect" placeholder="https://yoursite.com/thanks"></div>
      <div class="field"><label>Webhook URL</label><input id="cf-webhook" placeholder="https://hooks.slack.com/..."></div>
      <div class="field"><label>Allowed Origins (comma-separated)</label><input id="cf-origins" placeholder="* or example.com,app.example.com"></div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px">
        <button type="button" class="btn btn-outline" id="cancel-modal">Cancel</button>
        <button type="submit" class="btn btn-primary">Create</button>
      </div>
    </form>
  </div></div>`;
}

function renderFormDetail() {
  const f = state.selectedForm;
  if (!f) return '<div class="container"><p>Loading...</p></div>';
  const endpoint = `${location.origin}/f/${f.id}`;
  return `<div class="container">
    <div style="margin-bottom:20px"><a href="#" data-action="back">← Back</a></div>
    <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:20px">
      <div><h2>${esc(f.name)}</h2><div class="meta" style="margin-top:4px">${f.submission_count} submissions · Created ${new Date(f.created_at).toLocaleDateString()}</div></div>
      <div style="display:flex;gap:8px"><button class="btn btn-outline btn-sm" data-action="export" data-id="${esc(f.id)}">Export CSV</button></div>
    </div>
    <div class="card"><h3>Endpoint</h3><div class="code copy-wrap" style="margin-top:8px"><button class="copy-btn" data-copy="${esc(endpoint)}">Copy</button>${esc(endpoint)}</div>
    <h3 style="margin-top:16px">HTML Example</h3>
    <div class="code" style="margin-top:8px;font-size:.8em">&lt;form action="${esc(endpoint)}" method="POST"&gt;
  &lt;input type="email" name="email" required&gt;
  &lt;textarea name="message"&gt;&lt;/textarea&gt;
  &lt;input type="text" name="${esc(f.honeypot_field || '_gotcha')}" style="display:none"&gt;
  &lt;button type="submit"&gt;Send&lt;/button&gt;
&lt;/form&gt;</div>
    <h3 style="margin-top:16px">Settings</h3>
    <div class="meta" style="margin-top:4px">Notify: ${esc(f.notify_email || 'none')} · Redirect: ${esc(f.redirect_url || 'default')} · Webhook: ${esc(f.webhook_url || 'none')} · Origins: ${esc(f.allowed_origins || '*')}</div></div>
    <h3 style="margin-bottom:12px">Submissions</h3>
    ${state.submissions.length === 0 ? '<div class="empty">No submissions yet</div>' : `<table><thead><tr><th>Date</th><th>Data</th><th>IP</th><th></th></tr></thead><tbody>
    ${state.submissions.map(s => {
      const d = typeof s.data === 'string' ? JSON.parse(s.data) : s.data;
      const preview = Object.entries(d).map(([k,v]) => `<b>${esc(k)}:</b> ${esc(String(v).slice(0,80))}`).join(' · ');
      return `<tr${s.is_spam ? ' style="opacity:.4"' : ''}><td style="white-space:nowrap">${new Date(s.created_at).toLocaleString()}</td><td>${preview}${s.is_spam ? ' 🚫 spam' : ''}</td><td style="font-size:.8em">${esc(s.ip || '')}</td><td><button class="btn btn-danger btn-sm del-sub" data-fid="${esc(f.id)}" data-sid="${esc(s.id)}">×</button></td></tr>`;
    }).join('')}
    </tbody></table>`}
  </div>`;
}

// ---------------------------------------------------------------- Users (admin)

function renderUsers() {
  const admins = state.users.filter(u => u.role === 'admin').length;
  return `<div class="container">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
      <h2>Users</h2><button class="btn btn-primary" id="new-user-btn">+ New User</button>
    </div>
    <div class="stats">
      <div class="stat"><div class="num">${state.users.length}</div><div class="label">Accounts</div></div>
      <div class="stat"><div class="num">${admins}</div><div class="label">Admins</div></div>
      <div class="stat"><div class="num">${state.users.filter(u => !u.is_active).length}</div><div class="label">Disabled</div></div>
      <div class="stat"><div class="num">${state.registrationEnabled ? 'Open' : 'Closed'}</div><div class="label">Registration</div></div>
    </div>
    ${state.registrationEnabled
      ? `<div class="card"><div class="meta">Public sign-up is <b>open</b> — anyone who can reach this instance can create an account. Set <code>DISABLE_REGISTRATION=1</code> and restart to close it; accounts can still be created here.</div></div>`
      : `<div class="card"><div class="meta">Public sign-up is <b>closed</b> (<code>DISABLE_REGISTRATION</code> is set). This page is the only way to create an account.</div></div>`}
    <table><thead><tr><th>Email</th><th>Role</th><th>Plan</th><th>Status</th><th>Forms</th><th>Submissions</th><th>Created</th><th></th></tr></thead><tbody>
    ${state.users.map(u => {
      const self = u.id === state.user?.id;
      return `<tr${u.is_active ? '' : ' style="opacity:.5"'}>
        <td>${esc(u.email)}${self ? ' <span class="badge">you</span>' : ''}</td>
        <td>${u.role === 'admin' ? '<span class="badge badge-admin">admin</span>' : 'user'}</td>
        <td>${esc(u.plan)}</td>
        <td>${u.is_active ? '<span class="badge badge-ok">active</span>' : '<span class="badge badge-off">disabled</span>'}</td>
        <td>${u.form_count}</td>
        <td>${u.submission_count}</td>
        <td style="white-space:nowrap">${new Date(u.created_at.replace(' ', 'T') + 'Z').toLocaleDateString()}</td>
        <td style="white-space:nowrap">
          <button class="btn btn-outline btn-sm edit-user" data-id="${esc(u.id)}">Edit</button>
          ${self ? '' : `<button class="btn btn-danger btn-sm delete-user" data-id="${esc(u.id)}" data-email="${esc(u.email)}" data-forms="${u.form_count}" data-subs="${u.submission_count}">Delete</button>`}
        </td></tr>`;
    }).join('')}
    </tbody></table>
    ${state.userModal ? renderUserModal() : ''}
  </div>`;
}

function renderUserModal() {
  const creating = state.userModal === 'create';
  const u = creating ? { email: '', role: 'user', plan: 'free', is_active: 1 } : state.userModal;
  const self = !creating && u.id === state.user?.id;
  const opt = (value, current, label) => `<option value="${esc(value)}"${value === current ? ' selected' : ''}>${esc(label || value)}</option>`;
  return `<div class="modal-overlay" id="modal-overlay"><div class="modal">
    <h2>${creating ? 'Create User' : `Edit ${esc(u.email)}`}</h2>
    <form id="user-form" data-id="${esc(u.id || '')}">
      <div class="field"><label>Email *</label><input id="uf-email" type="email" required value="${esc(u.email)}"></div>
      <div class="field"><label>Password ${creating ? '*' : '(leave blank to keep unchanged)'}</label>
        <input id="uf-password" type="password" ${creating ? 'required' : ''} minlength="6" autocomplete="new-password"></div>
      <div class="field"><label>Role</label><select id="uf-role"${self ? ' disabled' : ''}>
        ${opt('user', u.role)}${opt('admin', u.role)}
      </select>${self ? '<div class="meta" style="margin-top:4px">You cannot change your own role.</div>' : ''}</div>
      <div class="field"><label>Plan</label><select id="uf-plan">
        ${opt('free', u.plan)}${opt('pro', u.plan)}${opt('unlimited', u.plan)}
      </select></div>
      <div class="field"><label>Status</label><select id="uf-active"${self ? ' disabled' : ''}>
        <option value="1"${u.is_active ? ' selected' : ''}>Active</option>
        <option value="0"${u.is_active ? '' : ' selected'}>Disabled</option>
      </select>${self ? '<div class="meta" style="margin-top:4px">You cannot deactivate your own account.</div>'
        : '<div class="meta" style="margin-top:4px">Disabling blocks login and immediately invalidates existing tokens and API keys. Forms and submissions are kept.</div>'}</div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px">
        ${creating ? '' : `<button type="button" class="btn btn-outline" id="regen-user-key" data-id="${esc(u.id)}">Regenerate API Key</button>`}
        <button type="button" class="btn btn-outline" id="cancel-modal">Cancel</button>
        <button type="submit" class="btn btn-primary">${creating ? 'Create' : 'Save'}</button>
      </div>
    </form>
  </div></div>`;
}

// ---------------------------------------------------------------- Account

function renderAccount() {
  const u = state.user || {};
  return `<div class="container">
    <h2 style="margin-bottom:20px">Account</h2>
    <div class="card">
      <h3>${esc(u.email || '')}</h3>
      <div class="meta" style="margin-top:4px">
        Role: ${esc(u.role || 'user')} · Plan: ${esc(u.plan || 'free')} ·
        ${u.form_count ?? 0} forms · ${u.total_submissions ?? 0} submissions
      </div>
      <h3 style="margin-top:16px">API Key</h3>
      <div class="code copy-wrap" style="margin-top:8px"><button class="copy-btn" data-copy="${esc(u.api_key || '')}">Copy</button>${esc(u.api_key || '')}</div>
      <button class="btn btn-outline btn-sm" id="regen-key" style="margin-top:8px">Regenerate API Key</button>
    </div>
    <div class="card">
      <h3>Change Password</h3>
      <form id="password-form" style="margin-top:12px;max-width:400px">
        <div class="field"><label>Current password</label><input type="password" id="pw-current" required autocomplete="current-password"></div>
        <div class="field"><label>New password</label><input type="password" id="pw-new" required minlength="6" autocomplete="new-password"></div>
        <button type="submit" class="btn btn-primary">Update Password</button>
      </form>
    </div>
  </div>`;
}

function esc(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : s; return d.innerHTML; }

// The export endpoint needs an Authorization header, so a plain <a href> to it
// just returned 401. Fetch it and hand the browser a blob instead.
async function exportCsv(formId) {
  try {
    const res = await fetch(`${API}/forms/${formId}/export`, {
      headers: state.token ? { Authorization: `Bearer ${state.token}` } : {}
    });
    if (!res.ok) throw new Error('Export failed');
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${(state.selectedForm?.name || 'form').replace(/[^\w.-]+/g, '_')}-submissions.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (e) { toast(e.message, 'error'); }
}

function bindEvents() {
  // Declarative navigation / actions, replacing inline onclick attributes.
  document.querySelectorAll('[data-nav]').forEach(el => {
    el.onclick = () => navigate(el.dataset.nav);
  });
  document.querySelectorAll('[data-action]').forEach(el => {
    el.onclick = async e => {
      const action = el.dataset.action;
      if (action === 'logout') return logout();
      if (action === 'back') { e.preventDefault(); navigate('dashboard'); return loadForms(); }
      if (action === 'export') { e.preventDefault(); return exportCsv(el.dataset.id); }
      if (action === 'users') {
        state.view = 'users'; state.userModal = null;
        try { return await loadUsers(); } catch (err) { return toast(err.message, 'error'); }
      }
    };
  });
  // Navigating back to Forms needs the list refreshed, not just the view swapped.
  document.querySelectorAll('[data-nav="dashboard"]').forEach(el => {
    el.onclick = async () => { navigate('dashboard'); try { await loadForms(); } catch { /* rendered empty */ } };
  });
  // The Account page shows counts and the API key, which the login response
  // does not carry -- re-read the profile on the way in.
  document.querySelectorAll('[data-nav="account"]').forEach(el => {
    el.onclick = async () => {
      navigate('account');
      try { state.user = await api('/auth/me'); render(); } catch { /* keep what we have */ }
    };
  });

  // Auth form. With registration closed the page is login-only and there is no
  // toggle to flip, so the mode starts (and stays) on login.
  const authForm = document.getElementById('auth-form');
  let isLogin = !state.registrationEnabled;
  const toggle = document.getElementById('auth-toggle');
  if (toggle) toggle.onclick = e => {
    e.preventDefault(); isLogin = !isLogin;
    document.getElementById('auth-title').textContent = isLogin ? 'Log In' : 'Sign Up';
    document.getElementById('auth-submit').textContent = isLogin ? 'Log In' : 'Create Account';
    document.getElementById('auth-mode-text').textContent = isLogin ? "Don't have an account?" : 'Already have an account?';
    document.getElementById('auth-toggle').textContent = isLogin ? 'Sign up' : 'Log in';
  };
  if (authForm) authForm.onsubmit = async e => {
    e.preventDefault();
    try {
      const res = await api(`/auth/${isLogin ? 'login' : 'register'}`, {
        method: 'POST', body: JSON.stringify({ email: document.getElementById('auth-email').value, password: document.getElementById('auth-password').value })
      });
      state.token = res.token; state.user = res.user;
      localStorage.setItem('fb_token', res.token);
      state.view = 'dashboard'; await loadForms();
      toast(isLogin ? 'Welcome back!' : 'Account created!');
    } catch (e) { toast(e.message, 'error'); }
  };

  // New form
  const nf = document.getElementById('new-form-btn');
  if (nf) nf.onclick = () => { state.formModal = true; render(); };
  const cm = document.getElementById('cancel-modal');
  if (cm) cm.onclick = () => { closeModals(); };
  const mo = document.getElementById('modal-overlay');
  if (mo) mo.onclick = e => { if (e.target === mo) closeModals(); };

  // Create form submit
  const cf = document.getElementById('create-form-form');
  if (cf) cf.onsubmit = async e => {
    e.preventDefault();
    try {
      await api('/forms', { method: 'POST', body: JSON.stringify({
        name: document.getElementById('cf-name').value,
        notify_email: document.getElementById('cf-email').value || undefined,
        redirect_url: document.getElementById('cf-redirect').value || undefined,
        webhook_url: document.getElementById('cf-webhook').value || undefined,
        allowed_origins: document.getElementById('cf-origins').value || undefined
      })});
      state.formModal = false; await loadForms(); toast('Form created!');
    } catch (e) { toast(e.message, 'error'); }
  };

  // Click form card
  document.querySelectorAll('[data-form-id]').forEach(el => {
    el.onclick = async e => {
      if (e.target.closest('.copy-endpoint') || e.target.closest('.delete-form')) return;
      state.selectedForm = state.forms.find(f => f.id === el.dataset.formId);
      state.view = 'form-detail';
      await loadSubmissions(state.selectedForm.id);
    };
  });

  // Copy endpoint
  document.querySelectorAll('.copy-endpoint').forEach(el => {
    el.onclick = e => { e.stopPropagation(); navigator.clipboard.writeText(`${location.origin}/f/${el.dataset.id}`); toast('Endpoint copied!'); };
  });
  document.querySelectorAll('.copy-btn[data-copy]').forEach(el => {
    el.onclick = () => { navigator.clipboard.writeText(el.dataset.copy); toast('Copied!'); };
  });

  // Delete form
  document.querySelectorAll('.delete-form').forEach(el => {
    el.onclick = async e => {
      e.stopPropagation();
      if (!confirm('Delete this form and all submissions?')) return;
      try { await api(`/forms/${el.dataset.id}`, { method: 'DELETE' }); await loadForms(); toast('Form deleted'); } catch (e) { toast(e.message, 'error'); }
    };
  });

  // Delete submission
  document.querySelectorAll('.del-sub').forEach(el => {
    el.onclick = async () => {
      try { await api(`/forms/${el.dataset.fid}/submissions/${el.dataset.sid}`, { method: 'DELETE' }); await loadSubmissions(el.dataset.fid); toast('Deleted'); } catch (e) { toast(e.message, 'error'); }
    };
  });

  bindUserEvents();
  bindAccountEvents();
}

function closeModals() {
  state.formModal = false;
  state.userModal = null;
  render();
}

function bindUserEvents() {
  const nu = document.getElementById('new-user-btn');
  if (nu) nu.onclick = () => { state.userModal = 'create'; render(); };

  document.querySelectorAll('.edit-user').forEach(el => {
    el.onclick = () => {
      state.userModal = state.users.find(u => u.id === el.dataset.id) || null;
      render();
    };
  });

  document.querySelectorAll('.delete-user').forEach(el => {
    el.onclick = async () => {
      const { email, forms, subs } = el.dataset;
      // Deleting cascades, so say what goes with the account rather than
      // asking a bare "are you sure?".
      if (!confirm(`Delete ${email}?\n\nThis also deletes ${forms} form(s) and ${subs} submission(s). This cannot be undone.`)) return;
      try { await api(`/admin/users/${el.dataset.id}`, { method: 'DELETE' }); await loadUsers(); toast('User deleted'); }
      catch (e) { toast(e.message, 'error'); }
    };
  });

  const rk = document.getElementById('regen-user-key');
  if (rk) rk.onclick = async () => {
    if (!confirm("Regenerate this user's API key? Their existing key stops working immediately.")) return;
    try { await api(`/admin/users/${rk.dataset.id}/regenerate-key`, { method: 'POST' }); toast('API key regenerated'); }
    catch (e) { toast(e.message, 'error'); }
  };

  const uf = document.getElementById('user-form');
  if (uf) uf.onsubmit = async e => {
    e.preventDefault();
    const creating = state.userModal === 'create';
    const password = document.getElementById('uf-password').value;
    const body = {
      email: document.getElementById('uf-email').value,
      role: document.getElementById('uf-role').value,
      plan: document.getElementById('uf-plan').value,
      is_active: document.getElementById('uf-active').value === '1'
    };
    // A blank password field on edit means "keep the current one" -- sending
    // an empty string would fail validation instead.
    if (password) body.password = password;
    // The disabled role/status selects on your own row are not submitted, so
    // the request cannot trip the server's self-guards.
    if (!creating && state.userModal.id === state.user?.id) { delete body.role; delete body.is_active; }

    try {
      if (creating) await api('/admin/users', { method: 'POST', body: JSON.stringify(body) });
      else await api(`/admin/users/${uf.dataset.id}`, { method: 'PATCH', body: JSON.stringify(body) });
      state.userModal = null;
      await loadUsers();
      // Editing yourself changes what the nav should show, so refresh it.
      if (!creating && uf.dataset.id === state.user?.id) {
        try { state.user = await api('/auth/me'); render(); } catch { /* nav stays as-is */ }
      }
      toast(creating ? 'User created' : 'User updated');
    } catch (err) { toast(err.message, 'error'); }
  };
}

function bindAccountEvents() {
  const rk = document.getElementById('regen-key');
  if (rk) rk.onclick = async () => {
    if (!confirm('Regenerate your API key? Anything using the old key stops working immediately.')) return;
    try {
      const res = await api('/auth/me/regenerate-key', { method: 'POST' });
      state.user = { ...state.user, api_key: res.api_key };
      render();
      toast('API key regenerated');
    } catch (e) { toast(e.message, 'error'); }
  };

  const pf = document.getElementById('password-form');
  if (pf) pf.onsubmit = async e => {
    e.preventDefault();
    try {
      await api('/auth/me/password', { method: 'POST', body: JSON.stringify({
        current_password: document.getElementById('pw-current').value,
        new_password: document.getElementById('pw-new').value
      })});
      pf.reset();
      toast('Password updated');
    } catch (err) { toast(err.message, 'error'); }
  };
}

// Boot
init().then(() => { if (state.view === 'dashboard') loadForms(); });
