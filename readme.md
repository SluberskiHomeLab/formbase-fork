# ⬡ FormBase

**Open-source form backend for developers.** Collect form submissions without writing server code.

Drop-in replacement for Formspree, Basin, Getform — but self-hosted, free, and yours.

![License](https://img.shields.io/badge/license-MIT-blue) ![Node](https://img.shields.io/badge/node-20%2B-green) ![Docker](https://img.shields.io/badge/docker-ready-blue)

## Features

- **🛡️ Spam Protection** — Built-in honeypot fields catch bots silently
- **📧 Email Notifications** — Get notified on every submission (SMTP configurable)
- **🔗 Webhooks** — Forward submissions to Slack, Discord, Zapier, or any URL
- **📊 CSV Export** — One-click download of all submissions
- **🔑 REST API** — Full API with JWT auth + API key access
- **👤 Multi-user** — User accounts with plan-based limits
- **🔒 Closable sign-up** — `DISABLE_REGISTRATION=1` locks the instance to invite-only
- **👑 Admin panel** — First account is an admin; create, edit, disable and delete users
- **🎨 Dashboard** — Beautiful dark-mode admin panel (no build step!)
- **🐳 Docker Ready** — Deploy in one command
- **💾 SQLite** — Zero-config database, no external dependencies

## Quick Start

```bash
git clone https://github.com/kszongic/formbase.git
cd formbase
npm install
node src/server.js
# → Running on http://localhost:3000
```

### Docker Compose (recommended)

```bash
docker compose up -d
```

That's it — no configuration required. A signing secret is generated on first
run and persisted in the data volume. Open http://localhost:3000 and create an
account.

To customise, copy `.env.example` to `.env` and set what you need; everything
in it is optional. Three worth knowing about:

- **`DISABLE_REGISTRATION=1`** — closes public sign-up (see
  [Users & Access Control](#users--access-control)).
- **`TRUST_PROXY=1`** — set this if a reverse proxy sits in front, otherwise
  every request looks like it came from the proxy and rate limiting throttles
  all users as one.
- **`SSRF_ALLOW_PRIVATE=1`** — webhooks to private/LAN addresses are blocked by
  default; set this only if your webhook target really is on your network.

Data lives in the `formbase-data` named volume and survives `docker compose
down`. Use `docker compose down -v` to delete it.

### Docker (manual)

```bash
docker build -t formbase .
docker run -p 3000:3000 -v formbase-data:/app/data formbase
```

The container runs as non-root (uid 1000). Named volumes inherit that
ownership; if you bind-mount a host directory instead, `chown 1000:1000` it
first.

## How It Works

1. **Create an account** at your FormBase instance
2. **Create a form** in the dashboard — you get a unique endpoint
3. **Point your HTML form** at the endpoint:

```html
<form action="https://your-server.com/f/FORM_ID" method="POST">
  <input type="email" name="email" required>
  <textarea name="message"></textarea>
  <!-- Honeypot: invisible to humans, catches bots -->
  <input type="text" name="_gotcha" style="display:none">
  <button type="submit">Send</button>
</form>
```

4. **View submissions** in the dashboard, get email alerts, or receive webhooks

## Users & Access Control

### Closing registration

An instance ships with public sign-up open. To close it:

```bash
DISABLE_REGISTRATION=1
```

`POST /api/auth/register` then returns **403 for everyone**, unconditionally —
there is no "unless the instance is empty" exception, and no way to talk the
endpoint into creating an account while the variable is set. The dashboard
reads `GET /api/auth/config` and renders a login-only page rather than offering
a sign-up form the server will refuse.

Existing accounts are unaffected and keep working. Accounts are still created
afterwards, just by an admin instead of by whoever finds the URL.

### Roles

Two roles, `admin` and `user`:

- **The first account created on an instance becomes an admin.** Every account
  after it is a plain user.
- A plain **user** sees only their own forms and submissions — unchanged from
  before.
- An **admin** additionally gets a **Users** page in the dashboard: list every
  account, create accounts, change email/password/plan/role, disable and
  re-enable accounts, regenerate someone's API key, and delete accounts.

Roles are read from the database on every request rather than from the JWT, so
disabling or demoting someone takes effect immediately instead of when their
week-long token happens to expire. Disabling blocks login and invalidates both
their tokens and their API key, while keeping their forms and submissions;
deleting removes the account and cascades to both.

An admin cannot demote, disable, or delete **their own** account. Since every
route requires an active admin, that one rule is what guarantees an instance
always keeps at least one way in. (If an account is nonetheless lost outside
the app, the oldest remaining account is promoted to admin at the next boot.)

### Bootstrapping a locked-down instance

The usual order is: start with registration open, sign up (you become the
admin), then set `DISABLE_REGISTRATION=1` and restart.

To bring an instance up with registration *already* closed there would be no
way to create that first admin, so set both of these:

```bash
DISABLE_REGISTRATION=1
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=a-long-password-you-chose
```

They are applied **only when the database has no users at all**, so they cannot
overwrite or resurrect an account on an instance already in use. Change the
password from the dashboard's Account page after first login and drop
`ADMIN_PASSWORD` from the environment.

If registration is closed and no account exists and these are unset, the server
starts and logs a warning saying nobody can sign in.

## API Reference

### Authentication

```bash
# Register
curl -X POST /api/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"secret123"}'

# Login
curl -X POST /api/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"secret123"}'
# → { "token": "eyJ...", "user": { ... } }

# Is registration open? (public, no auth)
curl /api/auth/config
# → { "registration_enabled": true }

# Change your own password
curl -X POST /api/auth/me/password -H 'Authorization: Bearer TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"current_password":"secret123","new_password":"newsecret456"}'
```

### Admin — user management

Admin only, JWT only (an API key cannot manage accounts).

```bash
# List all users, with per-account form and submission counts
curl /api/admin/users -H 'Authorization: Bearer TOKEN'

# Create an account — the way to add people once sign-up is closed
curl -X POST /api/admin/users -H 'Authorization: Bearer TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"email":"new@example.com","password":"secret123","role":"user","plan":"pro"}'

# Update: any of email, password, plan, role, is_active
curl -X PATCH /api/admin/users/USER_ID -H 'Authorization: Bearer TOKEN' \
  -H 'Content-Type: application/json' -d '{"is_active":false}'

# Regenerate someone's API key
curl -X POST /api/admin/users/USER_ID/regenerate-key -H 'Authorization: Bearer TOKEN'

# Delete (cascades to their forms and submissions)
curl -X DELETE /api/admin/users/USER_ID -H 'Authorization: Bearer TOKEN'
```

### Forms

```bash
# List forms
curl /api/forms -H 'Authorization: Bearer TOKEN'

# Create form
curl -X POST /api/forms -H 'Authorization: Bearer TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"name":"Contact","notify_email":"me@example.com","webhook_url":"https://hooks.slack.com/..."}'

# Get submissions
curl /api/forms/FORM_ID/submissions -H 'Authorization: Bearer TOKEN'

# Export CSV
curl /api/forms/FORM_ID/export -H 'Authorization: Bearer TOKEN' > subs.csv
```

### Form Submission (public endpoint)

```bash
# JSON
curl -X POST /f/FORM_ID -H 'Content-Type: application/json' \
  -d '{"email":"user@test.com","message":"Hello!"}'

# Form-encoded (standard HTML forms)
curl -X POST /f/FORM_ID -d 'email=user@test.com&message=Hello!'
```

## Configuration

Environment variables (`.env` or system):

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `DISABLE_REGISTRATION` | — | `1` closes public sign-up entirely |
| `ADMIN_EMAIL` | — | Seeds the first admin — only on an empty database |
| `ADMIN_PASSWORD` | — | Password for that seeded admin (required with `ADMIN_EMAIL`) |
| `JWT_SECRET` | generated | JWT signing key; random one persisted in `DATA_DIR` if unset |
| `JWT_EXPIRES_IN` | `7d` | How long a login stays valid |
| `DATA_DIR` | `./data` | SQLite database directory |
| `SMTP_HOST` | — | SMTP server for email notifications |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | — | SMTP username |
| `SMTP_PASS` | — | SMTP password |
| `SMTP_FROM` | `SMTP_USER` | From address — **must be one your relay may send as** |
| `SMTP_SECURE` | port `465` | Implicit TLS; inferred from the port, override only if needed |

### Email notifications

Set `SMTP_HOST` to turn notifications on. The configuration is checked at
startup, so `docker compose logs formbase | grep mail` tells you where you
stand:

```
[mail] ready: smtp.example.com:587 (STARTTLS, auth as you@example.com) sending as you@example.com
```

**If alerts are not arriving, `SMTP_FROM` is the usual reason.** A relay only
sends as addresses it is authoritative for. A From on any other domain is
rejected with `553 Sender is not allowed to relay emails` and the notification
is lost. Set `SMTP_FROM` to an address on your own domain — normally the same
one as `SMTP_USER`.

Notifications are sent in the background, so a slow or unreachable mail server
never delays the visitor's confirmation page. That also means a failure shows
up only in the logs; grep for `[mail]`, which prints both the error and what to
change.

## Plans & Limits

| Feature | Free | Pro | Unlimited |
|---------|------|-----|-----------|
| Forms | 3 | 50 | ∞ |
| Submissions/month | 100/form | 10,000/form | ∞ |
| Webhooks | ✅ | ✅ | ✅ |
| Email notifications | ✅ | ✅ | ✅ |
| CSV export | ✅ | ✅ | ✅ |
| API access | ✅ | ✅ | ✅ |

## Architecture

```
formbase/
├── src/
│   ├── server.js          # Express app entry
│   ├── db.js              # SQLite setup & migrations
│   ├── auth.js            # JWT + API key middleware, requireAdmin
│   ├── lib/
│   │   └── users.js       # User creation, roles, registration switch
│   └── routes/
│       ├── users.js       # Auth & profile endpoints
│       ├── admin.js       # Admin user management
│       ├── forms.js       # CRUD forms + submissions
│       └── submit.js      # Public submission endpoint
├── public/
│   ├── index.html         # Dashboard SPA markup + styles
│   └── app.js             # Dashboard SPA logic (external, for a strict CSP)
├── Dockerfile
└── package.json
```

- **Zero build step** — Dashboard is a single HTML file with vanilla JS
- **SQLite with WAL** — Fast, concurrent reads, no database server needed
- **Stateless API** — JWT auth, deploy multiple instances behind a load balancer

## Comparison

| | FormBase | Formspree | Basin | Getform |
|---|---|---|---|---|
| Self-hosted | ✅ | ❌ | ❌ | ❌ |
| Open source | ✅ | ❌ | ❌ | ❌ |
| Free tier | Unlimited | 50/mo | 100/mo | 50/mo |
| Webhooks | ✅ | Paid | Paid | Paid |
| CSV export | ✅ | Paid | ✅ | Paid |
| Price | $0 | $10-40/mo | $8-49/mo | $8-79/mo |

## Contributing

PRs welcome! This is a solo project but contributions are appreciated.

## License

MIT © [kszongic](https://github.com/kszongic)
