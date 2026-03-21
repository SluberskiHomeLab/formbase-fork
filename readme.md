# ⬡ FormBase

**Open-source form backend for developers.** Collect form submissions without writing server code.

Drop-in replacement for Formspree, Basin, Getform — but self-hosted, free, and yours.

![License](https://img.shields.io/badge/license-MIT-blue) ![Node](https://img.shields.io/badge/node-18%2B-green) ![Docker](https://img.shields.io/badge/docker-ready-blue)

## Features

- **🛡️ Spam Protection** — Built-in honeypot fields catch bots silently
- **📧 Email Notifications** — Get notified on every submission (SMTP configurable)
- **🔗 Webhooks** — Forward submissions to Slack, Discord, Zapier, or any URL
- **📊 CSV Export** — One-click download of all submissions
- **🔑 REST API** — Full API with JWT auth + API key access
- **👤 Multi-user** — User accounts with plan-based limits
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

### Docker

```bash
docker build -t formbase .
docker run -p 3000:3000 -v formbase-data:/app/data formbase
```

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
| `JWT_SECRET` | dev secret | JWT signing key (**change in production!**) |
| `DATA_DIR` | `./data` | SQLite database directory |
| `SMTP_HOST` | — | SMTP server for email notifications |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | — | SMTP username |
| `SMTP_PASS` | — | SMTP password |
| `SMTP_FROM` | `noreply@formbase.dev` | From address |

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
│   ├── auth.js            # JWT + API key middleware
│   └── routes/
│       ├── users.js       # Auth & profile endpoints
│       ├── forms.js       # CRUD forms + submissions
│       └── submit.js      # Public submission endpoint
├── public/
│   └── index.html         # Single-file dashboard SPA
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
