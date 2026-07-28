const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');

require('dotenv').config({ quiet: true });
require('./db'); // init database

const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// API routes
app.use('/api/auth', require('./routes/users'));
app.use('/api/forms', require('./routes/forms'));
app.use('/f', require('./routes/submit'));

// Dashboard SPA
app.use(express.static(path.join(__dirname, '..', 'public')));
app.get('/dashboard{/*splat}', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'index.html')));

// Health check
app.get('/api/health', (req, res) => {
  const db = require('./db');
  const users = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const forms = db.prepare('SELECT COUNT(*) as c FROM forms').get().c;
  const subs = db.prepare('SELECT COUNT(*) as c FROM submissions').get().c;
  res.json({ status: 'ok', users, forms, submissions: subs, uptime: process.uptime() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 FormBase running on http://localhost:${PORT}`));
