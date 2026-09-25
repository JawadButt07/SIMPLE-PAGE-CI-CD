const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const Redis = require('ioredis');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error('JWT_SECRET is not set. Refusing to start.');
  process.exit(1);
}

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false },
});

const redis = new Redis({
  host: process.env.REDIS_HOST || 'redis',
  port: process.env.REDIS_PORT || 6379,
  lazyConnect: true,
  retryStrategy: () => null,
});

redis.on('error', (err) => console.error('Redis error:', err.message));

const CACHE_TTL_SECONDS = 300; // 5 minutes
const PUBLIC_DIR = path.join(__dirname, 'public');

async function cachedStaticFile(filePath, contentType, res) {
  const cacheKey = `static:${filePath}`;

  try {
    if (redis.status === 'wait') await redis.connect().catch(() => {});
    const cached = await redis.get(cacheKey);
    if (cached) {
      console.log(`[CACHE HIT] ${filePath} — ${new Date().toISOString()}`);
      res.set('X-Cache', 'HIT');
      res.type(contentType).send(cached);
      return;
    }
  } catch {
    // Redis unavailable — fall through to disk read below
  }

  const content = fs.readFileSync(filePath, 'utf8');
  console.log(`[CACHE MISS] ${filePath} — ${new Date().toISOString()}`);
  res.set('X-Cache', 'MISS');
  res.type(contentType).send(content);

  redis.setex(cacheKey, CACHE_TTL_SECONDS, content).catch(() => {});
}

app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => cachedStaticFile(path.join(PUBLIC_DIR, 'index.html'), 'text/html', res));
app.get('/signup.html', (req, res) => cachedStaticFile(path.join(PUBLIC_DIR, 'signup.html'), 'text/html', res));
app.get('/login.html', (req, res) => cachedStaticFile(path.join(PUBLIC_DIR, 'login.html'), 'text/html', res));
app.get('/dashboard.html', (req, res) => cachedStaticFile(path.join(PUBLIC_DIR, 'dashboard.html'), 'text/html', res));
app.get('/style.css', (req, res) => cachedStaticFile(path.join(PUBLIC_DIR, 'style.css'), 'text/css', res));

app.get('/blocked.html', (req, res) => {
  res.status(403).send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Restricted</title>
<style>
  body{margin:0;min-height:100vh;background:#f2efe4;color:#1c1f1a;font-family:Georgia,'Iowan Old Style',serif;display:flex;align-items:center;justify-content:center;padding:2rem;}
  .card{max-width:480px;width:100%;border:1px solid #3f4a34;padding:2.5rem 2.75rem;text-align:center;}
  h1{font-size:1.6rem;font-weight:400;margin:0 0 1rem 0;border-bottom:2px solid #1c1f1a;padding-bottom:.75rem;}
  p{line-height:1.6;font-size:1rem;color:#6f7d4f;}
</style>
</head>
<body>
  <div class="card">
    <h1>Access Restricted by Owner</h1>
    <p>This site is not available in your region. Access is currently limited to specific countries.</p>
  </div>
</body>
</html>`);
});

app.get('/healthz', (req, res) => res.status(200).send('ok'));

app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password || password.length < 8) {
    return res.status(400).json({ error: 'Email and a password of at least 8 characters are required.' });
  }

  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2)',
      [email, passwordHash]
    );

    return res.status(201).json({ message: 'Account created. You can log in now.' });
  } catch (err) {
    console.error('Signup error:', err.message);
    return res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const result = await pool.query(
      'SELECT id, password_hash FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const token = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: '2h' });
    res.cookie('session', token, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 2 * 60 * 60 * 1000,
    });

    return res.status(200).json({ message: 'Logged in.' });
  } catch (err) {
    console.error('Login error:', err.message);
    return res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

function requireAuth(req, res, next) {
  const token = req.cookies.session;
  if (!token) {
    return res.status(401).json({ error: 'Not logged in.' });
  }
  try {
    req.userId = jwt.verify(token, JWT_SECRET).sub;
    next();
  } catch {
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }
}

app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, created_at FROM users WHERE id = $1',
      [req.userId]
    );
    return res.json(result.rows[0]);
  } catch (err) {
    console.error('Me error:', err.message);
    return res.status(500).json({ error: 'Something went wrong.' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('session');
  return res.json({ message: 'Logged out.' });
});

app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
