import 'dotenv/config';
import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import express from 'express';
import { neon } from '@neondatabase/serverless';
import { rateLimit } from 'express-rate-limit';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { promisify } from 'node:util';

const app = express();
const port = Number(process.env.PORT || 3000);
const host = '127.0.0.1';
const appOrigin = process.env.APP_ORIGIN || `http://${host}:${port}`;
const rootDir = path.dirname(fileURLToPath(import.meta.url));
const SESSION_COOKIE = 'stockroom_session';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const scrypt = promisify(scryptCallback);
const passwordSalt = randomBytes(16);
let ownerEmail;
let ownerPasswordHash;

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is required. Copy .env.example to .env and add your Neon connection string.');
  process.exit(1);
}

const sql = neon(process.env.DATABASE_URL);
app.disable('x-powered-by');
app.use('/api/inventory/import', express.json({ limit: '1mb' }));
app.use(express.json({ limit: '16kb' }));

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  if (leftBuffer.length !== rightBuffer.length) return false;
  return timingSafeEqual(leftBuffer, rightBuffer);
}

function getSessionToken(request) {
  const cookies = request.get('cookie') || '';
  const cookie = cookies.split(';').map(part => part.trim()).find(part => part.startsWith(`${SESSION_COOKIE}=`));
  return cookie ? cookie.slice(SESSION_COOKIE.length + 1) : '';
}

function hashSessionToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

function setSessionCookie(response, token) {
  response.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: SESSION_TTL_MS,
    path: '/'
  });
}

function requireSameOrigin(request, response, next) {
  const origin = request.get('origin');
  if (!origin || origin !== appOrigin) {
    response.status(403).json({ error: 'Request origin could not be verified.' });
    return;
  }
  next();
}

async function requireSession(request, response, next) {
  const token = getSessionToken(request);
  if (!/^[a-f0-9]{64}$/.test(token)) {
    response.status(401).json({ error: 'Sign in to continue.' });
    return;
  }
  try {
    const sessions = await sql`
      SELECT owner_email
      FROM auth_sessions
      WHERE token_hash = ${hashSessionToken(token)} AND expires_at > NOW()
    `;
    if (!sessions.length) {
      response.clearCookie(SESSION_COOKIE, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/'
      });
      response.status(401).json({ error: 'Your session expired. Sign in again.' });
      return;
    }
    request.ownerEmail = sessions[0].owner_email;
    next();
  } catch (error) {
    next(error);
  }
}

const loginRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many sign-in attempts. Wait 15 minutes and try again.' }
});

function validateItem(body) {
  const { id, name, category, quantity, price, reorderLevel, description } = body ?? {};
  const sku = body?.sku ?? '';
  const valid = typeof id === 'string' && id.length > 0 && id.length <= 80
    && typeof sku === 'string' && sku.trim().length <= 60
    && typeof name === 'string' && name.trim().length > 0 && name.trim().length <= 120
    && typeof category === 'string' && category.length <= 80
    && Number.isInteger(quantity) && quantity >= 0
    && typeof price === 'number' && Number.isFinite(price) && price >= 0 && price <= 9999999999
    && Number.isInteger(reorderLevel) && reorderLevel >= 0
    && typeof description === 'string' && description.length <= 500;

  if (!valid) {
    const error = new Error('Invalid product. Check the name, SKU, category, quantity, price, reorder level, and description.');
    error.status = 400;
    throw error;
  }

  return { id, sku: sku.trim(), name: name.trim(), category: category.trim(), quantity, price, reorderLevel, description: description.trim() };
}

function duplicateError(error) {
  if (error.code === '23505') {
    error.status = 409;
    error.message = 'A product with that ID or SKU already exists.';
  }
  return error;
}

function toItem(row) {
  return {
    id: row.id,
    sku: row.sku,
    name: row.name,
    category: row.category,
    quantity: row.quantity,
    price: Number(row.price),
    reorderLevel: row.reorder_level,
    description: row.description
  };
}

app.get('/api/health', async (_request, response, next) => {
  try {
    await sql`SELECT 1`;
    response.json({ status: 'ok' });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/login', loginRateLimit, requireSameOrigin, async (request, response, next) => {
  try {
    const email = typeof request.body?.email === 'string' ? request.body.email.trim().toLowerCase() : '';
    const password = typeof request.body?.password === 'string' ? request.body.password : '';
    if (email.length > 254 || password.length > 1024) {
      response.status(400).json({ error: 'Enter a valid email and password.' });
      return;
    }
    const candidateHash = await scrypt(password, passwordSalt, 64);
    const validEmail = safeEqual(email, ownerEmail);
    const validPassword = safeEqual(candidateHash, ownerPasswordHash);
    if (!validEmail || !validPassword) {
      response.status(401).json({ error: 'Email or password is incorrect.' });
      return;
    }

    const token = randomBytes(32).toString('hex');
    const tokenHash = hashSessionToken(token);
    await sql`
      INSERT INTO auth_sessions (token_hash, owner_email, expires_at)
      VALUES (${tokenHash}, ${ownerEmail}, NOW() + INTERVAL '7 days')
    `;
    setSessionCookie(response, token);
    response.json({ user: { email: ownerEmail } });
  } catch (error) {
    next(error);
  }
});

app.get('/api/auth/me', requireSession, (request, response) => {
  response.json({ user: { email: request.ownerEmail } });
});

app.post('/api/auth/logout', requireSameOrigin, async (request, response, next) => {
  try {
    const token = getSessionToken(request);
    if (/^[a-f0-9]{64}$/.test(token)) {
      await sql`DELETE FROM auth_sessions WHERE token_hash = ${hashSessionToken(token)}`;
    }
    response.clearCookie(SESSION_COOKIE, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/'
    });
    response.status(204).end();
  } catch (error) {
    next(error);
  }
});

app.use('/api/inventory', requireSession);
app.use('/api/inventory', (request, response, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(request.method)) return next();
  requireSameOrigin(request, response, next);
});

app.get('/api/inventory', async (_request, response, next) => {
  try {
    const rows = await sql`
      SELECT id, sku, name, category, quantity, price, reorder_level, description
      FROM inventory_items
      ORDER BY name ASC
    `;
    response.json(rows.map(toItem));
  } catch (error) {
    next(error);
  }
});

app.post('/api/inventory', async (request, response, next) => {
  try {
    const item = validateItem(request.body);
    const rows = await sql`
      INSERT INTO inventory_items (id, sku, name, category, quantity, price, reorder_level, description)
      VALUES (${item.id}, ${item.sku}, ${item.name}, ${item.category}, ${item.quantity}, ${item.price}, ${item.reorderLevel}, ${item.description})
      RETURNING id, sku, name, category, quantity, price, reorder_level, description
    `;
    response.status(201).json(toItem(rows[0]));
  } catch (error) {
    next(duplicateError(error));
  }
});

app.post('/api/inventory/import', async (request, response, next) => {
  try {
    const rows = request.body?.items;
    if (!Array.isArray(rows) || rows.length === 0 || rows.length > 1000) {
      response.status(400).json({ error: 'Import between 1 and 1000 products at a time.' });
      return;
    }
    const items = rows.map((row, index) => {
      try {
        return validateItem({ ...row, id: typeof row?.id === 'string' && row.id ? row.id : `id_${randomBytes(6).toString('hex')}` });
      } catch {
        const error = new Error(`Row ${index + 2} is invalid. Check its name, SKU, quantity, price, and reorder level.`);
        error.status = 400;
        throw error;
      }
    });

    const existing = await sql`SELECT id, sku, name FROM inventory_items`;
    const byId = new Map(existing.map(row => [row.id, row.id]));
    const bySku = new Map(existing.filter(row => row.sku).map(row => [row.sku.toLowerCase(), row.id]));
    const byName = new Map(existing.map(row => [row.name.toLowerCase(), row.id]));
    const queries = [];
    let created = 0;
    let updated = 0;

    for (const item of items) {
      const targetId = (byId.has(item.id) && item.id)
        || (item.sku && bySku.get(item.sku.toLowerCase()))
        || byName.get(item.name.toLowerCase());
      if (targetId) {
        updated += 1;
        queries.push(sql`
          UPDATE inventory_items
          SET sku = ${item.sku}, name = ${item.name}, category = ${item.category}, quantity = ${item.quantity},
              price = ${item.price}, reorder_level = ${item.reorderLevel}, description = ${item.description},
              updated_at = NOW()
          WHERE id = ${targetId}
        `);
      } else {
        created += 1;
        queries.push(sql`
          INSERT INTO inventory_items (id, sku, name, category, quantity, price, reorder_level, description)
          VALUES (${item.id}, ${item.sku}, ${item.name}, ${item.category}, ${item.quantity}, ${item.price}, ${item.reorderLevel}, ${item.description})
        `);
        byId.set(item.id, item.id);
        if (item.sku) bySku.set(item.sku.toLowerCase(), item.id);
        byName.set(item.name.toLowerCase(), item.id);
      }
    }

    await sql.transaction(queries);
    response.json({ created, updated });
  } catch (error) {
    next(duplicateError(error));
  }
});

app.put('/api/inventory/:id', async (request, response, next) => {
  try {
    const item = validateItem({ ...request.body, id: request.params.id });
    const rows = await sql`
      UPDATE inventory_items
      SET sku = ${item.sku}, name = ${item.name}, category = ${item.category}, quantity = ${item.quantity},
          price = ${item.price}, reorder_level = ${item.reorderLevel}, description = ${item.description},
          updated_at = NOW()
      WHERE id = ${item.id}
      RETURNING id, sku, name, category, quantity, price, reorder_level, description
    `;
    if (!rows.length) {
      response.status(404).json({ error: 'Product not found.' });
      return;
    }
    response.json(toItem(rows[0]));
  } catch (error) {
    next(duplicateError(error));
  }
});

app.delete('/api/inventory/:id', async (request, response, next) => {
  try {
    const rows = await sql`
      DELETE FROM inventory_items
      WHERE id = ${request.params.id}
      RETURNING id
    `;
    if (!rows.length) {
      response.status(404).json({ error: 'Product not found.' });
      return;
    }
    response.status(204).end();
  } catch (error) {
    next(error);
  }
});

app.use('/api', (_request, response) => {
  response.status(404).json({ error: 'API route not found.' });
});

app.get('/', (_request, response) => {
  response.sendFile(path.join(rootDir, 'index.html'));
});

app.use('/img', express.static(path.join(rootDir, 'img'), { dotfiles: 'deny' }));

app.use((error, _request, response, _next) => {
  const status = Number.isInteger(error.status) ? error.status : 500;
  if (status >= 500) console.error('API request failed:', error);
  response.status(status).json({
    error: status >= 500 ? 'The server could not complete the request.' : error.message
  });
});

async function start() {
  ownerEmail = process.env.OWNER_EMAIL?.trim().toLowerCase();
  const ownerPassword = process.env.OWNER_PASSWORD || '';
  if (!ownerEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(ownerEmail)) {
    throw new Error('Set OWNER_EMAIL to the email address used for the single owner account.');
  }
  if (ownerPassword.length < 16 || ownerPassword.length > 1024) {
    throw new Error('Set OWNER_PASSWORD to a unique password between 16 and 1024 characters.');
  }
  ownerPasswordHash = await scrypt(ownerPassword, passwordSalt, 64);

  await sql`
    CREATE TABLE IF NOT EXISTS inventory_items (
      id TEXT PRIMARY KEY,
      sku VARCHAR(60) NOT NULL DEFAULT '',
      name VARCHAR(120) NOT NULL,
      category VARCHAR(80) NOT NULL DEFAULT '',
      quantity INTEGER NOT NULL CHECK (quantity >= 0),
      price NUMERIC(12, 2) NOT NULL CHECK (price >= 0),
      reorder_level INTEGER NOT NULL DEFAULT 10 CHECK (reorder_level >= 0),
      description VARCHAR(500) NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;
  await sql`ALTER TABLE inventory_items ADD COLUMN IF NOT EXISTS sku VARCHAR(60) NOT NULL DEFAULT ''`;
  await sql`CREATE UNIQUE INDEX IF NOT EXISTS inventory_items_sku_idx ON inventory_items (LOWER(sku)) WHERE sku <> ''`;
  await sql`
    CREATE TABLE IF NOT EXISTS auth_sessions (
      token_hash CHAR(64) PRIMARY KEY,
      owner_email VARCHAR(254) NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;
  await sql`CREATE INDEX IF NOT EXISTS auth_sessions_expires_at_idx ON auth_sessions (expires_at)`;
  await sql`DELETE FROM auth_sessions WHERE expires_at <= NOW()`;
  app.listen(port, host, () => {
    console.log(`Stockroom is running at http://${host}:${port}`);
  });
}

start().catch(error => {
  console.error('Could not initialize the Neon database:', error);
  process.exit(1);
});
