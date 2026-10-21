import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import { createHmac, randomBytes, createHash } from 'crypto';
import Database from 'better-sqlite3';
import PRICES_DATA from './prices.js'; // Импортируем твои цены

const app = express();
app.use(cors());
app.use(express.json());
const JWT_SECRET = 'fg-super-secret-key-123';
const PORT = process.env.PORT || 3001;

// --- База данных ---
const db = new Database('freegrader.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    balance REAL NOT NULL DEFAULT 100.0,
    xp INTEGER NOT NULL DEFAULT 0,
    level INTEGER NOT NULL DEFAULT 0,
    pf_server_seed TEXT, pf_committed_hash TEXT, pf_client_seed TEXT,
    pf_nonce INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    template_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
`);

// --- Генерация пула скинов из твоих цен ---
const SKIN_DATA = {};
for (const fullName in PRICES_DATA) {
  const price = PRICES_DATA[fullName];
  if (typeof price !== 'number' || price <= 0) continue;
  let name = fullName, variant = "base";
  if (name.startsWith("StatTrak™ ")) { variant = "st"; name = name.substring(10); }
  else if (name.startsWith("Souvenir ")) { variant = "souvenir"; name = name.substring(9); }
  const p = name.lastIndexOf(" (");
  if (p === -1) continue;
  const wear = name.substring(p + 2, name.length - 1);
  const itemName = name.substring(0, p);
  const pi = itemName.indexOf(" | ");
  if (pi === -1) continue;
  const weaponFull = itemName.substring(0, pi).trim();
  const skin = itemName.substring(pi + 3).trim();
  const weaponClean = weaponFull.startsWith("★ ") ? weaponFull.substring(2).trim() : weaponFull;
  const key = `${weaponClean}|${skin}`;
  if (!SKIN_DATA[key]) SKIN_DATA[key] = { weaponClean, weaponFull, skin, wears: {} };
  if (!SKIN_DATA[key].wears[wear]) SKIN_DATA[key].wears[wear] = {};
  SKIN_DATA[key].wears[wear][variant] = price;
}

const MASTER_POOL = [];
let idCounter = 0;
for (const key in SKIN_DATA) {
  const d = SKIN_DATA[key];
  for (const wear in d.wears) {
    const v = d.wears[wear];
    if (v.base != null) MASTER_POOL.push({ templateId: idCounter++, weapon: d.weaponClean, weaponFull: d.weaponFull, skin: d.skin, wear, name: `${d.weaponFull} | ${d.skin} (${wear})`, shortName: `${d.weaponFull} | ${d.skin}`, price: v.base });
    if (v.st != null) MASTER_POOL.push({ templateId: idCounter++, weapon: d.weaponClean, weaponFull: d.weaponFull, skin: d.skin, wear, name: `StatTrak™ ${d.weaponFull} | ${d.skin} (${wear})`, shortName: `ST™ ${d.weaponFull} | ${d.skin}`, price: v.st });
  }
}
MASTER_POOL.sort((a, b) => a.price - b.price);
const POOL_BY_ID = new Map(MASTER_POOL.map(t => [t.templateId, t]));
console.log(`✅ Пул загружен: ${MASTER_POOL.length} шаблонов`);

// --- Вспомогательные функции ---
const genSeed = () => randomBytes(32).toString('hex');
const sha256 = (s) => createHash('sha256').update(s).digest('hex');
const computeRoll = (serverSeed, clientSeed, nonce) =>
  (parseInt(createHmac('sha256', serverSeed).update(`${clientSeed}:${nonce}`).digest('hex').slice(0, 8), 16) % 1000000) / 10000;

function auth(req, res, next) {
  const t = req.headers.authorization?.split(' ')[1];
  if (!t) return res.status(401).json({ error: 'no token' });
  try {
    req.user = db.prepare('SELECT * FROM users WHERE id = ?').get(jwt.verify(t, JWT_SECRET).uid);
    if (!req.user) return res.status(401).json({ error: 'user not found' });
    next();
  } catch { res.status(401).json({ error: 'bad token' }); }
}

function getUserState(userId) {
  const user = db.prepare('SELECT id, username, balance, xp, level FROM users WHERE id = ?').get(userId);
  const inv = db.prepare('SELECT id, template_id FROM inventory WHERE user_id = ?').all(userId);
  const inventory = inv.map(r => ({ ...POOL_BY_ID.get(r.template_id), id: r.id }));
  return { user, inventory };
}

// --- API Эндпоинты ---
app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || password.length < 4) return res.status(400).json({ error: 'invalid' });
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) return res.status(409).json({ error: 'taken' });
  const seed = genSeed();
  const info = db.prepare(`INSERT INTO users (username, password_hash, pf_server_seed, pf_committed_hash, pf_client_seed, created_at) VALUES (?,?,?,?,?,?)`)
    .run(username, bcrypt.hashSync(password, 10), seed, sha256(seed), genSeed().slice(0, 16), Date.now());
  const token = jwt.sign({ uid: info.lastInsertRowid }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, ...getUserState(info.lastInsertRowid) });
});

app.post('/api/auth/login', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(req.body.username);
  if (!u || !bcrypt.compareSync(req.body.password, u.password_hash)) return res.status(401).json({ error: 'invalid' });
  const token = jwt.sign({ uid: u.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, ...getUserState(u.id) });
});

app.get('/api/me', auth, (req, res) => res.json(getUserState(req.user.id)));
app.get('/api/pool', (req, res) => res.json({ pool: MASTER_POOL }));

app.post('/api/upgrade/roll', auth, (req, res) => {
  const { fromIds, toTemplateId, customChance, customChanceVal } = req.body;
  if (!Array.isArray(fromIds) || !fromIds.length || fromIds.length > 5) return res.status(400).json({ error: 'fromIds 1-5 required' });
  const toTpl = POOL_BY_ID.get(toTemplateId);
  if (!toTpl) return res.status(400).json({ error: 'invalid target' });

  const fromItems = [];
  for (const id of fromIds) {
    const row = db.prepare('SELECT template_id FROM inventory WHERE id = ? AND user_id = ?').get(id, req.user.id);
    if (!row) return res.status(400).json({ error: `item ${id} not yours` });
    fromItems.push({ ...POOL_BY_ID.get(row.template_id), id });
  }

  const totalFrom = fromItems.reduce((s, x) => s + x.price, 0);
  const levelBonus = Math.min(4, (req.user.level || 0) * 0.2);
  let chance = customChance
    ? Math.max(0.1, Math.min(99.9, parseFloat(customChanceVal) || 50))
    : Math.max(1, Math.min(95, (totalFrom / toTpl.price) * 100 + levelBonus));
  chance = Math.round(chance * 10) / 10;

  const nonce = req.user.pf_nonce + 1;
  const roll = computeRoll(req.user.pf_server_seed, req.user.pf_client_seed, nonce);
  const won = roll < chance;
  let compensation = 0;

  db.transaction(() => {
    db.prepare('UPDATE users SET pf_nonce = ?, xp = xp + ? WHERE id = ?').run(nonce, won ? 25 : 10, req.user.id);
    for (const id of fromIds) db.prepare('DELETE FROM inventory WHERE id = ?').run(id);
    if (won) {
      db.prepare('INSERT INTO inventory (user_id, template_id, created_at) VALUES (?,?,?)').run(req.user.id, toTemplateId, Date.now());
    } else {
      compensation = Math.round(totalFrom * (0.01 + Math.random() * 0.04) * 100) / 100;
      db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(compensation, req.user.id);
    }
    const u = db.prepare('SELECT xp FROM users WHERE id = ?').get(req.user.id);
    db.prepare('UPDATE users SET level = ? WHERE id = ?').run(Math.floor(Math.sqrt(u.xp / 100)), req.user.id);
  })();

  res.json({ result: { won, roll, chance, nonce, compensation }, ...getUserState(req.user.id) });
});

app.post('/api/inventory/sell', auth, (req, res) => {
  const row = db.prepare('SELECT template_id FROM inventory WHERE id = ? AND user_id = ?').get(req.body.inventoryId, req.user.id);
  if (!row) return res.status(400).json({ error: 'not found' });
  const tpl = POOL_BY_ID.get(row.template_id);
  db.transaction(() => {
    db.prepare('DELETE FROM inventory WHERE id = ?').run(req.body.inventoryId);
    db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(tpl.price, req.user.id);
  })();
  res.json(getUserState(req.user.id));
});

app.listen(PORT, () => console.log(`✅ Сервер запущен на порту ${PORT}`));
