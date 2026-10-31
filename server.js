// Meta Uber — servidor Node/Express com Postgres (Supabase) e login por PIN
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const DB_URL = (process.env.DATABASE_URL || '').trim();
const app = express();
app.use(express.json({ limit: '2mb' }));

// ---------- Banco ----------
let pool = null;
let dbOk = false;
let dbErro = DB_URL ? 'conectando' : 'DATABASE_URL não configurada';
let SECRET = process.env.SESSION_SECRET || '';

async function iniciarBanco() {
  if (!DB_URL) return;
  const local = /localhost|127\.0\.0\.1/.test(DB_URL);
  pool = new Pool({
    connectionString: DB_URL,
    ssl: local ? false : { rejectUnauthorized: false },
    max: 5,
    idleTimeoutMillis: 30000,
  });
  pool.on('error', e => console.error('[db] erro no pool:', e.message));
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS mu_config (k TEXT PRIMARY KEY, v JSONB NOT NULL);
      CREATE TABLE IF NOT EXISTS mu_dias (
        id TEXT PRIMARY KEY,
        data DATE NOT NULL,
        d JSONB NOT NULL,
        criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE INDEX IF NOT EXISTS mu_dias_data ON mu_dias (data);
      CREATE TABLE IF NOT EXISTS mu_gastos (
        id TEXT PRIMARY KEY,
        data DATE NOT NULL,
        d JSONB NOT NULL,
        criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS mu_abast (
        id TEXT PRIMARY KEY,
        km NUMERIC NOT NULL,
        d JSONB NOT NULL,
        criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);
    if (!SECRET) {
      const r = await pool.query(`SELECT v FROM mu_config WHERE k='secret'`);
      if (r.rows[0]) SECRET = r.rows[0].v;
      else {
        SECRET = crypto.randomBytes(32).toString('hex');
        await pool.query(`INSERT INTO mu_config (k, v) VALUES ('secret', $1) ON CONFLICT (k) DO NOTHING`, [JSON.stringify(SECRET)]);
        const r2 = await pool.query(`SELECT v FROM mu_config WHERE k='secret'`);
        SECRET = r2.rows[0].v;
      }
    }
    dbOk = true; dbErro = null;
    console.log('[db] conectado e tabelas prontas');
  } catch (e) {
    dbOk = false; dbErro = e.message;
    console.error('[db] falha ao conectar:', e.message);
    setTimeout(iniciarBanco, 15000); // tenta de novo
  }
}

async function getCfg(k) {
  const r = await pool.query('SELECT v FROM mu_config WHERE k=$1', [k]);
  return r.rows[0] ? r.rows[0].v : null;
}
async function setCfg(k, v) {
  await pool.query(
    'INSERT INTO mu_config (k, v) VALUES ($1, $2) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v',
    [k, JSON.stringify(v)]
  );
}

// ---------- PIN e sessão ----------
const hashPin = (pin, salt) => crypto.scryptSync(String(pin), salt, 32).toString('hex');
const pinValido = p => /^\d{4,8}$/.test(String(p || ''));

function token(versao) {
  const exp = Date.now() + 1000 * 60 * 60 * 24 * 90; // 90 dias
  const corpo = `${versao}.${exp}`;
  const sig = crypto.createHmac('sha256', SECRET).update(corpo).digest('hex');
  return `${corpo}.${sig}`;
}
async function autenticar(req, res, next) {
  if (!dbOk) return res.status(503).json({ erro: 'Banco indisponível' });
  try {
    const t = (req.get('authorization') || '').replace(/^Bearer\s+/i, '');
    const [versao, exp, sig] = t.split('.');
    if (!sig) throw 0;
    const esperado = crypto.createHmac('sha256', SECRET).update(`${versao}.${exp}`).digest('hex');
    if (sig.length !== esperado.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(esperado))) throw 0;
    if (Date.now() > +exp) throw 0;
    const pin = await getCfg('pin');
    if (!pin || String(pin.versao) !== versao) throw 0; // PIN trocado invalida sessões antigas
    next();
  } catch (_) {
    res.status(401).json({ erro: 'Sessão expirada. Digite o PIN.' });
  }
}

// limite de tentativas de PIN (por IP)
const tentativas = new Map();
function bloqueado(ip) {
  const t = tentativas.get(ip);
  return t && t.ate > Date.now() ? Math.ceil((t.ate - Date.now()) / 1000) : 0;
}
function falhou(ip) {
  const t = tentativas.get(ip) || { n: 0, ate: 0 };
  t.n++;
  if (t.n >= 5) { t.ate = Date.now() + 5 * 60 * 1000; t.n = 0; }
  tentativas.set(ip, t);
}

// ---------- Rotas ----------
const wrap = fn => (req, res) => fn(req, res).catch(e => {
  console.error('[api]', e.message);
  res.status(500).json({ erro: 'Erro no servidor' });
});

app.get('/api/status', wrap(async (req, res) => {
  let pinDefinido = false;
  if (dbOk) pinDefinido = !!(await getCfg('pin'));
  res.json({ db: dbOk, pinDefinido, aviso: dbOk ? null : dbErro });
}));

app.post('/api/pin/criar', wrap(async (req, res) => {
  if (!dbOk) return res.status(503).json({ erro: 'Banco indisponível' });
  const { pin } = req.body || {};
  if (!pinValido(pin)) return res.status(400).json({ erro: 'O PIN precisa ter de 4 a 8 números' });
  if (await getCfg('pin')) return res.status(409).json({ erro: 'PIN já foi criado' });
  const salt = crypto.randomBytes(16).toString('hex');
  const dados = { salt, hash: hashPin(pin, salt), versao: 1 };
  await setCfg('pin', dados);
  res.json({ token: token(dados.versao) });
}));

app.post('/api/login', wrap(async (req, res) => {
  if (!dbOk) return res.status(503).json({ erro: 'Banco indisponível' });
  const ip = req.ip;
  const espera = bloqueado(ip);
  if (espera) return res.status(429).json({ erro: `Muitas tentativas. Aguarde ${Math.ceil(espera / 60)} min.` });
  const dados = await getCfg('pin');
  if (!dados) return res.status(400).json({ erro: 'Crie um PIN primeiro' });
  const { pin } = req.body || {};
  const h = hashPin(pin, dados.salt);
  if (!pinValido(pin) || !crypto.timingSafeEqual(Buffer.from(h), Buffer.from(dados.hash))) {
    falhou(ip);
    return res.status(401).json({ erro: 'PIN incorreto' });
  }
  tentativas.delete(ip);
  res.json({ token: token(dados.versao) });
}));

app.post('/api/pin/trocar', autenticar, wrap(async (req, res) => {
  const { atual, novo } = req.body || {};
  const dados = await getCfg('pin');
  if (hashPin(atual, dados.salt) !== dados.hash) return res.status(401).json({ erro: 'PIN atual incorreto' });
  if (!pinValido(novo)) return res.status(400).json({ erro: 'O novo PIN precisa ter de 4 a 8 números' });
  const salt = crypto.randomBytes(16).toString('hex');
  const novoDados = { salt, hash: hashPin(novo, salt), versao: (dados.versao || 1) + 1 };
  await setCfg('pin', novoDados);
  res.json({ token: token(novoDados.versao) });
}));

app.get('/api/dados', autenticar, wrap(async (req, res) => {
  const cfg = await getCfg('cfg');
  const r = await pool.query('SELECT d FROM mu_dias ORDER BY data, criado_em');
  const a = await pool.query('SELECT d FROM mu_abast ORDER BY km, criado_em');
  const g = await pool.query('SELECT d FROM mu_gastos ORDER BY data, criado_em');
  res.json({ cfg, dias: r.rows.map(x => x.d), abast: a.rows.map(x => x.d), gastos: g.rows.map(x => x.d) });
}));

app.put('/api/cfg', autenticar, wrap(async (req, res) => {
  const cfg = req.body;
  if (!cfg || typeof cfg !== 'object') return res.status(400).json({ erro: 'Ajustes inválidos' });
  await setCfg('cfg', cfg);
  res.json({ ok: true });
}));

function limparDia(d) {
  const n = v => { const x = Number(v); return Number.isFinite(x) ? x : 0; };
  if (!d || !/^\d{4}-\d{2}-\d{2}$/.test(d.data) || !d.id) return null;
  return {
    id: String(d.id).slice(0, 40), data: d.data,
    kmI: n(d.kmI), kmF: n(d.kmF), horas: n(d.horas),
    uber: n(d.uber), d99: n(d.d99), bonus: n(d.bonus), abast: n(d.abast),
    hIni: /^\d{2}:\d{2}$/.test(d.hIni) ? d.hIni : '', hFim: /^\d{2}:\d{2}$/.test(d.hFim) ? d.hFim : '',
    intervalo: n(d.intervalo),
  };
}

function limparAbast(d) {
  const n = v => { const x = Number(v); return Number.isFinite(x) ? x : 0; };
  if (!d || !/^\d{4}-\d{2}-\d{2}$/.test(d.data) || !d.id || !(n(d.litros) > 0)) return null;
  return {
    id: String(d.id).slice(0, 40), data: d.data, km: n(d.km), litros: n(d.litros),
    valor: n(d.valor), comb: d.comb === 'etanol' ? 'etanol' : 'gasolina', cheio: d.cheio !== false,
  };
}
async function gravarAbast(db, a) {
  await db.query(
    'INSERT INTO mu_abast (id, km, d) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET km = EXCLUDED.km, d = EXCLUDED.d',
    [a.id, a.km, JSON.stringify(a)]
  );
}
app.post('/api/abast', autenticar, wrap(async (req, res) => {
  const a = limparAbast(req.body);
  if (!a) return res.status(400).json({ erro: 'Abastecimento inválido' });
  await gravarAbast(pool, a);
  res.json({ ok: true, abast: a });
}));
app.delete('/api/abast/:id', autenticar, wrap(async (req, res) => {
  await pool.query('DELETE FROM mu_abast WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
}));

const CATS = ['lanche', 'agua', 'cafe', 'lavagem', 'estacionamento', 'outro'];
function limparGasto(d) {
  const v = Number(d && d.valor);
  if (!d || !/^\d{4}-\d{2}-\d{2}$/.test(d.data) || !d.id || !(v > 0)) return null;
  return {
    id: String(d.id).slice(0, 40), data: d.data, valor: v,
    cat: CATS.includes(d.cat) ? d.cat : 'outro', desc: String(d.desc || '').slice(0, 80),
    pessoal: d.pessoal === true,
  };
}
async function gravarGasto(db, g) {
  await db.query(
    'INSERT INTO mu_gastos (id, data, d) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, d = EXCLUDED.d',
    [g.id, g.data, JSON.stringify(g)]
  );
}
app.post('/api/gastos', autenticar, wrap(async (req, res) => {
  const g = limparGasto(req.body);
  if (!g) return res.status(400).json({ erro: 'Gasto inválido' });
  await gravarGasto(pool, g);
  res.json({ ok: true, gasto: g });
}));
app.delete('/api/gastos/:id', autenticar, wrap(async (req, res) => {
  await pool.query('DELETE FROM mu_gastos WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
}));

app.post('/api/dias', autenticar, wrap(async (req, res) => {
  const d = limparDia(req.body);
  if (!d) return res.status(400).json({ erro: 'Dia inválido' });
  await pool.query(
    'INSERT INTO mu_dias (id, data, d) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, d = EXCLUDED.d',
    [d.id, d.data, JSON.stringify(d)]
  );
  res.json({ ok: true, dia: d });
}));

app.delete('/api/dias/:id', autenticar, wrap(async (req, res) => {
  await pool.query('DELETE FROM mu_dias WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
}));

// importa (mescla) dias e, opcionalmente, ajustes — usado na migração do celular e no restaurar backup
app.post('/api/importar', autenticar, wrap(async (req, res) => {
  const { cfg, dias, abast, gastos, substituir } = req.body || {};
  const listaG = (Array.isArray(gastos) ? gastos : []).map(limparGasto).filter(Boolean);
  const lista = (Array.isArray(dias) ? dias : []).map(limparDia).filter(Boolean);
  const listaA = (Array.isArray(abast) ? abast : []).map(limparAbast).filter(Boolean);
  const cli = await pool.connect();
  try {
    await cli.query('BEGIN');
    if (substituir) { await cli.query('DELETE FROM mu_dias'); await cli.query('DELETE FROM mu_abast'); await cli.query('DELETE FROM mu_gastos'); }
    for (const a of listaA) await gravarAbast(cli, a);
    for (const g of listaG) await gravarGasto(cli, g);
    for (const d of lista) {
      await cli.query(
        'INSERT INTO mu_dias (id, data, d) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, d = EXCLUDED.d',
        [d.id, d.data, JSON.stringify(d)]
      );
    }
    if (cfg && typeof cfg === 'object') {
      await cli.query(
        `INSERT INTO mu_config (k, v) VALUES ('cfg', $1) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v`,
        [JSON.stringify(cfg)]
      );
    }
    await cli.query('COMMIT');
  } catch (e) {
    await cli.query('ROLLBACK'); throw e;
  } finally { cli.release(); }
  res.json({ ok: true, importados: lista.length });
}));

app.post('/api/apagar-tudo', autenticar, wrap(async (req, res) => {
  await pool.query('DELETE FROM mu_dias');
  await pool.query('DELETE FROM mu_abast');
  await pool.query('DELETE FROM mu_gastos');
  await pool.query(`DELETE FROM mu_config WHERE k = 'cfg'`);
  res.json({ ok: true });
}));

app.get('/saude', (req, res) => res.json({ ok: true, db: dbOk }));

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.set('trust proxy', 1);
app.listen(PORT, () => console.log(`Meta Uber rodando na porta ${PORT}`));
iniciarBanco();
