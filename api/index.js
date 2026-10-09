'use strict';
/*
 * FEES server. The ONLY thing allowed to write to the database (Firebase rules: write=false).
 * Env vars (Vercel -> Settings -> Environment Variables):
 *   ADMIN_PIN                 admin passcode (never sent to the browser)
 *   SESSION_SECRET            long random string (32+ chars)
 *   FIREBASE_SERVICE_ACCOUNT  service-account JSON (raw or base64)
 *   FIREBASE_DATABASE_URL     optional, defaults to the mac-fee database
 */
const crypto = require('crypto');

const DB_URL = process.env.FIREBASE_DATABASE_URL || 'https://mac-fee-default-rtdb.asia-southeast1.firebasedatabase.app';
const TZ = 'Asia/Kolkata';
const COOKIE = 'fees_s';
const SESSION_MS = 12 * 3600 * 1000;      // refreshed on every admin call
const SESSION_MAX_MS = 7 * 24 * 3600 * 1000;
const MAX_AMOUNT = 100000;

/* ---------- db ---------- */
let _db = null;
function getDb() {
  if (_db) return _db;
  const admin = require('firebase-admin');
  let raw = process.env.FIREBASE_SERVICE_ACCOUNT || '';
  if (!raw) throw new Error('FIREBASE_SERVICE_ACCOUNT missing');
  if (raw[0] !== '{') raw = Buffer.from(raw, 'base64').toString('utf8');
  if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(JSON.parse(raw)), databaseURL: DB_URL });
  return (_db = admin.database());
}
const val = async (path) => (await getDb().ref(path).get()).val();
let _test = false;
async function pubVal(path) {            // public data only: works even if admin env vars are missing
  if (_test) return val(path);
  const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), 8000);
  try {
    const r = await fetch(`${DB_URL}/${path}.json`, { signal: ctl.signal });
    if (!r.ok) throw new Error('database read failed: ' + r.status);
    return await r.json();
  } finally { clearTimeout(t); }
}

/* ---------- crypto helpers ---------- */
const secret = () => {
  const s = process.env.SESSION_SECRET || '';
  if (s.length < 32) throw new Error('SESSION_SECRET must be 32+ chars');
  return s;
};
const hmac = (s, n) => crypto.createHmac('sha256', secret()).update(s).digest('hex').slice(0, n || 64);
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

function makeToken(iat) {
  const now = Date.now();
  const body = b64u({ iat: iat || now, exp: now + SESSION_MS });
  return body + '.' + hmac('s.' + body);
}
function readToken(req) {
  const m = (req.headers.cookie || '').match(new RegExp('(?:^|; )' + COOKIE + '=([^;]+)'));
  if (!m) return null;
  const [body, sig] = m[1].split('.');
  if (!body || !sig || !safeEq(sig, hmac('s.' + body))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    const now = Date.now();
    if (!(p.exp > now) || !(p.iat > now - SESSION_MAX_MS)) return null;
    return p;
  } catch (e) { return null; }
}
function setCookie(res, req, token, maxAge) {
  const local = /^(localhost|127\.)/.test(req.headers.host || '');
  res.setHeader('Set-Cookie', `${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/api; Max-Age=${maxAge}${local ? '' : '; Secure'}`);
}

/* ---------- http helpers ---------- */
const clientIp = (req) => String(req.headers['x-vercel-forwarded-for'] || req.headers['x-forwarded-for'] || (req.socket && req.socket.remoteAddress) || 'x').split(',')[0].trim();
const send = (res, code, obj, extra) => {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.end(JSON.stringify(Object.assign({ ok: code < 400 }, obj, extra)));
};
const fail = (res, code, error, extra) => send(res, code, { error }, extra);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function body(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  let s = '';
  for await (const c of req) { s += c; if (s.length > 20000) break; }
  try { return JSON.parse(s || '{}'); } catch (e) { return {}; }
}

/* ---------- PIN throttle (shared via DB so it survives cold starts) ---------- */
async function checkPin(req, pin) {
  const expected = process.env.ADMIN_PIN || '';
  if (expected.length < 6) throw new Error('ADMIN_PIN must be 6+ chars');
  const key = 'fees_private/throttle/' + hmac('ip.' + clientIp(req), 24);
  const t = (await val(key)) || { n: 0, lvl: 0, until: 0 };
  const now = Date.now();
  if (t.until > now) return { ok: false, code: 429, error: 'Too many wrong attempts. Try again later.', retryAfter: Math.ceil((t.until - now) / 1000) };
  const good = typeof pin === 'string' && pin.length <= 64 && safeEq(pin, expected);
  if (good) {
    if (t.n || t.lvl) await getDb().ref(key).remove();
    return { ok: true };
  }
  t.n++;
  let left = 5 - t.n, until = 0;
  if (t.n >= 5) { until = now + Math.min(5 * 60000 * Math.pow(2, t.lvl), 24 * 3600000); t.lvl++; t.n = 0; left = 0; }
  await getDb().ref(key).set({ n: t.n, lvl: t.lvl, until, ts: now });
  await sleep(700);                       // slow every guess
  return until
    ? { ok: false, code: 429, error: 'Too many wrong attempts. Locked for a while.', retryAfter: Math.ceil((until - now) / 1000) }
    : { ok: false, code: 401, error: 'Incorrect PIN', left };
}

/* ---------- small validators / formatters ---------- */
const int = (v, lo, hi) => { const n = Number(v); return Number.isInteger(n) && n >= lo && n <= hi ? n : null; };
const clean = (s, n) => String(s == null ? '' : s).replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, n);
const REC = /^REC-\d{1,9}$/;
const numId = (r) => +String(r.id || '').replace(/\D/g, '') || 0;
const fmtDate = (d) => d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: TZ });
const fmtTime = (d) => d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', timeZone: TZ });
const list = (o) => Object.values(o || {}).filter(Boolean);

function installment(all, r) {
  const prior = all.filter(x => x.planId === r.planId && x.sl === r.sl && x.status === 'VALID' && numId(x) < numId(r));
  const prev = prior.reduce((a, x) => a + x.total, 0), cum = prev + r.total, diff = cum - r.planTarget;
  return { prev, cum, inst: prior.length + 1, due: diff < 0 ? -diff : 0, extra: diff > 0 ? diff : 0 };
}

/* ---------- public: verify (returns ONLY the one receipt, only if the key matches) ---------- */
const hits = new Map();
function limited(ip, max) {
  const now = Date.now(), h = (hits.get(ip) || []).filter(t => now - t < 60000);
  h.push(now); hits.set(ip, h);
  if (hits.size > 5000) hits.clear();
  return h.length > max;
}
async function verify(req, res, q) {
  if (limited(clientIp(req), 40)) return fail(res, 429, 'Too many checks. Wait a minute.');
  const id = clean(q.id, 20).toUpperCase(), k = clean(q.k, 40).toUpperCase();
  if (!k || (id && !REC.test(id))) return send(res, 200, { valid: false });
  let r = null;
  if (id) r = await pubVal('fees/receipts/' + id);
  else r = list(await pubVal('fees/receipts')).find(x => x.secKey && safeEq(String(x.secKey).toUpperCase(), k));
  if (!r || !r.secKey || !safeEq(String(r.secKey).toUpperCase(), k)) return send(res, 200, { valid: false });
  const all = list(await pubVal('fees/receipts'));
  const c = installment(all, r);
  send(res, 200, {
    valid: true, id: r.id, status: r.status, student: r.studentName, sl: r.sl, plan: r.planTitle, target: r.planTarget,
    total: r.total, cash: r.cash, upi: r.upi, date: r.date, time: r.timestamp, collector: r.collector,
    cum: c.cum, due: c.due, extra: c.extra, inst: c.inst,
    reason: r.status === 'DELETED' ? clean(r.deleteReason, 160) : undefined, deletedDate: r.deletedDate
  });
}

/* ---------- admin operations ---------- */
const SENSITIVE = new Set(['issue', 'delete', 'restore']);   // need PIN again, every time

async function migrate() {
  // moves phone numbers out of public data (one time)
  const db = getDb();
  if (await val('fees_private/migrated')) return;
  const up = {}, rec = await val('fees/receipts') || {}, old = await val('fees/phones') || {};
  Object.keys(old).forEach(k => { if (/^p\d+$/.test(k)) up['fees_private/phones/' + k] = String(old[k]).slice(0, 20); });
  Object.keys(rec).forEach(id => {
    const r = rec[id];
    if (r && r.phone) { if (r.sl) up['fees_private/phones/p' + r.sl] = up['fees_private/phones/p' + r.sl] || String(r.phone).slice(0, 20); up['fees/receipts/' + id + '/phone'] = null; }
  });
  up['fees/phones'] = null; up['fees_private/migrated'] = Date.now();
  await db.ref().update(up);
}

const OPS = {
  async phones() { return { phones: (await val('fees_private/phones')) || {} }; },

  async issue(d) {
    const db = getDb();
    const sl = int(d.sl, 1, 9999), cash = int(d.cash == null ? 0 : d.cash, 0, MAX_AMOUNT), upi = int(d.upi == null ? 0 : d.upi, 0, MAX_AMOUNT);
    if (!sl || cash == null || upi == null || cash + upi <= 0) return { code: 400, error: 'Enter a valid amount' };
    const [student, plan, rec, counter] = await Promise.all([val('fees/students/s' + sl), val('fees/plans/' + clean(d.planId, 60)), val('fees/receipts'), val('fees/counter')]);
    if (!student || !plan) return { code: 400, error: 'Unknown student or plan' };
    const all = list(rec);
    const paid = all.filter(x => x.planId === plan.id && x.sl === sl && x.status === 'VALID').reduce((a, x) => a + x.total, 0);
    if (paid >= plan.target) return { code: 409, error: `${student.name} has already paid in full` };
    const maxId = all.reduce((m, x) => Math.max(m, numId(x)), 0);
    const tx = await db.ref('fees/counter').transaction(c => Math.max(c == null ? 1001 : c, maxId + 1, counter || 0) + 1);
    const num = tx.snapshot.val() - 1, id = 'REC-' + num, now = new Date();
    const phone = String(d.phone || '').replace(/\D/g, '');
    if (phone && (phone.length < 10 || phone.length > 13)) return { code: 400, error: 'Check the phone number' };
    const r = {
      id, planId: plan.id, planTitle: plan.title, planTarget: plan.target, sl, studentName: student.name,
      date: fmtDate(now), timestamp: fmtTime(now), cash, upi, upiId: (upi > 0 && clean(d.upiRef, 40)) || 'N/A', total: cash + upi,
      collector: plan.officer, secKey: 'SEC-' + hmac(`${id}|${sl}|${cash + upi}|${now.getTime()}|${crypto.randomBytes(8).toString('hex')}`, 12).toUpperCase(),
      status: 'VALID'
    };
    const up = { ['fees/receipts/' + id]: r };
    if (phone) up['fees_private/phones/p' + sl] = phone;
    await db.ref().update(up);
    return { receipt: r };
  },

  async void(d) {
    if (!REC.test(d.id)) return { code: 400, error: 'Bad id' };
    const r = await val('fees/receipts/' + d.id);
    if (!r || (r.status !== 'VALID' && r.status !== 'VOID')) return { code: 409, error: 'Cannot change this receipt' };
    const next = r.status === 'VALID' ? 'VOID' : 'VALID';
    await getDb().ref('fees/receipts/' + d.id + '/status').set(next);
    return { status: next };
  },

  async delete(d) {
    if (!REC.test(d.id)) return { code: 400, error: 'Bad id' };
    const reason = clean(d.reason, 160);
    if (!reason) return { code: 400, error: 'Reason required' };
    const r = await val('fees/receipts/' + d.id);
    if (!r || r.status === 'DELETED') return { code: 409, error: 'Cannot delete this receipt' };
    const now = new Date();
    await getDb().ref('fees/receipts/' + d.id).update({
      status: 'DELETED', deleteReason: reason, deleteCat: d.test ? 'TEST' : null, deletedAt: now.getTime(), deletedDate: fmtDate(now)
    });
    return {};
  },

  async restore(d) {
    if (!REC.test(d.id)) return { code: 400, error: 'Bad id' };
    const r = await val('fees/receipts/' + d.id);
    if (!r || r.status !== 'DELETED') return { code: 409, error: 'Not a deleted receipt' };
    await getDb().ref('fees/receipts/' + d.id).update({ status: 'VALID', deleteReason: null, deleteCat: null, deletedAt: null, deletedDate: null });
    return {};
  },

  async settle(d) {
    const sl = int(d.sl, 1, 9999), planId = clean(d.planId, 60);
    const [plan, rec] = await Promise.all([val('fees/plans/' + planId), val('fees/receipts')]);
    if (!sl || !plan) return { code: 400, error: 'Bad request' };
    const paid = list(rec).filter(x => x.planId === planId && x.sl === sl && x.status === 'VALID').reduce((a, x) => a + x.total, 0);
    if (paid <= plan.target) return { code: 409, error: 'No extra money' };
    const now = new Date(), key = (planId + '__s' + sl).replace(/[.#$\[\]\/]/g, '_');
    await getDb().ref('fees/settled/' + key).set({ planId, sl, amount: paid - plan.target, ts: now.getTime(), date: fmtDate(now) });
    return {};
  },
  async unsettle(d) {
    const sl = int(d.sl, 1, 9999), planId = clean(d.planId, 60);
    if (!sl) return { code: 400, error: 'Bad request' };
    await getDb().ref('fees/settled/' + (planId + '__s' + sl).replace(/[.#$\[\]\/]/g, '_')).remove();
    return {};
  },

  async handover(d) {
    const amt = int(d.amount, 1, 1000000), mode = d.mode === 'GPAY' ? 'GPAY' : d.mode === 'CASH' ? 'CASH' : null, planId = clean(d.planId, 60);
    if (!amt || !mode) return { code: 400, error: 'Enter a valid amount' };
    const [plan, rec, hs] = await Promise.all([val('fees/plans/' + planId), val('fees/receipts'), val('fees/handovers')]);
    if (!plan) return { code: 400, error: 'Unknown plan' };
    const field = mode === 'CASH' ? 'cash' : 'upi';
    const inn = list(rec).filter(x => x.planId === planId && x.status === 'VALID').reduce((a, x) => a + x[field], 0);
    const out = list(hs).filter(h => h.planId === planId && h.mode === mode).reduce((a, h) => a + h.amount, 0);
    if (amt > inn - out) return { code: 409, error: `Only ₹${Math.max(0, inn - out)} available` };
    const now = new Date(), id = 'H' + now.getTime().toString(36).toUpperCase() + crypto.randomBytes(2).toString('hex').toUpperCase();
    await getDb().ref('fees/handovers/' + id).set({ id, planId, mode, amount: amt, note: clean(d.note, 80), date: fmtDate(now), timestamp: fmtTime(now), ts: now.getTime() });
    return {};
  },
  async unhandover(d) {
    if (!/^H[A-Z0-9]{4,20}$/.test(d.id || '')) return { code: 400, error: 'Bad id' };
    await getDb().ref('fees/handovers/' + d.id).remove();
    return {};
  },

  async addStudent(d) {
    const sl = int(d.sl, 1, 999), name = clean(d.name, 60).toUpperCase();
    if (!sl || name.length < 2) return { code: 400, error: 'Enter name and roll number' };
    if (await val('fees/students/s' + sl)) return { code: 409, error: 'That roll number already exists' };
    await getDb().ref('fees/students/s' + sl).set({ sl, name });
    return {};
  },
  async addPlan(d) {
    const title = clean(d.title, 50).toUpperCase(), target = int(d.target, 1, MAX_AMOUNT);
    if (title.length < 2 || !target) return { code: 400, error: 'Enter title and amount' };
    const id = 'plan_' + Date.now().toString(36) + crypto.randomBytes(2).toString('hex');
    await getDb().ref('fees/plans/' + id).set({ id, code: title.replace(/\W+/g, '_'), title, target, officer: clean(d.officer, 40) || 'Class Rep' });
    return { id };
  }
};

/* ---------- entry ---------- */
async function handler(req, res) {
  try {
    const url = new URL(req.url, 'http://x');
    const q = Object.fromEntries(url.searchParams);
    if (req.method === 'GET' && q.op === 'verify') return await verify(req, res, q);
    if (req.method === 'GET' && q.op === 'health') {
      let sa = false; try { sa = !!getDb(); } catch (e) {}
      return send(res, 200, { ADMIN_PIN: (process.env.ADMIN_PIN || '').length >= 6, SESSION_SECRET: (process.env.SESSION_SECRET || '').length >= 32, FIREBASE_SERVICE_ACCOUNT: sa });
    }

    if (req.method !== 'POST') return fail(res, 405, 'Method not allowed');
    // CSRF: same-origin only + custom header
    const origin = req.headers.origin, host = req.headers.host;
    if (!req.headers['x-fees'] || (origin && new URL(origin).host !== host)) return fail(res, 403, 'Forbidden');
    if (!/application\/json/.test(req.headers['content-type'] || '')) return fail(res, 415, 'JSON only');

    const d = await body(req), op = String(d.op || '');

    if (op === 'login') {
      const c = await checkPin(req, String(d.pin || ''));
      if (!c.ok) return fail(res, c.code, c.error, { left: c.left, retryAfter: c.retryAfter });
      setCookie(res, req, makeToken(), SESSION_MS / 1000);
      migrate().catch(() => {});
      return send(res, 200, { admin: true });
    }
    if (op === 'logout') { setCookie(res, req, '', 0); return send(res, 200, { admin: false }); }

    const sess = readToken(req);
    if (op === 'session') {
      if (sess) setCookie(res, req, makeToken(sess.iat), SESSION_MS / 1000);
      return send(res, 200, { admin: !!sess });
    }
    if (!sess) return fail(res, 401, 'Admin login required', { code: 'NOSESSION' });
    if (!Object.prototype.hasOwnProperty.call(OPS, op)) return fail(res, 404, 'Unknown action');

    if (SENSITIVE.has(op)) {
      const c = await checkPin(req, String(d.pin || ''));
      if (!c.ok) return fail(res, c.code, c.error, { left: c.left, retryAfter: c.retryAfter });
    }
    const out = await OPS[op](d);
    setCookie(res, req, makeToken(sess.iat), SESSION_MS / 1000);
    if (out && out.code) return fail(res, out.code, out.error);
    return send(res, 200, out || {});
  } catch (e) {
    console.error('api error', e && e.message);
    return fail(res, 500, 'Server error');
  }
}

module.exports = handler;
module.exports.__setDb = (d) => { _db = d; _test = true; };
