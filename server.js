process.env.TZ = 'Asia/Kuwait';
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const Database = require('better-sqlite3');
const E = process.env;
const db = new Database(path.join(E.DATA_DIR || __dirname, 'data.db'));
db.exec(`CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS msgs(wamid TEXT PRIMARY KEY, pid INTEGER, status TEXT);
CREATE TABLE IF NOT EXISTS pst(pid INTEGER PRIMARY KEY, status TEXT);
CREATE TABLE IF NOT EXISTS asent(pid INTEGER, kind TEXT, key TEXT, PRIMARY KEY(pid,kind));
CREATE TABLE IF NOT EXISTS alog(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, txt TEXT)`);

const app = express();
app.use(express.json({ limit: '2mb', verify: (req, _r, buf) => { req.raw = buf; } }));

// صلاحيتان: المدير (DASH_KEY) والموظف (STAFF_KEY اختياري)
const roleOf = req => {
  const k = req.get('x-api-key');
  if (E.DASH_KEY && k === E.DASH_KEY) return 'manager';
  if (E.STAFF_KEY && k === E.STAFF_KEY) return 'staff';
  return null;
};
const auth = (req, res, next) => {
  const r = roleOf(req);
  if (!r) return res.status(401).json({ error: 'unauthorized' });
  req.role = r; next();
};
const mgr = (req, res, next) => req.role === 'manager' ? next() : res.status(403).json({ error: 'manager only' });

app.get('/api/ping', (_q, r) => r.json({ ok: true }));
app.get('/api/whoami', auth, (q, r) => r.json({ role: q.role }));

app.get('/api/state', auth, (_q, r) => {
  const row = db.prepare("SELECT v FROM kv WHERE k='state'").get();
  if (!row) return r.json({ empty: true });
  const s = JSON.parse(row.v);
  const st = Object.fromEntries(db.prepare('SELECT pid,status FROM pst').all().map(x => [x.pid, x.status]));
  (s.pil || []).forEach(p => { p.st = st[p.id]; });
  r.json(s);
});

app.put('/api/state', auth, (q, r) => {
  const s = q.body || {};
  if (q.role === 'staff') { // الموظف لا يحذف ولا يغيّر الأتمتة
    const row = db.prepare("SELECT v FROM kv WHERE k='state'").get();
    const old = row ? JSON.parse(row.v) : {};
    const n = (a, b) => (a || []).length < (b || []).length;
    if (n(s.pil, old.pil) || n(s.rooms, old.rooms) || n(s.bus, old.bus)) return r.status(403).json({ error: 'manager only' });
    s.auto = old.auto; s.tpl = old.tpl;
  }
  (s.pil || []).forEach(p => { delete p.st; });
  delete s.tab;
  db.prepare("INSERT INTO kv(k,v) VALUES('state',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").run(JSON.stringify(s));
  r.json({ ok: true });
});

const when = t => t ? new Date(t).toLocaleString('ar-KW', { dateStyle: 'medium', timeStyle: 'short' }) : '-';
const phone = p => { p = String(p).replace(/\D/g, ''); return p.length === 8 ? '965' + p : p; };
const setStatus = (pid, status) => db.prepare('INSERT INTO pst(pid,status) VALUES(?,?) ON CONFLICT(pid) DO UPDATE SET status=excluded.status').run(pid, status);

async function sendTpl(p, tpl, params) {
  const res = await fetch(`https://graph.facebook.com/v21.0/${E.WA_PHONE_ID}/messages`, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + E.WA_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      messaging_product: 'whatsapp', to: phone(p.p), type: 'template',
      template: { name: tpl, language: { code: E.WA_LANG || 'ar' },
        components: [{ type: 'body', parameters: params.map(text => ({ type: 'text', text: String(text) })) }] }
    })
  });
  const j = await res.json();
  if (!res.ok) throw new Error(j.error && j.error.message || 'send failed');
  db.prepare('INSERT OR REPLACE INTO msgs(wamid,pid,status) VALUES(?,?,?)').run(j.messages[0].id, p.id, 'sent');
  setStatus(p.id, 'sent');
}
const seatKey = (p, bus) => [p.bus, p.seat, bus && bus.time].join('|');
const mark = (pid, kind, key) => db.prepare('INSERT OR REPLACE INTO asent(pid,kind,key) VALUES(?,?,?)').run(pid, kind, key);
async function sendOne(p, bus) {
  await sendTpl(p, E.WA_TEMPLATE || 'hajj_bus_info', [p.n, p.bus || '-', p.seat || '-', when(bus && bus.time), p.room || '-']);
  mark(p.id, 'seat', seatKey(p, bus));
}

app.post('/api/send', auth, mgr, async (q, r) => {
  const row = db.prepare("SELECT v FROM kv WHERE k='state'").get();
  if (!row) return r.status(400).json({ error: 'no state' });
  const s = JSON.parse(row.v);
  let ok = 0, fail = 0; const errors = [];
  for (const id of (q.body.ids || [])) {
    const p = (s.pil || []).find(x => x.id == id);
    if (!p) continue;
    try { await sendOne(p, (s.bus || []).find(b => b.no == p.bus)); ok++; }
    catch (e) { fail++; setStatus(p.id, 'failed'); errors.push({ id, error: e.message }); }
    await new Promise(z => setTimeout(z, 120)); // تخفيف سرعة الإرسال
  }
  r.json({ ok, fail, errors });
});

// ويب هوك ميتا: التحقق + حالات التسليم
app.get('/webhook', (q, r) =>
  q.query['hub.verify_token'] === E.WA_VERIFY_TOKEN ? r.send(q.query['hub.challenge']) : r.sendStatus(403));

app.post('/webhook', (q, r) => {
  if (E.WA_APP_SECRET) {
    const sig = 'sha256=' + crypto.createHmac('sha256', E.WA_APP_SECRET).update(q.raw || '').digest('hex');
    const got = q.get('x-hub-signature-256') || '';
    if (sig.length !== got.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(got))) return r.sendStatus(401);
  }
  const rank = { sent: 1, delivered: 2, read: 3, failed: 4 };
  for (const en of q.body.entry || []) for (const ch of en.changes || [])
    for (const st of (ch.value && ch.value.statuses) || []) {
      const m = db.prepare('SELECT pid FROM msgs WHERE wamid=?').get(st.id);
      if (!m || !rank[st.status]) continue;
      const cur = db.prepare('SELECT status FROM pst WHERE pid=?').get(m.pid);
      if (!cur || st.status === 'failed' || (rank[st.status] > (rank[cur.status] || 0))) setStatus(m.pid, st.status);
    }
  r.sendStatus(200);
});


// ===== الأتمتة: إرسال عند تحديد المقعد + تذكير قبل التحرك =====
const log = t => db.prepare('INSERT INTO alog(ts,txt) VALUES(?,?)').run(Date.now(), t);
app.get('/api/log', auth, mgr, (_q, r) => r.json(db.prepare('SELECT ts,txt FROM alog ORDER BY id DESC LIMIT 40').all()));
const seen = new Map();
const lastKey = (pid, kind) => (db.prepare('SELECT key FROM asent WHERE pid=? AND kind=?').get(pid, kind) || {}).key;
async function tick() {
  if (!E.WA_TOKEN || !E.WA_PHONE_ID) return;
  const row = db.prepare("SELECT v FROM kv WHERE k='state'").get();
  if (!row) return;
  const s = JSON.parse(row.v), a = s.auto || {}, now = Date.now();
  let n = 0;
  for (const p of s.pil || []) {
    if (n >= 20 || !p.p) continue;
    const bus = (s.bus || []).find(b => b.no == p.bus);
    if (a.onSeat && p.bus && p.seat) {
      const key = seatKey(p, bus);
      if (!seen.has(p.id) || seen.get(p.id).key !== key) seen.set(p.id, { key, since: now });
      if (lastKey(p.id, 'seat') !== key && now - seen.get(p.id).since >= 120000) { // تأخير دقيقتين حتى يستقر التعديل
        n++;
        try { await sendOne(p, bus); log('رسالة المقعد ← ' + p.n); }
        catch (e) { mark(p.id, 'seat', key); setStatus(p.id, 'failed'); log('فشل إرسال ' + p.n + ': ' + e.message); }
      }
    }
    if (a.remind && bus && bus.time && p.seat) {
      const bt = new Date(bus.time).getTime(), key = p.bus + '|' + bus.time;
      if (now < bt && now >= bt - (a.hours || 2) * 3600e3 && lastKey(p.id, 'remind') !== key) {
        n++; mark(p.id, 'remind', key);
        try { await sendTpl(p, E.WA_TEMPLATE_REMIND || 'hajj_bus_reminder', [p.n, p.bus, p.seat, when(bus.time)]); log('تذكير ← ' + p.n); }
        catch (e) { log('فشل تذكير ' + p.n + ': ' + e.message); }
      }
    }
    await new Promise(z => setTimeout(z, 100));
  }
}
let busy = false;
setInterval(async () => { if (busy) return; busy = true; try { await tick(); } catch (e) { console.error(e); } busy = false; }, 30000);


// ===== تذاكر الطيران =====
const fs = require('fs');
const TDIR = path.join(E.DATA_DIR || __dirname, 'tickets');
fs.mkdirSync(TDIR, { recursive: true });
const tfile = id => path.join(TDIR, parseInt(id, 10) + '.pdf');
const clearTk = id => db.prepare("DELETE FROM asent WHERE pid=? AND kind='ticket'").run(parseInt(id, 10));

app.get('/api/tickets', auth, mgr, (_q, r) => r.json(
  fs.readdirSync(TDIR).filter(f => /^\d+\.pdf$/.test(f)).map(f => { const pid = parseInt(f, 10); return { pid, sent: lastKey(pid, 'ticket') === 'sent' }; })));

app.post('/api/ticket/:pid', auth, mgr, express.raw({ type: () => true, limit: '10mb' }), (q, r) => {
  if (!Buffer.isBuffer(q.body) || q.body.slice(0, 4).toString() !== '%PDF') return r.status(400).json({ error: 'pdf only' });
  fs.writeFileSync(tfile(q.params.pid), q.body); clearTk(q.params.pid); r.json({ ok: true });
});

app.delete('/api/ticket/:pid', auth, mgr, (q, r) => {
  try { fs.unlinkSync(tfile(q.params.pid)); } catch (e) {}
  clearTk(q.params.pid); r.json({ ok: true });
});

app.post('/api/send-tickets', auth, mgr, async (q, r) => {
  const row = db.prepare("SELECT v FROM kv WHERE k='state'").get();
  const s = row ? JSON.parse(row.v) : { pil: [] };
  const H = { Authorization: 'Bearer ' + E.WA_TOKEN };
  let ok = 0, fail = 0;
  for (const id of q.body.ids || []) {
    const p = (s.pil || []).find(x => x.id == id);
    if (!p || !fs.existsSync(tfile(id))) continue;
    try {
      const fd = new FormData();
      fd.append('messaging_product', 'whatsapp');
      fd.append('type', 'application/pdf');
      fd.append('file', new Blob([fs.readFileSync(tfile(id))], { type: 'application/pdf' }), 'ticket.pdf');
      const up = await fetch(`https://graph.facebook.com/v21.0/${E.WA_PHONE_ID}/media`, { method: 'POST', headers: H, body: fd });
      const uj = await up.json();
      if (!up.ok) throw new Error(uj.error && uj.error.message || 'upload failed');
      const res = await fetch(`https://graph.facebook.com/v21.0/${E.WA_PHONE_ID}/messages`, {
        method: 'POST', headers: { ...H, 'Content-Type': 'application/json' },
        body: JSON.stringify({ messaging_product: 'whatsapp', to: phone(p.p), type: 'template',
          template: { name: E.WA_TEMPLATE_TICKET || 'hajj_ticket', language: { code: E.WA_LANG || 'ar' }, components: [
            { type: 'header', parameters: [{ type: 'document', document: { id: uj.id, filename: 'flight-ticket.pdf' } }] },
            { type: 'body', parameters: [{ type: 'text', text: String(p.n) }] }] } })
      });
      const j = await res.json();
      if (!res.ok) throw new Error(j.error && j.error.message || 'send failed');
      mark(p.id, 'ticket', 'sent'); log('تذكرة طيران ← ' + p.n); ok++;
    } catch (e) { fail++; log('فشل تذكرة ' + p.n + ': ' + e.message); }
    await new Promise(z => setTimeout(z, 150));
  }
  r.json({ ok, fail });
});

// ===== تتبع الباصات =====
app.set('trust proxy', 1);
db.exec('CREATE TABLE IF NOT EXISTS gps(bus TEXT PRIMARY KEY, lat REAL, lng REAL, spd REAL, ts INTEGER)');
const dtoken = bus => crypto.createHmac('sha256', E.DASH_KEY || '').update('bus:' + bus).digest('hex').slice(0, 16);

app.get('/api/driver-links', auth, mgr, (q, r) => {
  const row = db.prepare("SELECT v FROM kv WHERE k='state'").get();
  const buses = row ? (JSON.parse(row.v).bus || []) : [];
  const base = (E.PUBLIC_URL || (q.protocol + '://' + q.get('host'))).replace(/\/$/, '');
  r.json(buses.map(b => ({ bus: b.no, url: `${base}/driver.html?bus=${encodeURIComponent(b.no)}&t=${dtoken(String(b.no))}` })));
});

app.post('/api/gps', (q, res) => {
  const { bus, t, lat, lng, spd } = q.body || {};
  if (!bus || t !== dtoken(String(bus)) || !isFinite(lat) || !isFinite(lng)) return res.sendStatus(401);
  db.prepare('INSERT INTO gps(bus,lat,lng,spd,ts) VALUES(?,?,?,?,?) ON CONFLICT(bus) DO UPDATE SET lat=excluded.lat,lng=excluded.lng,spd=excluded.spd,ts=excluded.ts')
    .run(String(bus), +lat, +lng, spd == null ? null : +spd, Date.now());
  res.json({ ok: true });
});

app.get('/api/gps', auth, (_q, r) => r.json(db.prepare('SELECT bus,lat,lng,spd,ts FROM gps').all()));

app.use(express.static(path.join(__dirname, 'public')));
app.listen(E.PORT || 3000, () => console.log('Server on :' + (E.PORT || 3000)));
