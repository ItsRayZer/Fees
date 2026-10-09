process.env.ADMIN_PIN = '482913'; process.env.SESSION_SECRET = 'y'.repeat(48);
const http = require('http'), fs = require('fs'), path = require('path');
const handler = require('../api/index.js'), fakeDb = require('./fakedb.js');
const rec = (id, sl, name, total, extra) => Object.assign({ id, planId: 'plan1', planTitle: 'EXAM FEE 2026', planTarget: 1440, sl, studentName: name, cash: total, upi: 0, total, secKey: 'SEC-AAAA0000BBBB', status: 'VALID', date: 'Oct 9, 2026', timestamp: '10:00 AM', collector: 'Class Rep' }, extra || {});
const db = fakeDb({ fees: { students: { s5: { sl: 5, name: 'ABHINAV MATHEW' } }, plans: { plan1: { id: 'plan1', title: 'EXAM FEE 2026', target: 1440, officer: 'Class Rep' } }, counter: 1004,
  receipts: { 'REC-1001': rec('REC-1001', 5, 'ABHINAV MATHEW', 1000), 'REC-1002': rec('REC-1002', 5, 'ABHINAV MATHEW', 440, { secKey: 'SEC-CCCC1111DDDD' }),
    'REC-1003': rec('REC-1003', 5, 'ABHINAV MATHEW', 50, { status: 'DELETED', deleteReason: 'Test entry', deleteCat: 'TEST', secKey: 'SEC-EEEE2222FFFF' }) } } });
handler.__setDb(db);
const types = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.png': 'image/png', '.svg': 'image/svg+xml', '.webmanifest': 'application/manifest+json' };
http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x'); if (u.pathname.startsWith('/api')) return handler(req, res);
  let p = u.pathname === '/' ? '/index.html' : u.pathname === '/verify' ? '/verify.html' : u.pathname;
  const f = path.join(__dirname, '../public', p);
  if (!fs.existsSync(f)) { res.statusCode = 404; return res.end('nf'); }
  res.setHeader('Content-Type', types[path.extname(f)] || 'text/plain'); res.end(fs.readFileSync(f));
}).listen(4173, () => console.log('up'));
