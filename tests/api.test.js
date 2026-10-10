// Run: node tests/api.test.js   (uses an in-memory database, no network)
process.env.ADMIN_PIN = '482913'; process.env.SESSION_SECRET = 'x'.repeat(48);
const http = require('http'), assert = require('assert');
const handler = require('../api/index.js');

const fakeDb = require('./fakedb.js');

const db = fakeDb({
  fees: {
    students: { s5: { sl: 5, name: 'ABHINAV MATHEW' }, s6: { sl: 6, name: 'ABHIRAM V NAIR' } },
    plans: { plan1: { id: 'plan1', title: 'EXAM FEE 2026', target: 1440, officer: 'Class Rep' } },
    counter: 1001,
    phones: { p6: '9876543210' },
    receipts: { 'REC-1000': { id: 'REC-1000', planId: 'plan1', planTitle: 'EXAM FEE 2026', planTarget: 1440, sl: 6, studentName: 'ABHIRAM V NAIR', cash: 500, upi: 0, total: 500, phone: '9876543210', secKey: 'SEC-0A1B2C3D', status: 'VALID', date: 'Oct 1, 2026', timestamp: '10:00 AM', collector: 'Class Rep' } }
  }
});
handler.__setDb(db);

const srv = http.createServer(handler);
let n = 0;
const call = async (port, body, o = {}) => {
  const r = await fetch(`http://localhost:${port}/api/index`, {
    method: 'POST', headers: Object.assign({ 'content-type': 'application/json', 'x-fees': '1', 'x-forwarded-for': o.ip || '1.1.1.1' }, o.cookie ? { cookie: o.cookie } : {}, o.headers || {}),
    body: JSON.stringify(body)
  });
  return { s: r.status, j: await r.json(), cookie: (r.headers.get('set-cookie') || '').split(';')[0] };
};
const verify = async (port, q) => { const r = await fetch(`http://localhost:${port}/api/index?op=verify&` + q, { headers: { 'x-forwarded-for': '9.9.9.' + (++n) } }); return { s: r.status, j: await r.json() }; };
let pass = 0; const ok = (c, m) => { assert(c, m); pass++; console.log('  ok -', m); };

srv.listen(0, async () => {
  const P = srv.address().port, PIN = '482913';
  try {
    let r = await call(P, { op: 'issue', sl: 5, planId: 'plan1', cash: 100 });
    ok(r.s === 401, 'issue without login is refused (401)');
    r = await call(P, { op: 'issue' }, { headers: { 'x-fees': '' } });
    ok(r.s === 403, 'request without CSRF header refused');
    r = await call(P, { op: 'login', pin: PIN }, { headers: { origin: 'https://evil.example' } });
    ok(r.s === 403, 'cross-origin login refused');

    for (let i = 1; i <= 4; i++) { r = await call(P, { op: 'login', pin: '000000' }, { ip: '2.2.2.2' }); ok(r.s === 401 && r.j.left === 5 - i, `wrong PIN #${i} -> 401, ${5 - i} left`); }
    r = await call(P, { op: 'login', pin: '000000' }, { ip: '2.2.2.2' });
    ok(r.s === 429, '5th wrong PIN locks the attacker out');
    r = await call(P, { op: 'login', pin: PIN }, { ip: '2.2.2.2' });
    ok(r.s === 429 && !r.cookie, 'even the right PIN is refused while that IP is locked');

    r = await call(P, { op: 'login', pin: PIN }, { ip: '3.3.3.3' });
    ok(r.s === 200 && /fees_s=/.test(r.cookie), 'admin logs in from another IP (not affected by the attacker lock)');
    const cookie = r.cookie;
    const raw = await fetch(`http://localhost:${P}/api/index`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-fees': '1', 'x-forwarded-for': '3.3.3.3' }, body: JSON.stringify({ op: 'login', pin: PIN }) });
    const sc = raw.headers.get('set-cookie');
    ok(/HttpOnly/.test(sc) && /SameSite=Strict/.test(sc), 'session cookie is HttpOnly + SameSite=Strict');

    r = await call(P, { op: 'session' }, { cookie });
    ok(r.j.admin === true, 'session recognised');
    r = await call(P, { op: 'session' }, { cookie: cookie.slice(0, -3) + 'abc' });
    ok(r.j.admin === false, 'tampered cookie rejected');
    r = await call(P, { op: 'phones' }, { cookie: 'fees_s=' + Buffer.from('{"iat":1,"exp":9999999999999}').toString('base64url') + '.deadbeef' });
    ok(r.s === 401, 'forged session token rejected');

    await new Promise(x => setTimeout(x, 100));
    ok(!db.root.fees.receipts['REC-1000'].phone && !db.root.fees.phones && db.root.fees_private.phones.p6 === '9876543210', 'legacy phone numbers moved out of public data');

    r = await call(P, { op: 'issue', sl: 5, planId: 'plan1', cash: 440, upi: 1000, phone: '9000000001' }, { cookie });
    ok(r.s === 401, 'issue needs the PIN again (no pin -> 401)');
    r = await call(P, { op: 'issue', sl: 5, planId: 'plan1', cash: -5, upi: 10 }, { cookie, ip: '3.3.3.3' }, PIN);
    r = await call(P, { op: 'issue', sl: 5, planId: 'plan1', cash: 440, upi: 1000, phone: '9000000001', pin: PIN }, { cookie });
    ok(r.s === 200 && r.j.receipt.id === 'REC-1001' && /^SEC-[0-9A-F]{12}$/.test(r.j.receipt.secKey), 'receipt issued with server-made HMAC key');
    ok(r.j.receipt.total === 1440 && !r.j.receipt.phone && db.root.fees_private.phones.p5 === '9000000001', 'total computed server-side, phone kept private');
    const rec = r.j.receipt;
    r = await call(P, { op: 'issue', sl: 5, planId: 'plan1', cash: 10, pin: PIN }, { cookie });
    ok(r.s === 409, 'cannot overpay a student already paid in full');
    r = await call(P, { op: 'issue', sl: 6, planId: 'plan1', cash: 99999999, pin: PIN }, { cookie });
    ok(r.s === 400, 'absurd amount rejected');

    let v = await verify(P, `id=${rec.id}&k=${rec.secKey}`);
    ok(v.j.valid && v.j.student === 'ABHINAV MATHEW' && v.j.total === 1440 && !v.j.phone, 'verify: genuine receipt shows details, no phone');
    v = await verify(P, `id=${rec.id}&k=SEC-000000000000`);
    ok(v.j.valid === false && Object.keys(v.j).length <= 2, 'verify: wrong key = fake, nothing leaked');
    v = await verify(P, `id=REC-9999&k=${rec.secKey}`);
    ok(v.j.valid === false, 'verify: unknown receipt = fake');
    v = await verify(P, `id=${rec.id}`);
    ok(v.j.valid === false, 'verify: no key = fake');
    v = await verify(P, `id=../../x&k=${rec.secKey}`);
    ok(v.j.valid === false, 'verify: malformed id rejected');
    v = await verify(P, `k=${rec.secKey}`);
    ok(v.j.valid === true, 'verify: key-only link still works');
    v = await verify(P, 'id=REC-1000&k=SEC-0A1B2C3D');
    ok(v.j.valid === true, 'verify: old receipts (old key format) still verify');

    r = await call(P, { op: 'delete', id: rec.id, reason: 'Test entry', test: true }, { cookie });
    ok(r.s === 401, 'delete needs the PIN');
    r = await call(P, { op: 'delete', id: rec.id, reason: 'Test entry', test: true, pin: PIN }, { cookie });
    ok(r.s === 200 && db.root.fees.receipts[rec.id].deleteCat === 'TEST', 'delete stores the Test category');
    v = await verify(P, `id=${rec.id}&k=${rec.secKey}`);
    ok(v.j.status === 'DELETED' && v.j.reason === 'Test entry', 'QR of a deleted receipt reports it as deleted');
    r = await call(P, { op: 'restore', id: rec.id, pin: PIN }, { cookie });
    ok(r.s === 200 && db.root.fees.receipts[rec.id].status === 'VALID', 'restore works with PIN');

    r = await call(P, { op: 'handover', planId: 'plan1', mode: 'CASH', amount: 999999 }, { cookie });
    ok(r.s === 409, 'cannot hand over more than collected');
    r = await call(P, { op: 'handover', planId: 'plan1', mode: 'GPAY', amount: 500 }, { cookie });
    ok(r.s === 200, 'valid handover saved');
    r = await call(P, { op: 'void', id: rec.id }, { cookie });
    ok(r.s === 200 && r.j.status === 'VOID', 'void toggles');
    r = await call(P, { op: 'addStudent', name: 'NEW KID', sl: 70 }, { cookie });
    ok(r.s === 200 && db.root.fees.students.s70.name === 'NEW KID', 'add student');
    r = await call(P, { op: 'addPlan', title: 'class trip', target: 500, officer: 'Aben' }, { cookie });
    ok(r.s === 200 && Object.values(db.root.fees.plans).some(p => p.title === 'CLASS TRIP'), 'add plan');
    r = await call(P, { op: 'settle', planId: 'plan1', sl: 6 }, { cookie });
    ok(r.s === 401, 'settle needs the PIN (401 without PIN)');
    r = await call(P, { op: 'settle', planId: 'plan1', sl: 6, pin: PIN }, { cookie });
    ok(r.s === 200, 'settle succeeds with PIN');
    const sKey = 'plan1__s6';
    const sRecord = db.root.fees.settled && db.root.fees.settled[sKey];
    ok(sRecord && sRecord.amount > 0, 'settle saves amount in fees/settled');
    ok(sRecord && sRecord.log && Object.keys(sRecord.log).length > 0, 'settle creates individual repayment log entry');

    for (const bad of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) { r = await call(P, { op: bad }, { cookie }); ok(r.s === 404, `op "${bad}" is not an action`); }
    r = await call(P, { op: 'logout' }, { cookie });
    ok(/Max-Age=0/.test(r.cookie) || r.j.admin === false, 'logout clears session');
    console.log(`\nALL ${pass} CHECKS PASSED`);
  } catch (e) { console.error('\nFAIL:', e.message); process.exitCode = 1; }
  srv.close();
});
