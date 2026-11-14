/**
 * The system subscription (migration 019). Run: npm run test:billing
 *
 * A business pays 30,000₮ a month per active machine, through QPay on the
 * operator's merchant; each payment extends paid_until; three days after it
 * lapses the business's machines refuse sales until it pays. What this file
 * holds the bridge to:
 *   - the state names and the fee the portal shows;
 *   - an invoice for N months at machines × fee × N, reused while open;
 *   - the signed callback credits once, from the later of paid_until and now;
 *   - a suspended business's machine refuses a sale, and sells again the
 *     moment it pays — no cache in the way;
 *   - the operator's manual payment, fee override and exemption;
 *   - reminders once per stage (three days before, the day it runs out,
 *     the day the machines stop), by SMS with no link, never going back;
 *   - the operator's ledger (021): cash, transfer and free months by name,
 *     open QPay invoices voided when a payment is confirmed by hand, and
 *     only the newest manual payment taken back, to exactly where it was;
 *   - the house (020): with OPERATOR_MERCHANT_OWNER_ID set, the subscription
 *     and unregistered machines' sales go to that business's own QPay; what
 *     the env account issued before the switch is still checked there; a
 *     house that cannot be used refuses instead of falling back.
 */
import { createHmac, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';

process.env.CRED_KEYS = process.env.CRED_KEYS ?? `k1:${Buffer.from(Array.from({ length: 32 }, (_, i) => i * 7 % 256)).toString('base64')}`;
process.env.CRED_KEY_ACTIVE = process.env.CRED_KEY_ACTIVE ?? 'k1';
process.env.CRED_FP_KEY = process.env.CRED_FP_KEY ?? Buffer.from(Array.from({ length: 32 }, (_, i) => i * 11 % 256)).toString('base64');

const { query, close } = await import('../src/db.js');
const { registerOwner } = await import('../src/register-owner.js');
const { SIGNABLE, buildSign, timestamp } = await import('../src/sign.js');

const results = [];
const check = async (name, fn) => {
  try {
    const ok = await fn();
    results.push([ok === true, name, ok === true ? '' : ` — ${typeof ok === 'string' ? ok : JSON.stringify(ok)}`]);
  } catch (err) {
    results.push([false, name, ` — ${err.message.split('\n')[0]}`]);
  }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, ms = 6000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return true;
    await sleep(150);
  }
  return false;
};

// ---- Supabase stand-in ---------------------------------------------------------
const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'ES256', use: 'sig' };
const JWKS_PORT = 4641;
const ISS = `http://127.0.0.1:${JWKS_PORT}`;
const jwks = createServer((q, r) => {
  r.setHeader('content-type', 'application/json');
  r.end(JSON.stringify({ keys: [jwk] }));
});
await new Promise((r) => jwks.listen(JWKS_PORT, '127.0.0.1', r));
const mint = (sub) =>
  new SignJWT({}).setProtectedHeader({ alg: 'ES256', kid: 'k1' }).setSubject(sub).setIssuedAt()
    .setIssuer(`${ISS}/auth/v1`).setAudience('authenticated').setExpirationTime('1h').sign(privateKey);

// ---- QPay stand-in -----------------------------------------------------------
const QPAY_PORT = 4642;
const invoices = new Map(); // id -> { body, bearer }
const paid = new Map(); // id -> amount
const checks = []; // { id, bearer } — which merchant asked about which invoice
const deletes = []; // invoice ids QPay was asked to void
const qpayFake = createServer((req, res) => {
  let raw = '';
  req.on('data', (d) => (raw += d));
  req.on('end', () => {
    const auth = req.headers.authorization ?? '';
    res.setHeader('content-type', 'application/json');
    if (req.url === '/v2/auth/token') {
      const [user] = Buffer.from(auth.replace('Basic ', ''), 'base64').toString().split(':');
      return res.end(JSON.stringify({ access_token: `tok-${user}`, expires_in: 3600 }));
    }
    if (req.url === '/v2/invoice' && req.method === 'POST') {
      const body = JSON.parse(raw);
      const id = `binv-${invoices.size + 1}`;
      invoices.set(id, { body, bearer: auth.slice(7) });
      return res.end(JSON.stringify({
        invoice_id: id, qr_text: 'QRTEXT', qr_image: 'iVBORw0KGgo=', qPay_shortUrl: `https://s.qpay.mn/${id}`,
        urls: [{ name: 'Khan bank', description: 'Хаан банк', logo: 'https://qpay.mn/q/logo/khanbank.png', link: `khanbank://q?qPay_QRcode=${id}` }],
      }));
    }
    if (req.url === '/v2/payment/check') {
      const j = JSON.parse(raw);
      checks.push({ id: j.object_id, bearer: auth.slice(7) });
      const a = paid.get(j.object_id);
      return res.end(JSON.stringify({ rows: a !== undefined ? [{ payment_id: `p-${j.object_id}`, payment_status: 'PAID', payment_amount: a }] : [] }));
    }
    if (req.method === 'DELETE') {
      const id = decodeURIComponent(req.url.split('/').pop());
      deletes.push(id);
      // A paid invoice cannot be voided: QPay says so, and the bridge must credit it instead.
      if (paid.has(id)) {
        res.statusCode = 400;
        return res.end(JSON.stringify({ error: 'INVOICE_PAID', message: 'INVOICE_PAID' }));
      }
      return res.end('{}');
    }
    res.statusCode = 404;
    res.end('{}');
  });
});
await new Promise((r) => qpayFake.listen(QPAY_PORT, '127.0.0.1', r));

// ---- SMS gateway stand-in ------------------------------------------------------------
const SMS_PORT = 4643;
const smsOut = [];
const smsFake = createServer((req, res) => {
  let raw = '';
  req.on('data', (d) => (raw += d));
  req.on('end', () => {
    const p = new URLSearchParams(raw);
    smsOut.push({ to: p.get('sendto'), text: p.get('message') });
    res.setHeader('content-type', 'application/json');
    res.end('{"status":1}');
  });
});
await new Promise((r) => smsFake.listen(SMS_PORT, '127.0.0.1', r));

// ---- a machine that answers PAYSUCCESS -----------------------------------------------
const MACHINE_PORT = 4644;
const notifies = [];
const machine = createServer((req, res) => {
  let raw = '';
  req.on('data', (d) => (raw += d));
  req.on('end', () => {
    notifies.push(JSON.parse(raw || '{}')?.data?.orderNo);
    res.end(JSON.stringify({ returnCode: 'SUCCESS', msg: 'SUCCESS' }));
  });
});
await new Promise((r) => machine.listen(MACHINE_PORT, '127.0.0.1', r));

// ---- businesses ------------------------------------------------------------------------
const DA = `BA${Math.floor(Math.random() * 1e8)}`;
const DA2 = `BB${Math.floor(Math.random() * 1e8)}`;
const a = await registerOwner({
  ownerName: 'Төлбөр ХХК', contactPhone: '99110081', deviceNo: DA, location: 'A',
  username: 'userA', password: 'passA', invoiceCode: 'INV_A',
});
// A second machine on the same business: the fee is per machine.
await query(
  `insert into public.machines (owner_id, device_no, label, location, notify_url, qpay_credential_id, status)
   select owner_id, $2, label, 'A2', notify_url, qpay_credential_id, 'active' from public.machines where device_no = $1`,
  [DA, DA2]
).catch(async () => {
  // Older column sets: copy whatever the first machine has.
  await query(
    `insert into public.machines (owner_id, device_no, qpay_credential_id, status)
     select owner_id, $2, qpay_credential_id, 'active' from public.machines where device_no = $1`,
    [DA, DA2]
  );
});
const b = await registerOwner({
  ownerName: 'Бусад ХХК', contactPhone: '99110082', deviceNo: `BC${Math.floor(Math.random() * 1e8)}`, location: 'B',
  username: 'userB', password: 'passB', invoiceCode: 'INV_B',
});
const UA = randomUUID();
const UB = randomUUID();
const OPERATOR = randomUUID();
await query(`insert into auth.users (id, phone) values ($1,'97699110081'), ($2,'97699110082'), ($3,'97699110089')`, [UA, UB, OPERATOR]);
await query(`insert into public.owner_members (owner_id, user_id, role) values ($1,$2,'admin'), ($3,$4,'admin')`, [a.ownerId, UA, b.ownerId, UB]);
await query(`insert into public.operators (user_id, label) values ($1, 'Тест оператор')`, [OPERATOR]);

// ---- the bridge ----------------------------------------------------------------------------
const PORT = 3196;
const ENV = {
  ...process.env,
  PORT: String(PORT),
  JETINNO_USERNAME: 'testname',
  JETINNO_APIKEY: 'DBRW17YE7FHKR72T',
  PUBLIC_URL: `http://localhost:${PORT}`,
  QPAY_BASE_URL: `http://127.0.0.1:${QPAY_PORT}`,
  QPAY_USERNAME: 'operator',
  QPAY_PASSWORD: 'op-pass',
  QPAY_INVOICE_CODE: 'INV_OPERATOR',
  SUPABASE_URL: ISS,
  PORTAL_ORIGIN: 'https://kofe.mn',
  SMS_API_URL: `http://127.0.0.1:${SMS_PORT}/send`,
  SMS_API_KEY: 'k',
  SEND_SMS_HOOK_SECRET: `v1,whsec_${Buffer.from('x'.repeat(32)).toString('base64')}`,
  ALLOW_PRIVATE_NOTIFY: '1',
  CRED_ALLOW_HTTP: '1',
  SWEEP_INTERVAL_MS: '1000',
};
delete ENV.QPAY_MOCK;
function boot(extra = {}) {
  const child = spawn(process.execPath, ['src/server.js'], { env: { ...ENV, ...extra }, stdio: ['ignore', 'pipe', 'pipe'] });
  child.logText = '';
  child.stdout.on('data', (d) => (child.logText += d));
  child.stderr.on('data', (d) => (child.logText += d));
  return child;
}
async function waitUp() {
  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(`http://localhost:${PORT}/health`)).ok) return;
    } catch {
      // not yet
    }
    await sleep(250);
  }
  throw new Error('bridge did not start');
}
let bridge = boot();
await waitUp();

const call = async (path, { token, body, method = body ? 'POST' : 'GET' } = {}) => {
  const res = await fetch(`http://localhost:${PORT}${path}`, {
    method,
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  return { status: res.status, json };
};
const setPaidUntil = (ownerId, sql) => query(`update public.owners set paid_until = ${sql} where id = $1`, [ownerId]);
const ownerA = `?ownerId=${a.ownerId}`;
const tA = await mint(UA);
const op = await mint(OPERATOR);

function signedSale(deviceNo, orderNo) {
  const data = { deviceNo, productId: '1', productName: 'Латте', orderNo, orderAmount: '450000', notifyUrl: `http://127.0.0.1:${MACHINE_PORT}/notify` };
  const body = { username: 'testname', time: timestamp(), data };
  body.sign = buildSign({ username: body.username, time: body.time, ...data }, SIGNABLE.getQrCodeRequest, 'DBRW17YE7FHKR72T');
  return body;
}
const sale = (deviceNo, orderNo) =>
  fetch(`http://localhost:${PORT}/jetinno/getQrCode`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(signedSale(deviceNo, orderNo)) })
    .then((r) => r.json());
const MAC_KEY = createHmac('sha256', 'DBRW17YE7FHKR72T').update('qpay-billing-v1').digest();
const macFor = (id) => createHmac('sha256', MAC_KEY).update(id).digest('base64url').slice(0, 22);

// ---- states ------------------------------------------------------------------------------------
await check('шинэ бизнес эхний сар үнэгүй: идэвхтэй, 2 машин × 30,000₮ = 60,000₮/сар', async () => {
  const r = await call(`/owner/v1/billing${ownerA}`, { token: tA });
  const j = r.json;
  const days = Math.round((new Date(j.paidUntil) - Date.now()) / 86400000);
  return (r.status === 200 && j.state === 'active' && j.machines === 2 && j.feePerMachineMnt === 30000 &&
    j.monthlyFeeMnt === 60000 && days >= 27 && days <= 32 &&
    j.options.map((o) => `${o.months}:${o.amountMnt}`).join() === '1:60000,3:180000,6:360000,12:720000') || j;
});

await check('төлөвүүд: due_soon (3 хоногийн өмнө), overdue (хугацаа өнгөрсөн), suspended (3 хоногийн дараа)', async () => {
  const out = [];
  for (const [sql, want] of [["now() + interval '2 days'", 'due_soon'], ["now() - interval '1 day'", 'overdue'], ["now() - interval '4 days'", 'suspended']]) {
    await setPaidUntil(a.ownerId, sql);
    out.push((await call(`/owner/v1/billing${ownerA}`, { token: tA })).json?.state === want ? want : `!${want}`);
  }
  return out.every((x) => !x.startsWith('!')) || out;
});

// ---- suspension at the machine -------------------------------------------------------------------
await check('төлбөр хугацаа хэтэрсэн (suspended) бизнесийн машин зарахгүй, шалтгаан бүртгэгдэнэ', async () => {
  const r = await sale(DA, 'B-SUSP-1');
  const logged = await until(async () =>
    (await query(`select count(*)::int n from public.ingest_errors where device_no = $1 and reason = 'SALE_REFUSED_BILLING_SUSPENDED'`, [DA])).rows[0].n >= 1);
  return (r.returnCode === 'FAIL' && logged) || r;
});

await check('өөр бизнесийн машин хэвийн зарна', async () => {
  const r = await sale((await query(`select device_no from public.machines where owner_id = $1`, [b.ownerId])).rows[0].device_no, 'B-OTHER-1');
  return r.returnCode === 'SUCCESS' || r;
});

// ---- paying ------------------------------------------------------------------------------------------
let inv;
await check('3 сарын нэхэмжлэх: 180,000₮, операторын дансаар, QR + банкны холбоостой, гарын үсэгтэй callback', async () => {
  const r = await call(`/owner/v1/billing/invoices${ownerA}`, { token: tA, body: { months: 3 } });
  inv = r.json?.invoice;
  const q = [...invoices.values()].at(-1);
  return (r.status === 200 && inv.amountMnt === 180000 && inv.months === 3 && inv.qrImage && inv.bankUrls[0]?.link.startsWith('khanbank://') &&
    q.bearer === 'tok-operator' && q.body.amount === 180000 && q.body.callback_url.endsWith(`/qpay/billing/${inv.id}/${macFor(inv.id)}`)) || { r: r.json, q };
});

await check('ижил хугацааны нээлттэй нэхэмжлэхийг дахин өгнө — шинээр үүсгэхгүй', async () => {
  const before = invoices.size;
  const r = await call(`/owner/v1/billing/invoices${ownerA}`, { token: tA, body: { months: 3 } });
  const bad = await call(`/owner/v1/billing/invoices${ownerA}`, { token: tA, body: { months: 2 } });
  return (r.json?.invoice?.id === inv.id && invoices.size === before && bad.status === 400 && bad.json?.error === 'INVALID_MONTHS') || { r: r.json, bad };
});

await check('төлөөгүй байхад «шалгах» open буцаана; өөр бизнесийнх 404', async () => {
  const r = await call(`/owner/v1/billing/invoices/${inv.id}/check${ownerA}`, { token: tA, body: {} });
  const other = await call(`/owner/v1/billing/invoices/${inv.id}/check?ownerId=${b.ownerId}`, { token: await mint(UB), body: {} });
  return (r.json?.status === 'open' && other.status === 404) || { r: r.json, other: other.status };
});

await check('гарын үсэггүй callback юу ч хийхгүй', async () => {
  paid.set([...invoices.keys()].at(-1), 180000);
  const r = await fetch(`http://localhost:${PORT}/qpay/billing/${inv.id}/AAAAAAAAAAAAAAAAAAAAAA`, { method: 'POST' });
  const row = (await query(`select status from public.billing_invoices where id = $1`, [inv.id])).rows[0];
  return (r.status === 200 && row.status === 'open') || row;
});

await check('гарын үсэгтэй callback: 3 сар нэмэгдэж (одооноос, учир нь хугацаа өнгөрсөн), машин ШУУД зарна', async () => {
  const r = await fetch(`http://localhost:${PORT}/qpay/billing/${inv.id}/${macFor(inv.id)}`, { method: 'POST' });
  const o = (await query(`select paid_until from public.owners where id = $1`, [a.ownerId])).rows[0];
  const days = Math.round((new Date(o.paid_until) - Date.now()) / 86400000);
  const s = await sale(DA, 'B-AFTER-PAY');
  return (r.status === 200 && days >= 88 && days <= 93 && s.returnCode === 'SUCCESS') || { status: r.status, days, s };
});

await check('QPay дахин дуудсан ч дахин сунгахгүй (нэг л удаа)', async () => {
  const before = (await query(`select paid_until from public.owners where id = $1`, [a.ownerId])).rows[0].paid_until;
  await fetch(`http://localhost:${PORT}/qpay/billing/${inv.id}/${macFor(inv.id)}`, { method: 'POST' });
  const after = (await query(`select paid_until from public.owners where id = $1`, [a.ownerId])).rows[0].paid_until;
  return before.getTime() === after.getTime() || `${before} -> ${after}`;
});

await check('хугацаа дуусаагүй үед төлбөл одоогийн хугацааны ард залгагдана', async () => {
  const before = (await query(`select paid_until from public.owners where id = $1`, [a.ownerId])).rows[0].paid_until;
  const r = await call(`/owner/v1/billing/invoices${ownerA}`, { token: tA, body: { months: 1 } });
  paid.set([...invoices.keys()].at(-1), 60000);
  const c = await call(`/owner/v1/billing/invoices/${r.json.invoice.id}/check${ownerA}`, { token: tA, body: {} });
  const after = (await query(`select paid_until from public.owners where id = $1`, [a.ownerId])).rows[0].paid_until;
  const days = (after - before) / 86400000;
  return (c.json?.status === 'paid' && days >= 28 && days <= 31) || { c: c.json, days };
});

await check('дутуу төлбөрөөр хугацаа сунгахгүй', async () => {
  const r = await call(`/owner/v1/billing/invoices${ownerA}`, { token: tA, body: { months: 6 } });
  paid.set([...invoices.keys()].at(-1), 1000);
  const c = await call(`/owner/v1/billing/invoices/${r.json.invoice.id}/check${ownerA}`, { token: tA, body: {} });
  const row = (await query(`select status from public.billing_invoices where id = $1`, [r.json.invoice.id])).rows[0];
  return (c.json?.status === 'open' && row.status === 'open') || { c: c.json, row };
});

await check('түүх: QPay-ийн төлбөрүүд хугацааны хамт харагдана', async () => {
  const j = (await call(`/owner/v1/billing${ownerA}`, { token: tA })).json;
  const paidRows = j.history.filter((h) => h.status === 'paid');
  return (paidRows.length === 2 && paidRows.every((h) => h.source === 'qpay' && h.periodTo)) || j.history;
});

// ---- the operator ----------------------------------------------------------------------------------
await check('оператор бүх бизнесийн төлбөрийн төлөвийг харна; эзэмшигч харж чадахгүй', async () => {
  const r = await call('/admin/v1/billing', { token: op });
  const mine = r.json?.owners?.find((o) => o.ownerId === a.ownerId);
  const owner = await call('/admin/v1/billing', { token: tA });
  return (mine?.state === 'active' && mine.monthlyFeeMnt === 60000 && owner.status === 401) || { r: r.json, owner: owner.status };
});

await check('оператор гараар (бэлэн/шилжүүлэг) 1 сар бүртгэхэд хугацаа сунгагдаж, түүхэнд тэмдэглэлтэй орно', async () => {
  const before = (await query(`select paid_until from public.owners where id = $1`, [b.ownerId])).rows[0].paid_until;
  const r = await call(`/admin/v1/owners/${b.ownerId}/billing/extend`, { token: op, body: { months: 1, note: 'Бэлнээр' } });
  const after = (await query(`select paid_until from public.owners where id = $1`, [b.ownerId])).rows[0].paid_until;
  const h = (await call(`/admin/v1/owners/${b.ownerId}/billing`, { token: op })).json?.history?.[0];
  const days = (after - before) / 86400000;
  return (r.json?.status === 'ok' && days >= 28 && days <= 31 && h?.source === 'manual' && h.note === 'Бэлнээр' && h.amountMnt === 30000) || { r: r.json, h, days };
});

await check('оператор нэг бизнесийн машины үнийг өөрчилнө; хоосон бол үндсэн үнэ', async () => {
  const s1 = await call(`/admin/v1/owners/${a.ownerId}/billing/settings`, { token: op, body: { feePerMachineMnt: 20000 } });
  const v1 = (await call(`/owner/v1/billing${ownerA}`, { token: tA })).json;
  const s2 = await call(`/admin/v1/owners/${a.ownerId}/billing/settings`, { token: op, body: { feePerMachineMnt: null } });
  const v2 = (await call(`/owner/v1/billing${ownerA}`, { token: tA })).json;
  return (s1.json?.status === 'ok' && v1.monthlyFeeMnt === 40000 && s2.json?.status === 'ok' && v2.monthlyFeeMnt === 60000) || { v1: v1.monthlyFeeMnt, v2: v2.monthlyFeeMnt };
});

await check('чөлөөлсөн бизнес хугацаа хэтэрсэн ч зарна, нэхэмжлэх үүсгэхгүй', async () => {
  await call(`/admin/v1/owners/${a.ownerId}/billing/settings`, { token: op, body: { exempt: true } });
  await setPaidUntil(a.ownerId, "now() - interval '10 days'");
  const s = await sale(DA, 'B-EXEMPT');
  const j = (await call(`/owner/v1/billing${ownerA}`, { token: tA })).json;
  const inv2 = await call(`/owner/v1/billing/invoices${ownerA}`, { token: tA, body: { months: 1 } });
  await call(`/admin/v1/owners/${a.ownerId}/billing/settings`, { token: op, body: { exempt: false } });
  return (s.returnCode === 'SUCCESS' && j.state === 'exempt' && j.options.length === 0 && inv2.status === 409) || { s, state: j.state, inv2 };
});

await check('оператор биш хүн гараар бүртгэж, үнэ өөрчилж ЧАДАХГҮЙ', async () => {
  const r = await call(`/admin/v1/owners/${a.ownerId}/billing/extend`, { token: tA, body: { months: 12 } });
  return r.status === 401 || `status ${r.status}`;
});

// ---- the operator's ledger (021) ---------------------------------------------------------------------
const extendB = (body) => call(`/admin/v1/owners/${b.ownerId}/billing/extend`, { token: op, body });
const paidUntilOf = async (ownerId) => (await query(`select paid_until from public.owners where id = $1`, [ownerId])).rows[0].paid_until;
let cashRow;
let bankRow;
await check('гараар баталгаажуулах: бэлэн, данс хэлбэрээр; буруу хослол (үнэгүй+дүн, бэлэн+0, тодорхойгүй хэлбэр) татгалзана', async () => {
  const bad = [
    await extendB({ months: 1, method: 'free', amountMnt: 5000 }),
    await extendB({ months: 1, method: 'cash', amountMnt: 0 }),
    await extendB({ months: 1, method: 'crypto' }),
  ].map((r) => r.json?.status);
  const cash = await extendB({ months: 1, method: 'cash' });
  cashRow = cash.json?.invoiceId;
  const bank = await extendB({ months: 1, method: 'bank', amountMnt: 30000, note: 'Хаан банк, гүйлгээ 12345' });
  bankRow = bank.json?.invoiceId;
  const rows = (await query(`select id, method, amount_mnt, prev_paid_until, period_from, period_to from public.billing_invoices where id = any($1)`, [[cashRow, bankRow]])).rows;
  const c = rows.find((r) => r.id === cashRow);
  const k = rows.find((r) => r.id === bankRow);
  return (bad.every((s) => s === 'invalid') && cash.json?.status === 'ok' && bank.json?.status === 'ok' &&
    c?.method === 'cash' && c.amount_mnt === 30000 && k?.method === 'bank' &&
    k.prev_paid_until.getTime() === c.period_to.getTime()) || { bad, cash: cash.json, bank: bank.json, rows };
});

await check('«Төлбөр» жагсаалт: энэ сарын бүх төлбөр нэр, хэлбэр, бүртгэсэн хүнтэй; хэлбэрээр нийлбэр; зөвхөн сүүлийнх нь цуцлагдана', async () => {
  const r = await call('/admin/v1/billing/payments', { token: op });
  const j = r.json;
  const bank = j?.payments?.find((p) => p.id === bankRow);
  const cash = j?.payments?.find((p) => p.id === cashRow);
  const qpayRow = j?.payments?.find((p) => p.method === 'qpay' && p.status === 'paid');
  const old = await call('/admin/v1/billing/payments?month=2020-01', { token: op });
  const sum = j?.payments?.filter((p) => p.status === 'paid').reduce((s, p) => s + p.amountMnt, 0);
  return (r.status === 200 && /^\d{4}-\d{2}$/.test(j.month) && bank?.ownerName === 'Бусад ХХК' && bank.method === 'bank' &&
    bank.recordedBy === 'Тест оператор' && bank.note === 'Хаан банк, гүйлгээ 12345' && bank.voidable === true &&
    cash?.method === 'cash' && cash.voidable === false && qpayRow?.voidable === false && qpayRow.ownerName === 'Төлбөр ХХК' &&
    j.totals.byMethod.bank.amountMnt >= 30000 && j.totals.byMethod.cash.count >= 1 && j.totals.paidMnt === sum &&
    old.json?.month === '2020-01' && old.json.payments.length === 0) || { status: r.status, bank, cash, totals: j?.totals, old: old.json };
});

await check('цуцлах: сүүлийнх цуцлагдаж хугацаа яг өмнөх рүүгээ буцна, түүний өмнөх цуцлагдах боломжтой болно; давхар, QPay-ийнх, сүүлийнх биш нь татгалзана', async () => {
  const cashEnd = (await query(`select period_to from public.billing_invoices where id = $1`, [cashRow])).rows[0].period_to;
  const v = await call(`/admin/v1/billing/payments/${bankRow}/void`, { token: op, body: { reason: 'Буруу бизнест бүртгэсэн' } });
  const after = await paidUntilOf(b.ownerId);
  const again = await call(`/admin/v1/billing/payments/${bankRow}/void`, { token: op, body: {} });
  const qpayId = (await query(`select id from public.billing_invoices where owner_id = $1 and source = 'qpay' and status = 'paid' limit 1`, [a.ownerId])).rows[0].id;
  const notManual = await call(`/admin/v1/billing/payments/${qpayId}/void`, { token: op, body: {} });
  const older = (await query(`select id from public.billing_invoices where owner_id = $1 and source = 'manual' and status = 'paid' and id <> $2 order by paid_at limit 1`, [b.ownerId, cashRow])).rows[0].id;
  const notLatest = await call(`/admin/v1/billing/payments/${older}/void`, { token: op, body: {} });
  const j = (await call('/admin/v1/billing/payments', { token: op })).json;
  const bank = j.payments.find((p) => p.id === bankRow);
  const cash = j.payments.find((p) => p.id === cashRow);
  return (v.json?.status === 'ok' && after.getTime() === cashEnd.getTime() && new Date(v.json.paidUntil).getTime() === cashEnd.getTime() &&
    again.json?.status === 'already' && notManual.json?.status === 'not_manual' && notLatest.json?.status === 'not_latest' &&
    bank?.status === 'cancelled' && bank.cancelReason === 'Буруу бизнест бүртгэсэн' && bank.voidable === false && cash?.voidable === true &&
    j.payments.filter((p) => p.status === 'paid').every((p) => p.id !== bankRow)) ||
    { v: v.json, again: again.json, notManual: notManual.json, notLatest: notLatest.json, bank, cash, after, cashEnd };
});

await check('гараар баталгаажуулахад бизнесийн нээлттэй QPay нэхэмжлэх QPay дээр цуцлагдана; төлөгдсөн байвал QPay-ээр бүртгэгдэж, бэлэн давхар орохгүй', async () => {
  const one = await call(`/owner/v1/billing/invoices${ownerA}`, { token: tA, body: { months: 1 } });
  const openId = one.json?.invoice?.id;
  const openQ = (await query(`select qpay_invoice_id from public.billing_invoices where id = $1`, [openId])).rows[0]?.qpay_invoice_id;
  const from = deletes.length;
  const rec = await call(`/admin/v1/owners/${a.ownerId}/billing/extend`, { token: op, body: { months: 1, method: 'cash' } });
  const voided = (await query(`select status, cancel_reason from public.billing_invoices where id = $1`, [openId])).rows[0];
  // Now one QPay says is paid: the cash must not be recorded on top of it.
  const three = await call(`/owner/v1/billing/invoices${ownerA}`, { token: tA, body: { months: 3 } });
  const paidId = three.json?.invoice?.id;
  const paidQ = (await query(`select qpay_invoice_id from public.billing_invoices where id = $1`, [paidId])).rows[0]?.qpay_invoice_id;
  paid.set(paidQ, three.json?.invoice?.amountMnt);
  const manualBefore = (await query(`select count(*)::int n from public.billing_invoices where owner_id = $1 and source = 'manual'`, [a.ownerId])).rows[0].n;
  const rec2 = await call(`/admin/v1/owners/${a.ownerId}/billing/extend`, { token: op, body: { months: 1, method: 'cash' } });
  const manualAfter = (await query(`select count(*)::int n from public.billing_invoices where owner_id = $1 and source = 'manual'`, [a.ownerId])).rows[0].n;
  const credited = (await query(`select status from public.billing_invoices where id = $1`, [paidId])).rows[0];
  return (rec.json?.status === 'ok' && deletes.slice(from).includes(openQ) && voided?.status === 'cancelled' && voided.cancel_reason &&
    rec2.json?.status === 'qpay_paid' && credited?.status === 'paid' && manualAfter === manualBefore) ||
    { rec: rec.json, voided, rec2: rec2.json, credited, manualBefore, manualAfter, deleted: deletes.slice(from) };
});

await check('оператор биш хүн «Төлбөр» жагсаалт харж, цуцалж ЧАДАХГҮЙ', async () => {
  const list = await call('/admin/v1/billing/payments', { token: tA });
  const v = await call(`/admin/v1/billing/payments/${cashRow}/void`, { token: tA, body: {} });
  const row = (await query(`select status from public.billing_invoices where id = $1`, [cashRow])).rows[0];
  return (list.status === 401 && v.status === 401 && row.status === 'paid') || { list: list.status, v: v.status, row };
});

// ---- reminders -----------------------------------------------------------------------------------------
const restartForNotices = async () => {
  // The notices run on the hourly part of the sweep; a fresh process runs it on its first tick.
  bridge.kill('SIGTERM');
  await new Promise((r) => bridge.once('exit', r));
  bridge = boot();
  await waitUp();
};
const smsTo = (from, phone) => smsOut.slice(from).filter((m) => m.to === phone);
await check('сануулга: 3 хоногийн өмнө, хугацаа дуусах өдөр («...-нд зогсооно»), зогсох өдөр — тус бүр нэг SMS, холбоосгүй, латинаар', async () => {
  await setPaidUntil(a.ownerId, "now() + interval '2 days'");
  await query(`update public.owners set billing_notice_stage = null, billing_notice_for = null where id = $1`, [a.ownerId]);
  const from = smsOut.length;
  await restartForNotices();
  const first = await until(() => smsTo(from, '99110081').length > 0, 6000);
  const dueMsg = smsTo(from, '99110081')[0]?.text ?? '';
  await sleep(2500); // two more ticks: not hourly yet, and the stage is marked anyway
  const sentOnce = smsTo(from, '99110081').length === 1;
  // The day it runs out (inside the grace days): the machines stop on the grace date.
  await setPaidUntil(a.ownerId, "now() - interval '1 day'");
  const graceDay = (await query(
    `select to_char((paid_until + interval '3 days') at time zone 'Asia/Ulaanbaatar', 'YYYY-MM-DD') d from public.owners where id = $1`,
    [a.ownerId])).rows[0].d;
  const from2 = smsOut.length;
  await restartForNotices();
  const second = await until(() => smsTo(from2, '99110081').length > 0, 6000);
  const overMsg = smsTo(from2, '99110081')[0]?.text ?? '';
  // The same day again: nothing more.
  const from3 = smsOut.length;
  await restartForNotices();
  await sleep(2500);
  const quiet = smsTo(from3, '99110081').length === 0;
  // Past grace: one suspension notice.
  await setPaidUntil(a.ownerId, "now() - interval '4 days'");
  const from4 = smsOut.length;
  await restartForNotices();
  const third = await until(() => smsTo(from4, '99110081').length > 0, 6000);
  const susMsg = smsTo(from4, '99110081')[0]?.text ?? '';
  return (first && sentOnce && second && quiet && third &&
    /hugatsaa|duusna/i.test(dueMsg) &&
    /duuslaa/i.test(overMsg) && overMsg.includes(graceDay) && /zogsoono/i.test(overMsg) &&
    /zogsloo/i.test(susMsg) && !/https?:\/\//.test(dueMsg + overMsg + susMsg) &&
    // Plain ASCII: the gateway mangles anything else (and it costs a UCS-2 segment).
    /^[\x20-\x7E]*$/.test(dueMsg + overMsg + susMsg) && dueMsg.includes(' tug)') && overMsg.includes('"Tulbur"')) ||
    { first, sentOnce, second, quiet, third, graceDay, dueMsg, overMsg, susMsg };
});

await check('сануулга буцаж явахгүй: дууссаныг хэлсний дараа «дуусна» дахин үгүй; алгассан шатыг биш, одоогийн шатыг л хэлнэ', async () => {
  const due = async (sql, stage) => {
    await query(`update public.owners set paid_until = ${sql}, billing_notice_stage = $2,
                   billing_notice_for = case when $2::text is null then null else ${sql} end where id = $1`, [a.ownerId, stage]);
    // Pinned to one instant, so paid_until and billing_notice_for are the same value.
    await query(`update public.owners set billing_notice_for = paid_until where id = $1 and billing_notice_stage is not null`, [a.ownerId]);
    const r = await query(`select out_stage from app.billing_notices_due(30000, 3, 3) where out_owner_id = $1`, [a.ownerId]);
    return r.rows[0]?.out_stage ?? 'none';
  };
  const got = {
    overdueAfterDueSoon: await due("now() - interval '1 day'", 'due_soon'),
    overdueAgain: await due("now() - interval '1 day'", 'overdue'),
    overdueFirst: await due("now() - interval '1 day'", null),
    suspendedAfterOverdue: await due("now() - interval '4 days'", 'overdue'),
    suspendedAgain: await due("now() - interval '4 days'", 'suspended'),
    suspendedFirst: await due("now() - interval '4 days'", null),
  };
  const want = { overdueAfterDueSoon: 'overdue', overdueAgain: 'none', overdueFirst: 'overdue',
    suspendedAfterOverdue: 'suspended', suspendedAgain: 'none', suspendedFirst: 'suspended' };
  return Object.keys(want).every((k) => got[k] === want[k]) || got;
});

// ---- the house: the operator's money on a business's own QPay (020) ----------------------------------
const H = await registerOwner({
  ownerName: 'Coffeine ХХК', contactPhone: '99110083', deviceNo: `BH${Math.floor(Math.random() * 1e8)}`, location: 'H',
  username: 'userH', password: 'passH', invoiceCode: 'INV_H',
});
const HFP = (await query(`select fingerprint from public.qpay_credentials where id = $1`, [H.credentialId])).rows[0].fingerprint;
const HOUSE = `house:${H.credentialId}:${HFP}`;
const UNREG = `UN${Math.floor(Math.random() * 1e8)}`;
const DB = (await query(`select device_no from public.machines where owner_id = $1`, [b.ownerId])).rows[0].device_no;
const ownerB = `?ownerId=${b.ownerId}`;
const tB = await mint(UB);
const lastInvoice = () => [...invoices.entries()].at(-1);
const askedBy = (from, id) => checks.slice(from).filter((c) => c.id === id).map((c) => c.bearer);
const health = async () => (await fetch(`http://localhost:${PORT}/health`)).json();
const orderRow = async (deviceNo, orderNo) => {
  let row = null;
  await until(async () => {
    row = (await query(`select source, merchant_fp, machine_id, owner_id, qpay_credential_id from public.orders where device_no = $1 and order_no = $2`, [deviceNo, orderNo])).rows[0] ?? null;
    return row;
  });
  return row;
};
async function restart(extra) {
  bridge.kill('SIGTERM');
  await new Promise((r) => bridge.once('exit', r));
  bridge = boot(extra);
  await waitUp();
}

let envSaleId;
let envBill;
let envBillId;
await check('шилжүүлэхээс өмнө: бүртгэлгүй машин, системийн төлбөр хоёул env данс (operator) дээр', async () => {
  const s = await sale(UNREG, 'H-ENV-1');
  const [sid, sq] = lastInvoice();
  envSaleId = sid;
  const r = await call(`/owner/v1/billing/invoices${ownerB}`, { token: tB, body: { months: 1 } });
  envBill = r.json?.invoice;
  const [bid, bq] = lastInvoice();
  envBillId = bid;
  const row = (await query(`select merchant from public.billing_invoices where id = $1`, [envBill?.id])).rows[0];
  const o = await orderRow(UNREG, 'H-ENV-1');
  return (s.returnCode === 'SUCCESS' && sq.bearer === 'tok-operator' && bq.bearer === 'tok-operator' && row?.merchant === null &&
    o?.source === 'env' && o.merchant_fp === null) || { s, sq: sq.bearer, bq: bq.bearer, row, o };
});

await restart({ OPERATOR_MERCHANT_OWNER_ID: H.ownerId });

await check('OPERATOR_MERCHANT_OWNER_ID тавьсны дараа /health house=ok; хуучин env нэхэмжлэх хуудсанд харагдахгүй', async () => {
  const up = await until(async () => (await health()).house === 'ok');
  const j = (await call(`/owner/v1/billing${ownerB}`, { token: tB })).json;
  return (up && j.state === 'active' && j.openInvoice === null) || { house: (await health()).house, open: j.openInvoice?.id };
});

let houseBill;
let houseBillId;
await check('шинэ нэхэмжлэх «Coffeine»-ийн данс (userH, INV_H) дээр үүсч, аль данснаас гарсан нь тэмдэглэгдэнэ', async () => {
  const r = await call(`/owner/v1/billing/invoices${ownerB}`, { token: tB, body: { months: 1 } });
  houseBill = r.json?.invoice;
  const [id, q] = lastInvoice();
  houseBillId = id;
  const row = (await query(`select merchant from public.billing_invoices where id = $1`, [houseBill?.id])).rows[0];
  const again = await call(`/owner/v1/billing/invoices${ownerB}`, { token: tB, body: { months: 1 } });
  return (r.status === 200 && houseBill.id !== envBill.id && q.bearer === 'tok-userH' && q.body.invoice_code === 'INV_H' &&
    row?.merchant === HOUSE && again.json?.invoice?.id === houseBill.id) || { status: r.status, q: q.bearer, row, again: again.json?.invoice?.id };
});

await check('шилжүүлэхээс өмнөх env нэхэмжлэх төлөгдвөл env данснаас шалгагдаж, хугацаа сунгагдана', async () => {
  const before = (await query(`select paid_until from public.owners where id = $1`, [b.ownerId])).rows[0].paid_until;
  paid.set(envBillId, 30000);
  const from = checks.length;
  const r = await fetch(`http://localhost:${PORT}/qpay/billing/${envBill.id}/${macFor(envBill.id)}`, { method: 'POST' });
  const after = (await query(`select paid_until from public.owners where id = $1`, [b.ownerId])).rows[0].paid_until;
  const by = askedBy(from, envBillId);
  return (r.status === 200 && after > before && by.length >= 1 && by.every((x) => x === 'tok-operator')) || { status: r.status, by, before, after };
});

await check('«Coffeine»-ийн данс дээрх нэхэмжлэх «Coffeine»-ийн данснаас шалгагдаж, хугацаа сунгагдана', async () => {
  const before = (await query(`select paid_until from public.owners where id = $1`, [b.ownerId])).rows[0].paid_until;
  paid.set(houseBillId, 30000);
  const from = checks.length;
  const c = await call(`/owner/v1/billing/invoices/${houseBill.id}/check${ownerB}`, { token: tB, body: {} });
  const after = (await query(`select paid_until from public.owners where id = $1`, [b.ownerId])).rows[0].paid_until;
  const by = askedBy(from, houseBillId);
  return (c.json?.status === 'paid' && after > before && by.length >= 1 && by.every((x) => x === 'tok-userH')) || { c: c.json, by };
});

let houseSaleId;
await check('бүртгэлгүй машины борлуулалт «Coffeine»-ийн данс руу; захиалга env мөр хэвээр, house тэмдэгтэй', async () => {
  const s = await sale(UNREG, 'H-HOUSE-1');
  const [id, q] = lastInvoice();
  houseSaleId = id;
  const o = await orderRow(UNREG, 'H-HOUSE-1');
  return (s.returnCode === 'SUCCESS' && q.bearer === 'tok-userH' && q.body.invoice_code === 'INV_H' && o?.source === 'env' &&
    o.merchant_fp === HOUSE && o.machine_id === null && o.owner_id === null && o.qpay_credential_id === null) || { s, q: q.bearer, o };
});

await check('төлөгдсөн house захиалгыг «Coffeine»-ээс, өмнөх env захиалгыг env-ээс шалгаж, хоёуланд нь кофе гарна', async () => {
  const from = checks.length;
  for (const id of [houseSaleId, envSaleId]) {
    paid.set(id, invoices.get(id).body.amount);
    await fetch(invoices.get(id).body.callback_url, { method: 'POST' });
  }
  const done = await until(() => notifies.includes('H-HOUSE-1') && notifies.includes('H-ENV-1'));
  const h = askedBy(from, houseSaleId);
  const e = askedBy(from, envSaleId);
  return (done && h.length >= 1 && h.every((x) => x === 'tok-userH') && e.length >= 1 && e.every((x) => x === 'tok-operator')) || { done, h, e };
});

await check('дахин асаасны дараа (санах ой хоосон) ч house захиалгыг «Coffeine»-ийн данснаас шалгана', async () => {
  const s = await sale(UNREG, 'H-HOUSE-2');
  const [id] = lastInvoice();
  await orderRow(UNREG, 'H-HOUSE-2');
  await restart({ OPERATOR_MERCHANT_OWNER_ID: H.ownerId });
  paid.set(id, invoices.get(id).body.amount);
  const from = checks.length;
  await fetch(invoices.get(id).body.callback_url, { method: 'POST' });
  const done = await until(() => notifies.includes('H-HOUSE-2'));
  const by = askedBy(from, id);
  return (s.returnCode === 'SUCCESS' && done && by.length >= 1 && by.every((x) => x === 'tok-userH')) || { s, done, by };
});

await check('«Coffeine»-ийн QPay идэвхгүй бол бүртгэлгүй машин зарахгүй, нэхэмжлэх 503 — env данс руу ОРОХГҮЙ; бусад бизнес хэвийн', async () => {
  await query(`update public.qpay_credentials set is_active = false, status = 'disabled' where id = $1`, [H.credentialId]);
  await restart({ OPERATOR_MERCHANT_OWNER_ID: H.ownerId });
  const down = await until(async () => (await health()).house === 'not_connected');
  const before = invoices.size;
  const s = await sale(UNREG, 'H-DOWN-1');
  const inv2 = await call(`/owner/v1/billing/invoices${ownerB}`, { token: tB, body: { months: 3 } });
  const logged = await until(async () =>
    (await query(`select count(*)::int n from public.ingest_errors where device_no = $1 and reason = 'SALE_REFUSED_OPERATOR_MERCHANT_NOT_CONNECTED'`, [UNREG])).rows[0].n >= 1);
  const other = await sale(DB, 'H-DOWN-OTHER');
  const page = (await call(`/owner/v1/billing${ownerB}`, { token: tB })).json;
  return (down && s.returnCode === 'FAIL' && inv2.status === 503 && inv2.json?.error === 'UNAVAILABLE' && logged &&
    other.returnCode === 'SUCCESS' && invoices.size === before + 1 && page?.state && page.openInvoice === null) ||
    { down, s, inv2: inv2.status, logged, other: other.returnCode, made: invoices.size - before };
});

await check('OPERATOR_MERCHANT_OWNER_ID буруу утгатай бол env данс руу унахгүй — зарахгүй', async () => {
  await restart({ OPERATOR_MERCHANT_OWNER_ID: 'coffeine' });
  const h = await health();
  const before = invoices.size;
  const s = await sale(UNREG, 'H-BAD-1');
  return (h.house === 'misconfigured' && s.returnCode === 'FAIL' && invoices.size === before) || { house: h.house, s };
});

bridge.kill('SIGTERM');
await new Promise((r) => bridge.once('exit', r));
for (const s of [jwks, qpayFake, smsFake, machine]) s.close();
await close();

const passed = results.filter(([ok]) => ok).length;
for (const [ok, name, extra] of results) console.log(`  ${ok ? '✓' : '✗'} ${name}${extra}`);
console.log(`\n  ${passed}/${results.length} давлаа`);
if (passed !== results.length) console.log('\n--- bridge log (tail) ---\n' + bridge.logText.slice(-3000));
process.exit(passed === results.length ? 0 : 1);
