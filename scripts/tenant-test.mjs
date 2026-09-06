/**
 * Multi-tenant money-routing test. Run: npm run test:tenant
 *
 * The one claim that matters: a sale on owner A's machine creates the invoice
 * under owner A's QPay merchant, B's under B's, an unregistered machine under
 * the operator's env merchant, and a disabled credential refuses the sale
 * rather than silently routing the owner's money to the operator.
 *
 * A fake QPay server stands in for merchant.qpay.mn and records exactly which
 * Basic/Bearer identity and invoice_code every call carried — which is the
 * only way to assert routing without spending real money.
 */
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';

// Crypto env BEFORE any src/ import — the sealing key must be shared by this
// process (which registers owners) and the spawned bridge (which unseals).
process.env.CRED_KEYS = process.env.CRED_KEYS ?? `k1:${Buffer.from(Array.from({ length: 32 }, (_, i) => i * 7 % 256)).toString('base64')}`;
process.env.CRED_KEY_ACTIVE = process.env.CRED_KEY_ACTIVE ?? 'k1';
process.env.CRED_FP_KEY = process.env.CRED_FP_KEY ?? Buffer.from(Array.from({ length: 32 }, (_, i) => i * 11 % 256)).toString('base64');

const { query, close } = await import('../src/db.js');
const { registerOwner } = await import('../src/register-owner.js');
const { SIGNABLE, buildSign } = await import('../src/sign.js');

const results = [];
const check = async (name, fn) => {
  try {
    const ok = await fn();
    results.push([Boolean(ok), name, typeof ok === 'string' ? ` — ${ok}` : '']);
  } catch (err) {
    results.push([false, name, ` — ${err.message.split('\n')[0]}`]);
  }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- the fake QPay -------------------------------------------------------
const QPAY_PORT = 4603;
const invoices = new Map(); // invoice_id -> {invoiceCode, bearer, orderNo, amount}
const paid = new Map();     // invoice_id -> {payment_id, amount}
const checkCalls = [];      // {invoiceId, bearer}
let next401 = false;        // one authed call answers 401, then recovers

const qpayFake = createServer((req, res) => {
  let body = '';
  req.on('data', (d) => (body += d));
  req.on('end', () => {
    const auth = req.headers.authorization ?? '';
    res.setHeader('content-type', 'application/json');

    if (req.url === '/v2/auth/token' && req.method === 'POST') {
      const [user] = Buffer.from(auth.replace('Basic ', ''), 'base64').toString().split(':');
      return res.end(JSON.stringify({ access_token: `tok-${user}`, expires_in: 3600 }));
    }
    if (next401 && auth.startsWith('Bearer ')) {
      next401 = false;
      res.statusCode = 401;
      return res.end('{"error":"TOKEN_EXPIRED"}');
    }
    if (req.url === '/v2/invoice' && req.method === 'POST') {
      const j = JSON.parse(body);
      const id = `qinv-${invoices.size + 1}`;
      invoices.set(id, {
        invoiceCode: j.invoice_code,
        bearer: auth.replace('Bearer ', ''),
        orderNo: j.sender_invoice_no,
        amount: j.amount,
      });
      return res.end(JSON.stringify({ invoice_id: id, qr_text: 'Q'.repeat(242), qPay_shortUrl: `https://s.qpay.mn/${id}` }));
    }
    if (req.url === '/v2/payment/check' && req.method === 'POST') {
      const j = JSON.parse(body);
      checkCalls.push({ invoiceId: j.object_id, bearer: auth.replace('Bearer ', '') });
      const p = paid.get(j.object_id);
      return res.end(JSON.stringify({
        rows: p ? [{ payment_id: p.payment_id, payment_status: 'PAID', payment_amount: p.amount }] : [],
      }));
    }
    if (req.method === 'DELETE' && req.url.startsWith('/v2/invoice/')) {
      return res.end('{}');
    }
    res.statusCode = 404;
    res.end('{}');
  });
});
await new Promise((r) => qpayFake.listen(QPAY_PORT, '127.0.0.1', r));

// ---- the fake machine ----------------------------------------------------
const MACHINE_PORT = 4604;
const notifies = [];
const machine = createServer((req, res) => {
  let body = '';
  req.on('data', (d) => (body += d));
  req.on('end', () => {
    notifies.push(JSON.parse(body));
    res.end(JSON.stringify({ returnCode: 'SUCCESS', msg: 'SUCCESS' }));
  });
});
await new Promise((r) => machine.listen(MACHINE_PORT, '127.0.0.1', r));

// ---- two owners, two machines --------------------------------------------
const DA = `TA${Math.floor(Math.random() * 1e8)}`;
const DB = `TB${Math.floor(Math.random() * 1e8)}`;
const a = await registerOwner({
  ownerName: 'Альфа ХХК', contactPhone: '99110001', deviceNo: DA, location: 'A',
  username: 'userA', password: 'passA', invoiceCode: 'INV_A',
});
const b = await registerOwner({
  ownerName: 'Бета ХХК', contactPhone: '99110002', deviceNo: DB, location: 'B',
  username: 'userB', password: 'passB', invoiceCode: 'INV_B',
});

// ---- boot the bridge (NOT mock: it talks to the fake QPay) ---------------
const PORT = 3191;
const BRIDGE_ENV = {
  ...process.env,
  PORT: String(PORT),
  JETINNO_USERNAME: 'testname',
  JETINNO_APIKEY: 'DBRW17YE7FHKR72T',
  PUBLIC_URL: `http://localhost:${PORT}`,
  QPAY_BASE_URL: `http://127.0.0.1:${QPAY_PORT}`,
  QPAY_USERNAME: 'operator',
  QPAY_PASSWORD: 'op-pass',
  QPAY_INVOICE_CODE: 'INV_OPERATOR',
  ALLOW_PRIVATE_NOTIFY: '1',
};
delete BRIDGE_ENV.QPAY_MOCK;

function boot() {
  const child = spawn(process.execPath, ['src/server.js'], { env: BRIDGE_ENV, stdio: ['ignore', 'pipe', 'pipe'] });
  child.logText = '';
  child.stdout.on('data', (d) => (child.logText += d));
  child.stderr.on('data', (d) => (child.logText += d));
  return child;
}
async function waitUp() {
  for (let i = 0; i < 60; i += 1) {
    try {
      if ((await fetch(`http://localhost:${PORT}/health`)).ok) return;
    } catch {}
    await sleep(250);
  }
  throw new Error('bridge гарч ирсэнгүй');
}
let bridge = boot();
await waitUp();

function signedQr(deviceNo, orderNo) {
  const t = new Date();
  const p2 = (n) => String(n).padStart(2, '0');
  const time = `${t.getFullYear()}${p2(t.getMonth() + 1)}${p2(t.getDate())}${p2(t.getHours())}${p2(t.getMinutes())}${p2(t.getSeconds())}`;
  const data = {
    deviceNo, productId: '1', productName: 'Латте', orderNo,
    orderAmount: '450000', notifyUrl: `http://127.0.0.1:${MACHINE_PORT}/notify`,
  };
  const body = { username: 'testname', time, data };
  body.sign = buildSign({ username: body.username, time, ...data }, SIGNABLE.getQrCodeRequest, 'DBRW17YE7FHKR72T');
  return body;
}
const qr = (body) =>
  fetch(`http://localhost:${PORT}/jetinno/getQrCode`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }).then(async (r) => JSON.parse(await r.text()));
const invoiceOf = (orderNo) => [...invoices.entries()].find(([, v]) => v.orderNo === orderNo);

// ---- routing -------------------------------------------------------------
await check('А машины борлуулалт А эзэмшигчийн мерчантаар invoice үүсгэнэ', async () => {
  const r = await qr(signedQr(DA, 'ORD-A1'));
  const inv = invoiceOf('ORD-A1');
  return r.returnCode === 'SUCCESS' && inv && inv[1].invoiceCode === 'INV_A' && inv[1].bearer === 'tok-userA';
});

await check('Б машины борлуулалт Б-гийн мерчантаар — токен нь тусдаа', async () => {
  const r = await qr(signedQr(DB, 'ORD-B1'));
  const inv = invoiceOf('ORD-B1');
  return r.returnCode === 'SUCCESS' && inv[1].invoiceCode === 'INV_B' && inv[1].bearer === 'tok-userB';
});

await check('бүртгэлгүй машин операторын env мерчант руу унана + ingest_errors мөр', async () => {
  const r = await qr(signedQr('GHOST99', 'ORD-U1'));
  const inv = invoiceOf('ORD-U1');
  await sleep(600);
  const { rows } = await query(
    `select count(*)::int as n from public.ingest_errors where device_no='GHOST99' and reason='DEVICE_NOT_REGISTERED'`
  );
  return r.returnCode === 'SUCCESS' && inv[1].invoiceCode === 'INV_OPERATOR' && inv[1].bearer === 'tok-operator' && rows[0].n === 1;
});

await check('унтраасан credential-тэй машины борлуулалт ТАТГАЛЗАГДАНА — env руу унахгүй', async () => {
  // The schema derives is_active from status by CHECK, so disabling is a
  // status change — which is also how the real disable flow does it.
  await query(`update public.qpay_credentials set status='disabled', is_active=false where id=$1`, [b.credentialId]);
  const before = invoices.size;
  const r = await qr(signedQr(DB, 'ORD-B2'));
  await sleep(600);
  const { rows } = await query(
    `select count(*)::int as n from public.ingest_errors where reason='SALE_REFUSED_CREDENTIAL_DISABLED'`
  );
  await query(`update public.qpay_credentials set status='active', is_active=true where id=$1`, [b.credentialId]);
  return r.returnCode === 'FAIL' && invoices.size === before && rows[0].n === 1;
});

// ---- settlement under the issuing merchant -------------------------------
await check('төлбөрийн шалгалт invoice гаргасан мерчантаар явна, кофе гарна', async () => {
  const [invId, inv] = invoiceOf('ORD-A1');
  paid.set(invId, { payment_id: 'pay-A1', amount: inv.amount });
  const res = await fetch(`http://localhost:${PORT}/qpay/callback/ORD-A1`, { method: 'POST' });
  await sleep(1500);
  const checked = checkCalls.find((c) => c.invoiceId === invId);
  const { rows } = await query(`select status, paid_amount_mnt from public.orders where order_no='ORD-A1'`);
  return (
    res.status === 200 &&
    checked?.bearer === 'tok-userA' &&
    notifies.some((n) => n.data.orderNo === 'ORD-A1') &&
    rows[0]?.status === 'paid' &&
    rows[0]?.paid_amount_mnt === 4500
  );
});

await check('401 болсон токен нэг эргэлтэд эдгэрнэ — борлуулалт унахгүй', async () => {
  next401 = true;
  const r = await qr(signedQr(DA, 'ORD-A2'));
  const inv = invoiceOf('ORD-A2');
  return r.returnCode === 'SUCCESS' && inv[1].invoiceCode === 'INV_A';
});

// ---- restart: rehydrate rebuilds the OWNER's client ----------------------
await check('restart-ын дараа Б-гийн захиалга Б-гийн мерчантаар сэргэж төлөгдөнө', async () => {
  const [invId, inv] = invoiceOf('ORD-B1');
  paid.set(invId, { payment_id: 'pay-B1', amount: inv.amount });
  bridge.kill('SIGTERM');
  await sleep(500);
  bridge = boot();
  await waitUp();
  const res = await fetch(`http://localhost:${PORT}/qpay/callback/ORD-B1`, { method: 'POST' });
  await sleep(1500);
  const checked = checkCalls.filter((c) => c.invoiceId === invId);
  const { rows } = await query(`select status from public.orders where order_no='ORD-B1'`);
  return (
    res.status === 200 &&
    checked.some((c) => c.bearer === 'tok-userB') &&
    checked.every((c) => c.bearer === 'tok-userB') &&
    notifies.some((n) => n.data.orderNo === 'ORD-B1') &&
    rows[0]?.status === 'paid'
  );
});

bridge.kill('SIGTERM');
qpayFake.close();
machine.close();
await close();

const passed = results.filter(([ok]) => ok).length;
for (const [ok, name, extra] of results) console.log(`  ${ok ? '✓' : '✗'} ${name}${extra}`);
console.log(`\n  ${passed}/${results.length} давлаа`);
process.exit(passed === results.length ? 0 : 1);
