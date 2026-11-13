/**
 * The money path, against a real database and a fake QPay. Run: npm run test:settle
 *
 * What 018 changed, each as a claim this file checks:
 *   - a payment is on record BEFORE the machine is told, and a notify that
 *     fails is retried by the database-driven sweep, not by process memory;
 *   - a clear "no" from the machine is retried at once, a lost answer only
 *     after the grace window — never two cups for one payment;
 *   - QPay is answered 503 while the payment is not yet on record, SUCCESS
 *     once it is; an unsigned callback URL costs nothing and reveals nothing;
 *   - orders survive a restart, including the operator's own (env) sales;
 *   - an order whose credential now names another merchant is handed to a
 *     human, not checked with the wrong login;
 *   - the signature check neither leaks a valid signature nor accepts a
 *     value that splices in another message's fields;
 *   - notify URLs that point inside the network are refused.
 */
import { createHmac } from 'node:crypto';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';

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
    results.push([ok === true, name, typeof ok === 'string' ? ` — ${ok}` : ok === true ? '' : ` — ${JSON.stringify(ok)}`]);
  } catch (err) {
    results.push([false, name, ` — ${err.message.split('\n')[0]}`]);
  }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, ms = 8000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return true;
    await sleep(150);
  }
  return false;
};

// ---- fake QPay ------------------------------------------------------------
const QPAY_PORT = 4613;
const invoices = new Map(); // id -> { orderNo, bearer, callbackUrl, amount }
const paid = new Map(); // id -> amount (number or string)
const calls = { check: [], cancel: [] };
let checkFails = 0; // next N payment/check calls answer 500
let cancelSaysPaid = new Set();
const qpayFake = createServer((req, res) => {
  let body = '';
  req.on('data', (d) => (body += d));
  req.on('end', () => {
    const auth = req.headers.authorization ?? '';
    res.setHeader('content-type', 'application/json');
    if (req.url === '/v2/auth/token') {
      const [user] = Buffer.from(auth.replace('Basic ', ''), 'base64').toString().split(':');
      return res.end(JSON.stringify({ access_token: `tok-${user}`, expires_in: 3600 }));
    }
    if (req.url === '/v2/invoice' && req.method === 'POST') {
      const j = JSON.parse(body);
      const id = `inv-${invoices.size + 1}`;
      invoices.set(id, { orderNo: j.sender_invoice_no, bearer: auth.slice(7), callbackUrl: j.callback_url, amount: j.amount });
      return res.end(JSON.stringify({ invoice_id: id, qr_text: 'Q'.repeat(40), qPay_shortUrl: `https://s.qpay.mn/${id}` }));
    }
    if (req.url === '/v2/payment/check') {
      const j = JSON.parse(body);
      calls.check.push({ id: j.object_id, bearer: auth.slice(7) });
      if (checkFails > 0) {
        checkFails -= 1;
        res.statusCode = 500;
        return res.end('{"error":"INTERNAL","message":"username userA failed"}');
      }
      const amount = paid.get(j.object_id);
      return res.end(JSON.stringify({
        rows: amount !== undefined ? [{ payment_id: `pay-${j.object_id}`, payment_status: 'PAID', payment_amount: amount }] : [],
      }));
    }
    if (req.method === 'DELETE' && req.url.startsWith('/v2/invoice/')) {
      const id = req.url.split('/').pop();
      calls.cancel.push(id);
      if (cancelSaysPaid.has(id)) {
        res.statusCode = 400;
        return res.end('{"error":"INVOICE_PAID"}');
      }
      return res.end('{}');
    }
    res.statusCode = 404;
    res.end('{}');
  });
});
await new Promise((r) => qpayFake.listen(QPAY_PORT, '127.0.0.1', r));

// ---- fake machine ---------------------------------------------------------
// Answers by order number: 'ok', 'fail' (a clear no, once), 'hang' (never
// answers, once), 'fail-json' (FAIL whose message says SUCCESS, once).
const MACHINE_PORT = 4614;
const notifies = []; // orderNo of every notify received
const behaviour = new Map();
const machine = createServer((req, res) => {
  let body = '';
  req.on('data', (d) => (body += d));
  req.on('end', () => {
    const orderNo = JSON.parse(body || '{}')?.data?.orderNo;
    if (req.url !== '/notify-moved') notifies.push(orderNo);
    if (req.url === '/notify-moved') {
      res.statusCode = 307;
      res.setHeader('location', '/notify');
      return res.end();
    }
    const b = behaviour.get(orderNo) ?? 'ok';
    if (b !== 'ok') behaviour.delete(orderNo);
    if (b === 'hang') return; // no answer: the bridge times out
    if (b === 'fail') return res.end(JSON.stringify({ returnCode: 'FAIL', msg: 'device busy' }));
    if (b === 'fail-json') return res.end(JSON.stringify({ returnCode: 'FAIL', msg: 'not SUCCESS' }));
    res.end(JSON.stringify({ returnCode: 'SUCCESS', msg: 'SUCCESS' }));
  });
});
await new Promise((r) => machine.listen(MACHINE_PORT, '127.0.0.1', r));
const cups = (orderNo) => notifies.filter((o) => o === orderNo).length;

// ---- an owner and its machine ---------------------------------------------
const DA = `SA${Math.floor(Math.random() * 1e8)}`;
const DENV = `SE${Math.floor(Math.random() * 1e8)}`; // never registered: the operator's merchant
const a = await registerOwner({
  ownerName: 'Сэтл ХХК', contactPhone: '99110071', deviceNo: DA, location: 'A',
  username: 'userA', password: 'passA', invoiceCode: 'INV_A',
});

// ---- the bridge -------------------------------------------------------------
const PORT = 3193;
const DEBUG = 'settle-debug-key';
const BRIDGE_ENV = {
  ...process.env,
  PORT: String(PORT),
  JETINNO_USERNAME: 'testname',
  JETINNO_APIKEY: 'DBRW17YE7FHKR72T',
  PUBLIC_URL: `http://localhost:${PORT}/`, // a trailing slash, on purpose
  QPAY_BASE_URL: `http://127.0.0.1:${QPAY_PORT}`,
  QPAY_USERNAME: 'operator',
  QPAY_PASSWORD: 'op-pass',
  QPAY_INVOICE_CODE: 'INV_OPERATOR',
  ALLOW_PRIVATE_NOTIFY: '1',
  OWNER_CACHE_TTL_MS: '0',
  SWEEP_INTERVAL_MS: '1000',
  NOTIFY_TIMEOUT_MS: '700',
  NOTIFY_GRACE_SECONDS: '30',
  DEBUG_KEY: DEBUG,
};
delete BRIDGE_ENV.QPAY_MOCK;

function boot(env = BRIDGE_ENV) {
  const child = spawn(process.execPath, ['src/server.js'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  child.logText = '';
  child.stdout.on('data', (d) => (child.logText += d));
  child.stderr.on('data', (d) => (child.logText += d));
  return child;
}
async function waitUp(port) {
  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(`http://localhost:${port}/health`)).ok) return;
    } catch {
      // not yet
    }
    await sleep(250);
  }
  throw new Error(`bridge on ${port} did not start`);
}
let bridge = boot();
await waitUp(PORT);

function signed(deviceNo, orderNo, extra = {}) {
  const data = {
    deviceNo, productId: '1', productName: 'Латте', orderNo, orderAmount: '450000',
    notifyUrl: `http://127.0.0.1:${MACHINE_PORT}/notify`, ...extra,
  };
  const body = { username: 'testname', time: timestamp(), data };
  body.sign = buildSign({ username: body.username, time: body.time, ...data }, SIGNABLE.getQrCodeRequest, 'DBRW17YE7FHKR72T');
  return body;
}
const post = (body, port = PORT) =>
  fetch(`http://localhost:${port}/jetinno/getQrCode`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  }).then((r) => r.json());
const row = async (orderNo) => (await query(`select * from public.orders where order_no = $1`, [orderNo])).rows[0];
const invoiceOf = (orderNo) => [...invoices.entries()].find(([, v]) => v.orderNo === orderNo);
async function sale(deviceNo, orderNo, extra) {
  const r = await post(signed(deviceNo, orderNo, extra));
  if (r.returnCode !== 'SUCCESS') throw new Error(`getQrCode ${orderNo}: ${JSON.stringify(r)}`);
  await until(async () => Boolean((await row(orderNo))?.qpay_invoice_id), 5000);
  return invoiceOf(orderNo);
}
const callback = (url) => fetch(url.replace(/^http:\/\/localhost:\d+/, `http://localhost:${PORT}`), { method: 'POST' })
  .then(async (r) => ({ status: r.status, text: await r.text() }));

// ---- 1. the happy path, signed -------------------------------------------------
await check('захиалга QR харуулсны дараа нэг мөр болж хадгалагдана: invoice-тай, гарын үсэгтэй callback-тай', async () => {
  const [id, inv] = await sale(DA, 'S-OK');
  const r = await row('S-OK');
  return (r.status === 'awaiting_payment' && r.qpay_invoice_id === id && r.source === 'owner' &&
    r.merchant_fp !== null && /\/qpay\/cb\/SA\d+\/S-OK\/[A-Za-z0-9_-]{22}$/.test(inv.callbackUrl) &&
    !inv.callbackUrl.includes('//qpay')) || { r: r && { status: r.status, fp: r.merchant_fp }, url: inv.callbackUrl };
});

await check('төлбөр орж, гарын үсэгтэй callback ирэхэд яг нэг аяга гарна, мөр paid болно', async () => {
  const [id, inv] = invoiceOf('S-OK');
  paid.set(id, 4500);
  const r = await callback(inv.callbackUrl);
  const ok = await until(async () => (await row('S-OK')).status === 'paid');
  return (r.status === 200 && r.text === 'SUCCESS' && ok && cups('S-OK') === 1) || { r, cups: cups('S-OK'), status: (await row('S-OK')).status };
});

await check('QPay ижил callback-ийг 5 удаа зэрэг дуудсан ч аяга нэмэгдэхгүй', async () => {
  const [, inv] = invoiceOf('S-OK');
  await Promise.all(Array.from({ length: 5 }, () => callback(inv.callbackUrl)));
  await sleep(500);
  return cups('S-OK') === 1 || `cups ${cups('S-OK')}`;
});

await check('шинэ захиалгад 5 callback зэрэг ирэхэд нэг л аяга гарна', async () => {
  const [id, inv] = await sale(DA, 'S-RACE');
  paid.set(id, 4500);
  await Promise.all(Array.from({ length: 5 }, () => callback(inv.callbackUrl)));
  await until(async () => (await row('S-RACE')).status === 'paid');
  await sleep(300);
  return cups('S-RACE') === 1 || `cups ${cups('S-RACE')}`;
});

// ---- 2. a clear "no" from the machine -----------------------------------------
await check('машин тодорхой ТАТГАЛЗВАЛ төлбөр бүртгэлтэй үлдэж, QPay-д SUCCESS, sweep дахин мэдэгдэнэ', async () => {
  const [id, inv] = await sale(DA, 'S-REFUSED');
  paid.set(id, 4500);
  behaviour.set('S-REFUSED', 'fail');
  const r = await callback(inv.callbackUrl);
  const mid = await row('S-REFUSED');
  const recorded = mid.payment_confirmed_at !== null && mid.notify_sent_at === null && mid.status === 'payment_confirmed';
  const ok = await until(async () => (await row('S-REFUSED')).status === 'paid', 9000);
  return (r.status === 200 && recorded && ok && cups('S-REFUSED') === 2) ||
    { r, mid: { status: mid.status, conf: mid.payment_confirmed_at, sent: mid.notify_sent_at }, cups: cups('S-REFUSED') };
});

await check('returnCode FAIL боловч текстэнд SUCCESS орсон хариуг амжилт гэж үзэхгүй', async () => {
  const [id, inv] = await sale(DA, 'S-FAILJSON');
  paid.set(id, 4500);
  behaviour.set('S-FAILJSON', 'fail-json');
  await callback(inv.callbackUrl);
  const mid = await row('S-FAILJSON');
  const ok = await until(async () => (await row('S-FAILJSON')).status === 'paid', 9000);
  return (mid.status === 'payment_confirmed' && ok) || { mid: mid.status };
});

// ---- 3. a lost answer ------------------------------------------------------------
await check('машин хариулаагүй (timeout) бол grace хугацаанд ДАХИН МЭДЭГДЭХГҮЙ — хоёр аяга гарахгүй', async () => {
  const [id, inv] = await sale(DA, 'S-HANG');
  paid.set(id, 4500);
  behaviour.set('S-HANG', 'hang');
  const r = await callback(inv.callbackUrl);
  await sleep(3500); // three sweep ticks
  const mid = await row('S-HANG');
  return (r.status === 200 && cups('S-HANG') === 1 && mid.notify_sent_at !== null && mid.status !== 'paid') ||
    { r, cups: cups('S-HANG'), status: mid.status };
});

await check('grace хугацаа өнгөрмөгц sweep машинд дахин мэдэгдэж, paid болгоно', async () => {
  await query(`update public.orders set notify_sent_at = now() - interval '1 hour' where order_no = 'S-HANG'`);
  const ok = await until(async () => (await row('S-HANG')).status === 'paid', 6000);
  return (ok && cups('S-HANG') === 2) || { cups: cups('S-HANG'), status: (await row('S-HANG')).status };
});

// ---- 3b. stale rows: a payment too old to brew goes to a human ---------------------
await check('15 минутаас хуучин баталгаажсан төлбөрт машинд МЭДЭГДЭХГҮЙ — хүн шийдэх жагсаалтад орно', async () => {
  const [id, inv] = await sale(DA, 'S-STALE');
  paid.set(id, 4500);
  behaviour.set('S-STALE', 'fail');
  await callback(inv.callbackUrl);
  // As if the old in-memory settle confirmed it an hour ago and never wrote the rest.
  await query(`update public.orders set payment_confirmed_at = now() - interval '1 hour' where order_no = 'S-STALE'`);
  const ok = await until(async () => (await row('S-STALE')).status === 'needs_human', 6000);
  await sleep(1200);
  return (ok && cups('S-STALE') === 1) || { status: (await row('S-STALE')).status, cups: cups('S-STALE') };
});

await check('хуучин QR-ыг цуцлах үед QPay «төлөгдсөн» гэвэл машинд мэдэгдэхгүй — хүнд шилжинэ', async () => {
  const [id] = await sale(DA, 'S-OLDPAID');
  paid.set(id, 4500);
  cancelSaysPaid.add(id);
  await query(`update public.orders set created_at = now() - interval '2 hours', expires_at = now() - interval '110 minutes' where order_no = 'S-OLDPAID'`);
  const ok = await until(async () => (await row('S-OLDPAID')).status === 'needs_human', 6000);
  return (ok && cups('S-OLDPAID') === 0) || { status: (await row('S-OLDPAID')).status, cups: cups('S-OLDPAID') };
});

await check('notify хаяг 307-оор шилжүүлбэл дагаж, яг нэг аяга гаргана', async () => {
  const [id, inv] = await sale(DA, 'S-MOVED', { notifyUrl: `http://127.0.0.1:${MACHINE_PORT}/notify-moved` });
  paid.set(id, 4500);
  const r = await callback(inv.callbackUrl);
  const ok = await until(async () => (await row('S-MOVED')).status === 'paid');
  return (r.status === 200 && ok && cups('S-MOVED') === 1) || { r, cups: cups('S-MOVED') };
});

// ---- 4. QPay could not be asked ----------------------------------------------------
await check('QPay-ийн шалгалт 500 өгвөл QPay-д 503 (дахин дуудна), мөр төлөгдөөгүй хэвээр', async () => {
  const [id, inv] = await sale(DA, 'S-QPAY500');
  paid.set(id, 4500);
  checkFails = 1;
  const r = await callback(inv.callbackUrl);
  const mid = await row('S-QPAY500');
  const second = await callback(inv.callbackUrl);
  const ok = await until(async () => (await row('S-QPAY500')).status === 'paid');
  return (r.status === 503 && mid.status === 'awaiting_payment' && mid.last_error?.startsWith('check:') &&
    !mid.last_error.includes('userA') && second.status === 200 && ok && cups('S-QPAY500') === 1) ||
    { r: r.status, mid: { status: mid.status, err: mid.last_error }, second: second.status, cups: cups('S-QPAY500') };
});

// The bridge's own derivation (server.js): signed by a key derived from the
// Jetinno key, which this test knows.
const CB_KEY = createHmac('sha256', 'DBRW17YE7FHKR72T').update('qpay-callback-v1').digest();
const macFor = (d, o) => createHmac('sha256', CB_KEY).update(`${d}\n${o}`).digest('base64url').slice(0, 22);

await check('гарын үсэгтэй боловч мэдэгдэхгүй захиалгын callback 503 — QPay дахин оролдоно', async () => {
  const r = await fetch(`http://localhost:${PORT}/qpay/cb/${DA}/NOPE-1/${macFor(DA, 'NOPE-1')}`, { method: 'POST' });
  return r.status === 503 || `status ${r.status}`;
});

await check('гарын үсэггүй (буруу MAC) callback QPay-ээс юу ч асуухгүй, 200 буцаана', async () => {
  const [id] = await sale(DA, 'S-FORGED');
  paid.set(id, 4500);
  const before = calls.check.length;
  const r = await fetch(`http://localhost:${PORT}/qpay/cb/${DA}/S-FORGED/AAAAAAAAAAAAAAAAAAAAAA`, { method: 'POST' });
  await sleep(300);
  return (r.status === 200 && calls.check.length === before && cups('S-FORGED') === 0) || { status: r.status, checks: calls.check.length - before };
});

// ---- 5. amounts ----------------------------------------------------------------------
await check('дутуу төлбөрт аяга гарахгүй, операторт мэдэгдэнэ', async () => {
  const [id, inv] = await sale(DA, 'S-UNDER');
  paid.set(id, 4000);
  const r = await callback(inv.callbackUrl);
  const logged = await until(async () =>
    (await query(`select count(*)::int n from public.ingest_errors where order_no = 'S-UNDER' and reason = 'UNDERPAID'`)).rows[0].n === 1);
  return (r.status === 200 && cups('S-UNDER') === 0 && logged && (await row('S-UNDER')).status !== 'paid') ||
    { r, cups: cups('S-UNDER'), logged };
});

await check('QPay-ийн дүн тоо биш бол (4,500.00) аяга гарахгүй', async () => {
  const [id, inv] = await sale(DA, 'S-NAN');
  paid.set(id, '4,500.00');
  await callback(inv.callbackUrl);
  return (cups('S-NAN') === 0 && (await row('S-NAN')).status !== 'paid') || `cups ${cups('S-NAN')}`;
});

// ---- 6. the operator's own merchant ---------------------------------------------------
await check('бүртгэлгүй машины (операторын данс) захиалга ч мөр болж хадгалагдана, төлөгдвөл гарна', async () => {
  const [id, inv] = await sale(DENV, 'S-ENV');
  const r1 = await row('S-ENV');
  paid.set(id, 4500);
  const r = await callback(inv.callbackUrl);
  const ok = await until(async () => (await row('S-ENV')).status === 'paid');
  return (r1.source === 'env' && r1.owner_id === null && inv.bearer === 'tok-operator' && r.status === 200 && ok &&
    cups('S-ENV') === 1) || { src: r1?.source, bearer: inv.bearer, status: r.status };
});

// ---- 7. a restart between payment and callback ------------------------------------------
await check('restart хийгдсэн ч төлөгдсөн захиалга шинэ процесст нэг аяга гаргана (env захиалга ч)', async () => {
  const [ida, inva] = await sale(DA, 'S-RESTART');
  const [ide, inve] = await sale(DENV, 'S-RESTART-ENV');
  bridge.kill('SIGTERM');
  await new Promise((r) => bridge.once('exit', r));
  const graceful = bridge.logText.includes('shutting down SIGTERM');
  paid.set(ida, 4500);
  paid.set(ide, 4500);
  bridge = boot();
  await waitUp(PORT);
  const r1 = await callback(inva.callbackUrl);
  const r2 = await callback(inve.callbackUrl);
  const ok = await until(async () => (await row('S-RESTART')).status === 'paid' && (await row('S-RESTART-ENV')).status === 'paid');
  return (graceful && r1.status === 200 && r2.status === 200 && ok && cups('S-RESTART') === 1 && cups('S-RESTART-ENV') === 1) ||
    { graceful, r1: r1.status, r2: r2.status, a: cups('S-RESTART'), e: cups('S-RESTART-ENV') };
});

// ---- 8. abandoned QRs ------------------------------------------------------------------------
await check('хугацаа нь дууссан төлөгдөөгүй QR-ыг sweep QPay дээр цуцалж, cancelled болгоно', async () => {
  const [id] = await sale(DA, 'S-ABANDON');
  await query(`update public.orders set expires_at = now() - interval '1 minute' where order_no = 'S-ABANDON'`);
  const ok = await until(async () => (await row('S-ABANDON')).status === 'cancelled', 6000);
  const replay = await post(signed(DA, 'S-ABANDON'));
  return (ok && calls.cancel.includes(id) && replay.returnCode === 'FAIL') || { status: (await row('S-ABANDON')).status, replay };
});

await check('цуцлах үед QPay INVOICE_PAID гэвэл sweep төлбөрийг хүлээн авч нэг аяга гаргана', async () => {
  const [id] = await sale(DA, 'S-LATEPAY');
  paid.set(id, 4500);
  cancelSaysPaid.add(id);
  await query(`update public.orders set expires_at = now() - interval '1 minute' where order_no = 'S-LATEPAY'`);
  const ok = await until(async () => (await row('S-LATEPAY')).status === 'paid', 6000);
  return (ok && cups('S-LATEPAY') === 1) || { status: (await row('S-LATEPAY')).status, cups: cups('S-LATEPAY') };
});

// ---- 9. a credential re-pointed at another merchant -------------------------------------------
await check('захиалга нээлттэй байхад credential өөр мерчант руу солигдвол хуучин нэвтрэлтээр шалгахгүй — хүнд шилжүүлнэ', async () => {
  const [id, inv] = await sale(DA, 'S-SWITCH');
  // The credential now names another merchant (its fingerprint changed).
  await query(`update public.qpay_credentials set fingerprint = 'f'||repeat('0',63) where id = $1`, [a.credentialId]);
  bridge.kill('SIGTERM');
  await new Promise((r) => bridge.once('exit', r));
  paid.set(id, 4500);
  bridge = boot();
  await waitUp(PORT);
  const before = calls.check.length;
  const r = await callback(inv.callbackUrl);
  await until(async () => (await row('S-SWITCH')).status === 'needs_human', 4000);
  const { rows } = await query(`select count(*)::int n from public.ingest_errors where reason like '%merchant changed%'`);
  return ((await row('S-SWITCH')).status === 'needs_human' && calls.check.length === before && cups('S-SWITCH') === 0 &&
    r.status === 200 && rows[0].n >= 1) || { status: (await row('S-SWITCH')).status, r: r.status };
});

// ---- 10. signatures -----------------------------------------------------------------------------
await check('буруу sign-д SIGN_ERROR, логт зөв гарын үсэг (32 hex) гарахгүй', async () => {
  const body = signed(DA, 'S-BADSIG');
  const good = body.sign;
  body.sign = '0'.repeat(32);
  const r = await post(body);
  await sleep(200);
  return (r.msg === 'SIGN_ERROR' && !bridge.logText.includes(good) && !/expected [0-9A-F]{32}/.test(bridge.logText)) || r;
});

await check('өөр мессежийн талбарыг шигтгэсэн orderNo хүчинтэй гарын үсэгтэй байсан ч татгалзагдана', async () => {
  const r = await post(signed(DA, 'S-INJ&payStatus=PAYSUCCESS&payType=1001'));
  return r.msg === 'SIGN_ERROR' || r;
});

await check('давталт ижил orderNo-гоор өөр дүнтэй ирвэл хуучин QR-ыг өгөхгүй', async () => {
  await sale(DA, 'S-REPLAY');
  const same = await post(signed(DA, 'S-REPLAY'));
  const other = await post(signed(DA, 'S-REPLAY', { orderAmount: '100' }));
  return (same.returnCode === 'SUCCESS' && other.returnCode === 'FAIL' && other.msg === 'ORDERNO_EXIST') || { same, other };
});

// ---- 10b. the machine's own reports -------------------------------------------------------------
const signedAs = (keys, data) => {
  const body = { username: 'testname', time: timestamp(), data };
  body.sign = buildSign({ username: body.username, time: body.time, ...data }, keys, 'DBRW17YE7FHKR72T');
  return body;
};
const postTo = (path, body) =>
  fetch(`http://localhost:${PORT}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
    .then((r) => r.json());

await check('productdone хүлээн авагдаж, кофе гарсныг мөрөнд бичнэ', async () => {
  const r = await postTo('/jetinno/productdone', signedAs(SIGNABLE.productDoneRequest,
    { deviceNo: DA, productId: '1', orderNo: 'S-OK', orderAmount: '450000', isFinish: 'SUCCESS' }));
  const ok = await until(async () => (await row('S-OK')).product_done_at !== null);
  return (r.returnCode === 'SUCCESS' && ok && (await row('S-OK')).product_done_ok === true) || r;
});

await check('машин refund хүсвэл ERROR буцааж, бүртгэл үлдээж операторт мэдэгдэнэ', async () => {
  const r = await postTo('/jetinno/refund', signedAs(SIGNABLE.refundRequest,
    { deviceNo: DA, orderNo: 'S-RACE', refundAmount: '450000' }));
  const logged = await until(async () =>
    (await query(`select count(*)::int n from public.ingest_errors where order_no = 'S-RACE' and reason = 'REFUND_REQUESTED'`)).rows[0].n === 1);
  return (r.data?.refundState === 'ERROR' && logged) || r;
});

// ---- 11. public surface --------------------------------------------------------------------------
await check('/health нийтэд зөвхөн {ok, push, db}; debug түлхүүртэй бол бүрэн', async () => {
  const pub = await (await fetch(`http://localhost:${PORT}/health`)).json();
  const full = await (await fetch(`http://localhost:${PORT}/health`, { headers: { 'x-debug-key': DEBUG } })).json();
  return (Object.keys(pub).sort().join() === 'db,ok,push' && 'dwFailed' in full && 'ownerCache' in full) || { pub, full };
});

bridge.kill('SIGTERM');
await new Promise((r) => bridge.once('exit', r));

// ---- 12. notify URLs into the network, with no test escape hatch --------------------------------
const PORT2 = 3194;
const strict = boot({ ...BRIDGE_ENV, PORT: String(PORT2), PUBLIC_URL: `http://localhost:${PORT2}`, ALLOW_PRIVATE_NOTIFY: '' });
await waitUp(PORT2);
await check('дотоод сүлжээ рүү заасан notifyUrl татгалзагдана (IPv6, 127.1, төгсгөлийн цэг, нэвтрэх нэр, CGNAT)', async () => {
  const urls = [
    'http://[::1]:10000/x', 'http://127.1/x', 'http://localhost./x', 'http://user:pw@example.com/x',
    'http://100.64.1.2/x', 'http://[::ffff:127.0.0.1]/x', 'http://[fd00::1]/x', 'http://169.254.169.254/latest',
  ];
  const out = [];
  for (const [i, u] of urls.entries()) {
    const r = await post(signed(DA, `S-SSRF-${i}`, { notifyUrl: u }), PORT2);
    out.push(r.msg);
  }
  return out.every((m) => m === 'PARAM_ERROR: notifyUrl') || out;
});
await check('DEBUG_KEY-гүйгээр /check хаалттай (404)', async () => {
  const r = await fetch(`http://localhost:${PORT2}/check/${DA}/S-OK`);
  return r.status === 404 || `status ${r.status}`;
});
strict.kill('SIGTERM');
await new Promise((r) => strict.once('exit', r));

qpayFake.close();
machine.close();
await close();

const passed = results.filter(([ok]) => ok).length;
for (const [ok, name, extra] of results) console.log(`  ${ok ? '✓' : '✗'} ${name}${extra}`);
console.log(`\n  ${passed}/${results.length} давлаа`);
if (passed !== results.length) console.log('\n--- bridge log (tail) ---\n' + bridge.logText.slice(-4000));
process.exit(passed === results.length ? 0 : 1);
