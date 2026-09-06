/**
 * Integration test for the review's money-path fixes. Run: npm run test:recovery
 *
 * The scenario that matters most: the process restarts (every Render deploy)
 * between a customer paying and the webhook arriving. Before these fixes the
 * webhook was answered SUCCESS — which stops QPay's retries — while the empty
 * Map made settlement impossible: money taken, no coffee, no recovery. Now
 * the order is rehydrated from the dual-written Postgres row, and when even
 * that fails, the answer is NOT SUCCESS so QPay keeps retrying.
 */
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { query, close } from '../src/db.js';
import * as store from '../src/store.js';

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

// ---- a fake machine that records notifies --------------------------------
const MACHINE_PORT = 4602;
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

// ---- seed a machine + one live order (the "previous process" wrote it) ---
const ownerId = randomUUID();
const credId = randomUUID();
const machineId = randomUUID();
const deviceNo = `R${Math.floor(Math.random() * 1e9)}`;
await query(`insert into public.owners (id, name, contact_phone) values ($1,'Сэргээлт ХХК','99110001')`, [ownerId]);
await query(
  `insert into public.qpay_credentials (id, owner_id, label, sealed, key_id, fingerprint, status, is_active, source)
   values ($1,$2,'Үндсэн','v1.k1.a.b.c','k1',$3,'active',true,'cli')`,
  [credId, ownerId, 'e'.repeat(64)]
);
await query(
  `insert into public.machines (id, owner_id, qpay_credential_id, device_no, label, status)
   values ($1,$2,$3,$4,'Сэргээлт','active')`,
  [machineId, ownerId, credId, deviceNo]
);

const LOST = 'LOSTORDER1';
const row = await store.beginOrder({
  machineId,
  ownerId,
  credentialId: credId,
  orderNo: LOST,
  deviceNo,
  notifyUrl: `http://127.0.0.1:${MACHINE_PORT}/notify`,
  productId: '1',
  productName: 'Латте',
  rawOrderAmount: '450000',
  amountDivisor: 100,
  amountMnt: 4500,
  senderInvoiceNo: LOST,
  callbackUrl: 'http://x/cb',
  abandonAfterMs: 600000,
});
await store.attachInvoice(row.id, { invoiceId: `mock-${LOST}`, qrCode: 'https://s.qpay.mn/x' });

// ---- boot a FRESH bridge (its Map has never seen LOST) -------------------
const PORT = 3193;
const bridge = spawn(process.execPath, ['src/server.js'], {
  env: {
    ...process.env,
    PORT: String(PORT),
    QPAY_MOCK: '1',
    JETINNO_USERNAME: 'testname',
    JETINNO_APIKEY: 'DBRW17YE7FHKR72T',
    PUBLIC_URL: `http://localhost:${PORT}`,
    DEBUG_KEY: 'dk',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let bridgeLog = '';
bridge.stdout.on('data', (d) => (bridgeLog += d));
bridge.stderr.on('data', (d) => (bridgeLog += d));
for (let i = 0; i < 60; i += 1) {
  try {
    if ((await fetch(`http://localhost:${PORT}/health`)).ok) break;
  } catch {}
  await sleep(250);
}

await check('restart-ын дараах webhook: захиалга сангаас сэргэж, кофе гарна', async () => {
  const res = await fetch(`http://localhost:${PORT}/qpay/callback/${LOST}`, { method: 'POST' });
  const text = await res.text();
  await sleep(1500); // dw settle chain
  const after = await store.findOrderByMachine(machineId, LOST);
  return (
    res.status === 200 &&
    text === 'SUCCESS' &&
    notifies.length === 1 &&
    notifies[0].data.orderNo === LOST &&
    notifies[0].data.payStatus === 'PAYSUCCESS' &&
    after.status === 'paid'
  );
});

await check('мөн webhook дахин ирвэл хоёр дахь кофе гарахгүй', async () => {
  const res = await fetch(`http://localhost:${PORT}/qpay/callback/${LOST}`, { method: 'POST' });
  return res.status === 200 && (await res.text()) === 'SUCCESS' && notifies.length === 1;
});

await check('сангаас ч олдохгүй захиалгад SUCCESS БУЦААХГҮЙ — QPay дахин оролдоно', async () => {
  const res = await fetch(`http://localhost:${PORT}/qpay/callback/NEVEREXISTED`, { method: 'POST' });
  return res.status !== 200 && !(await res.text()).includes('SUCCESS');
});

bridge.kill('SIGTERM');

// ---- a second bridge with instant abandonment to exercise the sweep ------
const PORT2 = 3192;
const bridge2 = spawn(process.execPath, ['src/server.js'], {
  env: {
    ...process.env,
    PORT: String(PORT2),
    QPAY_MOCK: '1',
    JETINNO_USERNAME: 'testname',
    JETINNO_APIKEY: 'DBRW17YE7FHKR72T',
    PUBLIC_URL: `http://localhost:${PORT2}`,
    ABANDON_AFTER_MS: '0',
    SWEEP_INTERVAL_MS: '500',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let log2 = '';
bridge2.stdout.on('data', (d) => (log2 += d));
bridge2.stderr.on('data', (d) => (log2 += d));
for (let i = 0; i < 60; i += 1) {
  try {
    if ((await fetch(`http://localhost:${PORT2}/health`)).ok) break;
  } catch {}
  await sleep(250);
}

// Signed getQrCode against bridge2.
import { SIGNABLE, buildSign } from '../src/sign.js';
function signedQr(orderNo) {
  const t = new Date();
  const p2 = (n) => String(n).padStart(2, '0');
  const time = `${t.getFullYear()}${p2(t.getMonth() + 1)}${p2(t.getDate())}${p2(t.getHours())}${p2(t.getMinutes())}${p2(t.getSeconds())}`;
  const data = {
    deviceNo,
    productId: '1',
    productName: 'Латте',
    orderNo,
    orderAmount: '450000',
    notifyUrl: `http://127.0.0.1:${MACHINE_PORT}/notify`,
  };
  const body = { username: 'testname', time, data };
  body.sign = buildSign({ username: body.username, time, ...data }, SIGNABLE.getQrCodeRequest, 'DBRW17YE7FHKR72T');
  return body;
}
const post = (port, body) =>
  fetch(`http://localhost:${port}/jetinno/getQrCode`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }).then(async (r) => JSON.parse(await r.text()));

await check('зэрэгцээ давхар getQrCode нэг л QR буцаана — давхар invoice үүсэхгүй', async () => {
  const body = signedQr('DUP1');
  const [a, b] = await Promise.all([post(PORT2, body), post(PORT2, body)]);
  return (
    a.returnCode === 'SUCCESS' &&
    b.returnCode === 'SUCCESS' &&
    a.data.qrCode === b.data.qrCode
  );
});

await check('sweep цуцалсны дараа давталт үхсэн QR-ын оронд алдаа буцаана', async () => {
  const body = signedQr('SWEPT1');
  const first = await post(PORT2, body);
  if (first.returnCode !== 'SUCCESS') return 'эхний хүсэлт унав';
  // ABANDON_AFTER_MS=0: дараагийн sweep tick цуцална.
  for (let i = 0; i < 30; i += 1) {
    await sleep(500);
    if (log2.includes('sweep cancelled SWEPT1')) break;
  }
  if (!log2.includes('sweep cancelled SWEPT1')) return 'sweep хэзээ ч цуцалсангүй';
  const replay = await post(PORT2, body);
  return replay.returnCode === 'FAIL' && !JSON.stringify(replay).includes('mock/pay');
});

bridge2.kill('SIGTERM');
machine.close();
await close();

const passed = results.filter(([ok]) => ok).length;
for (const [ok, name, extra] of results) console.log(`  ${ok ? '✓' : '✗'} ${name}${extra}`);
console.log(`\n  ${passed}/${results.length} давлаа`);
process.exit(passed === results.length ? 0 : 1);
