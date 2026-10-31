/**
 * Phone notifications end to end (migration 017). Run: npm run test:notify
 *
 * A real sale goes through the bridge — signed getQrCode, a QPay callback,
 * the settle — and the push it causes arrives at a local HTTPS push service
 * that DECRYPTS it with the subscription's own keys, exactly as a phone's
 * browser would. Asserting on the decrypted payload is the only way to know
 * the lock screen would show the right words, rather than that some bytes
 * were posted somewhere.
 *
 * The operator's announcements go through the same push service and a fake
 * SMS gateway, and the owner's inbox is read back through the owner API.
 *
 * Needs DATABASE_URL and PUSH_TLS_DIR. scripts/notify-test.sh supplies both.
 */
import { randomUUID, randomBytes, createECDH } from 'node:crypto';
import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import webpush from 'web-push';
import ece from 'http_ece';

// Crypto env BEFORE any src/ import — this process seals the owners'
// credentials and the spawned bridge opens them.
process.env.CRED_KEYS = `k1:${randomBytes(32).toString('base64')}`;
process.env.CRED_KEY_ACTIVE = 'k1';
process.env.CRED_FP_KEY = randomBytes(32).toString('base64');

const { query, close } = await import('../src/db.js');
const { registerOwner } = await import('../src/register-owner.js');
const { SIGNABLE, buildSign } = await import('../src/sign.js');

// Only an exact `true` passes; a string explains a failure.
const results = [];
const check = async (name, fn) => {
  try {
    const ok = await fn();
    results.push([ok === true, name, typeof ok === 'string' ? ` — ${ok}` : '']);
  } catch (err) {
    results.push([false, name, ` — ${err.message.split('\n')[0]}`]);
  }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const listen = (server, port) => new Promise((r) => server.listen(port, '127.0.0.1', r));
const readBody = (req) =>
  new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
  });

// ---- a stand-in Supabase ---------------------------------------------------
const { publicKey: jwtPublic, privateKey: jwtPrivate } = await generateKeyPair('ES256', { extractable: true });
const jwk = { ...(await exportJWK(jwtPublic)), kid: 'k1', alg: 'ES256', use: 'sig' };
const JWKS_PORT = 4612;
const ISSUER_BASE = `http://127.0.0.1:${JWKS_PORT}`;
const jwks = createServer((req, res) => {
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify({ keys: [jwk] }));
});
await listen(jwks, JWKS_PORT);
const mint = (sub) =>
  new SignJWT({ amr: [{ method: 'otp', timestamp: Math.floor(Date.now() / 1000) }] })
    .setProtectedHeader({ alg: 'ES256', kid: 'k1' })
    .setSubject(sub)
    .setIssuedAt()
    .setIssuer(`${ISSUER_BASE}/auth/v1`)
    .setAudience('authenticated')
    .setExpirationTime('1h')
    .sign(jwtPrivate);

// ---- a stand-in QPay that can be told an invoice is paid ---------------------
const QPAY_PORT = 4610;
const invoices = new Map();
const paid = new Map();
const qpayFake = createServer(async (req, res) => {
  const body = (await readBody(req)).toString();
  const auth = req.headers.authorization ?? '';
  res.setHeader('content-type', 'application/json');
  if (req.url === '/v2/auth/token') {
    const [user] = Buffer.from(auth.replace('Basic ', ''), 'base64').toString().split(':');
    return res.end(JSON.stringify({ access_token: `tok-${user}`, expires_in: 3600 }));
  }
  if (req.url === '/v2/invoice' && req.method === 'POST') {
    const j = JSON.parse(body);
    const id = `qinv-${invoices.size + 1}`;
    invoices.set(id, { orderNo: j.sender_invoice_no, amount: j.amount });
    return res.end(JSON.stringify({ invoice_id: id, qr_text: 'Q'.repeat(200), qPay_shortUrl: `https://s.qpay.mn/${id}` }));
  }
  if (req.url === '/v2/payment/check') {
    const p = paid.get(JSON.parse(body).object_id);
    return res.end(JSON.stringify({ rows: p ? [{ payment_id: p.id, payment_status: 'PAID', payment_amount: p.amount }] : [] }));
  }
  if (req.method === 'DELETE') return res.end('{}');
  res.statusCode = 404;
  res.end('{}');
});
await listen(qpayFake, QPAY_PORT);

// ---- the coffee machine ------------------------------------------------------
const MACHINE_PORT = 4611;
const machine = createServer(async (req, res) => {
  await readBody(req);
  res.end('{"returnCode":"SUCCESS","msg":"SUCCESS"}');
});
await listen(machine, MACHINE_PORT);

// ---- an SMS gateway ------------------------------------------------------------
const SMS_PORT = 4613;
const smsOut = [];
const smsFake = createServer(async (req, res) => {
  const p = new URLSearchParams((await readBody(req)).toString());
  smsOut.push({ to: p.get('sendto'), text: p.get('message') });
  res.setHeader('content-type', 'application/json');
  res.end('{"status":1,"sent_count":1,"message":"ok"}');
});
await listen(smsFake, SMS_PORT);

// ---- a push service, and the phones it delivers to ---------------------------
// Each "phone" is a browser subscription: its own P-256 key pair and auth
// secret. The service decrypts what the bridge sent with that phone's keys.
const PUSH_PORT = 4614;
const phones = new Map();
const pushIn = [];
const gone = new Set();
function phone(name) {
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();
  const authSecret = randomBytes(16);
  const path = `/push/${name}`;
  phones.set(path, { ecdh, authSecret });
  return {
    endpoint: `https://localhost:${PUSH_PORT}${path}`,
    keys: { p256dh: ecdh.getPublicKey().toString('base64url'), auth: authSecret.toString('base64url') },
  };
}
const tls = process.env.PUSH_TLS_DIR;
const pushService = createHttpsServer(
  { key: readFileSync(`${tls}/key.pem`), cert: readFileSync(`${tls}/cert.pem`) },
  async (req, res) => {
    const raw = await readBody(req);
    if (gone.has(req.url)) {
      res.statusCode = 410;
      return res.end();
    }
    const device = phones.get(req.url);
    let payload;
    try {
      payload = JSON.parse(
        ece.decrypt(raw, { version: 'aes128gcm', privateKey: device.ecdh, authSecret: device.authSecret.toString('base64url') }).toString()
      );
    } catch (err) {
      payload = { undecryptable: err.message };
    }
    pushIn.push({ to: req.url, payload, authorization: req.headers.authorization ?? '' });
    res.statusCode = 201;
    res.end();
  }
);
await listen(pushService, PUSH_PORT);
const pushesTo = (name, from = 0) => pushIn.slice(from).filter((p) => p.to === `/push/${name}`);

// ---- two businesses, a person running each, and the operator -----------------
const OPERATOR = randomUUID();
const UA = randomUUID();
const UB = randomUUID();
await query(
  `insert into auth.users (id, phone, phone_confirmed_at) values
     ($1, '97699110007', now()), ($2, '97699110001', now()), ($3, '97699110002', now())`,
  [OPERATOR, UA, UB]
);
await query(`insert into public.operators (user_id, label) values ($1, 'Тест оператор')`, [OPERATOR]);
const DA = `NA${Math.floor(Math.random() * 1e8)}`;
const DB = `NB${Math.floor(Math.random() * 1e8)}`;
const a = await registerOwner({
  ownerName: 'Альфа ХХК', contactPhone: '99110001', deviceNo: DA, location: 'СБД, 1-р давхар',
  username: 'userA', password: 'passA', invoiceCode: 'INV_A',
});
const b = await registerOwner({
  ownerName: 'Бета ХХК', contactPhone: '99110002', deviceNo: DB, location: 'ХУД',
  username: 'userB', password: 'passB', invoiceCode: 'INV_B',
});
await query(
  `insert into public.owner_members (owner_id, user_id, role) values ($1, $2, 'admin'), ($3, $4, 'admin')`,
  [a.ownerId, UA, b.ownerId, UB]
);

// ---- boot the bridge -------------------------------------------------------------
const vapid = webpush.generateVAPIDKeys();
const PORT = 3195;
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
  OWNER_CACHE_TTL_MS: '0',
  SUPABASE_URL: ISSUER_BASE,
  PORTAL_ORIGIN: 'https://kofe.mn',
  CRED_ALLOW_HTTP: '1',
  SMS_API_URL: `http://127.0.0.1:${SMS_PORT}/send`,
  SMS_API_KEY: 'test-sms-key',
  VAPID_PUBLIC_KEY: vapid.publicKey,
  VAPID_PRIVATE_KEY: vapid.privateKey,
  VAPID_SUBJECT: 'https://coffeine-owner.vercel.app',
  PUSH_ALLOW_HOSTS: 'localhost',
  // Trusts the throwaway certificate above — in this child process only.
  NODE_TLS_REJECT_UNAUTHORIZED: '0',
};
delete BRIDGE_ENV.QPAY_MOCK;
const bridge = spawn(process.execPath, ['src/server.js'], { env: BRIDGE_ENV, stdio: ['ignore', 'pipe', 'pipe'] });
let log = '';
bridge.stdout.on('data', (d) => (log += d));
bridge.stderr.on('data', (d) => (log += d));
for (let i = 0; i < 60; i += 1) {
  try {
    if ((await fetch(`http://localhost:${PORT}/health`)).ok) break;
  } catch {}
  await sleep(250);
}

const call = async (path, { token, body } = {}) => {
  const res = await fetch(`http://localhost:${PORT}${path}`, {
    method: body ? 'POST' : 'GET',
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try {
    json = await res.json();
  } catch {}
  return { status: res.status, json };
};
const subCount = async () => (await query(`select count(*)::int n from public.push_subscriptions`)).rows[0].n;

function sale(deviceNo, orderNo) {
  const t = new Date();
  const p2 = (n) => String(n).padStart(2, '0');
  const time = `${t.getFullYear()}${p2(t.getMonth() + 1)}${p2(t.getDate())}${p2(t.getHours())}${p2(t.getMinutes())}${p2(t.getSeconds())}`;
  const data = {
    deviceNo, productId: '1', productName: 'Латте', orderNo,
    orderAmount: '450000', notifyUrl: `http://127.0.0.1:${MACHINE_PORT}/notify`,
  };
  const body = { username: 'testname', time, data };
  body.sign = buildSign({ username: body.username, time, ...data }, SIGNABLE.getQrCodeRequest, 'DBRW17YE7FHKR72T');
  return fetch(`http://localhost:${PORT}/jetinno/getQrCode`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }).then((r) => r.json());
}
async function pay(orderNo) {
  // A customer takes seconds to scan. Paying in the same millisecond as the
  // QR request races the order's own database insert, which no phone can do.
  await sleep(400);
  const [id, inv] = [...invoices.entries()].find(([, v]) => v.orderNo === orderNo);
  paid.set(id, { id: `pay-${orderNo}`, amount: inv.amount });
  return fetch(`http://localhost:${PORT}/qpay/callback/${orderNo}`, { method: 'POST' });
}

// ---- subscribing -------------------------------------------------------------------
const phoneA = phone('ua-phone');
const phoneA2 = phone('ua-tablet');
const phoneB = phone('ub-phone');

await check('/health push асаалттай гэж хэлнэ; түлхүүр нь нийтэд нээлттэй', async () => {
  const h = await call('/health');
  const k = await call('/owner/v1/push/key');
  return (h.json?.push === true && k.json?.publicKey === vapid.publicKey) || JSON.stringify({ h: h.json?.push, k: k.json });
});

await check('нэвтрээгүй хүн утас бүртгүүлж ЧАДАХГҮЙ', async () => {
  const r = await call('/owner/v1/push/subscribe', { body: phoneA });
  return r.status === 401 && (await subCount()) === 0;
});

await check('push үйлчилгээ биш хаяг, http хаягийг татгалзана (SSRF)', async () => {
  const token = await mint(UA);
  const meta = await call('/owner/v1/push/subscribe', { token, body: { ...phoneA, endpoint: 'https://169.254.169.254/latest/meta-data' } });
  const http = await call('/owner/v1/push/subscribe', { token, body: { ...phoneA, endpoint: phoneA.endpoint.replace('https:', 'http:') } });
  const noKeys = await call('/owner/v1/push/subscribe', { token, body: { endpoint: phoneA.endpoint } });
  return (meta.status === 400 && http.status === 400 && noKeys.status === 400 && (await subCount()) === 0) ||
    JSON.stringify([meta.status, http.status, noKeys.status]);
});

await check('эзэмшигч утсаа бүртгэнэ — орлогын мэдэгдэл анхдагчаар асаалттай', async () => {
  const r1 = await call('/owner/v1/push/subscribe', { token: await mint(UA), body: phoneA });
  const r2 = await call('/owner/v1/push/subscribe', { token: await mint(UA), body: phoneA2 });
  const r3 = await call('/owner/v1/push/subscribe', { token: await mint(UB), body: phoneB });
  return (
    r1.json?.subscribed === true && r1.json.notifySales === true && r2.status === 200 && r3.status === 200 &&
    (await subCount()) === 3
  ) || JSON.stringify([r1.json, r2.json, r3.json]);
});

await check('орлогын мэдэгдлийг унтрааж, дахин асаана; өөр хүний утсыг хөндөхгүй', async () => {
  const token = await mint(UA);
  const off = await call('/owner/v1/push/sales', { token, body: { endpoint: phoneA.endpoint, on: false } });
  const state = await call('/owner/v1/push/state', { token, body: { endpoint: phoneA.endpoint } });
  const on = await call('/owner/v1/push/sales', { token, body: { endpoint: phoneA.endpoint, on: true } });
  const foreign = await call('/owner/v1/push/sales', { token: await mint(UB), body: { endpoint: phoneA.endpoint, on: false } });
  const after = await call('/owner/v1/push/state', { token, body: { endpoint: phoneA.endpoint } });
  return (
    off.json?.notifySales === false && state.json?.subscribed === true && state.json.notifySales === false &&
    on.json?.notifySales === true && foreign.json?.subscribed === false && after.json?.notifySales === true
  ) || JSON.stringify({ off: off.json, state: state.json, on: on.json, foreign: foreign.json, after: after.json });
});

await check('туршилтын мэдэгдэл тухайн хүний бүх утсанд, шифрлэгдэж, VAPID-тай очно', async () => {
  const from = pushIn.length;
  const r = await call('/owner/v1/push/test', { token: await mint(UA), body: {} });
  await sleep(300);
  const got = pushIn.slice(from);
  return (
    r.json?.sent === 2 && got.length === 2 && got.every((p) => p.payload.title === 'Coffeine') &&
    got.every((p) => p.authorization.startsWith('vapid t=')) && pushesTo('ub-phone', from).length === 0
  ) || JSON.stringify({ r: r.json, got });
});

// ---- a sale -----------------------------------------------------------------------
await check('А-гийн машинд төлбөр ормогц А-гийн хүний утсанд «Орлого +4,500₮» очно, Б-д очихгүй', async () => {
  const from = pushIn.length;
  const qr = await sale(DA, 'N-A1');
  const res = await pay('N-A1');
  await sleep(1500);
  const mine = pushesTo('ua-phone', from);
  const { rows } = await query(`select status, sale_push_at from public.orders where order_no = 'N-A1'`);
  const p = mine[0]?.payload;
  return (
    qr.returnCode === 'SUCCESS' && res.status === 200 && rows[0]?.status === 'paid' && rows[0].sale_push_at !== null &&
    mine.length === 1 && pushesTo('ua-tablet', from).length === 1 && pushesTo('ub-phone', from).length === 0 &&
    p.title === 'Орлого +4,500₮' && p.body.includes('Латте') && p.body.includes(DA) &&
    p.body.includes('СБД, 1-р давхар') && p.url === '/sales'
  ) || JSON.stringify({ qr: qr.returnCode, status: rows[0]?.status, mine, log: log.slice(-600) });
});

await check('нэг төлбөрт нэг л мэдэгдэл — QPay дахин дуудсан ч давтахгүй', async () => {
  const from = pushIn.length;
  await fetch(`http://localhost:${PORT}/qpay/callback/N-A1`, { method: 'POST' });
  await sleep(1000);
  return pushIn.length === from || JSON.stringify(pushIn.slice(from));
});

await check('орлогын мэдэгдэл унтраасан утсанд очихгүй, бусдад нь очно', async () => {
  await call('/owner/v1/push/sales', { token: await mint(UA), body: { endpoint: phoneA2.endpoint, on: false } });
  const from = pushIn.length;
  await sale(DA, 'N-A2');
  await pay('N-A2');
  await sleep(1500);
  return (pushesTo('ua-phone', from).length === 1 && pushesTo('ua-tablet', from).length === 0) ||
    JSON.stringify(pushIn.slice(from).map((p) => p.to));
});

await check('push үйлчилгээ 410 гэвэл тэр утасны бүртгэл устана', async () => {
  gone.add('/push/ua-tablet');
  await call('/owner/v1/push/test', { token: await mint(UA), body: {} });
  await sleep(300);
  const { rows } = await query(`select count(*)::int n from public.push_subscriptions where endpoint = $1`, [phoneA2.endpoint]);
  return rows[0].n === 0 && (await subCount()) === 2;
});

// ---- announcements ------------------------------------------------------------------
const op = await mint(OPERATOR);
const announce = (body, token = op) => call('/admin/v1/notifications', { token, body });

await check('оператор биш хүн мэдэгдэл илгээж ЧАДАХГҮЙ', async () => {
  const r = await announce({ title: 'x', body: 'y', target: 'all', channel: 'app' }, await mint(UA));
  const n = (await query(`select count(*)::int n from public.notifications`)).rows[0].n;
  return r.status === 401 && n === 0;
});

await check('гадны холбоос, хоосон текст, хүлээн авагчгүй мэдэгдэл татгалзана', async () => {
  const link = await announce({ title: 'Т', body: 'Б', link: 'https://evil.example', target: 'all', channel: 'app' });
  const slashes = await announce({ title: 'Т', body: 'Б', link: '//evil.example', target: 'all', channel: 'app' });
  const empty = await announce({ title: ' ', body: 'Б', target: 'all', channel: 'app' });
  const nobody = await announce({ title: 'Т', body: 'Б', target: 'owners', ownerIds: [randomUUID()], channel: 'app' });
  return (
    link.json?.status === 'invalid_link' && slashes.json?.status === 'invalid_link' &&
    empty.json?.status === 'invalid_text' && nobody.json?.status === 'no_recipients'
  ) || JSON.stringify([link.json, slashes.json, empty.json, nobody.json]);
});

await check('сонгосон бизнест апп + SMS: А-гийн утсанд push, А-гийн дугаар руу латинаар SMS', async () => {
  const from = pushIn.length;
  const smsFrom = smsOut.length;
  const r = await announce({
    title: 'Шинэ үнэ', body: 'Маргаашаас латте 6000₮.', link: '/sales',
    target: 'owners', ownerIds: [a.ownerId], channel: 'both',
  });
  await sleep(1500);
  const p = pushesTo('ua-phone', from)[0]?.payload;
  const sms = smsOut.slice(smsFrom);
  const hist = await call('/admin/v1/notifications', { token: op });
  const h = hist.json?.notifications?.[0];
  return (
    r.json?.status === 'ok' && r.json.recipients === 1 &&
    p?.title === 'Шинэ үнэ' && p.url === '/sales' && pushesTo('ub-phone', from).length === 0 &&
    sms.length === 1 && sms[0].to === '99110001' && sms[0].text.startsWith('Shine une') &&
    h?.push_sent === 1 && h.sms_sent === 1 && h.owner_names === 'Альфа ХХК'
  ) || JSON.stringify({ r: r.json, p, sms, h });
});

await check('А-гийн «Мэдэгдэл»-д гарна: уншаагүй 1, нээсний дараа 0; Б-д харагдахгүй', async () => {
  const ta = await mint(UA);
  const list = await call('/owner/v1/notifications', { token: ta });
  const before = await call('/owner/v1/notifications/unread', { token: ta });
  const seen = await call('/owner/v1/notifications/seen', { token: ta, body: {} });
  const after = await call('/owner/v1/notifications/unread', { token: ta });
  const theirs = await call('/owner/v1/notifications', { token: await mint(UB) });
  const n = list.json?.notifications ?? [];
  return (
    n.length === 1 && n[0].title === 'Шинэ үнэ' && n[0].unread === true && before.json?.unread === 1 &&
    seen.json?.ok === true && after.json?.unread === 0 && (theirs.json?.notifications ?? []).length === 0
  ) || JSON.stringify({ n, before: before.json, after: after.json, theirs: theirs.json });
});

await check('өөр бизнесийн жагсаалтыг ownerId-ээр ч уншиж ЧАДАХГҮЙ', async () => {
  const r = await call(`/owner/v1/notifications?ownerId=${a.ownerId}`, { token: await mint(UB) });
  return r.status === 404;
});

await check('зөвхөн SMS: бүх бизнес рүү SMS, апп-д ч push-д ч орохгүй', async () => {
  const from = pushIn.length;
  const smsFrom = smsOut.length;
  const r = await announce({ title: 'Засвар', body: 'Маргааш 10-12 цагт засвар хийнэ.', target: 'all', channel: 'sms' });
  await sleep(1500);
  const list = await call('/owner/v1/notifications', { token: await mint(UA) });
  const to = smsOut.slice(smsFrom).map((s) => s.to).sort();
  return (
    r.json?.recipients === 2 && pushIn.length === from && to.join() === '99110001,99110002' &&
    (list.json?.notifications ?? []).length === 1
  ) || JSON.stringify({ r: r.json, to, pushes: pushIn.length - from });
});

await check('«бүх эзэмшигч», зөвхөн апп: хоёр бизнест push, Б-д уншаагүй 1', async () => {
  const from = pushIn.length;
  const smsFrom = smsOut.length;
  const r = await announce({ title: 'Сайн байна уу', body: 'Шинэ боломж нэмэгдлээ.', target: 'all', channel: 'app' });
  await sleep(1000);
  const unreadB = await call('/owner/v1/notifications/unread', { token: await mint(UB) });
  return (
    r.json?.recipients === 2 && pushesTo('ua-phone', from).length === 1 && pushesTo('ub-phone', from).length === 1 &&
    smsOut.length === smsFrom && unreadB.json?.unread === 1
  ) || JSON.stringify({ r: r.json, unreadB: unreadB.json });
});

await check('SMS-ийн илгээлт sms_sends-д announcement гэж бичигдэнэ', async () => {
  const { rows } = await query(`select count(*)::int n from public.sms_sends where purpose = 'announcement' and ok`);
  return rows[0].n === 3 || String(rows[0].n);
});

bridge.kill();
for (const s of [jwks, qpayFake, machine, smsFake, pushService]) s.close();
await close();

const passed = results.filter(([ok]) => ok).length;
for (const [ok, name, extra] of results) console.log(`  ${ok ? '✓' : '✗'} ${name}${ok ? '' : extra}`);
console.log(`\n  ${passed}/${results.length} давлаа`);
if (passed !== results.length) console.log('\n--- bridge log (tail) ---\n' + log.slice(-2500));
process.exit(passed === results.length ? 0 : 1);
