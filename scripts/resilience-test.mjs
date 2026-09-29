/**
 * The bridge with its database gone. Run: npm run test:resilience
 *
 * Needs no Postgres at all — DATABASE_URL points at a closed port, which is
 * the harshest version of a Supabase pooler blip or a statement timeout.
 *
 * Two failures this pins down:
 *  1. Express 4 ignores the promise an async handler returns. One rejected
 *     database call on /owner/v1/invites/redeem was an unhandled rejection,
 *     and Node exited — taking every machine's sales down with it.
 *  2. A sale whose owner could not be looked up went to the operator's own
 *     QPay merchant. Every machine sold today belongs to an owner, so that was
 *     an owner's money in the wrong account.
 */
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { SIGNABLE, buildSign } from '../src/sign.js';

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
const timed = (ms) => AbortSignal.timeout(ms);

// ---- a JWKS the bridge trusts, so the owner routes get past auth ------------
const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'ES256', use: 'sig' };
const JWKS_PORT = 4631;
const ISS = `http://127.0.0.1:${JWKS_PORT}`;
const jwks = createServer((q, r) => {
  r.setHeader('content-type', 'application/json');
  r.end(JSON.stringify({ keys: [jwk] }));
});
await new Promise((r) => jwks.listen(JWKS_PORT, '127.0.0.1', r));
const token = await new SignJWT({ amr: [{ method: 'otp', timestamp: Math.floor(Date.now() / 1000) }] })
  .setProtectedHeader({ alg: 'ES256', kid: 'k1' })
  .setSubject(randomUUID())
  .setIssuedAt()
  .setIssuer(`${ISS}/auth/v1`)
  .setAudience('authenticated')
  .setExpirationTime('1h')
  .sign(privateKey);

// ---- the bridge, pointed at a database that is not there ---------------------
const PORT = 3195;
const k = () => randomBytes(32).toString('base64');
const bridge = spawn(process.execPath, ['src/server.js'], {
  env: {
    ...process.env,
    PORT: String(PORT),
    QPAY_MOCK: '1',
    JETINNO_USERNAME: 'testname',
    JETINNO_APIKEY: 'DBRW17YE7FHKR72T',
    PUBLIC_URL: `http://localhost:${PORT}`,
    DATABASE_URL: 'postgresql://postgres:x@127.0.0.1:59999/none',
    SUPABASE_URL: ISS,
    PORTAL_ORIGIN: 'https://kofe.mn',
    CRED_KEYS: `k1:${k()}`,
    CRED_KEY_ACTIVE: 'k1',
    CRED_FP_KEY: k(),
    CRED_ALLOW_HTTP: '1',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let log = '';
bridge.stdout.on('data', (d) => (log += d));
bridge.stderr.on('data', (d) => (log += d));
for (let i = 0; i < 60 && !log.includes('listening'); i += 1) await sleep(250);

const health = () =>
  fetch(`http://localhost:${PORT}/health`, { signal: timed(3000) }).then((r) => r.status, () => 'down');

await check('сан байхгүй ч гүүр асна', async () => (await health()) === 200 || String(await health()));

await check('сангийн алдаа хүсэлтэд 503 болж буцна — өлгөөтэй үлдэхгүй', async () => {
  const r = await fetch(`http://localhost:${PORT}/owner/v1/invites/redeem`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', origin: 'https://kofe.mn' },
    body: JSON.stringify({ token: 'x'.repeat(32) }),
    signal: timed(10000),
  });
  return r.status === 503 || `HTTP ${r.status}`;
});

await check('тэр алдааны дараа гүүр амьд хэвээр — бусад машин зарсаар', async () => {
  await sleep(300);
  return (bridge.exitCode === null && (await health()) === 200) || `exit=${bridge.exitCode}`;
});

await check('эзэн нь тодорхойгүй борлуулалт операторын данс руу ОРОХГҮЙ', async () => {
  const t = new Date();
  const p2 = (n) => String(n).padStart(2, '0');
  const time = `${t.getFullYear()}${p2(t.getMonth() + 1)}${p2(t.getDate())}${p2(t.getHours())}${p2(t.getMinutes())}${p2(t.getSeconds())}`;
  const data = {
    deviceNo: 'OWNED-BUT-DB-DOWN',
    productId: '1',
    productName: 'Латте',
    orderNo: `RES${Date.now()}`,
    orderAmount: '450000',
    notifyUrl: 'http://127.0.0.1:4602/notify',
  };
  const body = { username: 'testname', time, data };
  body.sign = buildSign({ username: body.username, time, ...data }, SIGNABLE.getQrCodeRequest, 'DBRW17YE7FHKR72T');
  const r = await fetch(`http://localhost:${PORT}/jetinno/getQrCode`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: timed(15000),
  }).then((x) => x.text());
  // No QR at all: a QR here could only have been issued under the env merchant.
  return (!r.includes('qrCode":"http') && /FAIL|SYSTEM_ERROR/.test(r) && log.includes('merchant resolve failed, refusing')) || r.slice(0, 200);
});

bridge.kill('SIGTERM');
jwks.close();

const passed = results.filter(([ok]) => ok).length;
for (const [ok, name, extra] of results) console.log(`  ${ok ? '✓' : '✗'} ${name}${ok ? '' : extra}`);
console.log(`\n  ${passed}/${results.length} давлаа`);
if (passed !== results.length) console.log('\n--- bridge log (tail) ---\n' + log.slice(-2000));
process.exit(passed === results.length ? 0 : 1);
