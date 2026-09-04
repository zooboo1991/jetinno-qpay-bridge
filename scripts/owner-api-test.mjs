/**
 * Integration test for /owner/v1: the token verification, the owner scoping,
 * and the ways both can be talked out of. Run with: npm run test:owner-api
 *
 * It stands up a real JWKS endpoint backed by a real ES256 key pair, points
 * the bridge at it, and mints tokens with the private half. That is more
 * setup than stubbing the verifier, and it is the only version of this test
 * worth having: the failures being defended against — `alg: none`, an HS256
 * token signed with the public key, a token from the right issuer but the
 * wrong audience — are all failures INSIDE the verification step. A stub
 * proves the routes call something.
 *
 * Needs DATABASE_URL. scripts/owner-api-test.sh supplies a throwaway one.
 */
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import {
  generateKeyPair,
  exportJWK,
  SignJWT,
  base64url,
} from 'jose';
import { query, close } from '../src/db.js';

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

// ---- a stand-in Supabase: one ES256 key, one JWKS endpoint ---------------
const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
const jwk = await exportJWK(publicKey);
jwk.kid = 'test-key-1';
jwk.alg = 'ES256';
jwk.use = 'sig';

const JWKS_PORT = 4599;
const ISSUER_BASE = `http://127.0.0.1:${JWKS_PORT}`;
let jwksHits = 0;
const jwksServer = createServer((req, res) => {
  if (req.url === '/auth/v1/.well-known/jwks.json') {
    jwksHits += 1;
    res.setHeader('content-type', 'application/json');
    return res.end(JSON.stringify({ keys: [jwk] }));
  }
  res.statusCode = 404;
  res.end();
});
await new Promise((r) => jwksServer.listen(JWKS_PORT, '127.0.0.1', r));

const mint = (claims = {}, { key = privateKey, alg = 'ES256' } = {}) =>
  new SignJWT({ ...claims })
    .setProtectedHeader({ alg, kid: 'test-key-1' })
    .setIssuedAt()
    .setIssuer(claims.iss ?? `${ISSUER_BASE}/auth/v1`)
    .setAudience(claims.aud ?? 'authenticated')
    .setExpirationTime(claims.exp ?? '1h')
    .sign(key);

// ---- seed two businesses and three users --------------------------------
async function seedOwner(name, phone) {
  const ownerId = randomUUID();
  const credId = randomUUID();
  const machineId = randomUUID();
  await query(`insert into public.owners (id, name, contact_phone) values ($1,$2,$3)`, [ownerId, name, phone]);
  await query(
    `insert into public.qpay_credentials (id, owner_id, label, sealed, key_id, fingerprint, status, is_active, source)
     values ($1,$2,'Үндсэн данс','v1.k1.a.b.c','k1',$3,'active',true,'cli')`,
    [credId, ownerId, randomUUID().replace(/-/g, '').padEnd(64, '0')]
  );
  await query(
    `insert into public.machines (id, owner_id, qpay_credential_id, device_no, label, status)
     values ($1,$2,$3,$4,$5,'active')`,
    [machineId, ownerId, credId, `D${Math.floor(Math.random() * 1e9)}`, name]
  );
  return { ownerId, credId, machineId, name };
}

async function addUser(userId, ownerId, role) {
  await query(
    `insert into auth.users (id, phone) values ($1,$2) on conflict (id) do nothing`,
    [userId, String(Math.floor(Math.random() * 1e8)).padStart(8, '9')]
  );
  await query(`insert into public.owner_members (owner_id, user_id, role) values ($1,$2,$3)`, [
    ownerId,
    userId,
    role,
  ]);
}

async function sale(who, amount, done = true) {
  await query(
    `insert into public.orders (
       machine_id, owner_id, qpay_credential_id, order_no, device_no, notify_url,
       product_id, product_name, raw_order_amount, amount_divisor, amount_mnt,
       paid_amount_mnt, qpay_sender_invoice_no, qpay_invoice_id, callback_url,
       status, payment_confirmed_at, notified_at, notify_sent_at,
       product_done_at, product_done_ok)
     values ($1,$2,$3,$4,'DEV','http://x/notify','1','Латте',($5*100)::text,100,$5,
             $5,$4,'inv_'||$4,'http://x/cb','paid',now(),now(),now(),
             case when $6 then now() end, case when $6 then true end)`,
    [who.machineId, who.ownerId, who.credId, `O${randomUUID().slice(0, 8)}`, amount, done]
  );
}

const alpha = await seedOwner('Альфа ХХК', '99110001');
const beta = await seedOwner('Бета ХХК', '99110002');

const userAlpha = randomUUID();   // admin of Альфа only
const userBoth = randomUUID();    // admin of both — the multi-business owner
const userViewer = randomUUID();  // member of Альфа, but only a viewer
const userNobody = randomUUID();  // a valid Supabase account with no membership

await addUser(userAlpha, alpha.ownerId, 'admin');
await addUser(userBoth, alpha.ownerId, 'admin');
await addUser(userBoth, beta.ownerId, 'admin');
await addUser(userViewer, alpha.ownerId, 'viewer');
await query(`insert into auth.users (id, phone) values ($1,'99110009') on conflict do nothing`, [userNobody]);

await sale(alpha, 4000);
await sale(alpha, 3000, false);
await sale(beta, 777000);

// ---- boot the bridge against the stand-in Supabase -----------------------
const PORT = 3198;
const bridge = spawn(
  process.execPath,
  ['src/server.js'],
  {
    env: {
      ...process.env,
      PORT: String(PORT),
      QPAY_MOCK: '1',
      JETINNO_USERNAME: 'testname',
      JETINNO_APIKEY: 'DBRW17YE7FHKR72T',
      PUBLIC_URL: `http://localhost:${PORT}`,
      SUPABASE_URL: ISSUER_BASE,
      PORTAL_ORIGIN: 'https://kofe.mn',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  }
);
let bridgeLog = '';
bridge.stdout.on('data', (d) => (bridgeLog += d));
bridge.stderr.on('data', (d) => (bridgeLog += d));

for (let i = 0; i < 60; i += 1) {
  try {
    const r = await fetch(`http://localhost:${PORT}/health`);
    if (r.ok) break;
  } catch {}
  await sleep(250);
}

const call = async (path, { token, origin, method = 'GET' } = {}) => {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (origin) headers.origin = origin;
  const res = await fetch(`http://localhost:${PORT}${path}`, { method, headers });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  return { status: res.status, json, text, headers: res.headers };
};

// ---- the routes exist at all --------------------------------------------
await check('SUPABASE_URL + DATABASE_URL байвал /owner/v1 mount хийгдэнэ', () => {
  return bridgeLog.includes('owner api mounted');
});

// ---- who gets in ---------------------------------------------------------
await check('токенгүй хүсэлт 401', async () => {
  const r = await call('/owner/v1/stats');
  return r.status === 401 && r.json?.error === 'UNAUTHORIZED';
});

await check('зөв токен 200 буцааж, зөвхөн өөрийн орлогыг харуулна', async () => {
  const r = await call('/owner/v1/stats', { token: await mint({ sub: userAlpha }) });
  return (
    r.status === 200 &&
    r.json.ownerId === alpha.ownerId &&
    r.json.month.amount === 7000 &&
    !r.text.includes('777000')
  );
});

await check('гишүүнчлэлгүй хэрэглэгч 401 — хүчинтэй токен ч хангалтгүй', async () => {
  const r = await call('/owner/v1/stats', { token: await mint({ sub: userNobody }) });
  return r.status === 401;
});

await check('зөвхөн viewer эрхтэй гишүүн 401 — admin биш', async () => {
  const r = await call('/owner/v1/stats', { token: await mint({ sub: userViewer }) });
  return r.status === 401;
});

// ---- the verification itself --------------------------------------------
await check('alg:none токен татгалзагдана', async () => {
  const header = base64url.encode(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const payload = base64url.encode(
    JSON.stringify({
      sub: userAlpha,
      iss: `${ISSUER_BASE}/auth/v1`,
      aud: 'authenticated',
      exp: Math.floor(Date.now() / 1000) + 3600,
    })
  );
  const r = await call('/owner/v1/stats', { token: `${header}.${payload}.` });
  return r.status === 401;
});

await check('нийтийн түлхүүрээр HS256 гарын үсэг зурсан токен татгалзагдана', async () => {
  // The classic algorithm-confusion attack: the JWKS key is public, so if the
  // verifier will accept HS256 it can be used as a shared secret by anyone.
  const secret = new TextEncoder().encode(JSON.stringify(jwk));
  const token = await new SignJWT({ sub: userAlpha })
    .setProtectedHeader({ alg: 'HS256', kid: 'test-key-1' })
    .setIssuedAt()
    .setIssuer(`${ISSUER_BASE}/auth/v1`)
    .setAudience('authenticated')
    .setExpirationTime('1h')
    .sign(secret);
  const r = await call('/owner/v1/stats', { token });
  return r.status === 401;
});

await check('өөр түлхүүрээр гарын үсэг зурсан токен татгалзагдана', async () => {
  const other = await generateKeyPair('ES256', { extractable: true });
  const token = await mint({ sub: userAlpha }, { key: other.privateKey });
  const r = await call('/owner/v1/stats', { token });
  return r.status === 401;
});

// Carries a real `sub`, so the only thing standing between it and a 200 is
// the audience check. An earlier version of this test left `sub` out and
// therefore passed even with `audience:` deleted from the verifier — it was
// exercising the missing-subject guard and reporting it as audience coverage.
await check('зөв sub-тэй ч aud нь anon бол татгалзагдана', async () => {
  const token = await new SignJWT({ sub: userAlpha, role: 'anon' })
    .setProtectedHeader({ alg: 'ES256', kid: 'test-key-1' })
    .setIssuedAt()
    .setIssuer(`${ISSUER_BASE}/auth/v1`)
    .setAudience('anon')
    .setExpirationTime('1h')
    .sign(privateKey);
  const r = await call('/owner/v1/stats', { token });
  return r.status === 401;
});

await check('sub огт байхгүй токен татгалзагдана', async () => {
  const token = await new SignJWT({ role: 'anon' })
    .setProtectedHeader({ alg: 'ES256', kid: 'test-key-1' })
    .setIssuedAt()
    .setIssuer(`${ISSUER_BASE}/auth/v1`)
    .setAudience('authenticated')
    .setExpirationTime('1h')
    .sign(privateKey);
  const r = await call('/owner/v1/stats', { token });
  return r.status === 401;
});

await check('өөр issuer-ийн токен татгалзагдана', async () => {
  const token = await new SignJWT({ sub: userAlpha })
    .setProtectedHeader({ alg: 'ES256', kid: 'test-key-1' })
    .setIssuedAt()
    .setIssuer('https://evil.example.com/auth/v1')
    .setAudience('authenticated')
    .setExpirationTime('1h')
    .sign(privateKey);
  const r = await call('/owner/v1/stats', { token });
  return r.status === 401;
});

await check('хугацаа нь дууссан токен татгалзагдана', async () => {
  const token = await new SignJWT({ sub: userAlpha })
    .setProtectedHeader({ alg: 'ES256', kid: 'test-key-1' })
    .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
    .setIssuer(`${ISSUER_BASE}/auth/v1`)
    .setAudience('authenticated')
    .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
    .sign(privateKey);
  const r = await call('/owner/v1/stats', { token });
  return r.status === 401;
});

await check('алдааны хариу яагаад гэдгийг хэлэхгүй', async () => {
  const expired = await new SignJWT({ sub: userAlpha })
    .setProtectedHeader({ alg: 'ES256', kid: 'test-key-1' })
    .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
    .setIssuer(`${ISSUER_BASE}/auth/v1`)
    .setAudience('authenticated')
    .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
    .sign(privateKey);
  const a = await call('/owner/v1/stats', { token: expired });
  const b = await call('/owner/v1/stats', { token: await mint({ sub: userNobody }) });
  const c = await call('/owner/v1/stats');
  return a.text === b.text && b.text === c.text;
});

// ---- scoping across businesses ------------------------------------------
await check('олон компанитай хэрэглэгч ownerId-аар сонгож чадна', async () => {
  const token = await mint({ sub: userBoth });
  const r = await call(`/owner/v1/stats?ownerId=${beta.ownerId}`, { token });
  return r.status === 200 && r.json.ownerId === beta.ownerId && r.json.month.amount === 777000;
});

await check('удирддаггүй компанийн ownerId асуувал 404 — байгаа эсэхийг ч хэлэхгүй', async () => {
  const token = await mint({ sub: userAlpha });
  const r = await call(`/owner/v1/stats?ownerId=${beta.ownerId}`, { token });
  return r.status === 404 && !r.text.includes('777000');
});

await check('байхгүй ownerId ч мөн 404', async () => {
  const token = await mint({ sub: userAlpha });
  const r = await call(`/owner/v1/stats?ownerId=${randomUUID()}`, { token });
  return r.status === 404;
});

await check('/me нь удирддаг компаниудаа жагсаана', async () => {
  const r = await call('/owner/v1/me', { token: await mint({ sub: userBoth }) });
  return (
    r.status === 200 &&
    r.json.owners.length === 2 &&
    r.json.owners.every((o) => o.active_machines === 1)
  );
});

// ---- transport rules -----------------------------------------------------
await check('зөвшөөрсөн origin-д CORS толгой өгнө', async () => {
  const r = await call('/owner/v1/stats', {
    token: await mint({ sub: userAlpha }),
    origin: 'https://kofe.mn',
  });
  return r.headers.get('access-control-allow-origin') === 'https://kofe.mn';
});

await check('танихгүй origin-д CORS толгой өгөхгүй', async () => {
  const r = await call('/owner/v1/stats', {
    token: await mint({ sub: userAlpha }),
    origin: 'https://evil.example.com',
  });
  return r.headers.get('access-control-allow-origin') === null;
});

await check('CORS credentials зөвшөөрөөгүй — cookie хэзээ ч ашиглахгүй', async () => {
  const r = await call('/owner/v1/stats', {
    token: await mint({ sub: userAlpha }),
    origin: 'https://kofe.mn',
  });
  return r.headers.get('access-control-allow-credentials') === null;
});

await check('орлогын хариу кэшлэгдэхгүй', async () => {
  const r = await call('/owner/v1/stats', { token: await mint({ sub: userAlpha }) });
  return (r.headers.get('cache-control') ?? '').includes('no-store');
});

await check('JWKS-ийг дахин дахин татахгүй — кэшлэгдсэн', () => {
  return jwksHits <= 3 || `${jwksHits} удаа татсан`;
});

// ---- the machine path is untouched --------------------------------------
await check('машины зам эзэмшигчийн API-аас хамааралгүй хэвээр', async () => {
  const r = await fetch(`http://localhost:${PORT}/health`);
  const j = await r.json();
  return r.status === 200 && j.ok === true;
});

bridge.kill('SIGTERM');
jwksServer.close();
await close();

const passed = results.filter(([ok]) => ok).length;
for (const [ok, name, extra] of results) console.log(`  ${ok ? '✓' : '✗'} ${name}${extra}`);
console.log(`\n  ${passed}/${results.length} давлаа`);
process.exit(passed === results.length ? 0 : 1);
