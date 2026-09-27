/**
 * Onboarding end to end, over HTTP: the operator registers a business, issues
 * its invite, the owner redeems it from the right phone, and the owner's own
 * API then shows THEIR machine. Run: npm run test:onboarding
 *
 * The first thing this defends is a routing bug that shipped: /owner/v1 is
 * shared by two routers, and a router-wide auth gate on the first one
 * answered 401 to /owner/v1/invites/redeem — the one request that, by
 * definition, comes from somebody who is not a member yet. Every earlier test
 * seeded owner_members by hand, so none of them ever made that request.
 *
 * Needs DATABASE_URL. scripts/onboarding-test.sh supplies a throwaway one.
 */
import { randomUUID, randomBytes, createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { query, close } from '../src/db.js';

// Only an exact `true` passes. A check may return a STRING to explain a
// failure (`cond || JSON.stringify(state)`), and a truthy-means-pass helper
// would count that explanation as a pass — which made half of this file
// unable to fail until a negative control caught it.
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

// ---- a stand-in Supabase -------------------------------------------------
const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'ES256', use: 'sig' };
const JWKS_PORT = 4598;
const ISSUER_BASE = `http://127.0.0.1:${JWKS_PORT}`;
const jwks = createServer((req, res) => {
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify({ keys: [jwk] }));
});
await new Promise((r) => jwks.listen(JWKS_PORT, '127.0.0.1', r));

const now = () => Math.floor(Date.now() / 1000);
/** `otpAgo` is how many seconds ago the session's OTP was typed; null = no amr. */
const mint = (sub, { otpAgo = 0 } = {}) =>
  new SignJWT(otpAgo === null ? {} : { amr: [{ method: 'otp', timestamp: now() - otpAgo }] })
    .setProtectedHeader({ alg: 'ES256', kid: 'k1' })
    .setSubject(sub)
    .setIssuedAt()
    .setIssuer(`${ISSUER_BASE}/auth/v1`)
    .setAudience('authenticated')
    .setExpirationTime('1h')
    .sign(privateKey);

// ---- people ----------------------------------------------------------------
const OPERATOR = randomUUID();
const OWNER = randomUUID();     // the phone on the sales paperwork
const IMPOSTOR = randomUUID();  // holds the link, not the SIM
const OWNER_PHONE = '99887766';
await query(
  `insert into auth.users (id, phone, phone_confirmed_at) values
     ($1,'97699110007',now()), ($2,'976' || $4,now()), ($3,'97699001122',now())`,
  [OPERATOR, OWNER, IMPOSTOR, OWNER_PHONE]
);
await query(`insert into public.operators (user_id, label) values ($1,'Тест оператор')`, [OPERATOR]);

// ---- a stand-in QPay: the operator path proves credentials against it -----
const QPAY_PORT = 4597;
const qpayCalls = { token: 0, invoice: [], cancelled: [] };
const qpayFake = createServer((req, res) => {
  let raw = '';
  req.on('data', (d) => (raw += d));
  req.on('end', () => {
    res.setHeader('content-type', 'application/json');
    if (req.url === '/v2/auth/token') {
      qpayCalls.token += 1;
      const [, pass] = Buffer.from((req.headers.authorization ?? '').replace(/^Basic /, ''), 'base64').toString().split(':');
      if (pass === 'wrong-pass') { res.statusCode = 401; return res.end('{"error":"NO_CREDENTIALS"}'); }
      return res.end(JSON.stringify({ access_token: `tok-${Date.now()}`, expires_in: 3600, refresh_token: 'r' }));
    }
    if (req.url === '/v2/invoice' && req.method === 'POST') {
      const body = JSON.parse(raw || '{}');
      qpayCalls.invoice.push(body);
      if (body.invoice_code === 'BAD_CODE') { res.statusCode = 400; return res.end('{"error":"INVOICE_CODE_INVALID"}'); }
      return res.end(JSON.stringify({ invoice_id: `inv-${qpayCalls.invoice.length}`, qPay_shortUrl: 'https://s.qpay.mn/x' }));
    }
    if (req.url.startsWith('/v2/invoice/') && req.method === 'DELETE') {
      qpayCalls.cancelled.push(req.url.split('/').pop());
      return res.end('{}');
    }
    res.statusCode = 404;
    res.end('{}');
  });
});
await new Promise((r) => qpayFake.listen(QPAY_PORT, '127.0.0.1', r));

// ---- boot the bridge -------------------------------------------------------
const PORT = 3197;
const key = () => randomBytes(32).toString('base64');
const bridge = spawn(process.execPath, ['src/server.js'], {
  env: {
    ...process.env,
    PORT: String(PORT),
    QPAY_MOCK: '1',
    JETINNO_USERNAME: 'testname',
    JETINNO_APIKEY: 'DBRW17YE7FHKR72T',
    PUBLIC_URL: `http://localhost:${PORT}`,
    SUPABASE_URL: ISSUER_BASE,
    PORTAL_ORIGIN: 'https://kofe.mn',
    CRED_KEYS: `k1:${key()}`,
    CRED_KEY_ACTIVE: 'k1',
    CRED_FP_KEY: key(),
    CRED_ALLOW_HTTP: '1',
    QPAY_BASE_URL: `http://127.0.0.1:${QPAY_PORT}`,
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let log = '';
bridge.stdout.on('data', (d) => (log += d));
bridge.stderr.on('data', (d) => (log += d));
for (let i = 0; i < 80; i++) {
  if (log.includes('credentials api mounted') || log.includes('credentials api FAILED')) break;
  await sleep(250);
}

const call = async (path, { token, body, method = body ? 'POST' : 'GET' } = {}) => {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body) headers['content-type'] = 'application/json';
  const res = await fetch(`http://localhost:${PORT}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  return { status: res.status, json };
};

const op = await mint(OPERATOR);
const DEVICE = `D${Math.floor(Math.random() * 1e9)}`;
const newOwner = {
  name: 'Шинэ Кофе ХХК',
  contactPhone: '9988 7766',
  deviceNo: DEVICE,
  location: 'ХУД, 3-р хороо',
  invoiceCode: 'SHINE_KOFE_INVOICE',
};

await check('credentials api mount хийгдэнэ (CRED_* + SUPABASE_URL + PORTAL_ORIGIN)', () =>
  log.includes('credentials api mounted'));

// ---- provisioning ----------------------------------------------------------
await check('оператор биш хүн эзэмшигч үүсгэж ЧАДАХГҮЙ', async () => {
  const r = await call('/admin/v1/owners', { token: await mint(OWNER), body: newOwner });
  const n = await query(`select count(*)::int n from public.owners where name = $1`, [newOwner.name]);
  return r.status === 401 && n.rows[0].n === 0;
});

await check('буруу утас татгалзана', async () => {
  const r = await call('/admin/v1/owners', { token: op, body: { ...newOwner, contactPhone: '1234' } });
  return r.json?.status === 'invalid_phone';
});

let ownerId;
await check('эзэмшигч + машин + ХООСОН QPay слот нэг дор үүснэ', async () => {
  const r = await call('/admin/v1/owners', { token: op, body: newOwner });
  ownerId = r.json?.ownerId;
  const { rows } = await query(
    `select o.contact_phone, c.status, c.is_active, c.sealed, c.pending_invoice_code,
            m.device_no, m.location, m.qpay_credential_id = c.id as wired
       from public.owners o
       join public.qpay_credentials c on c.owner_id = o.id
       join public.machines m on m.owner_id = o.id
      where o.id = $1`,
    [ownerId]
  );
  const x = rows[0];
  return (
    r.json?.status === 'ok' &&
    x?.contact_phone === '97699887766' &&
    x.status === 'pending' && x.is_active === false && x.sealed === null &&
    x.pending_invoice_code === 'SHINE_KOFE_INVOICE' &&
    x.device_no === DEVICE && x.location === 'ХУД, 3-р хороо' && x.wired
  ) || JSON.stringify({ r: r.json, x });
});

await check('ижил машины дугаар хоёр дахь удаа бүртгэгдэхгүй', async () => {
  const r = await call('/admin/v1/owners', { token: op, body: { ...newOwner, name: 'Өөр ХХК' } });
  return r.json?.status === 'device_taken';
});

await check('аудитад owner_provisioned бичигдэнэ', async () => {
  const { rows } = await query(
    `select count(*)::int n from public.credential_audit where owner_id = $1 and action = 'owner_provisioned'`,
    [ownerId]
  );
  return rows[0].n === 1;
});

// ---- invites ---------------------------------------------------------------
await check('урилгын утас гэрээн дээрхээс өөр бол татгалзана', async () => {
  const r = await call(`/admin/v1/owners/${ownerId}/invite`, {
    token: op, body: { invitedPhone: '99887767', role: 'admin' },
  });
  return r.json?.status === 'phone_mismatch';
});

await check('эрхийг (admin/viewer) заавал сонгуулна — анхдагч утга байхгүй', async () => {
  const r = await call(`/admin/v1/owners/${ownerId}/invite`, { token: op, body: { invitedPhone: OWNER_PHONE } });
  return r.json?.status === 'invalid_role';
});

let first;
let second;
await check('урилга: токен НЭГ удаа буцна, санд зөвхөн hash нь хадгалагдана', async () => {
  const r = await call(`/admin/v1/owners/${ownerId}/invite`, {
    token: op, body: { invitedPhone: OWNER_PHONE, role: 'admin' },
  });
  first = r.json;
  const hash = createHash('sha256').update(first.token, 'utf8').digest();
  const { rows } = await query(
    `select count(*)::int n from public.owner_invites where token_hash = $1 and reference = $2`,
    [hash, first.reference]
  );
  const leaked = await query(
    `select count(*)::int n from public.owner_invites where encode(token_hash,'escape') like '%' || $1 || '%'`,
    [first.token.slice(0, 12)]
  );
  return (
    first.status === 'ok' && first.token.length >= 40 &&
    /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(first.reference) &&
    rows[0].n === 1 && leaked.rows[0].n === 0 && !log.includes(first.token)
  ) || JSON.stringify(first);
});

await check('шинэ урилга гаргахад өмнөх нь хүчингүй болно', async () => {
  const r = await call(`/admin/v1/owners/${ownerId}/invite`, {
    token: op, body: { invitedPhone: OWNER_PHONE, role: 'admin' },
  });
  second = r.json;
  const { rows } = await query(
    `select reference, revoked_reason from public.owner_invites where owner_id = $1 order by created_at`,
    [ownerId]
  );
  return second.status === 'ok' && rows.length === 2 && rows[0].revoked_reason === 'superseded' && rows[1].revoked_reason === null;
});

// ---- redemption: the path that was dead ------------------------------------
await check('гишүүн БИШ хүн /owner/v1/invites/redeem-д хүрнэ (401 биш)', async () => {
  const r = await call('/owner/v1/invites/redeem', { token: await mint(OWNER), body: { token: first.token } });
  return (r.status === 409 && r.json?.code === 'INVITE_REVOKED') || `${r.status} ${JSON.stringify(r.json)}`;
});

await check('линк байгаа ч утас нь өөр бол нэвтрүүлэхгүй', async () => {
  const r = await call('/owner/v1/invites/redeem', { token: await mint(IMPOSTOR), body: { token: second.token } });
  const m = await query(`select count(*)::int n from public.owner_members where owner_id = $1`, [ownerId]);
  return r.json?.code === 'INVITE_PHONE_MISMATCH' && m.rows[0].n === 0;
});

await check('зөв утаснаас урилга хүлээн авахад admin гишүүн болно', async () => {
  const r = await call('/owner/v1/invites/redeem', { token: await mint(OWNER), body: { token: second.token } });
  const m = await query(`select role from public.owner_members where owner_id = $1 and user_id = $2`, [ownerId, OWNER]);
  return (r.status === 200 && r.json?.status === 'accepted' && m.rows[0]?.role === 'admin') || JSON.stringify(r.json);
});

await check('ашигласан урилгыг өөр хүн дахин ашиглаж чадахгүй', async () => {
  const r = await call('/owner/v1/invites/redeem', { token: await mint(IMPOSTOR), body: { token: second.token } });
  return r.json?.code === 'INVITE_USED';
});

// ---- the owner's own view ----------------------------------------------------
await check('/owner/v1/me ЖИНХЭНЭ машины дугаар, байршил, слотын id-г буцаана', async () => {
  const r = await call('/owner/v1/me', { token: await mint(OWNER) });
  const o = r.json?.owners?.[0];
  const cred = await query(`select id from public.qpay_credentials where owner_id = $1`, [ownerId]);
  return (
    o?.id === ownerId &&
    o.machines?.length === 1 && o.machines[0].device_no === DEVICE && o.machines[0].location === 'ХУД, 3-р хороо' &&
    o.credential_id === cred.rows[0].id && o.credential_status === 'pending'
  ) || JSON.stringify(r.json);
});

await check('гишүүн биш хүнд /owner/v1/me-г 401 хэвээр', async () => {
  const r = await call('/owner/v1/me', { token: await mint(IMPOSTOR) });
  return r.status === 401;
});

await check('гишүүн /owner/v1/credentials/verify-д хүрнэ (маршрут дамжина)', async () => {
  const r = await call('/owner/v1/credentials/verify', { token: await mint(OWNER), body: { credentialId: 'x' } });
  return r.status === 400 && r.json?.code === 'INVALID_INPUT';
});

// ---- step-up ------------------------------------------------------------------
await check('урилга хүлээн авах нь step-up-д тооцогдоно', async () => {
  const r = await call('/owner/v1/step-up', { token: await mint(OWNER) });
  return r.json?.ageSeconds < 60 && r.json?.firstEntryMaxSeconds === 3600;
});

await check('step-up: OTP-ийн цаг токенд байхгүй бол бүртгэхгүй', async () => {
  const r = await call('/owner/v1/step-up', { method: 'POST', token: await mint(OWNER, { otpAgo: null }) });
  return r.status === 401 && r.json?.code === 'REAUTH_REQUIRED';
});

await check('step-up: 10 минутын өмнөх OTP шинэ биш', async () => {
  const r = await call('/owner/v1/step-up', { method: 'POST', token: await mint(OWNER, { otpAgo: 600 }) });
  return r.status === 401;
});

await check('step-up: дөнгөж оруулсан OTP бүртгэгдэнэ', async () => {
  await query(`update public.owner_step_up set last_otp_at = now() - interval '2 hours' where user_id = $1`, [OWNER]);
  const r = await call('/owner/v1/step-up', { method: 'POST', token: await mint(OWNER, { otpAgo: 5 }) });
  const age = await call('/owner/v1/step-up', { token: await mint(OWNER) });
  return r.status === 200 && age.json?.ageSeconds < 60;
});

// ---- invoice code ---------------------------------------------------------------
await check('нэхэмжлэхийн кодыг оператор засна, эзэмшигч засаж чадахгүй', async () => {
  const bad = await call(`/admin/v1/owners/${ownerId}/invoice-code`, { token: await mint(OWNER), body: { invoiceCode: 'X_HACK' } });
  const invalid = await call(`/admin/v1/owners/${ownerId}/invoice-code`, { token: op, body: { invoiceCode: 'бага' } });
  const ok = await call(`/admin/v1/owners/${ownerId}/invoice-code`, { token: op, body: { invoiceCode: 'FIXED_CODE_77' } });
  const { rows } = await query(`select pending_invoice_code, invoice_code_hint from public.qpay_credentials where owner_id = $1`, [ownerId]);
  return (
    bad.status === 401 && invalid.json?.status === 'invalid_invoice_code' && ok.json?.status === 'ok' &&
    rows[0].pending_invoice_code === 'FIXED_CODE_77' && rows[0].invoice_code_hint === 'E_77'
  ) || JSON.stringify({ bad: bad.status, invalid: invalid.json, ok: ok.json, row: rows[0] });
});

// ---- the machine refuses to sell until the owner connects ------------------------
// server.js's merchantFor() refuses a registered machine whose credential is
// not active — it never falls back to the operator's env merchant for one.
// What makes that true for a freshly provisioned machine is that it RESOLVES
// (so it is not "unregistered", which does fall back) to a pending slot.
await check('шинэ машин бүртгэлтэй, QPay слот нь pending — операторын данс руу унахгүй', async () => {
  const { resolveMachine } = await import('../src/owners.js');
  const r = await resolveMachine(DEVICE);
  return (r && r.credential_status === 'pending' && r.credential_active === false) || JSON.stringify(r);
});

// ---- the bootstrap: an operator named by phone ------------------------------------
// Nobody could reach the console before 009: the login SMS only goes to owner
// members and invitees, and the operator is neither.
const PHONE_OP = randomUUID();
await check('утсаар бүртгэсэн оператор SMS код авах эрхтэй, танихгүй дугаар авахгүй', async () => {
  await query(`insert into public.operator_phones (phone, label) values ('97699110088','Шинэ оператор')`);
  const { rows } = await query(
    `select app.phone_may_receive_otp('9911 0088') as op, app.phone_may_receive_otp('99110089') as stranger`
  );
  return rows[0].op === true && rows[0].stranger === false;
});

await check('утас БАТАЛГААЖААГҮЙ бол оператор биш — код хүссэн төдийгөөр эрх олгохгүй', async () => {
  await query(`insert into auth.users (id, phone, phone_confirmed_at) values ($1,'97699110088',null)`, [PHONE_OP]);
  const r = await call('/admin/v1/me', { token: await mint(PHONE_OP) });
  return r.status === 401;
});

await check('OTP-оор баталгаажсаны дараа консолд орно', async () => {
  await query(`update auth.users set phone_confirmed_at = now() where id = $1`, [PHONE_OP]);
  const r = await call('/admin/v1/me', { token: await mint(PHONE_OP) });
  return r.status === 200 && r.json?.isOperator === true;
});

await check('утсыг жагсаалтаас хасахад эрх тэр даруй алга болно', async () => {
  await query(`delete from public.operator_phones where phone = '97699110088'`);
  const r = await call('/admin/v1/me', { token: await mint(PHONE_OP) });
  return r.status === 401;
});

// ---- the operator configures an owner's QPay (migration 010) -------------------
const creds = (extra = {}) => ({
  username: 'shinekofe', password: 'Merchant-Pass-9', invoiceCode: 'SHINE_INV_01', confirmOwnership: true, ...extra,
});
const credOf = async (id) =>
  (await query(`select status, is_active, sealed, username_hint, pending_invoice_code from public.qpay_credentials where owner_id = $1`, [id])).rows[0];

await check('оператор биш хүн QPay тохируулж ЧАДАХГҮЙ', async () => {
  const r = await call(`/admin/v1/owners/${ownerId}/credentials`, { token: await mint(OWNER), body: creds() });
  return r.status === 401 && (await credOf(ownerId)).status === 'pending';
});

await check('операторын SMS код 10 минутаас хуучин бол дахин баталгаажуулахыг шаардана', async () => {
  const r = await call(`/admin/v1/owners/${ownerId}/credentials`, { token: await mint(OPERATOR, { otpAgo: 3600 }), body: creds() });
  return r.status === 401 && r.json?.code === 'REAUTH_REQUIRED';
});

await check('«энэ данс харилцагчийнх» гэж батлаагүй бол татгалзана', async () => {
  const r = await call(`/admin/v1/owners/${ownerId}/credentials`, { token: await mint(OPERATOR), body: creds({ confirmOwnership: false }) });
  return r.status === 400 && r.json?.field === 'confirmOwnership';
});

await check('буруу QPay нууц үг → AUTH_FAILED, слот хөндөгдөхгүй', async () => {
  const r = await call(`/admin/v1/owners/${ownerId}/credentials`, { token: await mint(OPERATOR), body: creds({ password: 'wrong-pass' }) });
  return r.json?.code === 'AUTH_FAILED' && (await credOf(ownerId)).status === 'pending';
});

await check('буруу нэхэмжлэхийн код → INVOICE_CODE_FAILED', async () => {
  const r = await call(`/admin/v1/owners/${ownerId}/credentials`, { token: await mint(OPERATOR), body: creds({ invoiceCode: 'BAD_CODE' }) });
  return r.json?.code === 'INVOICE_CODE_FAILED' && (await credOf(ownerId)).status === 'pending';
});

await check('оператор QPay тохируулна: идэвхжинэ, шифрлэгдэнэ, туршилтын нэхэмжлэх цуцлагдана', async () => {
  const before = qpayCalls.cancelled.length;
  const r = await call(`/admin/v1/owners/${ownerId}/credentials`, { token: await mint(OPERATOR), body: creds() });
  const c = await credOf(ownerId);
  const audit = await query(
    `select actor_user_id from public.credential_audit where owner_id = $1 and action = 'operator_configured'`, [ownerId]
  );
  const plaintext = await query(
    `select count(*)::int n from public.qpay_credentials where sealed like '%Merchant-Pass-9%' or sealed like '%shinekofe%'`
  );
  return (
    r.status === 200 && c.status === 'active' && c.is_active === true && c.sealed?.startsWith('v1.') &&
    c.username_hint === 'sh••••••fe' && c.pending_invoice_code === null &&
    audit.rows[0]?.actor_user_id === OPERATOR && plaintext.rows[0].n === 0 &&
    qpayCalls.cancelled.length === before + 1 && !log.includes('Merchant-Pass-9')
  ) || JSON.stringify({ r: r.json, c: { ...c, sealed: c?.sealed?.slice(0, 6) } });
});

await check('тохируулсны дараа машин эзэмшигчийн дансаар ажиллана', async () => {
  const { resolveMachine, forgetAll } = await import('../src/owners.js');
  forgetAll();
  const m = await resolveMachine(DEVICE);
  return m?.credential_status === 'active' && m.credential_active === true;
});

await check('нэг QPay дансыг өөр харилцагчид давхар тохируулахгүй', async () => {
  const other = await call('/admin/v1/owners', {
    token: op,
    body: { ...newOwner, name: 'Өөр ХХК', contactPhone: '99887755', deviceNo: `D${Math.floor(Math.random() * 1e9)}` },
  });
  const r = await call(`/admin/v1/owners/${other.json.ownerId}/credentials`, { token: await mint(OPERATOR), body: creds() });
  return (r.status === 409 && r.json?.code === 'DUPLICATE_OTHER_OWNER') || JSON.stringify(r.json);
});

bridge.kill();
jwks.close();
qpayFake.close();
await close();

const passed = results.filter(([ok]) => ok).length;
for (const [ok, name, extra] of results) console.log(`  ${ok ? '✓' : '✗'} ${name}${ok ? '' : extra}`);
console.log(`\n  ${passed}/${results.length} давлаа`);
process.exit(passed === results.length ? 0 : 1);
