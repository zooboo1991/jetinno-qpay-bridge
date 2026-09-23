/**
 * Checks a deployment's configuration BEFORE it reaches Render.
 *
 *   node --env-file=.env scripts/preflight.mjs
 *
 * Exists because the expensive failures here are all silent. /health reports
 * dbConfigured from the presence of an environment variable, not from a
 * working connection, so a database the bridge cannot actually reach looks
 * identical to one it can — and the symptom surfaces later, as owner logins
 * returning 401 and a dwFailed counter nobody is watching yet.
 *
 * Nothing here writes. It is safe to run against production.
 */
import { Pool } from 'pg';

const checks = [];
const ok = (name, detail = '') => checks.push([true, name, detail]);
const bad = (name, detail = '') => checks.push([false, name, detail]);
const warn = (name, detail = '') => checks.push(['warn', name, detail]);

const {
  DATABASE_URL,
  SUPABASE_URL,
  CRED_KEYS,
  CRED_KEY_ACTIVE,
  CRED_FP_KEY,
  PORTAL_ORIGIN,
  SEND_SMS_HOOK_SECRET,
  SMS_API_URL,
  SMS_API_KEY,
  JETINNO_USERNAME,
  JETINNO_APIKEY,
  QPAY_USERNAME,
  QPAY_PASSWORD,
  QPAY_INVOICE_CODE,
  DEBUG_KEY,
} = process.env;

// ---- 1. the two that stop the process booting ---------------------------
JETINNO_USERNAME && JETINNO_APIKEY
  ? ok('JETINNO_USERNAME + JETINNO_APIKEY')
  : bad('JETINNO_USERNAME + JETINNO_APIKEY', 'эдгээргүйгээр сервер огт асахгүй');

// ---- 2. the operator's own merchant -------------------------------------
QPAY_USERNAME && QPAY_PASSWORD && QPAY_INVOICE_CODE
  ? ok('QPAY_* (операторын данс)', 'бүртгэлгүй машины fallback — хасаж болохгүй')
  : bad('QPAY_* (операторын данс)', 'гурвуулаа хэрэгтэй');

// ---- 3. the crypto keyring ----------------------------------------------
function checkKey(name, value, { prefixed = false } = {}) {
  if (!value) return bad(name, 'тохируулаагүй');
  const body = prefixed ? value.split(':').slice(1).join(':') : value;
  const bytes = Buffer.from(body, 'base64');
  if (bytes.length !== 32) {
    return bad(name, `${bytes.length} байт — 32 байх ёстой (буруу хуулсан байх)`);
  }
  ok(name, '32 байт');
}
checkKey('CRED_KEYS', CRED_KEYS, { prefixed: true });
checkKey('CRED_FP_KEY', CRED_FP_KEY);
if (CRED_KEYS && CRED_KEY_ACTIVE) {
  const ids = CRED_KEYS.split(/[,\n]/).map((k) => k.split(':')[0].trim());
  ids.includes(CRED_KEY_ACTIVE)
    ? ok('CRED_KEY_ACTIVE', `"${CRED_KEY_ACTIVE}" нь CRED_KEYS дотор бий`)
    : bad('CRED_KEY_ACTIVE', `"${CRED_KEY_ACTIVE}" нь CRED_KEYS дотор алга`);
}

// ---- 4. the database, actually connected --------------------------------
if (!DATABASE_URL) {
  bad('DATABASE_URL', 'тохируулаагүй — олон эзэмшигчийн горим бүхэлдээ унтарна');
} else if (/ЭНД_|ТӨСЛИЙН_REF|YOUR-PASSWORD/i.test(DATABASE_URL)) {
  bad('DATABASE_URL', 'орлуулагч утга хэвээр байна');
} else {
  const port = DATABASE_URL.match(/:(\d+)\//)?.[1];
  if (port === '5432' && DATABASE_URL.includes('pooler.')) ok('DATABASE_URL порт', '5432 (session pooler) — зөв');
  else if (port === '6543') warn('DATABASE_URL порт', '6543 = transaction pooler. Ажиллана, гэхдээ байнгын процесст session pooler (5432, pooler.*) илүү тохирно');
  else if (port === '5432') warn('DATABASE_URL порт', '5432 шууд холболт бол IPv6-only — Render холбогдохгүй. Connect → Session pooler-ийг ав');
  else warn('DATABASE_URL порт', `порт ${port ?? '?'}`);

  const pool = new Pool({ connectionString: DATABASE_URL, connectionTimeoutMillis: 8000 });
  try {
    const r = await pool.query('select current_database() as db, version() as v');
    ok('Санд холбогдлоо', r.rows[0].db);

    const need = [
      ['orders', "to_regclass('public.orders')"],
      ['owner_members', "to_regclass('public.owner_members')"],
      ['owner_invites', "to_regclass('public.owner_invites')"],
      ['sms_sends', "to_regclass('public.sms_sends')"],
    ];
    for (const [label, expr] of need) {
      const { rows } = await pool.query(`select ${expr} is not null as present`);
      rows[0].present ? ok(`Хүснэгт ${label}`) : bad(`Хүснэгт ${label}`, 'миграц дутуу');
    }
    for (const [label, fn] of [
      ['app.owner_stats', 'owner_stats'],
      ['app.give_up_exhausted', 'give_up_exhausted'],
      ['app.phone_may_receive_otp', 'phone_may_receive_otp'],
      ['app.accept_owner_invite', 'accept_owner_invite'],
    ]) {
      const { rows } = await pool.query(
        `select exists(select 1 from pg_proc p join pg_namespace n on n.oid=p.pronamespace
          where n.nspname='app' and p.proname=$1) as present`,
        [fn]
      );
      rows[0].present ? ok(`Функц ${label}`) : bad(`Функц ${label}`, 'миграц дутуу');
    }
    const { rows: c } = await pool.query(
      `select exists(select 1 from information_schema.columns
        where table_schema='public' and table_name='sms_sends' and column_name='gateway_reply') as present`
    );
    c[0].present ? ok('005-ийн нэмэлт (gateway_reply)') : bad('005-ийн нэмэлт', 'patches/005_gateway_reply.sql ажиллуулна уу');

    const { rows: m } = await pool.query(`select count(*)::int as n from public.machines`);
    const { rows: o } = await pool.query(`select count(*)::int as n from public.owners`);
    ok('Бүртгэгдсэн', `${o[0].n} эзэмшигч, ${m[0].n} машин`);
  } catch (err) {
    bad('Санд холбогдох', err.message.split('\n')[0]);
    if (/self.signed|certificate|SELF_SIGNED/i.test(err.message)) {
      bad('  ↳ TLS', 'sslmode-г шалгана уу. Supabase-ийн мөрийг ӨӨРЧЛӨЛГҮЙ хуулах ёстой');
    }
  } finally {
    await pool.end().catch(() => {});
  }
}

// ---- 5. the owner portal API --------------------------------------------
if (!SUPABASE_URL) bad('SUPABASE_URL', '/owner/v1 mount хийгдэхгүй');
else if (/ТӨСЛИЙН_REF/.test(SUPABASE_URL)) bad('SUPABASE_URL', 'орлуулагч утга хэвээр');
else {
  try {
    const res = await fetch(`${SUPABASE_URL.replace(/\/+$/, '')}/auth/v1/.well-known/jwks.json`, {
      signal: AbortSignal.timeout(8000),
    });
    const j = await res.json().catch(() => ({}));
    const n = j?.keys?.length ?? 0;
    n > 0
      ? ok('Supabase JWKS', `${n} түлхүүр — токен шалгах боломжтой`)
      : bad('Supabase JWKS', 'түлхүүр алга. Auth → JWT Keys дээр asymmetric болгох хэрэгтэй');
  } catch (err) {
    bad('Supabase JWKS', err.message.split('\n')[0]);
  }
}

PORTAL_ORIGIN
  ? (/^https:\/\/[^/]+$/.test(PORTAL_ORIGIN)
      ? ok('PORTAL_ORIGIN', PORTAL_ORIGIN)
      : bad('PORTAL_ORIGIN', 'https://домэйн хэлбэртэй, ташуу зураасаар төгсөхгүй байх ёстой'))
  : warn('PORTAL_ORIGIN', 'тохируулаагүй — credentials роутер mount хийгдэхгүй');

// ---- 6. login SMS --------------------------------------------------------
if (!SEND_SMS_HOOK_SECRET && !SMS_API_URL && !SMS_API_KEY) {
  warn('SMS', 'гурвуулаа тохируулаагүй — /hooks/send-sms mount хийгдэхгүй');
} else {
  SEND_SMS_HOOK_SECRET?.startsWith('v1,whsec_')
    ? ok('SEND_SMS_HOOK_SECRET', 'хэлбэр зөв')
    : bad('SEND_SMS_HOOK_SECRET', 'v1,whsec_ -ээр эхлэх ёстой (бүтнээр нь хуулна)');
  if (SMS_API_URL) {
    try {
      const res = await fetch(SMS_API_URL, { signal: AbortSignal.timeout(8000) });
      const body = (await res.text()).slice(0, 120);
      ok('SMS гарц хүрэлцэхүйц', `HTTP ${res.status}`);
      if (/status"?\s*:\s*0/.test(body)) ok('  ↳ хариу', 'JSON статус буцааж байна (хүлээгдсэн)');
    } catch (err) {
      bad('SMS гарц', err.message.split('\n')[0]);
    }
  } else bad('SMS_API_URL', 'тохируулаагүй');
  SMS_API_KEY ? ok('SMS_API_KEY') : bad('SMS_API_KEY', 'тохируулаагүй');
}

DEBUG_KEY ? ok('DEBUG_KEY') : warn('DEBUG_KEY', 'үүнгүй бол /errors, /recent бүгд 404');

// ---- report --------------------------------------------------------------
const bads = checks.filter(([s]) => s === false).length;
const warns = checks.filter(([s]) => s === 'warn').length;
console.log('');
for (const [status, name, detail] of checks) {
  const mark = status === true ? '✓' : status === 'warn' ? '!' : '✗';
  console.log(`  ${mark} ${name}${detail ? ` — ${detail}` : ''}`);
}
console.log('');
if (bads) console.log(`  ${bads} зүйл засах шаардлагатай${warns ? `, ${warns} анхааруулга` : ''}.`);
else if (warns) console.log(`  Блоклох зүйл алга. ${warns} анхааруулга — дээрхийг уншина уу.`);
else console.log('  Бүгд бэлэн.');
process.exit(bads ? 1 : 0);
