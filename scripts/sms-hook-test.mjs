/**
 * Integration test for the Send SMS auth hook. Run with: npm run test:sms
 *
 * This endpoint is the one place where an HTTP request from the internet
 * spends money and rings a stranger's phone, so the tests are mostly about
 * refusing: a forged signature, a replayed request, a phone nobody invited,
 * and a number that has already had its codes for the hour.
 *
 * A fake gateway stands in for Skytel and records exactly what it was asked to
 * send — which is also how the "never log the OTP" and "transliterate the
 * Cyrillic" claims get checked rather than asserted.
 */
import { randomUUID, createHmac } from 'node:crypto';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
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

// ---- a stand-in Skytel ---------------------------------------------------
const GATEWAY_PORT = 4601;
let sent = [];
let gatewayMode = 'ok';
const gateway = createServer((req, res) => {
  let body = '';
  req.on('data', (d) => (body += d));
  req.on('end', () => {
    const url = new URL(req.url, `http://localhost:${GATEWAY_PORT}`);
    // Params may arrive in the query string or the form body depending on the
    // configured method; the fake gateway reads both, like the real one does.
    const params = new URLSearchParams(body || url.search);
    sent.push({
      method: req.method,
      url: req.url,
      to: params.get('sendto'),
      message: params.get('message'),
      token: params.get('token'),
    });
    if (gatewayMode === 'fail') {
      res.statusCode = 500;
      return res.end('gateway exploded');
    }
    if (gatewayMode === 'softfail') return res.end('ERROR: balance');
    // The real Skytel endpoint answers 200 with a JSON status; a failed send
    // is status 0, which must never be recorded as delivered.
    if (gatewayMode === 'jsonfail') {
      return res.end('{"status":0,"sent_count":0,"message":"Дугаар буруу"}');
    }
    res.end('{"status":1,"sent_count":1}');
  });
});
await new Promise((r) => gateway.listen(GATEWAY_PORT, '127.0.0.1', r));

// ---- seed: one invited owner, one open invite, one stranger --------------
const ownerId = randomUUID();
const credId = randomUUID();
const userId = randomUUID();
const MEMBER_PHONE = '97699110001';
const INVITED_PHONE = '97699110002';
const STRANGER_PHONE = '97699119999';

await query(`insert into public.owners (id, name, contact_phone) values ($1,'Тест ХХК','99110001')`, [ownerId]);
await query(
  `insert into public.qpay_credentials (id, owner_id, label, sealed, key_id, fingerprint, status, is_active, source)
   values ($1,$2,'Үндсэн данс','v1.k1.a.b.c','k1',$3,'active',true,'cli')`,
  [credId, ownerId, 'a'.repeat(64)]
);
await query(`insert into auth.users (id, phone) values ($1,$2)`, [userId, MEMBER_PHONE]);
await query(`insert into public.owner_members (owner_id, user_id, role) values ($1,$2,'admin')`, [ownerId, userId]);
await query(
  `insert into public.owner_invites (owner_id, role, token_hash, reference, invited_phone)
   values ($1,'admin',$2,'ABCD-1234',$3)`,
  [ownerId, Buffer.from('x'.repeat(32)), INVITED_PHONE]
);

// ---- boot the bridge -----------------------------------------------------
const SECRET_RAW = Buffer.from('a-test-signing-secret-32-bytes!!').toString('base64');
const SECRET = `v1,whsec_${SECRET_RAW}`;
const PORT = 3196;
const bridge = spawn(process.execPath, ['src/server.js'], {
  env: {
    ...process.env,
    PORT: String(PORT),
    QPAY_MOCK: '1',
    JETINNO_USERNAME: 'testname',
    JETINNO_APIKEY: 'DBRW17YE7FHKR72T',
    PUBLIC_URL: `http://localhost:${PORT}`,
    SEND_SMS_HOOK_SECRET: SECRET,
    SMS_API_URL: `http://127.0.0.1:${GATEWAY_PORT}/apiSend`,
    // SMS_API_METHOD deliberately unset: the default must be POST.
    SMS_PARAM_TO: 'sendto',
    SMS_PARAM_TEXT: 'message',
    SMS_PARAM_KEY: 'token',
    SMS_API_KEY: 'test-gateway-token',
    SMS_ERROR_MATCH: 'ERROR',
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

function sign(body, { id = randomUUID(), timestamp = Math.floor(Date.now() / 1000), secret = SECRET } = {}) {
  const key = Buffer.from(secret.replace(/^v1,/, '').replace(/^whsec_/, ''), 'base64');
  const sig = createHmac('sha256', key).update(`${id}.${timestamp}.${body}`).digest('base64');
  return { 'webhook-id': id, 'webhook-timestamp': String(timestamp), 'webhook-signature': `v1,${sig}` };
}

const payloadFor = (phone, otp = '123456') =>
  JSON.stringify({ user: { id: userId, phone }, sms: { otp } });

async function post(body, headers) {
  const res = await fetch(`http://localhost:${PORT}/hooks/send-sms`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body,
  });
  return { status: res.status, text: await res.text() };
}

// ---- mounted at all ------------------------------------------------------
await check('нууц үг + гарц + сан байвал hook mount хийгдэнэ', () =>
  bridgeLog.includes('send-sms hook mounted')
);

// ---- the signature -------------------------------------------------------
await check('зөв гарын үсэгтэй хүсэлт SMS илгээнэ', async () => {
  sent = [];
  const body = payloadFor(MEMBER_PHONE);
  const r = await post(body, sign(body));
  return r.status === 200 && sent.length === 1 && sent[0].to === '99110001';
});

await check('гарын үсэггүй хүсэлт 401, SMS явуулахгүй', async () => {
  sent = [];
  const r = await post(payloadFor(MEMBER_PHONE), {});
  return r.status === 401 && sent.length === 0;
});

await check('өөр нууц үгээр зурсан гарын үсэг 401', async () => {
  sent = [];
  const body = payloadFor(MEMBER_PHONE);
  const other = `v1,whsec_${Buffer.from('a-different-secret-of-32-bytes!!!').toString('base64')}`;
  const r = await post(body, sign(body, { secret: other }));
  return r.status === 401 && sent.length === 0;
});

await check('биеийг өөрчилсөн хүсэлт 401 — гарын үсэг байтуудыг хамарна', async () => {
  sent = [];
  const body = payloadFor(MEMBER_PHONE);
  const headers = sign(body);
  const tampered = payloadFor(STRANGER_PHONE); // дугаарыг сольсон
  const r = await post(tampered, headers);
  return r.status === 401 && sent.length === 0;
});

// A body that is valid JSON but NOT what JSON.stringify would produce. It
// only verifies if the server hashed the bytes it received; a server that
// re-serialises the parsed object computes a different string and rejects a
// request it should have accepted. The reordering test below cannot show this
// on its own — every payload this client sends is already canonical, so
// re-serialising is a no-op and both implementations agree.
await check('зай, шинэ мөр бүхий бие ч ажиллана — түүхий байтыг хэшилдэг', async () => {
  sent = [];
  const body = `{\n  "user" : { "id": "${userId}",\n    "phone": "${MEMBER_PHONE}" },\n  "sms": {  "otp": "111222" }\n}`;
  const r = await post(body, sign(body));
  return r.status === 200 && sent.length === 1 && (sent[0].message ?? '').includes('111222');
});

await check('JSON-ы дарааллыг өөрчилсөн ч 401 — задалсныг биш, байтыг шалгана', async () => {
  sent = [];
  const body = payloadFor(MEMBER_PHONE);
  const headers = sign(body);
  const reordered = JSON.stringify({ sms: { otp: '123456' }, user: { phone: MEMBER_PHONE, id: userId } });
  const r = await post(reordered, headers);
  return r.status === 401 && sent.length === 0;
});

await check('5 минутаас хуучин хүсэлт 401 — давталтаас хамгаална', async () => {
  sent = [];
  const body = payloadFor(MEMBER_PHONE);
  const old = Math.floor(Date.now() / 1000) - 600;
  const r = await post(body, sign(body, { timestamp: old }));
  return r.status === 401 && sent.length === 0;
});

await check('ирээдүйн цагтай хүсэлт ч 401', async () => {
  sent = [];
  const body = payloadFor(MEMBER_PHONE);
  const future = Math.floor(Date.now() / 1000) + 600;
  const r = await post(body, sign(body, { timestamp: future }));
  return r.status === 401 && sent.length === 0;
});

// ---- who may be texted ---------------------------------------------------
await check('урилгагүй дугаар 403 — SMS явуулахгүй', async () => {
  sent = [];
  const body = payloadFor(STRANGER_PHONE);
  const r = await post(body, sign(body));
  return r.status === 403 && sent.length === 0;
});

await check('нээлттэй урилгатай дугаар руу явуулна', async () => {
  sent = [];
  const body = payloadFor(INVITED_PHONE);
  const r = await post(body, sign(body));
  return r.status === 200 && sent.length === 1 && sent[0].to === '99110002';
});

await check('урилга цуцлагдсаны дараа тэр дугаар 403 болно', async () => {
  await query(`update public.owner_invites set revoked_at = now() where invited_phone = $1`, [INVITED_PHONE]);
  sent = [];
  const body = payloadFor(INVITED_PHONE);
  const r = await post(body, sign(body));
  await query(`update public.owner_invites set revoked_at = null where invited_phone = $1`, [INVITED_PHONE]);
  return r.status === 403 && sent.length === 0;
});

// ---- the message itself --------------------------------------------------
await check('мессеж латинаар явна — Skytel кирилл гажуудуулдаг', async () => {
  sent = [];
  const body = payloadFor(MEMBER_PHONE, '654321');
  await post(body, sign(body));
  const msg = sent[0]?.message ?? '';
  return msg.includes('654321') && !/[Ѐ-ӿ]/.test(msg) && msg.toLowerCase().includes('coffeine');
});

await check('мессежид холбоос байхгүй — фишингийн хэлбэрийг заахгүй', async () => {
  return !(sent[0]?.message ?? '').match(/https?:\/\//);
});

await check('гарцын түлхүүр параметрээр явсан', async () => {
  return sent[0]?.token === 'test-gateway-token';
});

// Skytel-д HTTPS байхгүй (порт 443 хариу өгдөггүй), тиймээс хүсэлт задгай
// сүлжээгээр явна. POST нь ядаж кодыг URL-аас гаргаж, замын дагуух бүх
// хандалтын логоос салгана.
await check('POST-оор явна — код ба токен URL-д ороогүй', async () => {
  sent = [];
  const body = payloadFor(MEMBER_PHONE, '777888');
  await post(body, sign(body));
  const g = sent[0];
  return (
    g?.method === 'POST' &&
    !g.url.includes('777888') &&
    !g.url.includes('test-gateway-token') &&
    g.message.includes('777888')
  );
});

await check('гарц 200 дотор status:0 буцаавал амжилтгүй — тохиргоо шаардахгүй', async () => {
  gatewayMode = 'jsonfail';
  const body = payloadFor(MEMBER_PHONE);
  const r = await post(body, sign(body));
  gatewayMode = 'ok';
  const { rows } = await query(
    `select ok from public.sms_sends where phone = $1 order by at desc limit 1`,
    [MEMBER_PHONE]
  );
  return r.status === 502 && rows[0]?.ok === false;
});

await check('гарцын хариу хадгалагдана — амжилтын хэлбэрийг мэдэхийн тулд', async () => {
  const body = payloadFor(MEMBER_PHONE);
  await post(body, sign(body));
  const { rows } = await query(
    `select gateway_reply from public.sms_sends where phone = $1 and ok order by at desc limit 1`,
    [MEMBER_PHONE]
  );
  return (rows[0]?.gateway_reply ?? '').includes('sent_count');
});

// ---- what gets recorded --------------------------------------------------
await check('лог мессежийн текст ч, OTP ч хадгалдаггүй', async () => {
  const { rows } = await query(`select * from public.sms_sends order by at desc limit 20`);
  const blob = JSON.stringify(rows);
  return (
    rows.length > 0 &&
    !blob.includes('654321') &&
    !blob.includes('123456') &&
    !blob.includes('777888') &&
    !blob.includes('111222') &&
    !blob.includes('Coffeine')
  );
});

await check('серверийн лог OTP-г хэвлэдэггүй', () => {
  return ['123456', '654321', '777888', '111222'].every((c) => !bridgeLog.includes(c));
});

await check('серверийн лог бүтэн дугаар хэвлэдэггүй', () => {
  return !bridgeLog.includes(MEMBER_PHONE) && !bridgeLog.includes('99110001');
});

// ---- the budget ----------------------------------------------------------
await check('цагийн хязгаар хэтэрвэл 429, SMS явахаа болино', async () => {
  // Дээр аль хэдийн 2 амжилттай явсан; хязгаар 5.
  for (let i = 0; i < 4; i += 1) {
    const body = payloadFor(MEMBER_PHONE);
    await post(body, sign(body));
  }
  sent = [];
  const body = payloadFor(MEMBER_PHONE);
  const r = await post(body, sign(body));
  return r.status === 429 && sent.length === 0;
});

await check('429-ийн мессеж хэдэн минут хүлээхийг хэлнэ', async () => {
  const body = payloadFor(MEMBER_PHONE);
  const r = await post(body, sign(body));
  return /минут/.test(r.text);
});

await check('бүтэлгүй илгээлт хязгаарыг иддэггүй', async () => {
  // Өөр дугаар: гарцыг унагаад 5 удаа оролдоод дараа нь амжилттай явах ёстой.
  await query(`insert into public.owner_invites (owner_id, role, token_hash, reference, invited_phone)
               values ($1,'admin',$2,'ABCD-5678',$3)`, [ownerId, Buffer.from('y'.repeat(32)), '97699110003']);
  gatewayMode = 'fail';
  for (let i = 0; i < 6; i += 1) {
    const body = payloadFor('97699110003');
    await post(body, sign(body));
  }
  gatewayMode = 'ok';
  sent = [];
  const body = payloadFor('97699110003');
  const r = await post(body, sign(body));
  return r.status === 200 && sent.length === 1;
});

await check('гарц 200 дотор алдаа буцаавал амжилтгүйд тооцно', async () => {
  gatewayMode = 'softfail';
  const body = payloadFor('97699110003');
  const r = await post(body, sign(body));
  gatewayMode = 'ok';
  const { rows } = await query(
    `select ok from public.sms_sends where phone = '97699110003' order by at desc limit 1`
  );
  return r.status === 502 && rows[0]?.ok === false;
});

// ---- payload shape -------------------------------------------------------
await check('otp дутуу бол 400', async () => {
  const body = JSON.stringify({ user: { id: userId, phone: INVITED_PHONE } });
  const r = await post(body, sign(body));
  return r.status === 400;
});

await check('JSON биш бие бол 400', async () => {
  const body = 'not json at all';
  const r = await post(body, sign(body));
  return r.status === 400;
});

// ---- the machine path is untouched --------------------------------------
await check('машины зам SMS-ээс хамааралгүй хэвээр', async () => {
  const r = await fetch(`http://localhost:${PORT}/health`);
  return r.ok && (await r.json()).ok === true;
});

bridge.kill('SIGTERM');
gateway.close();
await close();

const passed = results.filter(([ok]) => ok).length;
for (const [ok, name, extra] of results) console.log(`  ${ok ? '✓' : '✗'} ${name}${extra}`);
console.log(`\n  ${passed}/${results.length} давлаа`);
process.exit(passed === results.length ? 0 : 1);
