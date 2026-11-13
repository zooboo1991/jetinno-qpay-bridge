import express from 'express';
import './async-errors.js';
import { isIP } from 'node:net';
import { lookup } from 'node:dns/promises';
import { SIGNABLE, buildSign, verifySign, flatten, timestamp } from './sign.js';
import * as qpay from './qpay.js';
import * as db from './db.js';
import * as store from './store.js';
import { ownerApi, authConfigured } from './owner-api.js';
import { adminApi } from './admin-api.js';
import * as owners from './owners.js';
import * as alerts from './alerts.js';
import { authHook, authHookConfigured } from './auth-hook.js';
import { guardApi, guardConfigured } from './guard.js';
import { pushConfigured, pushSale } from './push.js';
import { open, credentialAad } from './crypto.js';
import { createHmac, timingSafeEqual as cryptoTimingSafeEqual } from 'node:crypto';

const app = express();
// Render puts exactly one proxy in front of the process. Without this req.ip
// is that proxy's address for every caller, which made the per-IP limit on
// the public callback route and the audit's source_ip both meaningless.
app.set('trust proxy', 1);
/**
 * Deliberately NOT a global parser.
 *
 * body-parser sets `req._body` before parsing and skips if it is already set,
 * so a global parser makes any later route-scoped limit dead code — a 50 KB
 * body reached the handlers with HTTP 200. It also attaches the raw request
 * text to `err.body` when JSON is malformed, so once credential routes exist,
 * a single well-meaning error-logging middleware would put a merchant's
 * password into the /recent ring.
 *
 * Each route opts in with the smallest limit it can use. A Jetinno request is
 * a few hundred bytes.
 */
const jetinnoBody = express.json({ limit: '16kb' });

/**
 * No fallback values. The documentation's sample key used to sit here as a
 * default, in a public repository — so any deploy that lost JETINNO_APIKEY
 * would keep serving happily while accepting requests signed with a key the
 * whole internet can read. Refusing to boot turns that silent downgrade into
 * an obvious failure.
 */
function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} орчны хувьсагч тохируулаагүй байна`);
  return value;
}

/**
 * A number from the environment, or the default when the variable is empty,
 * not a number, or outside [min, max]. `Number('')` is 0: a variable saved
 * empty on Render made the sweep run every millisecond and voided every QR
 * the moment it was shown.
 */
function envInt(name, def, { min = -Infinity, max = Infinity } = {}) {
  const raw = process.env[name];
  if (raw === undefined || String(raw).trim() === '') return def;
  const n = Number(raw);
  return Number.isFinite(n) && n >= min && n <= max ? n : def;
}

const APIKEY = requiredEnv('JETINNO_APIKEY');
const USERNAME = requiredEnv('JETINNO_USERNAME');
// QPay builds its callback from this, so it has to be the origin the outside
// world reaches — never localhost in production. Render injects
// RENDER_EXTERNAL_URL with the service's own https origin, which saves
// hand-copying the domain back into the config after the first deploy.
// A trailing slash made every callback URL `…//qpay/…`, which QPay refused.
const PUBLIC_URL = (process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || 'http://localhost:3000').replace(/\/+$/, '');
const MOCK = process.env.QPAY_MOCK === '1';

// Jetinno documents orderAmount in cents, so 100000 means 1000₮ and QPay —
// which takes whole tugrik — needs it divided by 100. That is a reading of
// the spec, not something a real machine has confirmed yet, so it stays an
// env var: watch the first live getQrCode log and flip this to 1 if the
// machine turns out to send tugrik directly. It prices EVERY machine; the
// per-machine column of the same name is not read (see boot checks below).
const AMOUNT_DIVISOR = envInt('AMOUNT_DIVISOR', 100, { min: 1, max: 10000 });

// How long an unpaid QR stays live before we void it at QPay. Below a minute
// only in mock mode, where the tests sweep within seconds.
const ABANDON_AFTER_MS = envInt('ABANDON_AFTER_MS', 10 * 60 * 1000, { min: MOCK ? 0 : 60_000, max: 3_600_000 });

// After a notify the machine did not clearly answer, how long to assume a cup
// may be brewing before telling it again. A lost answer must not brew twice.
const NOTIFY_GRACE_S = envInt('NOTIFY_GRACE_SECONDS', 120, { min: 30, max: 3600 });
// Jetinno's own budget for the notify POST. Shorter only for the tests.
const NOTIFY_TIMEOUT_MS = envInt('NOTIFY_TIMEOUT_MS', 8000, { min: 500, max: 8000 });

/*
 * How old a payment may be and still make a machine brew. Past this, the
 * person who paid has long gone and the cup would go to whoever stands at
 * the machine — or be a second cup for a sale already served by the old
 * in-memory settle, whose database record never caught up. Such rows go to
 * a human (needs_human) instead of the machine. This matters most on the
 * first deploy of the database-driven sweep, which finds every stale row
 * the previous version left behind.
 */
const BREW_WINDOW_MS = envInt('BREW_WINDOW_MS', 15 * 60 * 1000, { min: 60_000, max: 3_600_000 });
const tooOldToBrew = (at) => !at || Date.now() - new Date(at).getTime() > BREW_WINDOW_MS;

/**
 * (deviceNo, orderNo) -> order.
 *
 * Keyed by both: Jetinno's orderNo is unique per machine only, and keyed by
 * orderNo alone a second machine's sale with the same number was refused as
 * ORDERNO_EXIST. The Map is this process's cache and its in-memory gate; with
 * a database configured, the database decides who settles (see settle()).
 */
const orders = new Map();
const keyOf = (deviceNo, orderNo) => `${deviceNo}\u0000${orderNo}`;

// Every log line is also kept in a ring buffer served at /recent, so the
// machine installer can read the server's view from a phone browser on site
// — no Render dashboard needed.
const recent = [];
const log = (...a) => {
  const line = `${new Date().toISOString()} ${a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' ')}`;
  console.log(line);
  recent.push(line);
  if (recent.length > 200) recent.shift();
};

const DUAL_WRITE = db.configured();

/** Identifies which process holds a settle lease. Render gives no stable id. */
const INSTANCE = `${process.env.RENDER_INSTANCE_ID ?? 'local'}-${process.pid}`;

// Mirror-write failures counted for /health: the counter tells an uptime
// monitor THAT a write is failing; /errors and the ring tell a human what.
let dwFailed = 0;
let dwLastFailure = null;

/*
 * Work that must finish before the process exits. Render sends SIGTERM on
 * every deploy and Node's default is to exit at once — mid-settle, with the
 * order's database writes half done. The shutdown handler waits for these.
 */
const inflight = new Set();
function track(promise) {
  inflight.add(promise);
  promise.finally(() => inflight.delete(promise)).catch(() => {});
  return promise;
}

/**
 * A database write nothing waits on. Logged and counted, never thrown; and
 * tracked, so a deploy does not cut it off.
 */
function dw(label, fn) {
  if (!DUAL_WRITE) return;
  const started = Date.now();
  track(
    Promise.resolve()
      .then(fn)
      .then(() => log('dw', label, `${Date.now() - started}ms`))
      // Only the message: a pg error can carry the failing row, and that row is
      // one schema change away from holding something that should not be logged.
      .catch((err) => {
        dwFailed += 1;
        dwLastFailure = { label, at: new Date().toISOString() };
        log('dw FAILED', label, `${Date.now() - started}ms`, err.message.split('\n')[0]);
      })
  );
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const firstLine = (err) => String(err?.message ?? err).split('\n')[0];

/**
 * QPay's callback URL for one order, signed.
 *
 * The callback route is public and every hit costs a database read or a QPay
 * round trip; an unsigned URL also answered differently for orders that exist
 * and orders that do not. The MAC is derived from the Jetinno key — stable
 * across restarts, which a callback for an invoice made before a deploy
 * needs — and a hit without a valid one gets the cheap, rate-limited path.
 */
const CALLBACK_KEY = createHmac('sha256', APIKEY).update('qpay-callback-v1').digest();
const callbackMac = (deviceNo, orderNo) =>
  createHmac('sha256', CALLBACK_KEY).update(`${deviceNo}\n${orderNo}`).digest('base64url').slice(0, 22);
const callbackUrlFor = (deviceNo, orderNo) =>
  `${PUBLIC_URL}/qpay/cb/${encodeURIComponent(deviceNo)}/${encodeURIComponent(orderNo)}/${callbackMac(deviceNo, orderNo)}`;
function macValid(deviceNo, orderNo, mac) {
  const a = Buffer.from(String(mac ?? ''));
  const b = Buffer.from(callbackMac(deviceNo, orderNo));
  return a.length === b.length && cryptoTimingSafeEqual(a, b);
}

/**
 * A small per-IP limiter for the public, unauthenticated routes. In memory:
 * it only has to stop one source hammering one process, and it resets on a
 * deploy, which is fine for that.
 */
function rateLimiter({ perMinute }) {
  const hits = new Map();
  setInterval(() => hits.clear(), 60_000).unref();
  return (req, res, next) => {
    const ip = req.ip ?? '?';
    const n = (hits.get(ip) ?? 0) + 1;
    hits.set(ip, n);
    if (n > perMinute) return res.status(429).send('SLOW_DOWN');
    next();
  };
}

function respond(res, data, signKeys) {
  const body = { returnCode: 'SUCCESS', msg: 'SUCCESS', time: timestamp(), data };
  body.sign = buildSign({ ...body, ...data }, signKeys, APIKEY);
  res.json(body);
}

function fail(res, msg) {
  log('FAIL', msg);
  res.json({ returnCode: 'FAIL', msg });
}

/*
 * Never the expected signature. Logged, it was a valid signature for whatever
 * the caller sent — and with values joined unescaped, the right orderNo made
 * that the PAYSUCCESS signature of a real order: anyone who could read the
 * log (an installer with the debug key) could make a machine brew for free.
 */
function failSign(res, check, flat) {
  log('SIGN_ERROR', check.injected ? 'injected field' : 'mismatch', `device=${flat?.deviceNo ?? '-'}`, `order=${flat?.orderNo ?? '-'}`);
  res.json({ returnCode: 'FAIL', msg: 'SIGN_ERROR' });
}

/**
 * The notify URL comes from the signed machine request, so using it requires
 * a valid Jetinno signature — but the bridge still refuses to be pointed at
 * itself or at anything inside the network it runs on. A compromised vendor
 * key must not become an SSRF proxy that POSTs signed bodies at internal
 * services and logs their replies for read-back.
 *
 * Literal addresses are checked here; names are resolved and checked again
 * just before the POST (notifyMachine), and the POST never follows a redirect.
 *
 * MOCK runs keep localhost: that is where the simulated machine lives.
 */
function privateV4(ip) {
  const [a, b] = ip.split('.').map(Number);
  return (
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0) ||
    (a === 198 && (b === 18 || b === 19))
  );
}
function privateV6(ip) {
  const x = ip.toLowerCase();
  if (x === '::' || x === '::1') return true;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(x) ?? /^64:ff9b::(\d+\.\d+\.\d+\.\d+)$/.exec(x);
  if (mapped) return privateV4(mapped[1]);
  if (/^::ffff:[0-9a-f]{1,4}:[0-9a-f]{1,4}$/.test(x)) return true; // mapped, hex-spelled
  return /^f[cd]/.test(x) || /^fe[89ab]/.test(x) || /^ff/.test(x);
}
function privateAddress(ip) {
  const v = isIP(ip);
  return v === 4 ? privateV4(ip) : v === 6 ? privateV6(ip) : false;
}

function notifyUrlAllowed(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
  // MOCK is where the simulated machine lives; ALLOW_PRIVATE_NOTIFY is the
  // integration tests driving a real (fake-QPay) flow against a local
  // machine. Neither belongs in a production environment, and both are
  // explicit enough to be found when they end up there anyway.
  if (MOCK || process.env.ALLOW_PRIVATE_NOTIFY === '1') return true;
  if (url.username || url.password) return false;
  // Brackets off an IPv6 literal, and a trailing dot off a name: `localhost.`
  // is localhost, and `[::1]` is loopback.
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  if (!host || host === 'localhost' || /\.(localhost|local|internal)$/.test(host)) return false;
  if (isIP(host)) return !privateAddress(host);
  return true;
}

/**
 * Which merchant a sale on this device belongs to.
 *
 * The business model is that each machine's revenue lands in ITS OWNER's QPay
 * account, so this is the routing decision for actual money:
 *
 *   owner client   — the machine is registered and its credential is usable.
 *   env fallback   — no database configured, or a device the database says
 *                    nobody has registered. The operator's own merchant
 *                    takes the sale.
 *   db unreachable — the last answer seen for that device (owners.js), or a
 *                    refusal. Never the env merchant: that would put an
 *                    owner's money in the operator's account.
 *   refusal        — the machine IS registered but its credential, owner or
 *                    machine row is disabled. Falling back to env here would
 *                    take a known owner's money into the operator's account,
 *                    which is worse than a failed sale: one is an apology,
 *                    the other is an accounting dispute.
 *
 * Every non-happy outcome leaves a durable ingest_errors row when the
 * database can be reached, because after the cutover these are the cases
 * that stop a sale — and a log line that rotates away is not a record.
 */
/*
 * Without a database the bridge cannot tell an owner's machine from an
 * unregistered one, and used to invoice EVERY sale on the operator's own
 * merchant — the README even prescribed removing DATABASE_URL as the
 * emergency stop. Now that refuses to sell, unless the deployment says in so
 * many words that it is the operator's only merchant (a demo, one machine).
 */
const ENV_MERCHANT_ONLY = process.env.ENV_MERCHANT_ONLY === '1';

async function merchantFor(deviceNo, orderNo) {
  if (!DUAL_WRITE) {
    if (MOCK || ENV_MERCHANT_ONLY) return { client: null, source: 'env' };
    log('sale refused: no database and ENV_MERCHANT_ONLY is not set', deviceNo);
    return { refused: 'NO_DATABASE' };
  }

  let machine;
  try {
    // Through the 60-second cache: this is the same three-table join for
    // every cup, inside Jetinno's 8-second budget, and the answer changes a
    // few times in the life of a machine. The cache is invalidated the
    // moment a credential is promoted.
    machine = await owners.resolveMachine(deviceNo);
  } catch (err) {
    // The database cannot say whose machine this is (owners.js already served
    // any answer it had seen). Every machine sold today belongs to an owner,
    // so the operator's merchant here would most likely take an owner's money:
    // one refused cup — the customer taps again — is the smaller harm.
    log('merchant resolve failed, refusing', deviceNo, err.message.split('\n')[0]);
    return { refused: 'DB_UNAVAILABLE' };
  }

  if (!machine) {
    dw('ingestError', () =>
      store.logIngestError({ path: '/jetinno/getQrCode', deviceNo, orderNo, reason: 'DEVICE_NOT_REGISTERED' })
    );
    return { client: null, source: 'env-unregistered' };
  }

  const blocked =
    machine.machine_status !== 'active'
      ? `MACHINE_${machine.machine_status}`
      : machine.owner_status !== 'active'
        ? `OWNER_${machine.owner_status}`
        : machine.credential_status !== 'active'
          ? `CREDENTIAL_${machine.credential_status}`
          : !machine.credential_active
            ? 'CREDENTIAL_INACTIVE'
            : null;
  if (blocked) {
    const reason = `SALE_REFUSED_${blocked}`.toUpperCase();
    log('sale refused', deviceNo, reason);
    dw('ingestError', () => store.logIngestError({ path: '/jetinno/getQrCode', deviceNo, orderNo, reason }));
    return { refused: reason, machine };
  }

  // MOCK mode has no QPay to talk to, so no client — but the registration and
  // status gates above still ran, which is what the tests exercise.
  if (MOCK) return { client: null, source: 'mock', machine };

  try {
    const cred = open(machine.sealed, {
      context: credentialAad({ credentialId: machine.qpay_credential_id, ownerId: machine.owner_id }),
    });
    return {
      client: qpay.clientForSealed(cred, machine.qpay_credential_id),
      source: 'owner',
      machine,
    };
  } catch (err) {
    // A registered owner whose credential cannot be unsealed: the sealing key
    // is wrong or the row was tampered with. Refuse — env fallback here would
    // misroute the owner's money.
    log('credential unseal failed', deviceNo, err.message.split('\n')[0]);
    dw('ingestError', () =>
      store.logIngestError({ path: '/jetinno/getQrCode', deviceNo, orderNo, reason: 'CREDENTIAL_UNSEAL_FAILED' })
    );
    return { refused: 'CREDENTIAL_UNSEAL_FAILED', machine };
  }
}

app.post('/jetinno/getQrCode', jetinnoBody, async (req, res) => {
  log('getQrCode <-', JSON.stringify(req.body));
  const flat = flatten(req.body);
  const check = verifySign(req.body, SIGNABLE.getQrCodeRequest, APIKEY);
  if (!check.ok) return failSign(res, check, flat);

  const { deviceNo, orderNo, orderAmount, notifyUrl, productId, productName } = flat;
  if (!deviceNo || !orderNo) return fail(res, 'PARAM_ERROR: deviceNo/orderNo');
  const key = keyOf(deviceNo, orderNo);

  // The machine retries when our 8-second budget is missed, and a retry
  // arrives with the same orderNo. Creating a second invoice is not an
  // option — QPay rejects a repeated sender_invoice_no forever — so hand
  // back the QR already made for this order.
  const existing = orders.get(key);
  if (existing) {
    // A retry can land while the first request is still inside the QPay round
    // trip. Racing it would create a second invoice with the same
    // sender_invoice_no — which QPay rejects forever — so the retry waits for
    // the first request's outcome and answers with the same QR.
    if (existing.pending) {
      try {
        await existing.pending;
      } catch {
        return fail(res, 'SYSTEM_ERROR');
      }
    }
    if (existing.status === 'cancelled') {
      // The sweep has voided this invoice at QPay. Handing its QR back would
      // put an unpayable code on the screen: the customer scans, the bank
      // refuses, and nobody in that loop can tell why. An error at least
      // makes the machine show a failure and lets them start a fresh order.
      log('getQrCode replay of cancelled order', orderNo);
      return fail(res, 'SYSTEM_ERROR');
    }
    // A replay must be the same order. A different amount or notify URL under
    // a reused orderNo is a new sale wearing an old number.
    if (String(existing.orderAmount) !== String(orderAmount) || existing.notifyUrl !== notifyUrl) {
      log('getQrCode replay with different amount or notifyUrl', orderNo);
      return fail(res, 'ORDERNO_EXIST');
    }
    if (!existing.qrCode) return fail(res, 'SYSTEM_ERROR');
    log('getQrCode replay ->', orderNo, existing.qrCode);
    return respond(res, { deviceNo, orderNo, qrCode: existing.qrCode }, SIGNABLE.getQrCodeResponse);
  }

  const amount = Math.round(Number(orderAmount) / AMOUNT_DIVISOR);
  if (!Number.isFinite(amount) || amount <= 0) return fail(res, `PARAM_ERROR: orderAmount=${orderAmount}`);
  if (!notifyUrlAllowed(notifyUrl)) return fail(res, 'PARAM_ERROR: notifyUrl');

  // Whose QPay account takes this sale. Resolved BEFORE the invoice exists,
  // because it decides which merchant the invoice is created under.
  const merchant = await merchantFor(deviceNo, orderNo);
  if (merchant.refused) return fail(res, 'SYSTEM_ERROR');

  // Registered in the Map BEFORE the QPay round trip, so a machine retry that
  // arrives mid-flight finds this entry and awaits `pending` above instead of
  // creating a duplicate invoice on the request the machine is actually
  // waiting for.
  const order = {
    deviceNo,
    orderNo,
    orderAmount,
    notifyUrl,
    productId,
    productName,
    amountMnt: amount,
    status: 'creating',
    settling: false,
    createdAt: Date.now(),
    source: merchant.machine ? 'owner' : 'env',
    machineId: merchant.machine?.machine_id ?? null,
    ownerId: merchant.machine?.owner_id ?? null,
    credentialId: merchant.machine?.qpay_credential_id ?? null,
    merchantFp: merchant.machine?.credential_fingerprint ?? null,
    pgId: null,
  };
  // A function-valued property: JSON.stringify skips it, so the debug /orders
  // dump can never serialize the credential closed over inside the client.
  if (merchant.client) order.qpay = merchant.client;

  const callbackUrl = callbackUrlFor(deviceNo, orderNo);
  order.pending = (async () => {
    const invoice = MOCK
      ? { invoiceId: `mock-${deviceNo}-${orderNo}`, shortUrl: `${PUBLIC_URL}/mock/pay/${encodeURIComponent(deviceNo)}/${encodeURIComponent(orderNo)}`, qrText: null }
      : await (order.qpay ?? qpay).createInvoice({
          orderNo,
          amount,
          description: productName || `Coffee ${productId}`,
          callbackUrl,
        });

    // qr_text is the standard QPay QR every bank app scans, but it is
    // routinely longer than Jetinno's 128-character qrCode field, so the
    // short URL is what actually fits on the machine screen.
    const qrCode = invoice.shortUrl ?? invoice.qrText;
    if (!qrCode) throw Object.assign(new Error('qpay returned no qr'), { publicMsg: 'SYSTEM_ERROR: qpay returned no qr' });
    if (qrCode.length > 128) {
      throw Object.assign(new Error(`qr too long (${qrCode.length})`), {
        publicMsg: `SYSTEM_ERROR: qr too long (${qrCode.length} > 128)`,
      });
    }

    Object.assign(order, {
      invoiceId: invoice.invoiceId,
      qrCode,
      // Kept for the Jetinno negotiation: qr_text is what bank apps scan,
      // and its real length is the number we need the 128-char field raised
      // to. Visible via GET /orders/:orderNo.
      qrTextLen: invoice.qrText ? invoice.qrText.length : null,
      status: 'awaiting_payment',
    });
    return invoice;
  })();
  orders.set(key, order);

  try {
    await order.pending;
  } catch (err) {
    // A failed creation is removed so a later fresh retry can start over —
    // holding the dead placeholder would turn every retry into SYSTEM_ERROR.
    orders.delete(key);
    log('getQrCode failed', orderNo, firstLine(err));
    noteInvoiceFailure(order, err);
    return fail(res, err.publicMsg ?? 'SYSTEM_ERROR');
  } finally {
    delete order.pending;
  }

  try {
    log('getQrCode ->', orderNo, `${amount}₮`, order.qrCode);
    respond(res, { deviceNo, orderNo, qrCode: order.qrCode }, SIGNABLE.getQrCodeResponse);
  } catch (err) {
    // Response/logging failure after the invoice already exists. The order
    // stays in the Map: the machine's retry replays the stored QR.
    log('getQrCode respond failed', orderNo, firstLine(err));
  }

  // machines.last_seen_at: the only signal that separates a machine standing
  // in a quiet lobby from one that is unplugged. Throttled in SQL.
  dw('touchSeen', () => store.touchMachineSeen(deviceNo));
  // A merchant that had been failing just took an invoice: clear the alarm.
  if (merchant.machine?.credential_auth_fail_count > 0) dw('saleOk', () => store.noteSaleOk(order.credentialId));

  // The durable copy, written once and complete (the QR is already on the
  // screen; the customer needs far longer to pay than this takes). settle()
  // waits for it before deciding anything.
  if (DUAL_WRITE) order.persisting = track(persistOrder(order, callbackUrl));
});

/**
 * Writes the order row. Retried a few times over several seconds: a database
 * blip here is the difference between a payment that survives a restart and
 * one only QPay remembers. Resolves to the row id, or null.
 */
async function persistOrder(order, callbackUrl) {
  for (const delay of [0, 2000, 6000]) {
    if (delay) await sleep(delay);
    try {
      order.pgId = await store.insertOrder({
        source: order.source,
        machineId: order.machineId,
        ownerId: order.ownerId,
        credentialId: order.credentialId,
        merchantFp: order.merchantFp,
        orderNo: order.orderNo,
        deviceNo: order.deviceNo,
        notifyUrl: order.notifyUrl,
        productId: order.productId,
        productName: order.productName,
        rawOrderAmount: String(order.orderAmount),
        amountDivisor: AMOUNT_DIVISOR,
        amountMnt: order.amountMnt,
        senderInvoiceNo: order.orderNo,
        callbackUrl,
        invoiceId: order.invoiceId,
        qrCode: order.qrCode,
        qrTextLen: order.qrTextLen,
        abandonAfterMs: ABANDON_AFTER_MS,
      });
      if (order.pgId) return order.pgId;
      // Written, but a different order already holds this (device, orderNo)
      // — a reused number. Retrying cannot change that.
      log('order row conflicts with an existing order', order.orderNo);
      return null;
    } catch (err) {
      log('order write failed', order.orderNo, firstLine(err));
    }
  }
  dwFailed += 1;
  dwLastFailure = { label: 'insertOrder', at: new Date().toISOString() };
  log('order NOT persisted — settles in memory only', order.orderNo);
  return null;
}

/*
 * An invoice QPay refused is a sale that did not happen. It left nothing but
 * a log line, so an owner whose QPay password had been changed in QPay's own
 * portal failed every sale while every console said all was well. Throttled:
 * one durable row per device and reason a minute.
 */
const invoiceFailureSeen = new Map();
function noteInvoiceFailure(order, err) {
  if (!DUAL_WRITE) return;
  const status = Number(err?.status);
  const code = qpay.qpayCode(String(err?.message ?? '').slice(String(err?.message ?? '').indexOf(': ') + 2));
  const reason = `INVOICE_FAILED${Number.isFinite(status) ? `_${status}` : ''}${code ? `_${code}` : ''}`.slice(0, 80);
  const k = `${order.deviceNo}:${reason}`;
  const now = Date.now();
  if (now - (invoiceFailureSeen.get(k) ?? 0) < 60_000) return;
  invoiceFailureSeen.set(k, now);
  dw('ingestError', () =>
    store.logIngestError({ path: '/jetinno/getQrCode', deviceNo: order.deviceNo, orderNo: order.orderNo, reason })
  );
  if ((status === 401 || status === 403) && order.credentialId) {
    dw('saleAuthFailure', () => store.noteSaleAuthFailure(order.credentialId, 'QPAY_AUTH_FAILED'));
  }
}

app.post('/jetinno/productdone', jetinnoBody, (req, res) => {
  log('productdone <-', JSON.stringify(req.body));
  const flat = flatten(req.body);
  const check = verifySign(req.body, SIGNABLE.productDoneRequest, APIKEY);
  if (!check.ok) return failSign(res, check, flat);

  const { deviceNo, orderNo, isFinish } = flat;
  const order = orders.get(keyOf(deviceNo, orderNo));
  if (order) order.finished = isFinish;
  log('productdone', orderNo, isFinish);
  res.json({ returnCode: 'SUCCESS', msg: 'SUCCESS' });

  dw('productDone', async () => {
    const id = order?.pgId ?? (await store.findOrderIdByDevice(deviceNo, orderNo));
    if (id) await store.recordProductDone(id, isFinish === 'SUCCESS');
  });
});

/*
 * The bridge cannot refund through QPay (no refund API on this merchant
 * integration), so the machine is told ERROR — as before. What changed: the
 * request is now a durable record and pages the operator, because it means a
 * paying customer did not get their coffee.
 */
app.post('/jetinno/refund', jetinnoBody, (req, res) => {
  log('refund <-', JSON.stringify(req.body));
  const flat = flatten(req.body);
  const check = verifySign(req.body, SIGNABLE.refundRequest, APIKEY);
  if (!check.ok) return failSign(res, check, flat);
  const { deviceNo, orderNo, refundAmount } = flat;
  respond(res, { deviceNo, orderNo, refundState: 'ERROR' }, ['returnCode', 'msg', 'time', 'deviceNo', 'orderNo', 'refundState']);
  dw('ingestError', () => store.logIngestError({ path: '/jetinno/refund', deviceNo, orderNo, reason: 'REFUND_REQUESTED' }));
  alerts.pageOperator('machine asked to refund a paid order', { deviceNo, orderNo, amount: refundAmount });
});

/**
 * Tells the machine to brew. Throws on failure; `err.refused` marks a clear
 * "no" (an answer that says it did not take the order), as opposed to a lost
 * answer, after which a cup may already be on its way.
 */
async function notifyMachine(order) {
  const body = {
    username: USERNAME,
    time: timestamp(),
    data: {
      deviceNo: order.deviceNo,
      orderNo: order.orderNo,
      orderAmount: order.orderAmount,
      payType: '1001',
      payStatus: 'PAYSUCCESS',
    },
  };
  body.sign = buildSign(flatten(body), SIGNABLE.paymentCallback, APIKEY);

  // A name is resolved and checked at the last moment: notifyUrlAllowed only
  // sees literal addresses, and a public name can point anywhere.
  const hostAllowed = async (raw) => {
    if (MOCK || process.env.ALLOW_PRIVATE_NOTIFY === '1') return true;
    if (!notifyUrlAllowed(raw)) return false;
    const host = new URL(raw).hostname.replace(/^\[|\]$/g, '').replace(/\.+$/, '');
    if (isIP(host)) return true;
    const addrs = await lookup(host, { all: true }).catch(() => []);
    return addrs.length > 0 && !addrs.some((a) => privateAddress(a.address));
  };

  log('notify ->', order.notifyUrl, JSON.stringify(body));
  // Redirects are followed by hand, at most three, each target checked like
  // the first — fetch's own following is how a public notify URL reaches an
  // internal one after every check has passed. 307/308 keep the POST; the
  // others turn into a GET, exactly as fetch would have done.
  const signal = AbortSignal.timeout(NOTIFY_TIMEOUT_MS);
  let url = order.notifyUrl;
  let method = 'POST';
  let reply;
  for (let hop = 0; ; hop += 1) {
    if (!(await hostAllowed(url))) {
      throw Object.assign(new Error(`notify host refused: ${new URL(url).host}`), { refused: true });
    }
    try {
      reply = await fetch(url, {
        method,
        headers: method === 'POST' ? { 'Content-Type': 'application/json' } : {},
        body: method === 'POST' ? JSON.stringify(body) : undefined,
        redirect: 'manual',
        signal,
      });
    } catch (err) {
      // Timed out or the connection dropped: the machine may have it.
      throw new Error(`notify failed: ${firstLine(err)}`);
    }
    const location = reply.headers.get('location');
    if (reply.status < 300 || reply.status >= 400 || !location) break;
    await reply.arrayBuffer().catch(() => {}); // free the connection
    if (hop >= 3) throw Object.assign(new Error('notify: too many redirects'), { refused: true });
    url = new URL(location, url).toString();
    if (reply.status !== 307 && reply.status !== 308) method = 'GET';
    log('notify redirected', reply.status, new URL(url).host);
  }
  const text = await reply.text().catch(() => '');
  log('notify <-', reply.status, text.slice(0, 300));
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    // Not JSON: judged on the text, as before.
  }
  // A JSON answer is judged by its returnCode, not by containing the word —
  // {"returnCode":"FAIL","msg":"…SUCCESS…"} was a success here.
  const accepted =
    reply.ok &&
    (json && typeof json === 'object' && 'returnCode' in json ? json.returnCode === 'SUCCESS' : text.includes('SUCCESS'));
  if (!accepted) {
    // A 5xx may be a relay that did its job and then failed: not a clear no.
    throw Object.assign(new Error(`machine rejected notify: ${reply.status} ${text.slice(0, 120)}`), {
      refused: reply.status < 500,
    });
  }
  return text;
}

/**
 * Rebuilds a Map entry from the order's Postgres row.
 *
 * Reached only when the Map has no entry — after a restart, which on Render
 * is every deploy. The row carries the notify URL, device, amounts and the
 * QPay invoice id: everything settle() needs. Its status is kept as it is: the
 * database's claim, not this object, decides whether it may be settled now.
 */
async function rehydrateOrder(deviceNo, orderNo) {
  try {
    const row = deviceNo ? await store.findLiveOrderByDevice(deviceNo, orderNo) : await store.findLiveOrder(orderNo);
    if (!row) return null;
    const key = keyOf(row.device_no, row.order_no);
    const existing = orders.get(key);
    if (existing) return existing;
    const order = orderFromRow(row);
    const merchant = await clientForRow(row);
    if (merchant.error) {
      // The credential that issued this invoice is gone or now names another
      // merchant: its login cannot check or cancel this invoice. A person has
      // to — with the order on their list, not in a loop of QPay retries.
      log('rehydrate: cannot settle', orderNo, merchant.error);
      dw('giveUp', () => store.giveUp(row.id, merchant.error));
      alerts.pageOperator('paid order cannot be checked: its merchant changed', { deviceNo: row.device_no, orderNo: row.order_no });
      order.status = 'needs_human';
    } else if (merchant.client) {
      order.qpay = merchant.client;
    }
    // Another path may have rebuilt it while this one awaited the database.
    // One order object per order is what makes the `settling` flag work.
    const again = orders.get(key);
    if (again) return again;
    orders.set(key, order);
    log('order rehydrated from db', orderNo, `was ${row.status}`);
    return order;
  } catch (err) {
    log('rehydrate failed', orderNo, firstLine(err));
    return null;
  }
}

function orderFromRow(row) {
  return {
    deviceNo: row.device_no,
    orderNo: row.order_no,
    orderAmount: row.raw_order_amount,
    notifyUrl: row.notify_url,
    productId: row.product_id,
    productName: row.product_name,
    amountMnt: row.amount_mnt,
    invoiceId: row.qpay_invoice_id,
    qrCode: row.qr_code,
    qrTextLen: row.qr_text_len,
    status: row.status === 'settling' ? 'awaiting_payment' : row.status,
    settling: false,
    createdAt: new Date(row.created_at).getTime(),
    source: row.source ?? 'owner',
    machineId: row.machine_id,
    ownerId: row.owner_id,
    credentialId: row.qpay_credential_id,
    merchantFp: row.merchant_fp,
    pgId: row.id,
    rehydrated: true,
  };
}

/**
 * The client that can check or cancel this row's invoice: the operator's own
 * merchant for an env order, otherwise the credential snapshotted on the row
 * — rebuilt even if since deactivated (settling an existing sale is not a new
 * sale), but only while it still names the merchant that issued the invoice.
 */
async function clientForRow(row) {
  if (MOCK) return { client: null };
  if (row.source === 'env' || !row.qpay_credential_id) return { client: null };
  const cred = await store.getCredentialById(row.qpay_credential_id);
  if (!cred?.sealed) return { error: 'CREDENTIAL_MISSING' };
  if (row.merchant_fp && cred.fingerprint && cred.fingerprint !== row.merchant_fp) return { error: 'MERCHANT_CHANGED' };
  try {
    const plain = open(cred.sealed, {
      context: credentialAad({ credentialId: row.qpay_credential_id, ownerId: cred.owner_id }),
    });
    return { client: qpay.clientForSealed(plain, row.qpay_credential_id) };
  } catch (err) {
    log('credential unseal failed for order', row.order_no, firstLine(err));
    return { error: 'CREDENTIAL_UNSEAL_FAILED' };
  }
}

/*
 * QPay fires its callback more than once, and after a restart every one of
 * them misses the Map at the same moment. Concurrent misses share one rebuild.
 */
const rehydrating = new Map();
function rehydrateOnce(deviceNo, orderNo) {
  const k = `${deviceNo ?? ''}\u0000${orderNo}`;
  let pending = rehydrating.get(k);
  if (!pending) {
    pending = rehydrateOrder(deviceNo, orderNo).finally(() => rehydrating.delete(k));
    rehydrating.set(k, pending);
  }
  return pending;
}

/** The Map entry for an orderNo alone — the legacy callback URL carries no device. */
function findByOrderNo(orderNo) {
  let found = null;
  for (const o of orders.values()) {
    if (o.orderNo === orderNo && (!found || o.createdAt > found.createdAt)) found = o;
  }
  return found;
}

/**
 * Confirms payment with QPay and tells the machine to brew. Safe to call from
 * anywhere, as often as you like — the QPay webhook, the sweep and the debug
 * /check do arrive at the same instant.
 *
 * WITH A DATABASE (every real deployment) the database decides, before
 * anything is sent:
 *
 *   claim           only one caller across every process gets the row; a row
 *                   told to brew within the grace window, or whose cup came
 *                   out, is refused — a lost ACK must not brew twice
 *   check           QPay says paid, for at least the invoiced amount
 *   confirm         the payment is durable BEFORE the machine hears of it
 *   notify_sent     stamped BEFORE the POST
 *   notify          the machine brews
 *   finish          paid
 *
 * A failure after confirm leaves the order on the database's list, and the
 * sweep's drain tells the machine again (or, attempts exhausted, a human is
 * paged). Before this, a timed-out notify was answered SUCCESS to QPay and
 * the only retry lived in this process's memory — gone at the next deploy.
 *
 * WITHOUT one (local demos), or for an order the database never got, the
 * in-memory `settling` flag gates as it always did.
 *
 * `claimed` is a row the caller already claimed (the abandoned-QR sweep).
 * Returns { ok, reason, durable } — durable when the payment is on record.
 */
async function settle(order, { claimed = null } = {}) {
  if (!order) return { ok: false, reason: 'unknown order' };
  if (order.pending || order.status === 'creating') return { ok: false, reason: 'not paid yet' };
  if (order.status === 'paid') return { ok: true, already: true };
  if (order.status === 'needs_human') return { ok: false, reason: 'needs human', durable: true };
  if (order.settling) return { ok: false, reason: 'settle already in progress' };

  // `settling` is claimed synchronously, before the first await. Without it
  // two callers in this process both pass the checks above.
  order.settling = true;
  try {
    if (!order.pgId && order.persisting) await order.persisting.catch(() => null);

    let row = claimed;
    let durable = false;
    if (!row && order.pgId) {
      try {
        row = await store.claimSettle(order.pgId, { leaseSeconds: 90, instance: INSTANCE, notifyGraceSeconds: NOTIFY_GRACE_S });
      } catch (err) {
        // The database cannot be asked. The customer has paid and is
        // waiting; this process's own gate still holds, so it goes ahead in
        // memory and the record is written once the database is back.
        log('settle claim failed, settling in memory', order.orderNo, firstLine(err));
        row = undefined;
      }
      if (row === null) {
        // Refused: another process holds it, it was told to brew moments ago,
        // its cup came out, or its attempts ran out.
        const state = await store.orderState(order.pgId).catch(() => null);
        if (state?.status === 'paid') {
          order.status = 'paid';
          return { ok: true, already: true };
        }
        return { ok: false, reason: 'settle already in progress', durable: Boolean(state?.payment_confirmed_at) };
      }
    }
    const gated = Boolean(row);

    let paymentRef = null;
    let paidAmount = order.amountMnt;
    if (!MOCK) {
      let paid;
      let amount;
      try {
        // The credential that ISSUED the invoice answers for it — owner orders
        // check under the owner's merchant, env orders under the operator's.
        ({ paid, paymentId: paymentRef, amount } = await (order.qpay ?? qpay).checkPayment(order.invoiceId));
      } catch (err) {
        if (gated) await store.releaseSettle(order.pgId, `check: ${firstLine(err)}`.slice(0, 200)).catch(() => {});
        throw err;
      }
      if (!paid) {
        // Benign: not an attempt. Without that, anyone who can reach the
        // callback could burn an order's attempts and force it to a human.
        if (gated) await store.releaseSettle(order.pgId, null, false).catch(() => {});
        return { ok: false, reason: 'not paid yet' };
      }
      // QPay invoices are fixed-amount, so this should never fire — which is
      // exactly why a payment below the invoice must not brew quietly. An
      // amount that is not a number is not "enough".
      if (!(Number.isFinite(amount) && amount >= order.amountMnt)) {
        log('underpaid, not brewing', order.orderNo, `${amount} < ${order.amountMnt}`);
        if (gated) await store.releaseSettle(order.pgId, 'UNDERPAID').catch(() => {});
        dw('ingestError', () =>
          store.logIngestError({ path: '/qpay/callback', deviceNo: order.deviceNo, orderNo: order.orderNo, reason: 'UNDERPAID' })
        );
        alerts.pageOperator('payment below the invoice amount', { deviceNo: order.deviceNo, orderNo: order.orderNo });
        return { ok: false, reason: 'underpaid', durable: gated };
      }
      paidAmount = amount;
    }
    order.paymentRef = paymentRef;
    order.paidAmount = paidAmount;

    // A concurrent path may have finished the sale while QPay was asked.
    if (order.status === 'paid') {
      if (gated) await store.releaseSettle(order.pgId, null, false).catch(() => {});
      return { ok: true, already: true };
    }

    if (gated) {
      // The database confirms only the invoiced amount. A payment above it
      // (QPay invoices are fixed, so this should never happen) still brews,
      // as it always did, and is noted rather than refused.
      if (paidAmount > order.amountMnt) log('paid more than invoiced', order.orderNo, `${paidAmount} > ${order.amountMnt}`);
      const confirmed = await store.markPaymentConfirmed(order.pgId, {
        paymentId: paymentRef,
        paidAmountMnt: Math.min(paidAmount, order.amountMnt),
      });
      if (!confirmed) {
        await store.releaseSettle(order.pgId, 'confirm declined (amount/state mismatch)').catch(() => {});
        alerts.pageOperator('paid order refused by the database', { deviceNo: order.deviceNo, orderNo: order.orderNo });
        return { ok: false, reason: 'confirm declined', durable: false };
      }
      durable = true;
      // The money is on record: tell the owner's phone. pushSale claims the
      // order in SQL, so a second settle path cannot send it twice.
      pushSale(order.pgId, log);
      if (!(await store.markNotifySent(order.pgId))) {
        await store.releaseSettle(order.pgId, 'notify-sent declined').catch(() => {});
        return { ok: false, reason: 'settle already in progress', durable };
      }
    }

    let machineReply;
    try {
      machineReply = await notifyMachine(order);
    } catch (err) {
      log('notify failed', order.orderNo, firstLine(err));
      if (gated) {
        const why = `notify: ${firstLine(err)}`.slice(0, 200);
        await (err.refused ? store.releaseSettleUndelivered(order.pgId, why) : store.releaseSettle(order.pgId, why)).catch(() => {});
        return { ok: false, reason: 'notify failed', durable };
      }
      throw err;
    }
    order.status = 'paid';
    order.paidAt = new Date().toISOString();

    if (gated) {
      dw('finishSettle', async () => {
        for (const delay of [0, 2000, 6000]) {
          if (delay) await sleep(delay);
          if (await store.finishSettle(order.pgId).catch(() => null)) return;
        }
        throw new Error('finish not recorded');
      });
    } else {
      mirrorAfterTheFact(order);
    }
    return { ok: true, machineReply, durable: gated };
  } finally {
    order.settling = false;
  }
}

/**
 * The record of a sale settled in memory (the database could not be asked),
 * written as soon as it can be — the same steps the gated path takes, in
 * order, each one checked.
 */
function mirrorAfterTheFact(order) {
  dw('settle mirror', async () => {
    let id = order.pgId;
    if (!id && order.persisting) id = await order.persisting.catch(() => null);
    if (!id) id = await store.findOrderIdByDevice(order.deviceNo, order.orderNo, order.invoiceId);
    if (!id) return log('settle mirror: no row', order.orderNo);
    order.pgId = id;
    const claimed = await store.claimSettle(id, { leaseSeconds: 60, instance: INSTANCE, notifyGraceSeconds: 0 });
    if (!claimed) return log('settle mirror declined', order.orderNo, 'claim');
    try {
      const confirmed = await store.markPaymentConfirmed(id, {
        paymentId: order.paymentRef ?? null,
        paidAmountMnt: order.paidAmount == null ? null : Math.min(order.paidAmount, order.amountMnt),
      });
      if (!confirmed) return await store.releaseSettle(id, 'confirm declined (amount/state mismatch)');
      pushSale(id, log);
      if (!(await store.markNotifySent(id))) return await store.releaseSettle(id, 'notify-sent declined');
      if (!(await store.finishSettle(id))) return await store.releaseSettle(id, 'finish declined');
    } catch (err) {
      await store.releaseSettle(id, firstLine(err)).catch(() => {});
      throw err;
    }
  });
}

/** Finds (or rebuilds) the order for a route, then settles it. */
async function settleByKey(deviceNo, orderNo) {
  let order = deviceNo ? orders.get(keyOf(deviceNo, orderNo)) : findByOrderNo(orderNo);
  // The Map is empty after every restart — and Render restarts the process on
  // every deploy. A paid order must survive that, so a miss falls back to the
  // Postgres row, which carries everything a settle needs.
  if (!order && DUAL_WRITE) order = await rehydrateOnce(deviceNo, orderNo);
  return settle(order);
}

function settleRoute(req, res) {
  const { deviceNo, orderNo } = req.params;
  track(
    settleByKey(deviceNo ?? null, orderNo)
      .then((result) => res.status(result.ok ? 200 : result.reason === 'unknown order' ? 404 : 202).json(result))
      .catch((err) => {
        // The detail stays in the log. err.message here can carry a QPay
        // response body, and this endpoint answers whoever asked.
        log('settle failed', orderNo, firstLine(err));
        res.status(500).json({ error: 'SYSTEM_ERROR' });
      })
  );
}

/**
 * QPay's webhook. It fires more than once for one payment, and a forged hit
 * is harmless: settle() re-checks against QPay using the invoice id on our
 * own record, never anything from this request.
 *
 * QPay wants exactly HTTP 200 with the body "SUCCESS"; anything else makes it
 * call again. That is used deliberately on the signed URL: when the payment
 * is not yet on record (QPay or the database could not be asked), 503 brings
 * QPay back. Once it is on record, SUCCESS — the drain finishes the job.
 */
function answerCallback(res, result, { signed }) {
  if (result.ok) return res.status(200).send('SUCCESS');
  // An order this process has genuinely lost (restart, row not found): the
  // retry IS the recovery path.
  if (result.reason === 'unknown order') return res.status(503).send('RETRY');
  if (signed && result.reason === 'not paid yet') return res.status(503).send('RETRY');
  if (signed && result.reason === 'notify failed' && !result.durable) return res.status(503).send('RETRY');
  // Somebody else is mid-settle and the payment is not on record yet: if that
  // attempt fails before recording it, this retry is what brings it back.
  if (signed && result.reason === 'settle already in progress' && !result.durable) return res.status(503).send('RETRY');
  return res.status(200).send('SUCCESS');
}

const callbackLimit = rateLimiter({ perMinute: 30 });

app.all('/qpay/cb/:deviceNo/:orderNo/:mac', (req, res) => {
  const { deviceNo, orderNo, mac } = req.params;
  if (macValid(deviceNo, orderNo, mac)) {
    return track(
      settleByKey(deviceNo, orderNo)
        .then((result) => {
          log('qpay callback', orderNo, JSON.stringify(result));
          answerCallback(res, result, { signed: true });
        })
        .catch((err) => {
          log('qpay callback failed', orderNo, firstLine(err));
          // Not on record yet (QPay or the database could not be asked).
          res.status(503).send('RETRY');
        })
    );
  }
  // A URL we did not sign. Nothing is looked up for it; QPay is told
  // SUCCESS so it does not come back, and a stranger learns nothing.
  callbackLimit(req, res, () => {
    log('qpay callback with a bad signature', orderNo);
    res.status(200).send('SUCCESS');
  });
});

/*
 * The URL invoices created before 018's deploy carry. Kept for them — QPay
 * may still call — but rate-limited per IP, since it is unsigned.
 */
app.all('/qpay/callback/:orderNo', callbackLimit, (req, res) => {
  const { orderNo } = req.params;
  track(
    settleByKey(null, orderNo)
      .then((result) => {
        log('qpay callback (legacy)', orderNo, JSON.stringify(result));
        answerCallback(res, result, { signed: false });
      })
      .catch((err) => {
        log('qpay callback failed', orderNo, firstLine(err));
        // A transient settle failure still answers SUCCESS here: an unsigned
        // URL must not tell a stranger which orders exist.
        res.status(200).send('SUCCESS');
      })
  );
});

// The same settle by hand — the operator's manual recovery path. Always
// behind the debug key: open, it confirmed live orderNos to anyone and let
// strangers spend our QPay API quota. The ?key= cookie exchange keeps it
// usable from a phone on site. No key configured, no endpoint.
app.get('/check/:deviceNo/:orderNo', (req, res) => {
  if (exchangeKeyForCookie(req, res)) return;
  if (!debugAllowed(req)) return res.status(404).end();
  settleRoute(req, res);
});
app.get('/check/:orderNo', (req, res) => {
  if (exchangeKeyForCookie(req, res)) return;
  if (!debugAllowed(req)) return res.status(404).end();
  settleRoute(req, res);
});

// Only exists in mock mode. Registered unconditionally it was harmless today
// (settle still verifies against QPay), but it is one stray QPAY_MOCK=1 away
// from being a public free-coffee endpoint — so it should not exist at all in
// a real deployment.
if (MOCK) {
  app.all('/mock/pay/:deviceNo/:orderNo', settleRoute);
  app.all('/mock/pay/:orderNo', settleRoute);
}

/*
 * The owner portal's API. Mounted only when both halves of what it needs are
 * present: a Supabase project to verify tokens against, and a database to
 * read. Missing either, the routes do not exist at all — a 404 is the honest
 * answer, and it is a great deal safer than a router that authenticates
 * nobody because one environment variable was forgotten on a new deploy.
 *
 * Its absence cannot affect a coffee: nothing on the machine path touches it.
 */
if (authConfigured() && DUAL_WRITE) {
  app.use('/owner/v1', ownerApi({ log, portalOrigin: process.env.PORTAL_ORIGIN ?? '' }));
  log('owner api mounted', process.env.PORTAL_ORIGIN ? `origin=${process.env.PORTAL_ORIGIN}` : 'origin=(unset)');

  // The operator console. Same conditions as the owner API — it reads the
  // same database through the same verified token — but every response
  // crosses every tenant boundary, so the router checks operator membership
  // before any handler runs AND every SQL function it calls checks again.
  app.use('/admin/v1', adminApi({ log, portalOrigin: process.env.PORTAL_ORIGIN ?? '' }));
  log('admin api mounted');
} else {
  log('owner api NOT mounted', `supabase=${authConfigured()} db=${DUAL_WRITE}`);
  log('admin api NOT mounted', `supabase=${authConfigured()} db=${DUAL_WRITE}`);
}

/*
 * Supabase's Send SMS hook. Needs a signing secret, a configured gateway and a
 * database to check the invite list against — anything missing and it does not
 * exist, because the failure mode of a half-configured SMS endpoint is a phone
 * bill.
 */
if (authHookConfigured() && DUAL_WRITE) {
  app.use('/hooks', authHook({ log }));
  log('send-sms hook mounted');
} else {
  log('send-sms hook NOT mounted', `secret+gateway=${authHookConfigured()} db=${DUAL_WRITE}`);
}

/*
 * The portal's login guard: per-IP and per-phone attempt windows, in
 * Postgres. Needs the shared secret the portal presents; absent, the portal
 * skips the check and logs in exactly as before.
 */
if (guardConfigured() && DUAL_WRITE) {
  app.use('/guard/v1', guardApi({ log }));
  log('auth guard mounted');
} else {
  log('auth guard NOT mounted', `secret=${guardConfigured()} db=${DUAL_WRITE}`);
}

/*
 * Owner self-service credentials — the only network path that ever sees a
 * plaintext QPay merchant password.
 *
 * Mounted last among the owner routes and behind its own conditions, because
 * it needs more than they do: a Supabase project to verify tokens against, a
 * database, and a PORTAL_ORIGIN to accept a browser POST from. It also reads
 * those at module load and throws without them, so the import itself is
 * deferred rather than risk taking the machine path down with it.
 *
 * Loaded dynamically for that reason alone: a top-level import of a module
 * that throws on a missing env var would stop this process from booting, and
 * this process is what sells coffee.
 */
if (authConfigured() && DUAL_WRITE && process.env.PORTAL_ORIGIN) {
  try {
    const { default: credentialsRouter, operatorRouter, mountVerifyCallback, sweepAbandonedVerifications } =
      await import('./credentials.js');
    app.use('/owner/v1', credentialsRouter);
    // After adminApi: its operator gate passes a verified operator through,
    // and this router — the one console route that sees a QPay password —
    // checks again on its own.
    app.use('/admin/v1', operatorRouter);
    mountVerifyCallback(app);
    // Verification invoices are 10₮ and live on the owner's own merchant. An
    // abandoned one is a trivial loss; an untracked one is not.
    setInterval(
      () => sweepAbandonedVerifications().catch((e) => log('verify sweep error', e.message.split('\n')[0])),
      5 * 60_000
    ).unref();
    log('credentials api mounted');
  } catch (err) {
    log('credentials api FAILED to mount', err.message.split('\n')[0]);
  }
} else {
  log(
    'credentials api NOT mounted',
    `supabase=${authConfigured()} db=${DUAL_WRITE} portalOrigin=${Boolean(process.env.PORTAL_ORIGIN)}`
  );
}

// Debug endpoints are gated behind DEBUG_KEY: the log ring includes expected
// signatures on SIGN_ERROR, and handing those out publicly would let anyone
// forge a valid request in one round trip. No key configured — no endpoint.
const DEBUG_KEY = process.env.DEBUG_KEY ?? '';

/**
 * The debug key is accepted in a header, or once in the query string.
 *
 * A header alone would be correct and would also destroy the reason these
 * endpoints exist: an installer standing at a machine opens them in a phone
 * browser, where headers cannot be set. So a `?key=` is exchanged for an
 * httpOnly cookie and the caller is redirected to the clean URL — the key
 * appears in one access-log line instead of every request, and never in the
 * address bar after the first hop.
 */
const COOKIE_RE = /(?:^|;\s*)dbg=([^;]+)/;

// Constant-time compare. `===` on secrets leaks match-length through timing;
// nobody has demonstrated extracting a key this way over the public internet,
// but the correct comparison costs one import and zero readability.
function keyMatches(candidate) {
  if (typeof candidate !== 'string' || !DEBUG_KEY) return false;
  const a = Buffer.from(candidate);
  const b = Buffer.from(DEBUG_KEY);
  return a.length === b.length && cryptoTimingSafeEqual(a, b);
}

function debugAllowed(req) {
  if (!DEBUG_KEY) return false;
  if (keyMatches(req.get('x-debug-key'))) return true;
  const cookie = COOKIE_RE.exec(req.headers.cookie ?? '');
  return cookie ? keyMatches(decodeURIComponent(cookie[1])) : false;
}

/** Returns true when it has handled the request itself. */
function exchangeKeyForCookie(req, res) {
  if (!DEBUG_KEY || !keyMatches(req.query.key)) return false;
  // Secure when the proxy says the hop was TLS (Render always is); omitted on
  // plain-HTTP local runs so the cookie still works there.
  const secure = req.get('x-forwarded-proto') === 'https' ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `dbg=${encodeURIComponent(DEBUG_KEY)}; HttpOnly; Path=/; Max-Age=3600; SameSite=Strict${secure}`
  );
  res.redirect(302, req.path);
  return true;
}

// Server log, phone-readable on site. First visit: /recent?key=<DEBUG_KEY>
app.get('/recent', (req, res) => {
  if (exchangeKeyForCookie(req, res)) return;
  if (!debugAllowed(req)) return res.status(404).end();
  res.type('text/plain').send(recent.join('\n') || '(лог хоосон)');
});

app.get('/orders', (req, res) => {
  if (exchangeKeyForCookie(req, res)) return;
  if (!debugAllowed(req)) return res.status(404).end();
  res.json([...orders.values()].map((o) => ({ ...o, persisting: undefined })));
});

/**
 * Read-only view of an order — gated like the others. It was open, which meant
 * anyone who guessed an orderNo could read that machine's notifyUrl and QPay
 * invoice id. Neither is a credential, but neither is anyone else's business,
 * and orderNo is a timestamp with a short prefix.
 */
app.get('/orders/:orderNo', (req, res) => {
  if (exchangeKeyForCookie(req, res)) return;
  if (!debugAllowed(req)) return res.status(404).end();
  const order = findByOrderNo(req.params.orderNo);
  if (!order) return res.status(404).json({ error: 'unknown order' });
  res.json({ ...order, persisting: undefined });
});

/**
 * Cheap on purpose: uptime monitors poll it, so it never touches the
 * database. dwFailed is the one number that says the durable mirror is
 * falling behind — a monitor alerting on it catches a broken DATABASE_URL
 * hours before the phase-3 cutover would have.
 */
/*
 * Publicly, only whether it is up. The counters used to be public too — and
 * polled once a minute they were the fleet's live sales volume, plus the
 * moment the database mirror started failing. Behind the debug key (header
 * or cookie) the full picture comes back as before.
 */
app.get('/health', (req, res) => {
  const pub = { ok: true, push: pushConfigured(), db: DUAL_WRITE };
  if (!debugAllowed(req)) return res.json(pub);
  res.json({
    ...pub,
    mock: MOCK,
    qpayConfigured: qpay.qpayConfigured(),
    dbConfigured: DUAL_WRITE,
    dwFailed,
    dwLastFailure,
    // A hit rate near zero says the TTL is shorter than the gap between
    // sales, i.e. the cache is costing a lookup and buying nothing.
    ownerCache: DUAL_WRITE ? owners.cacheStats() : null,
    keyring: keyringStatus,
    publicUrl: PUBLIC_URL,
    orders: orders.size,
    inflight: inflight.size,
  });
});

/**
 * The durable error sinks, readable from a phone on site.
 *
 * Everything here already existed and was invisible: ingest_errors had no
 * reader but psql, orders.last_error rotated out of nobody's view, sms_sends
 * failures sat in a table. An error sink nobody can see is a log line that
 * costs money to write.
 */
app.get('/errors', async (req, res) => {
  if (exchangeKeyForCookie(req, res)) return;
  if (!debugAllowed(req)) return res.status(404).end();
  if (!DUAL_WRITE) return res.json({ dbConfigured: false, dwFailed, dwLastFailure });
  try {
    const [ingest, orderErrors, needsHuman, smsFailures] = await Promise.all([
      db.query(
        `select at, path, device_no, order_no, reason from public.ingest_errors
          order by at desc limit 50`
      ),
      db.query(
        `select created_at, order_no, device_no, status, amount_mnt, last_error, last_error_at, settle_attempts
           from public.orders where last_error is not null
          order by last_error_at desc limit 50`
      ),
      db.query(
        `select created_at, order_no, device_no, amount_mnt, payment_confirmed_at, last_error
           from public.orders where status = 'needs_human'
          order by created_at desc limit 50`
      ),
      db.query(
        `select at, phone, gateway_status, error from public.sms_sends
          where not ok order by at desc limit 20`
      ),
    ]);
    res.json({
      dwFailed,
      dwLastFailure,
      needsHuman: needsHuman.rows,
      ingestErrors: ingest.rows,
      orderErrors: orderErrors.rows,
      smsFailures: smsFailures.rows,
    });
  } catch (err) {
    log('errors endpoint failed', err.message.split('\n')[0]);
    res.status(500).json({ error: 'SYSTEM_ERROR' });
  }
});

/**
 * The sweep, once a minute.
 *
 * With a database it is driven by the database, so it survives the restart
 * that empties the Map:
 *
 *   unnotified   money confirmed, machine not told — or told and never
 *                answered past the grace window, or clearly refused: tell it
 *                again
 *   abandoned    QRs past their life: void them at QPay; if QPay answers
 *                INVOICE_PAID the customer did pay after all, so settle
 *   exhausted    attempts ran out: needs_human, and the operator is paged
 *
 * The Map is still swept for what it alone holds: an order whose row could
 * not be written, every order when there is no database, and the eviction of
 * finished entries.
 */
// Finished orders are kept a day for replay/productdone matching, then
// evicted. Without this the Map grows by every sale ever made and the fix
// arrives as an OOM restart at month three.
const RETAIN_FINISHED_MS = envInt('RETAIN_FINISHED_MS', 24 * 60 * 60 * 1000, { min: 60_000 });

async function sweepMap() {
  const now = Date.now();
  for (const [key, order] of orders) {
    if (
      (order.status === 'paid' || order.status === 'cancelled' || order.status === 'needs_human') &&
      now - order.createdAt > RETAIN_FINISHED_MS
    ) {
      orders.delete(key);
      continue;
    }
    // Persisted orders belong to the database sweep below.
    if (DUAL_WRITE && order.pgId) continue;
    if (order.persisting && !order.pgId && DUAL_WRITE) continue; // still being written
    if (order.status !== 'awaiting_payment' || order.settling || order.pending) continue;
    if (now - order.createdAt < ABANDON_AFTER_MS) continue;

    order.status = 'cancelled';
    if (MOCK) {
      log('sweep cancelled', order.orderNo);
      continue;
    }
    try {
      const result = await (order.qpay ?? qpay).cancelInvoice(order.invoiceId);
      // Anything after an await must re-check the status it wrote before the
      // await: a QPay webhook can run settle() to completion while
      // cancelInvoice is in flight. Writing 'awaiting_payment' over that
      // settle's 'paid' re-arms settle for the same order — and the machine
      // brews a second cup for one payment.
      if (result.paid) {
        if (order.status === 'cancelled' && tooOldToBrew(new Date(order.createdAt + ABANDON_AFTER_MS))) {
          order.status = 'needs_human';
          alerts.pageOperator('an old QR was paid long after it was shown — check and refund', { deviceNo: order.deviceNo, orderNo: order.orderNo });
        } else if (order.status === 'cancelled') {
          order.status = 'awaiting_payment';
          log('sweep found payment, settling', order.orderNo);
          await settle(order);
        } else {
          log('sweep: settled concurrently, leaving as', order.status, order.orderNo);
        }
      } else if (order.status === 'cancelled') {
        log('sweep cancelled', order.orderNo);
      }
    } catch (err) {
      if (order.status === 'cancelled') order.status = 'awaiting_payment';
      order.sweepFailures = (order.sweepFailures ?? 0) + 1;
      log('sweep failed', order.orderNo, firstLine(err));
      // Bounded: an order the database never got must not loop forever.
      if (order.sweepFailures >= 10) {
        order.status = 'needs_human';
        alerts.pageOperator('unrecorded order could not be voided or settled', { deviceNo: order.deviceNo, orderNo: order.orderNo });
      }
    }
  }
}

/** The Map entry for a claimed row, created from the row if this process has none. */
function orderForRow(row) {
  const key = keyOf(row.device_no, row.order_no);
  let order = orders.get(key);
  if (!order) {
    order = orderFromRow(row);
    orders.set(key, order);
  }
  if (!order.pgId) order.pgId = row.id;
  return order;
}

async function drainUnnotified() {
  const rows = await store.claimUnnotified({ limit: 20, leaseSeconds: 90, instance: INSTANCE, notifyGraceSeconds: NOTIFY_GRACE_S });
  let stale = 0;
  for (const row of rows) {
    const order = orderForRow(row);
    try {
      if (order.status !== 'paid' && tooOldToBrew(row.payment_confirmed_at)) {
        await store.giveUp(row.id, 'STALE_PAYMENT: confirmed too long ago to brew');
        order.status = 'needs_human';
        stale += 1;
        continue;
      }
      if (order.status === 'paid') {
        // The notify went through here; only the finish was lost.
        if (!(await store.finishSettle(row.id))) await store.releaseSettle(row.id, 'finish declined');
        continue;
      }
      if (!row.payment_confirmed_at) {
        // claim_unnotified_orders only returns confirmed rows; a row here
        // without it is somebody else's problem, not a cup to brew.
        await store.releaseSettle(row.id, null, false);
        continue;
      }
      if (!(await store.markNotifySent(row.id))) {
        await store.releaseSettle(row.id, 'notify-sent declined');
        continue;
      }
      try {
        await notifyMachine(order);
      } catch (err) {
        const why = `notify (retry): ${firstLine(err)}`.slice(0, 200);
        log('notify retry failed', row.order_no, firstLine(err));
        await (err.refused ? store.releaseSettleUndelivered(row.id, why) : store.releaseSettle(row.id, why));
        continue;
      }
      order.status = 'paid';
      order.paidAt = new Date().toISOString();
      if (!(await store.finishSettle(row.id))) await store.releaseSettle(row.id, 'finish declined');
      log('sweep: told the machine again, settled', row.order_no);
    } catch (err) {
      log('drain failed', row.order_no, firstLine(err));
      await store.releaseSettle(row.id, firstLine(err).slice(0, 200)).catch(() => {});
    }
  }
  if (stale) {
    log('sweep: stale paid orders handed to a human', stale);
    alerts.pageOperator(`${stale} paid order(s) too old to brew — check and refund if needed`, {});
  }
}

async function drainAbandoned() {
  const rows = await store.claimAbandoned({ limit: 50, leaseSeconds: 90, instance: INSTANCE });
  for (const row of rows) {
    const order = orderForRow(row);
    try {
      // Not this path's to handle: a payment already on record belongs to the
      // unnotified drain, which respects the grace window after a notify; and
      // an order being settled right now, or already settled here, is not an
      // abandoned QR.
      if (row.payment_confirmed_at || order.settling) {
        await store.releaseSettle(row.id, null, false);
        continue;
      }
      if (order.status === 'paid') {
        if (!(await store.finishSettle(row.id).catch(() => null))) await store.releaseSettle(row.id, 'finish declined');
        continue;
      }
      let result = { cancelled: true };
      if (!MOCK) {
        const merchant = order.qpay ? { client: order.qpay } : await clientForRow(row);
        if (merchant.error) {
          await store.giveUp(row.id, merchant.error);
          order.status = 'needs_human';
          alerts.pageOperator('expired order cannot be voided: its merchant changed', { deviceNo: row.device_no, orderNo: row.order_no });
          continue;
        }
        if (merchant.client) order.qpay = merchant.client;
        result = await (order.qpay ?? qpay).cancelInvoice(row.qpay_invoice_id);
      }
      if (result.paid && tooOldToBrew(new Date(new Date(row.created_at).getTime() + ABANDON_AFTER_MS))) {
        // Paid, but the QR is long past its life: no machine is waiting for
        // this order any more.
        await store.giveUp(row.id, 'PAID_TOO_LATE: invoice paid long after it was shown');
        order.status = 'needs_human';
        alerts.pageOperator('an old QR was paid long after it was shown — check and refund', { deviceNo: row.device_no, orderNo: row.order_no });
        continue;
      }
      if (result.paid) {
        log('sweep found payment, settling', row.order_no);
        order.status = 'awaiting_payment';
        // The row is already claimed by this sweep; settle continues from it.
        const r = await settle(order, { claimed: row });
        log('sweep settle', row.order_no, JSON.stringify(r));
        continue;
      }
      if (await store.markCancelled(row.id)) {
        order.status = 'cancelled';
        log('sweep cancelled', row.order_no);
      } else {
        // A refusal usually means a payment was confirmed in the meantime.
        await store.releaseSettle(row.id, 'cancel declined (payment confirmed?)');
      }
    } catch (err) {
      log('sweep failed', row.order_no, firstLine(err));
      await store.releaseSettle(row.id, `sweep: ${firstLine(err)}`.slice(0, 200)).catch(() => {});
    }
  }
}

let lastPrune = 0;
async function sweepTick() {
  await sweepMap();
  if (!DUAL_WRITE) return;
  await drainUnnotified().catch((e) => log('drain error', firstLine(e)));
  await drainAbandoned().catch((e) => log('sweep error', firstLine(e)));
  // Rows whose settle attempts ran out would otherwise vanish from every
  // worker's WHERE clause — money confirmed, machine never told, nobody's
  // problem. needs_human makes them somebody's problem, and the page says so.
  const n = await store.giveUpExhausted().catch((e) => {
    log('give-up error', firstLine(e));
    return 0;
  });
  if (n > 0) alerts.pageOperator(`${n} order(s) ran out of settle attempts and need a human`, {});
  if (Date.now() - lastPrune > 3600_000) {
    lastPrune = Date.now();
    store.pruneAuthAttempts().catch(() => {});
  }
}

let sweeping = false;
const SWEEP_INTERVAL_MS = envInt('SWEEP_INTERVAL_MS', 60_000, { min: MOCK ? 100 : 1000 });
const sweepTimer = setInterval(() => {
  // One tick at a time: a slow QPay must not stack sweeps on each other.
  if (sweeping) return;
  sweeping = true;
  track(
    sweepTick()
      .catch((e) => log('sweep error', firstLine(e)))
      .finally(() => {
        sweeping = false;
      })
  );
}, SWEEP_INTERVAL_MS);
sweepTimer.unref();

/*
 * Boot checks: things that are wrong for every sale, found at boot rather
 * than by the first customer.
 */
let keyringStatus = null;
if (DUAL_WRITE && !MOCK) {
  track(
    (async () => {
      // A lost or replaced CRED_KEYS deploys green and fails every owner's
      // sale with CREDENTIAL_UNSEAL_FAILED. One active credential per key id
      // is opened here; the result is in /health (debug) and pages if bad.
      try {
        const sample = await store.credentialPerKey();
        let bad = 0;
        for (const c of sample) {
          try {
            open(c.sealed, { context: credentialAad({ credentialId: c.id, ownerId: c.owner_id }) });
          } catch {
            bad += 1;
          }
        }
        keyringStatus = { checked: sample.length, unopenable: bad };
        if (bad) {
          log('KEYRING CANNOT OPEN STORED CREDENTIALS', `${bad}/${sample.length}`);
          alerts.pageOperator('the credential keyring cannot open stored QPay credentials', { unopenable: bad });
        }
      } catch (err) {
        keyringStatus = { error: firstLine(err) };
      }
      try {
        const n = await store.divisorMismatches(AMOUNT_DIVISOR);
        if (n) log('note:', `${n} machine(s) record an amount_divisor other than AMOUNT_DIVISOR=${AMOUNT_DIVISOR}; the env value prices every machine`);
      } catch {
        // A check, not a dependency.
      }
    })()
  );
}
if (!DUAL_WRITE && !MOCK && !ENV_MERCHANT_ONLY) {
  log('NO DATABASE: every sale is refused. Set DATABASE_URL, or ENV_MERCHANT_ONLY=1 for an operator-only deployment.');
}

const port = envInt('PORT', 3000, { min: 1, max: 65535 });
/*
 * The last stop for anything a route threw or rejected. body-parser attaches
 * the raw request text to its errors as err.body — for a credential route
 * that is a merchant password — so it is dropped before anything reads err.
 * The request gets a plain answer; the process keeps selling coffee.
 */
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  delete err.body;
  log('request failed', req.method, req.path, String(err?.message ?? err).split('\n')[0]);
  if (res.headersSent) return res.end();
  const status = err.status >= 400 && err.status < 500 ? err.status : 503;
  res.status(status).json({ ok: false, code: status === 503 ? 'UNAVAILABLE' : 'BAD_REQUEST' });
});

// A rejection nobody awaited (a fire-and-forget mirror write) is logged, not
// fatal: exiting would drop every live order held in memory.
process.on('unhandledRejection', (err) => {
  log('unhandled rejection', String(err?.message ?? err).split('\n')[0]);
});

const server = app.listen(port, () => log(`listening :${port} mock=${MOCK} qpay=${qpay.qpayConfigured()} public=${PUBLIC_URL}`));

/*
 * Render sends SIGTERM on every deploy, and Node's default was to exit at
 * once: an in-flight settle stopped between telling the machine and writing
 * it down, an order row was never written, an announcement's SMS loop died
 * half way. Stop taking requests, let what is running finish (Render allows
 * 30 s), then exit.
 */
let stopping = false;
function shutdown(signal) {
  if (stopping) return;
  stopping = true;
  log('shutting down', signal, `inflight=${inflight.size}`);
  clearInterval(sweepTimer);
  server.close();
  const deadline = sleep(20_000).then(() => 'timeout');
  Promise.race([Promise.allSettled([...inflight]).then(() => 'drained'), deadline]).then((how) => {
    log('shutdown', how, `inflight=${inflight.size}`);
    process.exit(0);
  });
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
