import express from 'express';
import { SIGNABLE, buildSign, verifySign, flatten, timestamp } from './sign.js';
import * as qpay from './qpay.js';
import * as db from './db.js';
import * as store from './store.js';
import { ownerApi, authConfigured } from './owner-api.js';
import { authHook, authHookConfigured } from './auth-hook.js';
import { open, credentialAad } from './crypto.js';
import { timingSafeEqual as cryptoTimingSafeEqual } from 'node:crypto';

const app = express();
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

const APIKEY = requiredEnv('JETINNO_APIKEY');
const USERNAME = requiredEnv('JETINNO_USERNAME');
// QPay builds its callback from this, so it has to be the origin the outside
// world reaches — never localhost in production. Render injects
// RENDER_EXTERNAL_URL with the service's own https origin, which saves
// hand-copying the domain back into the config after the first deploy.
const PUBLIC_URL = process.env.PUBLIC_URL ?? process.env.RENDER_EXTERNAL_URL ?? 'http://localhost:3000';
const MOCK = process.env.QPAY_MOCK === '1';

// Jetinno documents orderAmount in cents, so 100000 means 1000₮ and QPay —
// which takes whole tugrik — needs it divided by 100. That is a reading of
// the spec, not something a real machine has confirmed yet, so it stays an
// env var: watch the first live getQrCode log and flip this to 1 if the
// machine turns out to send tugrik directly.
const AMOUNT_DIVISOR = Number(process.env.AMOUNT_DIVISOR ?? 100);

// How long an unpaid QR stays live before we void it at QPay.
const ABANDON_AFTER_MS = Number(process.env.ABANDON_AFTER_MS ?? 10 * 60 * 1000);

/** orderNo -> order. In memory on purpose: one machine, one process, first test. */
const orders = new Map();

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

/**
 * Phase 2 dual-write (docs/multi-tenant-plan.md §6).
 *
 * Orders are written to Postgres as well as the Map, but the Map still answers
 * every read and still gates every decision. That ordering is the whole point:
 * a database that is slow, down, or wrong cannot cost a customer their coffee
 * while we are still learning how it behaves under real traffic.
 *
 * Fire-and-forget, never awaited. The machine's 8-second budget must not grow
 * by a database round trip for a write nothing reads yet — and the timing is
 * logged either way, which is what this phase exists to measure.
 */
const DUAL_WRITE = db.configured();

/** Identifies which process holds a settle lease. Render gives no stable id. */
const INSTANCE = `${process.env.RENDER_INSTANCE_ID ?? 'local'}-${process.pid}`;

// Dual-write failures counted durably-enough for /health: the counter tells
// an uptime monitor THAT the mirror is failing; /errors and the ring tell a
// human what exactly failed.
let dwFailed = 0;
let dwLastFailure = null;

function dw(label, fn) {
  if (!DUAL_WRITE) return;
  const started = Date.now();
  Promise.resolve()
    .then(fn)
    .then(() => log('dw', label, `${Date.now() - started}ms`))
    // Only the message: a pg error can carry the failing row, and that row is
    // one schema change away from holding something that should not be logged.
    .catch((err) => {
      dwFailed += 1;
      dwLastFailure = { label, at: new Date().toISOString() };
      log('dw FAILED', label, `${Date.now() - started}ms`, err.message.split('\n')[0]);
    });
}

/** Resolves an order's Postgres id without depending on when the insert landed. */
async function pgOrderId(deviceNo, orderNo) {
  const machine = await store.resolveMachine(deviceNo);
  if (!machine) return null;
  const row = await store.findOrderByMachine(machine.machine_id, orderNo);
  return row?.id ?? null;
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

// The expected signature goes to the server log only. Echoing it in the
// response would hand any caller a valid signature for the exact payload
// they just sent — a one-round-trip bypass of the whole scheme.
function failSign(res, check) {
  log('SIGN_ERROR', 'expected', check.expected, 'got', check.got);
  res.json({ returnCode: 'FAIL', msg: 'SIGN_ERROR' });
}

/**
 * The notify URL comes from the signed machine request, so using it requires
 * a valid Jetinno signature — but the bridge still refuses to be pointed at
 * itself or at anything inside the network it runs on. A compromised vendor
 * key must not become an SSRF proxy that POSTs signed bodies at internal
 * services and logs their replies for read-back.
 *
 * MOCK runs keep localhost: that is where the simulated machine lives.
 */
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
  const host = url.hostname;
  const isPrivate =
    host === 'localhost' ||
    host === '0.0.0.0' ||
    host === '::1' ||
    host.startsWith('127.') ||
    host.startsWith('10.') ||
    host.startsWith('192.168.') ||
    host.startsWith('169.254.') ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host);
  return !isPrivate;
}

/**
 * Which merchant a sale on this device belongs to.
 *
 * The business model is that each machine's revenue lands in ITS OWNER's QPay
 * account, so this is the routing decision for actual money:
 *
 *   owner client   — the machine is registered and its credential is usable.
 *   env fallback   — no database, database unreachable, or a device nobody
 *                    has registered. The operator's own merchant takes the
 *                    sale; for an unregistered device that is today's exact
 *                    behavior, and for a database blip it keeps coffee
 *                    working — the Map-decides rule extends to routing.
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
async function merchantFor(deviceNo, orderNo) {
  if (!DUAL_WRITE) return { client: null, source: 'env' };

  let machine;
  try {
    machine = await store.resolveMachine(deviceNo);
  } catch (err) {
    log('merchant resolve failed, env fallback', deviceNo, err.message.split('\n')[0]);
    return { client: null, source: 'env-db-down' };
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
      client: qpay.clientFor({
        username: cred.username,
        password: cred.password,
        invoiceCode: cred.invoice_code,
        cacheKey: machine.qpay_credential_id,
      }),
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
  const check = verifySign(req.body, SIGNABLE.getQrCodeRequest, APIKEY);
  if (!check.ok) return failSign(res, check);

  const { deviceNo, orderNo, orderAmount, notifyUrl, productId, productName } = flatten(req.body);

  // The machine retries when our 8-second budget is missed, and a retry
  // arrives with the same orderNo. Creating a second invoice is not an
  // option — QPay rejects a repeated sender_invoice_no forever — so hand
  // back the QR already made for this order. Only a genuine collision
  // between two different machines is an error.
  const existing = orders.get(orderNo);
  if (existing) {
    if (existing.deviceNo !== deviceNo) return fail(res, 'ORDERNO_EXIST');
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
    orderAmount,
    notifyUrl,
    productId,
    amountMnt: amount,
    status: 'creating',
    settling: false,
    createdAt: Date.now(),
  };
  // A function-valued property: JSON.stringify skips it, so the debug /orders
  // dump can never serialize the credential closed over inside the client.
  if (merchant.client) order.qpay = merchant.client;

  const callbackUrl = `${PUBLIC_URL}/qpay/callback/${orderNo}`;
  order.pending = (async () => {
    const invoice = MOCK
      ? { invoiceId: `mock-${orderNo}`, shortUrl: `${PUBLIC_URL}/mock/pay/${orderNo}`, qrText: null }
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
  orders.set(orderNo, order);

  let invoice;
  try {
    invoice = await order.pending;
  } catch (err) {
    // A failed creation is removed so a later fresh retry can start over —
    // holding the dead placeholder would turn every retry into SYSTEM_ERROR.
    orders.delete(orderNo);
    log('getQrCode failed', orderNo, err.message);
    return fail(res, err.publicMsg ?? 'SYSTEM_ERROR');
  } finally {
    delete order.pending;
  }

  try {
    const qrCode = order.qrCode;
    log('getQrCode ->', orderNo, `${amount}₮`, qrCode);
    respond(res, { deviceNo, orderNo, qrCode }, SIGNABLE.getQrCodeResponse);

    dw('beginOrder', async () => {
      // merchantFor already resolved (and logged the unregistered case).
      const machine = merchant.machine ?? (await store.resolveMachine(deviceNo));
      if (!machine) return;
      const inserted = await store.beginOrder({
        machineId: machine.machine_id,
        ownerId: machine.owner_id,
        credentialId: machine.qpay_credential_id,
        orderNo,
        deviceNo,
        notifyUrl,
        productId,
        productName,
        rawOrderAmount: String(orderAmount),
        amountDivisor: AMOUNT_DIVISOR,
        amountMnt: amount,
        senderInvoiceNo: orderNo,
        callbackUrl,
        abandonAfterMs: ABANDON_AFTER_MS,
      });
      const id = inserted?.id ?? (await store.findOrderByMachine(machine.machine_id, orderNo))?.id;
      if (id) {
        await store.attachInvoice(id, {
          invoiceId: invoice.invoiceId,
          qrCode: order.qrCode,
          qrTextLen: invoice.qrText ? invoice.qrText.length : null,
        });
      }
    });
  } catch (err) {
    // Response/logging failure after the invoice already exists. The order
    // stays in the Map: the machine's retry replays the stored QR.
    log('getQrCode respond failed', orderNo, err.message);
  }
});

app.post('/jetinno/productdone', jetinnoBody, (req, res) => {
  log('productdone <-', JSON.stringify(req.body));
  const check = verifySign(req.body, SIGNABLE.productDoneRequest, APIKEY);
  if (!check.ok) return failSign(res, check);

  const { deviceNo, orderNo, isFinish } = flatten(req.body);
  const order = orders.get(orderNo);
  if (order) order.finished = isFinish;
  log('productdone', orderNo, isFinish);
  res.json({ returnCode: 'SUCCESS', msg: 'SUCCESS' });

  dw('productDone', async () => {
    const id = await pgOrderId(deviceNo ?? order?.deviceNo, orderNo);
    if (id) await store.recordProductDone(id, isFinish === 'SUCCESS');
  });
});

app.post('/jetinno/refund', jetinnoBody, (req, res) => {
  log('refund <-', JSON.stringify(req.body));
  const check = verifySign(req.body, SIGNABLE.refundRequest, APIKEY);
  if (!check.ok) return failSign(res, check);
  const { deviceNo, orderNo } = flatten(req.body);
  respond(res, { deviceNo, orderNo, refundState: 'ERROR' }, ['returnCode', 'msg', 'time', 'deviceNo', 'orderNo', 'refundState']);
});

async function notifyMachine(orderNo, order) {
  const body = {
    username: USERNAME,
    time: timestamp(),
    data: {
      deviceNo: order.deviceNo,
      orderNo,
      orderAmount: order.orderAmount,
      payType: '1001',
      payStatus: 'PAYSUCCESS',
    },
  };
  body.sign = buildSign(flatten(body), SIGNABLE.paymentCallback, APIKEY);

  log('notify ->', order.notifyUrl, JSON.stringify(body));
  const reply = await fetch(order.notifyUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(8000),
  });
  const text = await reply.text();
  log('notify <-', reply.status, text);
  if (!reply.ok || !text.includes('SUCCESS')) throw new Error(`machine rejected notify: ${reply.status} ${text}`);
  return text;
}

/**
 * Confirms payment with QPay and tells the machine to brew. Safe to call from
 * anywhere, as often as you like — the QPay webhook and the /check poll do
 * genuinely arrive at the same instant.
 *
 * `settling` is claimed synchronously, before the first await. Without that
 * claim both callers pass the status test, both reach notifyMachine, and the
 * machine brews twice for one payment. The flag is only released once the
 * machine has acknowledged, so a failed notify leaves the order retryable
 * rather than silently marked paid with no coffee delivered.
 */
/**
 * Rebuilds a Map entry from the dual-written Postgres row.
 *
 * Reached only when the Map has no entry — after a restart, which on Render
 * is every deploy. The row carries the notify URL, device, amounts and the
 * QPay invoice id: everything settle() needs to finish the sale it was
 * mid-way through. Only live rows qualify; a paid or cancelled order stays
 * finished.
 */
async function rehydrateOrder(orderNo) {
  try {
    const row = await store.findLiveOrder(orderNo);
    if (!row) return null;
    const order = {
      deviceNo: row.device_no,
      orderAmount: row.raw_order_amount,
      notifyUrl: row.notify_url,
      productId: row.product_id,
      amountMnt: row.amount_mnt,
      invoiceId: row.qpay_invoice_id,
      qrCode: row.qr_code,
      qrTextLen: row.qr_text_len,
      status: 'awaiting_payment',
      settling: false,
      createdAt: new Date(row.created_at).getTime(),
      rehydrated: true,
    };

    // The invoice was issued under the credential snapshotted on the row, and
    // only that credential can check or cancel it. Rebuilt even for a
    // credential that has since been deactivated: settlement of an existing
    // sale must finish under the merchant that took the money — deactivation
    // gates NEW invoices, not the completion of old ones. If it cannot be
    // unsealed at all, settling is impossible and the caller's 503 keeps
    // QPay retrying while someone looks.
    if (!MOCK && row.qpay_credential_id) {
      const cred = await store.getCredentialById(row.qpay_credential_id);
      if (!cred?.sealed) {
        log('rehydrate: credential row missing', orderNo);
        return null;
      }
      try {
        const plain = open(cred.sealed, {
          context: credentialAad({ credentialId: row.qpay_credential_id, ownerId: cred.owner_id }),
        });
        order.qpay = qpay.clientFor({
          username: plain.username,
          password: plain.password,
          invoiceCode: plain.invoice_code,
          cacheKey: row.qpay_credential_id,
        });
      } catch (err) {
        log('rehydrate: unseal failed', orderNo, err.message.split('\n')[0]);
        return null;
      }
    }
    orders.set(orderNo, order);
    log('order rehydrated from db', orderNo, `was ${row.status}`);
    return order;
  } catch (err) {
    log('rehydrate failed', orderNo, err.message.split('\n')[0]);
    return null;
  }
}

async function settle(orderNo) {
  let order = orders.get(orderNo);
  // The Map is empty after every restart — and Render restarts the process on
  // every deploy. A paid order must survive that, so a miss falls back to the
  // dual-written Postgres row, which carries everything a settle needs.
  if (!order && DUAL_WRITE) order = await rehydrateOrder(orderNo);
  if (!order) return { ok: false, reason: 'unknown order' };
  if (order.pending || order.status === 'creating') return { ok: false, reason: 'not paid yet' };
  if (order.status === 'paid') return { ok: true, already: true };
  if (order.settling) return { ok: false, reason: 'settle already in progress' };

  order.settling = true;
  try {
    if (!MOCK) {
      // The credential that ISSUED the invoice answers for it — owner orders
      // check under the owner's merchant, env orders under the operator's.
      const { paid, paymentId, amount } = await (order.qpay ?? qpay).checkPayment(order.invoiceId);
      if (!paid) return { ok: false, reason: 'not paid yet' };
      order.paymentRef = paymentId;
      order.paidAmount = amount;
    } else {
      // No QPay to ask, so the simulation pays exactly what was invoiced.
      order.paidAmount = order.amountMnt;
    }

    // The sweep can relabel this order while checkPayment is in flight. If a
    // concurrent path already finished the sale, this one stops here — the
    // single-notify invariant is worth more than this call's return value.
    if (order.status === 'paid') return { ok: true, already: true };

    const machineReply = await notifyMachine(orderNo, order);
    order.status = 'paid';
    order.paidAt = new Date().toISOString();

    // Mirrored after the fact, not used as the gate. The Map's `settling` flag
    // is still what stops a second coffee; app.claim_order_for_settle takes
    // that job at the phase-3 cutover, once a day of these timings says the
    // round trip fits inside Jetinno's budget.
    // Each step returns the row it changed, or null for "declined", and every
    // declined or thrown step RELEASES the claim with the reason written to
    // orders.last_error. Without the release, a declined step leaves the row
    // in 'settling' holding a lease, with last_error empty — durable state
    // that quietly disagrees with the Map, discovered only at the phase-3
    // cutover. last_error is also what the /errors monitoring reads.
    dw('settle', async () => {
      const id = await pgOrderId(order.deviceNo, orderNo);
      if (!id) return;
      const claimed = await store.claimSettle(id, { leaseSeconds: 60, instance: INSTANCE });
      if (!claimed) return log('dw settle declined', orderNo, 'claim');
      try {
        const confirmed = await store.markPaymentConfirmed(id, {
          paymentId: order.paymentRef ?? null,
          paidAmountMnt: order.paidAmount ?? null,
        });
        if (!confirmed) return await store.releaseSettle(id, 'confirm declined (amount/state mismatch)');
        if (!(await store.markNotifySent(id))) return await store.releaseSettle(id, 'notify-sent declined');
        if (!(await store.finishSettle(id))) return await store.releaseSettle(id, 'finish declined');
      } catch (err) {
        await store.releaseSettle(id, err.message.split('\n')[0]).catch(() => {});
        throw err;
      }
    });

    return { ok: true, machineReply };
  } finally {
    order.settling = false;
  }
}

function settleRoute(req, res) {
  settle(req.params.orderNo)
    .then((result) => res.status(result.ok ? 200 : result.reason === 'unknown order' ? 404 : 202).json(result))
    .catch((err) => {
      // The detail stays in the log. err.message here can carry a QPay
      // response body, and this endpoint answers whoever asked.
      log('settle failed', req.params.orderNo, err.message);
      res.status(500).json({ error: 'SYSTEM_ERROR' });
    });
}

/**
 * QPay's webhook. It fires more than once for one payment, and a forged hit
 * is harmless: settle() re-checks against QPay using the invoice id on our
 * own record, never anything from this request.
 *
 * QPay wants exactly HTTP 200 with the body "SUCCESS" — a JSON body, a
 * redirect or any error status makes it retry the same callback on a loop.
 * So every outcome here, including a crash, is logged and answered SUCCESS.
 */
app.all('/qpay/callback/:orderNo', (req, res) => {
  settle(req.params.orderNo)
    .then((result) => {
      log('qpay callback', req.params.orderNo, JSON.stringify(result));
      // 'unknown order' is the one outcome that must NOT be answered SUCCESS.
      // SUCCESS is what stops QPay's retries, and for an order this process
      // has genuinely lost (restart with the row also missing), the retry IS
      // the recovery path: by the next attempt the rehydration above may have
      // a database to read. Every other outcome — settled, already settled,
      // not paid yet — is final for this callback and answers SUCCESS.
      if (!result.ok && result.reason === 'unknown order') {
        return res.status(503).send('RETRY');
      }
      res.status(200).send('SUCCESS');
    })
    .catch((err) => {
      log('qpay callback failed', req.params.orderNo, err.message);
      // A transient settle failure still answers SUCCESS: the sweep finds the
      // payment on the next pass (cancelInvoice -> INVOICE_PAID -> settle),
      // and an error here would have QPay hammering a struggling process.
      res.status(200).send('SUCCESS');
    });
});

// The same settle by hand — the operator's manual recovery path, and how a
// real QPay payment gets confirmed during local testing without a tunnel.
// When a DEBUG_KEY is configured (every real deployment) it is required here
// too: an open version confirmed live orderNos to anyone and let strangers
// spend our QPay API quota. The ?key= cookie exchange keeps it usable from a
// phone on site.
app.get('/check/:orderNo', (req, res) => {
  if (process.env.DEBUG_KEY) {
    if (exchangeKeyForCookie(req, res)) return;
    if (!debugAllowed(req)) return res.status(404).end();
  }
  settleRoute(req, res);
});

// Only exists in mock mode. Registered unconditionally it was harmless today
// (settle still verifies against QPay), but it is one stray QPAY_MOCK=1 away
// from being a public free-coffee endpoint — so it should not exist at all in
// a real deployment.
if (MOCK) app.all('/mock/pay/:orderNo', settleRoute);

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
} else {
  log('owner api NOT mounted', `supabase=${authConfigured()} db=${DUAL_WRITE}`);
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
  res.json([...orders.entries()].map(([orderNo, o]) => ({ orderNo, ...o })));
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
  const order = orders.get(req.params.orderNo);
  if (!order) return res.status(404).json({ error: 'unknown order' });
  res.json({ orderNo: req.params.orderNo, ...order });
});

/**
 * Cheap on purpose: uptime monitors poll it, so it never touches the
 * database. dwFailed is the one number that says the durable mirror is
 * falling behind — a monitor alerting on it catches a broken DATABASE_URL
 * hours before the phase-3 cutover would have.
 */
app.get('/health', (req, res) =>
  res.json({
    ok: true,
    mock: MOCK,
    qpayConfigured: qpay.qpayConfigured(),
    dbConfigured: DUAL_WRITE,
    dwFailed,
    dwLastFailure,
    publicUrl: PUBLIC_URL,
    orders: orders.size,
  })
);

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
 * Voids QRs nobody paid. If QPay answers INVOICE_PAID the customer did pay
 * after all and the order is settled instead of thrown away.
 */
// Finished orders are kept a day for replay/productdone matching, then
// evicted. Without this the Map — the process's source of truth — grows by
// every sale ever made and the fix arrives as an OOM restart at month three.
const RETAIN_FINISHED_MS = Number(process.env.RETAIN_FINISHED_MS ?? 24 * 60 * 60 * 1000);

async function sweepAbandoned() {
  const now = Date.now();
  for (const [orderNo, order] of orders) {
    if (
      (order.status === 'paid' || order.status === 'cancelled') &&
      now - order.createdAt > RETAIN_FINISHED_MS
    ) {
      orders.delete(orderNo);
      continue;
    }
    if (order.status !== 'awaiting_payment' || order.settling || order.pending) continue;
    if (now - order.createdAt < ABANDON_AFTER_MS) continue;

    order.status = 'cancelled';
    if (MOCK) {
      log('sweep cancelled', orderNo);
      dwSweepCancel(order, orderNo);
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
        if (order.status === 'cancelled') {
          order.status = 'awaiting_payment';
          log('sweep found payment, settling', orderNo);
          await settle(orderNo);
        } else {
          log('sweep: settled concurrently, leaving as', order.status, orderNo);
        }
      } else if (order.status === 'cancelled') {
        log('sweep cancelled', orderNo);
        dwSweepCancel(order, orderNo);
      }
    } catch (err) {
      if (order.status === 'cancelled') order.status = 'awaiting_payment';
      log('sweep failed', orderNo, err.message);
    }
  }

  // Rows whose settle attempts ran out would otherwise vanish from every
  // worker's WHERE clause — money confirmed, machine never told, nobody's
  // problem. needs_human at least makes them somebody's problem.
  dw('giveUpExhausted', () => store.giveUpExhausted());
}

/**
 * Mirrors a sweep cancellation. mark_cancelled requires the row to be claimed
 * first (status 'settling'), so this claims, cancels, and releases the claim
 * if the cancel is refused — a refusal usually means a payment was confirmed
 * in the meantime, which the release records instead of discarding.
 */
function dwSweepCancel(order, orderNo) {
  dw('sweepCancel', async () => {
    const id = await pgOrderId(order.deviceNo, orderNo);
    if (!id) return;
    const claimed = await store.claimSettle(id, { leaseSeconds: 60, instance: INSTANCE });
    if (!claimed) return log('dw sweepCancel declined', orderNo, 'claim');
    if (!(await store.markCancelled(id))) {
      await store.releaseSettle(id, 'cancel declined (payment confirmed?)');
    }
  });
}

const SWEEP_INTERVAL_MS = Number(process.env.SWEEP_INTERVAL_MS ?? 60_000);
setInterval(() => sweepAbandoned().catch((e) => log('sweep error', e.message)), SWEEP_INTERVAL_MS).unref();

const port = process.env.PORT ?? 3000;
app.listen(port, () => log(`listening :${port} mock=${MOCK} qpay=${qpay.qpayConfigured()} public=${PUBLIC_URL}`));
