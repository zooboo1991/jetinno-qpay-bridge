import express from 'express';
import { SIGNABLE, buildSign, verifySign, flatten, timestamp } from './sign.js';
import * as qpay from './qpay.js';
import * as db from './db.js';
import * as store from './store.js';
import { ownerApi, authConfigured } from './owner-api.js';
import { authHook, authHookConfigured } from './auth-hook.js';

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

function dw(label, fn) {
  if (!DUAL_WRITE) return;
  const started = Date.now();
  Promise.resolve()
    .then(fn)
    .then(() => log('dw', label, `${Date.now() - started}ms`))
    // Only the message: a pg error can carry the failing row, and that row is
    // one schema change away from holding something that should not be logged.
    .catch((err) => log('dw FAILED', label, `${Date.now() - started}ms`, err.message.split('\n')[0]));
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
    log('getQrCode replay ->', orderNo, existing.qrCode);
    return respond(res, { deviceNo, orderNo, qrCode: existing.qrCode }, SIGNABLE.getQrCodeResponse);
  }

  const amount = Math.round(Number(orderAmount) / AMOUNT_DIVISOR);
  if (!Number.isFinite(amount) || amount <= 0) return fail(res, `PARAM_ERROR: orderAmount=${orderAmount}`);

  try {
    const callbackUrl = `${PUBLIC_URL}/qpay/callback/${orderNo}`;
    const invoice = MOCK
      ? { invoiceId: `mock-${orderNo}`, shortUrl: `${PUBLIC_URL}/mock/pay/${orderNo}`, qrText: null }
      : await qpay.createInvoice({
          orderNo,
          amount,
          description: productName || `Coffee ${productId}`,
          callbackUrl,
        });

    // qr_text is the standard QPay QR every bank app scans, but it is
    // routinely longer than Jetinno's 128-character qrCode field, so the
    // short URL is what actually fits on the machine screen. Whether banks
    // scan it is the one thing still to prove on real hardware.
    const qrCode = invoice.shortUrl ?? invoice.qrText;
    if (!qrCode) return fail(res, 'SYSTEM_ERROR: qpay returned no qr');
    if (qrCode.length > 128) return fail(res, `SYSTEM_ERROR: qr too long (${qrCode.length} > 128)`);

    orders.set(orderNo, {
      deviceNo,
      orderAmount,
      notifyUrl,
      productId,
      amountMnt: amount,
      invoiceId: invoice.invoiceId,
      qrCode,
      // Kept for the Jetinno negotiation: qr_text is what bank apps scan,
      // and its real length is the number we need the 128-char field raised
      // to. Visible via GET /orders/:orderNo.
      qrTextLen: invoice.qrText ? invoice.qrText.length : null,
      status: 'awaiting_payment',
      settling: false,
      createdAt: Date.now(),
    });
    log('getQrCode ->', orderNo, `${amount}₮`, qrCode);
    respond(res, { deviceNo, orderNo, qrCode }, SIGNABLE.getQrCodeResponse);

    dw('beginOrder', async () => {
      const machine = await store.resolveMachine(deviceNo);
      if (!machine) {
        // The machine is not registered yet — expected until it is seeded, and
        // worth a row rather than a log line that rotates away, because after
        // the cutover this is the case that stops a sale.
        await store.logIngestError({
          path: '/jetinno/getQrCode',
          deviceNo,
          orderNo,
          reason: 'DEVICE_NOT_REGISTERED',
        });
        return;
      }
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
          qrCode,
          qrTextLen: invoice.qrText ? invoice.qrText.length : null,
        });
      }
    });
  } catch (err) {
    // The detail goes to the log, not to the caller. err.message here can
    // carry up to 300 characters of a QPay response body, and this response
    // travels back through Jetinno's servers to the machine.
    log('getQrCode failed', orderNo, err.message);
    fail(res, 'SYSTEM_ERROR');
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
async function settle(orderNo) {
  const order = orders.get(orderNo);
  if (!order) return { ok: false, reason: 'unknown order' };
  if (order.status === 'paid') return { ok: true, already: true };
  if (order.settling) return { ok: false, reason: 'settle already in progress' };

  order.settling = true;
  try {
    if (!MOCK) {
      const { paid, paymentId, amount } = await qpay.checkPayment(order.invoiceId);
      if (!paid) return { ok: false, reason: 'not paid yet' };
      order.paymentRef = paymentId;
      order.paidAmount = amount;
    } else {
      // No QPay to ask, so the simulation pays exactly what was invoiced.
      order.paidAmount = order.amountMnt;
    }

    const machineReply = await notifyMachine(orderNo, order);
    order.status = 'paid';
    order.paidAt = new Date().toISOString();

    // Mirrored after the fact, not used as the gate. The Map's `settling` flag
    // is still what stops a second coffee; app.claim_order_for_settle takes
    // that job at the phase-3 cutover, once a day of these timings says the
    // round trip fits inside Jetinno's budget.
    // Each step returns the row it changed, or null for "declined". A step
    // that declines and is ignored is not a guard: mark_payment_confirmed
    // refusing a mismatched amount, followed by an unconditional
    // finish_settle, is how the row reaches 'paid' with no confirmation
    // behind it — which the orders_confirmed_shape constraint then rejects.
    dw('settle', async () => {
      const id = await pgOrderId(order.deviceNo, orderNo);
      if (!id) return;
      const claimed = await store.claimSettle(id, { leaseSeconds: 60, instance: INSTANCE });
      if (!claimed) return log('dw settle declined', orderNo, 'claim');
      const confirmed = await store.markPaymentConfirmed(id, {
        paymentId: order.paymentRef ?? null,
        paidAmountMnt: order.paidAmount ?? null,
      });
      if (!confirmed) return log('dw settle declined', orderNo, 'confirm');
      if (!(await store.markNotifySent(id))) return log('dw settle declined', orderNo, 'notify');
      if (!(await store.finishSettle(id))) return log('dw settle declined', orderNo, 'finish');
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
      log('settle failed', req.params.orderNo, err.message);
      res.status(500).json({ error: err.message });
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
    .then((result) => log('qpay callback', req.params.orderNo, JSON.stringify(result)))
    .catch((err) => log('qpay callback failed', req.params.orderNo, err.message))
    .finally(() => res.status(200).send('SUCCESS'));
});

// The same settle by hand. QPay cannot reach localhost, so this is how a real
// QPay payment gets confirmed during local testing without a tunnel.
app.get('/check/:orderNo', settleRoute);

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

function debugAllowed(req) {
  if (!DEBUG_KEY) return false;
  if (req.get('x-debug-key') === DEBUG_KEY) return true;
  const cookie = COOKIE_RE.exec(req.headers.cookie ?? '');
  return cookie ? decodeURIComponent(cookie[1]) === DEBUG_KEY : false;
}

/** Returns true when it has handled the request itself. */
function exchangeKeyForCookie(req, res) {
  if (!DEBUG_KEY || req.query.key !== DEBUG_KEY) return false;
  res.setHeader(
    'Set-Cookie',
    `dbg=${encodeURIComponent(DEBUG_KEY)}; HttpOnly; Path=/; Max-Age=3600; SameSite=Strict`
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

app.get('/health', (req, res) =>
  res.json({
    ok: true,
    mock: MOCK,
    qpayConfigured: qpay.qpayConfigured(),
    publicUrl: PUBLIC_URL,
    orders: orders.size,
  })
);

/**
 * Voids QRs nobody paid. If QPay answers INVOICE_PAID the customer did pay
 * after all and the order is settled instead of thrown away.
 */
async function sweepAbandoned() {
  const now = Date.now();
  for (const [orderNo, order] of orders) {
    if (order.status !== 'awaiting_payment' || order.settling) continue;
    if (now - order.createdAt < ABANDON_AFTER_MS) continue;

    order.status = 'cancelled';
    if (MOCK) {
      log('sweep cancelled', orderNo);
      continue;
    }
    try {
      const result = await qpay.cancelInvoice(order.invoiceId);
      if (result.paid) {
        order.status = 'awaiting_payment';
        log('sweep found payment, settling', orderNo);
        await settle(orderNo);
      } else {
        log('sweep cancelled', orderNo);
        dw('sweepCancel', async () => {
          const id = await pgOrderId(order.deviceNo, orderNo);
          if (id) await store.markCancelled(id);
        });
      }
    } catch (err) {
      order.status = 'awaiting_payment';
      log('sweep failed', orderNo, err.message);
    }
  }
}

setInterval(() => sweepAbandoned().catch((e) => log('sweep error', e.message)), 60_000).unref();

const port = process.env.PORT ?? 3000;
app.listen(port, () => log(`listening :${port} mock=${MOCK} qpay=${qpay.qpayConfigured()} public=${PUBLIC_URL}`));
