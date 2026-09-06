/**
 * QPay v2 merchant API, one client per merchant credential.
 *
 * Ported from the working gmath.mn integration and reshaped for the business
 * model: machines are sold to owners, and each machine's revenue must land in
 * ITS OWNER's QPay account. That means invoice creation, payment checking and
 * cancellation all run under whichever credential issued the invoice — never
 * under a single global merchant.
 *
 * Three details in here cost real incidents to get right — the token cache's
 * expires_in handling, the PAID-status check, and cancelInvoice's treatment
 * of INVOICE_PAID. Read the comments before simplifying any of them.
 */

const base = () => process.env.QPAY_BASE_URL ?? 'https://merchant.qpay.mn';

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} орчны хувьсагч тохируулаагүй байна`);
  return value;
}

export function qpayConfigured() {
  return Boolean(process.env.QPAY_USERNAME && process.env.QPAY_PASSWORD && process.env.QPAY_INVOICE_CODE);
}

async function detail(res) {
  return res
    .text()
    .then((t) => t.slice(0, 300))
    .catch(() => '');
}

/**
 * Every QPay call is bounded. Node's default socket timeout is measured in
 * minutes, and Jetinno gives the whole request 8 seconds — without a deadline
 * a hung QPay connection blows that budget, and worse, a hung checkPayment
 * holds settle()'s claim for minutes while the customer stands there having
 * already paid.
 */
const TIMEOUT_MS = {
  // On the getQrCode hot path: token (cold) + invoice must fit inside 8s with
  // room to spare.
  token: 2500,
  invoice: 4000,
  // Off the hot path, but each one holds the settle claim while it runs.
  check: 6000,
  cancel: 6000,
};

/** payment_status values that mean the money actually arrived. */
const SETTLED = new Set(['PAID']);

/**
 * Token cache, keyed per credential.
 *
 * QPay forbids fetching a fresh token on every request, so tokens are cached
 * for the life of the process — but a single module-level cache would hand
 * owner B's requests owner A's token the moment a second merchant existed.
 * The key is the credential id (or '__env__' for the operator's own account),
 * so client objects can be constructed freely while the cache stays shared.
 */
const tokenCaches = new Map();

/** Drops a cached token — called when a credential is rotated or revoked. */
export function evictCredential(cacheKey) {
  tokenCaches.delete(cacheKey);
}

function makeClient({ username, password, invoiceCode, cacheKey }) {
  const key = cacheKey ?? `user:${username}`;

  async function accessToken(force = false) {
    const now = Date.now();
    const cached = tokenCaches.get(key);
    if (!force && cached && cached.expiresAtMs - 60_000 > now) return cached.accessToken;

    const basic = Buffer.from(`${username}:${password}`).toString('base64');
    const res = await fetch(`${base()}/v2/auth/token`, {
      method: 'POST',
      headers: { Authorization: `Basic ${basic}` },
      signal: AbortSignal.timeout(TIMEOUT_MS.token),
    });
    if (!res.ok) throw new Error(`qpay auth ${res.status}: ${await detail(res)}`);
    const json = await res.json();

    // QPay's docs call expires_in a duration in seconds, but real responses
    // sometimes carry an absolute unix timestamp instead. Read as a duration,
    // a timestamp would cache the token as fresh for centuries — so anything
    // past ~120 days is treated as absolute rather than trusted as a duration.
    // And if the field is missing or unparsable, assume a conservative hour:
    // a NaN in the expiry comparison is always false, which would have made
    // the cache permanently stale-but-trusted.
    const asDurationMs = Number(json.expires_in) * 1000;
    const expiresAtMs = !Number.isFinite(asDurationMs)
      ? now + 60 * 60 * 1000
      : asDurationMs > 1000 * 60 * 60 * 24 * 120
        ? asDurationMs
        : now + asDurationMs;

    tokenCaches.set(key, { accessToken: json.access_token, expiresAtMs });
    return json.access_token;
  }

  /**
   * A 401 means the cached token died early — revoked, or QPay's clock
   * disagrees with the expiry we computed. One evict-and-retry heals it;
   * without this, a revoked token fails every sale until a process restart.
   */
  async function authed(path, init, timeoutMs) {
    const attempt = async (force) =>
      fetch(`${base()}${path}`, {
        ...init,
        headers: { ...init.headers, Authorization: `Bearer ${await accessToken(force)}` },
        signal: AbortSignal.timeout(timeoutMs),
      });
    let res = await attempt(false);
    if (res.status === 401) {
      tokenCaches.delete(key);
      res = await attempt(true);
    }
    return res;
  }

  return {
    /**
     * `senderInvoiceNo` must be unique for this merchant forever — QPay
     * rejects a repeat. The machine's orderNo satisfies that; a counter
     * would not.
     */
    async createInvoice({ orderNo, amount, description, callbackUrl }) {
      const res = await authed('/v2/invoice', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          invoice_code: invoiceCode,
          sender_invoice_no: orderNo,
          invoice_receiver_code: 'terminal',
          invoice_description: description,
          amount,
          callback_url: callbackUrl,
        }),
      }, TIMEOUT_MS.invoice);
      if (!res.ok) throw new Error(`qpay invoice ${res.status}: ${await detail(res)}`);

      const json = await res.json();
      return {
        invoiceId: json.invoice_id,
        qrText: json.qr_text,
        qrImage: json.qr_image,
        shortUrl: json.qPay_shortUrl,
      };
    },

    /**
     * The authoritative answer to "was this paid?". Always call this before
     * telling the machine to brew — the callback only says *when* to look, it
     * is never itself proof. Do not put this on a timer; QPay forbids cron
     * polling.
     */
    async checkPayment(invoiceId) {
      const res = await authed('/v2/payment/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          object_type: 'INVOICE',
          object_id: invoiceId,
          offset: { page_number: 1, page_limit: 100 },
        }),
      }, TIMEOUT_MS.check);
      if (!res.ok) throw new Error(`qpay check ${res.status}: ${await detail(res)}`);

      const json = await res.json();
      const rows = (json.rows ?? []).map((r) => ({
        paymentId: String(r.payment_id),
        status: r.payment_status,
        amount: Number(r.payment_amount),
      }));
      const settled = rows.find((r) => SETTLED.has(r.status));
      // The amount comes back from QPay, not from our own record: the
      // database refuses to confirm a payment whose amount differs from the
      // invoice, and that check only means something if the two numbers have
      // separate origins.
      return { paid: Boolean(settled), paymentId: settled?.paymentId, amount: settled?.amount, rows };
    },

    /**
     * Voids an invoice nobody paid, so its QR can never be paid later.
     * Without this a customer who walks away leaves a live QR on a machine
     * that has long since forgotten the order — someone pays it weeks later
     * and no coffee comes out.
     *
     * A 404 and QPay's INVOICE_ALREADY_CANCELED both mean "already gone", so
     * both count as success. INVOICE_PAID is different and must never be
     * swallowed: it means the customer did pay, and the caller has to settle
     * instead of voiding.
     */
    async cancelInvoice(invoiceId) {
      const res = await authed(`/v2/invoice/${invoiceId}`, { method: 'DELETE' }, TIMEOUT_MS.cancel);
      if (res.ok || res.status === 404) return { cancelled: true };

      const text = await detail(res);
      if (text.includes('INVOICE_ALREADY_CANCELED')) return { cancelled: true };
      if (text.includes('INVOICE_PAID')) return { cancelled: false, paid: true };
      throw new Error(`qpay cancel ${res.status}: ${text}`);
    },
  };
}

/**
 * A client for one owner's unsealed credential. The cacheKey should be the
 * credential id, so the token cache follows the credential across however
 * many client objects get constructed for it.
 */
export function clientFor({ username, password, invoiceCode, cacheKey }) {
  if (!username || !password || !invoiceCode) throw new Error('QPAY_CREDENTIAL_INCOMPLETE');
  return makeClient({ username, password, invoiceCode, cacheKey });
}

/*
 * The operator's own merchant, from the environment. Still used for machines
 * that are not registered to any owner, and for everything while DATABASE_URL
 * is absent — which is what keeps today's live machine selling through the
 * transition.
 */
let envClientCache = null;
function envClient() {
  if (!envClientCache) {
    envClientCache = makeClient({
      username: required('QPAY_USERNAME'),
      password: required('QPAY_PASSWORD'),
      invoiceCode: required('QPAY_INVOICE_CODE'),
      cacheKey: '__env__',
    });
  }
  return envClientCache;
}

export const createInvoice = (args) => envClient().createInvoice(args);
export const checkPayment = (invoiceId) => envClient().checkPayment(invoiceId);
export const cancelInvoice = (invoiceId) => envClient().cancelInvoice(invoiceId);
