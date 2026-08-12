/**
 * QPay v2 merchant API.
 *
 * Ported from the working gmath.mn integration. Three details in here cost
 * real incidents to get right — the token cache's expires_in handling, the
 * PAID-status check, and cancelInvoice's treatment of INVOICE_PAID. Read the
 * comments before simplifying any of them.
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

let tokenCache = null;

/**
 * QPay forbids fetching a fresh token on every request, so it is cached for
 * the whole life of the process.
 */
async function accessToken() {
  const now = Date.now();
  if (tokenCache && tokenCache.expiresAtMs - 60_000 > now) return tokenCache.accessToken;

  const basic = Buffer.from(`${required('QPAY_USERNAME')}:${required('QPAY_PASSWORD')}`).toString('base64');
  const res = await fetch(`${base()}/v2/auth/token`, {
    method: 'POST',
    headers: { Authorization: `Basic ${basic}` },
  });
  if (!res.ok) throw new Error(`qpay auth ${res.status}: ${await detail(res)}`);
  const json = await res.json();

  // QPay's docs call expires_in a duration in seconds, but real responses
  // sometimes carry an absolute unix timestamp instead. Read as a duration,
  // a timestamp would cache the token as fresh for centuries — so anything
  // past ~120 days is treated as absolute rather than trusted as a duration.
  const asDurationMs = json.expires_in * 1000;
  const expiresAtMs = asDurationMs > 1000 * 60 * 60 * 24 * 120 ? asDurationMs : now + asDurationMs;

  tokenCache = { accessToken: json.access_token, expiresAtMs };
  return tokenCache.accessToken;
}

async function authed(path, init) {
  const token = await accessToken();
  return fetch(`${base()}${path}`, {
    ...init,
    headers: { ...init.headers, Authorization: `Bearer ${token}` },
  });
}

/**
 * `senderInvoiceNo` must be unique for this merchant forever — QPay rejects a
 * repeat. The machine's orderNo satisfies that; a counter would not.
 */
export async function createInvoice({ orderNo, amount, description, callbackUrl }) {
  const res = await authed('/v2/invoice', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      invoice_code: required('QPAY_INVOICE_CODE'),
      sender_invoice_no: orderNo,
      invoice_receiver_code: 'terminal',
      invoice_description: description,
      amount,
      callback_url: callbackUrl,
    }),
  });
  if (!res.ok) throw new Error(`qpay invoice ${res.status}: ${await detail(res)}`);

  const json = await res.json();
  return {
    invoiceId: json.invoice_id,
    qrText: json.qr_text,
    qrImage: json.qr_image,
    shortUrl: json.qPay_shortUrl,
  };
}

/** payment_status values that mean the money actually arrived. */
const SETTLED = new Set(['PAID']);

/**
 * The authoritative answer to "was this paid?". Always call this before
 * telling the machine to brew — the callback only says *when* to look, it is
 * never itself proof. Do not put this on a timer; QPay forbids cron polling.
 */
export async function checkPayment(invoiceId) {
  const res = await authed('/v2/payment/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      object_type: 'INVOICE',
      object_id: invoiceId,
      offset: { page_number: 1, page_limit: 100 },
    }),
  });
  if (!res.ok) throw new Error(`qpay check ${res.status}: ${await detail(res)}`);

  const json = await res.json();
  const rows = (json.rows ?? []).map((r) => ({
    paymentId: String(r.payment_id),
    status: r.payment_status,
    amount: Number(r.payment_amount),
  }));
  const settled = rows.find((r) => SETTLED.has(r.status));
  return { paid: Boolean(settled), paymentId: settled?.paymentId, rows };
}

/**
 * Voids an invoice nobody paid, so its QR can never be paid later. Without
 * this a customer who walks away leaves a live QR on a machine that has long
 * since forgotten the order — someone pays it weeks later and no coffee comes
 * out.
 *
 * A 404 and QPay's INVOICE_ALREADY_CANCELED both mean "already gone", so both
 * count as success. INVOICE_PAID is different and must never be swallowed: it
 * means the customer did pay, and the caller has to settle instead of voiding.
 */
export async function cancelInvoice(invoiceId) {
  const res = await authed(`/v2/invoice/${invoiceId}`, { method: 'DELETE' });
  if (res.ok || res.status === 404) return { cancelled: true };

  const text = await detail(res);
  if (text.includes('INVOICE_ALREADY_CANCELED')) return { cancelled: true };
  if (text.includes('INVOICE_PAID')) return { cancelled: false, paid: true };
  throw new Error(`qpay cancel ${res.status}: ${text}`);
}
