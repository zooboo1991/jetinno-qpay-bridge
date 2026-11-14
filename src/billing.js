import { createHmac, timingSafeEqual } from 'node:crypto';
import * as store from './store.js';
import * as qpay from './qpay.js';
import * as owners from './owners.js';
import { pushToOwners } from './push.js';
import { sendSms, smsConfigured, localNumber } from './sms.js';

/**
 * The system subscription (migration 019).
 *
 * Every business pays BILLING_FEE_PER_MACHINE_MNT a month for each active
 * machine, through QPay on the OPERATOR's own merchant (the env QPAY_*
 * account — the same one an unregistered machine sells on). Each payment
 * extends owners.paid_until by the months bought. BILLING_GRACE_DAYS after
 * it lapses the business is suspended: its machines refuse QPay sales and
 * its portal shows only the billing page, until a payment lands.
 *
 * The fee and the grace come from here and are passed into SQL, so what is
 * charged, what is shown and what is enforced cannot disagree.
 */

function envInt(name, def, min, max) {
  const raw = process.env[name];
  if (raw === undefined || String(raw).trim() === '') return def;
  const n = Number(raw);
  return Number.isInteger(n) && n >= min && n <= max ? n : def;
}

export const BILLING = {
  fee: envInt('BILLING_FEE_PER_MACHINE_MNT', 30_000, 0, 10_000_000),
  graceDays: envInt('BILLING_GRACE_DAYS', 3, 0, 60),
  noticeDays: envInt('BILLING_NOTICE_DAYS', 3, 0, 60),
};
export const MONTH_OPTIONS = [1, 3, 6, 12];

const PUBLIC_URL = (process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || 'http://localhost:3000').replace(/\/+$/, '');

/*
 * The payment callback URL is signed like the sale callback, with its own
 * derivation from the Jetinno key: stable across restarts, never in the
 * repository, and a hit without it costs nothing.
 */
const MAC_KEY = createHmac('sha256', process.env.JETINNO_APIKEY ?? '').update('qpay-billing-v1').digest();
const macFor = (invoiceId) => createHmac('sha256', MAC_KEY).update(String(invoiceId)).digest('base64url').slice(0, 22);
export function billingMacValid(invoiceId, mac) {
  const a = Buffer.from(String(mac ?? ''));
  const b = Buffer.from(macFor(invoiceId));
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Whether a machine row from resolveMachine belongs to a suspended business.
 * Read from the cached row, so the sale path spends no extra query on it.
 */
export function saleSuspended(row, now = Date.now()) {
  if (!row || row.owner_billing_exempt || !row.owner_paid_until) return false;
  return now >= new Date(row.owner_paid_until).getTime() + BILLING.graceDays * 86_400_000;
}

const iso = (d) => (d ? new Date(d).toISOString() : null);

function invoiceView(row) {
  if (!row) return null;
  return {
    id: row.id,
    months: row.months,
    amountMnt: row.amount_mnt,
    status: row.status,
    createdAt: iso(row.created_at),
    qrImage: row.qr_image ?? null,
    qrText: row.qr_text ?? null,
    shortUrl: row.short_url ?? null,
    bankUrls: (Array.isArray(row.bank_urls) ? row.bank_urls : [])
      .filter((u) => u && typeof u.link === 'string')
      .map((u) => ({
        name: String(u.name ?? '').slice(0, 60),
        description: String(u.description ?? '').slice(0, 120),
        logo: String(u.logo ?? '').slice(0, 300),
        link: String(u.link).slice(0, 2000),
      })),
  };
}

/** B1: where a business stands, what it may buy, and what it has paid. */
export async function billingFor(ownerId, { autoCheck = true, log = () => {} } = {}) {
  const b = await store.ownerBilling(ownerId, BILLING);
  if (!b) return null;
  let open = await store.openBillingInvoice(ownerId);
  // Back from the bank app with the page reloaded: the payment is usually
  // there before QPay's callback is. Checked at most every 20 s per invoice.
  if (open && autoCheck && checkable(open.id)) {
    const r = await checkInvoice(open.id, { log }).catch(() => null);
    if (r?.status === 'paid') return billingFor(ownerId, { autoCheck: false, log });
    open = await store.openBillingInvoice(ownerId);
  }
  const billable = b.out_state !== 'exempt' && b.out_state !== 'no_machines';
  const history = await store.billingHistory(ownerId);
  return {
    state: b.out_state,
    paidUntil: iso(b.out_paid_until),
    graceUntil: iso(b.out_grace_until),
    daysLeft: Math.ceil((new Date(b.out_paid_until).getTime() - Date.now()) / 86_400_000),
    machines: b.out_machines,
    feePerMachineMnt: b.out_fee_per_machine,
    monthlyFeeMnt: b.out_monthly_fee,
    exempt: b.out_exempt,
    feeOverride: b.out_fee_override,
    defaultFeePerMachineMnt: BILLING.fee,
    options: billable ? MONTH_OPTIONS.map((months) => ({ months, amountMnt: b.out_monthly_fee * months })) : [],
    openInvoice: invoiceView(open),
    history: history.map((h) => ({
      id: h.id,
      source: h.source,
      months: h.months,
      amountMnt: h.amount_mnt,
      status: h.status,
      createdAt: iso(h.created_at),
      paidAt: iso(h.paid_at),
      periodFrom: iso(h.period_from),
      periodTo: iso(h.period_to),
      note: h.note ?? null,
    })),
  };
}

const lastCheck = new Map();
function checkable(id) {
  const now = Date.now();
  if (now - (lastCheck.get(id) ?? 0) < 20_000) return false;
  lastCheck.set(id, now);
  if (lastCheck.size > 5000) lastCheck.clear();
  return true;
}

export class BillingError extends Error {
  constructor(code, status) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

/** B2: a QPay invoice for `months`, or the open one already made for them. */
export async function createInvoice(ownerId, months, userId, log = () => {}) {
  if (!MONTH_OPTIONS.includes(months)) throw new BillingError('INVALID_MONTHS', 400);
  const b = await store.ownerBilling(ownerId, BILLING);
  if (!b) throw new BillingError('NOT_FOUND', 404);
  if (b.out_state === 'exempt' || b.out_state === 'no_machines' || b.out_monthly_fee <= 0) {
    throw new BillingError('NOTHING_TO_BILL', 409);
  }
  // Only the NEWEST open invoice is reused, and only for the same months and
  // amount: it is the one the billing page shows, so handing back an older
  // one would put a different invoice on the screen than the one asked for.
  const newest = await store.openBillingInvoice(ownerId);
  if (newest && newest.months === months && newest.amount_mnt === b.out_monthly_fee * months) return invoiceView(newest);
  // A button that creates invoices on somebody else's merchant account.
  if ((await store.billingInvoicesLastHour(ownerId)) >= 10) throw new BillingError('RATE_LIMITED', 429);

  const amount = b.out_monthly_fee * months;
  const row = await store.insertBillingInvoice({
    ownerId, months, machines: b.out_machines, feePerMachine: b.out_fee_per_machine, amount, createdBy: userId,
  });
  // Unique for the operator's merchant forever, and never shaped like a
  // sale's orderNo or a credential probe's.
  const senderInvoiceNo = `bill-${row.id.replace(/-/g, '').slice(0, 12)}-${Date.now()}`;
  let invoice;
  try {
    invoice = await qpay.createInvoice({
      senderInvoiceNo,
      amount,
      description: `Coffeine систем ${months} сар · ${b.out_machines} машин`,
      callbackUrl: `${PUBLIC_URL}/qpay/billing/${row.id}/${macFor(row.id)}`,
    });
  } catch (err) {
    await store.cancelBillingInvoice(row.id).catch(() => {});
    log('billing invoice failed', ownerId, String(err?.message ?? err).split('\n')[0]);
    throw new BillingError('QPAY_UNREACHABLE', 502);
  }
  await store.attachBillingQpay(row.id, {
    invoiceId: invoice.invoiceId,
    senderInvoiceNo,
    qrText: invoice.qrText,
    qrImage: invoice.qrImage,
    shortUrl: invoice.shortUrl,
    urls: invoice.urls,
  });
  log('billing invoice', ownerId, `${months} сар`, `${amount}₮`);
  return invoiceView(await store.billingInvoice(row.id));
}

/**
 * B3 and the callback: asks QPay, and credits the months when it is paid.
 * Returns { status, paidUntil, ownerId }.
 */
export async function checkInvoice(invoiceId, { log = () => {} } = {}) {
  const row = await store.billingInvoice(invoiceId);
  if (!row) return { status: 'not_found' };
  if (row.status === 'paid') {
    const b = await store.ownerBilling(row.owner_id, BILLING);
    return { status: 'paid', paidUntil: iso(b?.out_paid_until), ownerId: row.owner_id, already: true };
  }
  if (!row.qpay_invoice_id) return { status: row.status, ownerId: row.owner_id };
  const { paid, paymentId, amount } = await qpay.checkPayment(row.qpay_invoice_id);
  if (!paid) {
    const b = await store.ownerBilling(row.owner_id, BILLING);
    return { status: row.status, paidUntil: iso(b?.out_paid_until), ownerId: row.owner_id };
  }
  const r = await store.billingMarkPaid(row.id, paymentId, Number.isFinite(amount) ? Math.round(amount) : null);
  if (r.out_status === 'underpaid') {
    log('billing underpaid', row.owner_id, `${amount} < ${row.amount_mnt}`);
    return { status: row.status, ownerId: row.owner_id, underpaid: true };
  }
  if (r.out_status === 'ok') {
    // Its machines may sell again this second, not in a minute.
    owners.forgetOwner(row.owner_id);
    log('billing paid', row.owner_id, `${row.months} сар`, `→ ${iso(r.out_paid_until)}`);
    const until = ubDate(r.out_paid_until);
    pushToOwners(
      [row.owner_id],
      { title: 'Төлбөр баталгаажлаа', body: `Coffeine систем ${until} хүртэл төлөгдсөн.`, url: '/billing', tag: 'billing' },
      log
    ).catch(() => {});
  }
  return { status: 'paid', paidUntil: iso(r.out_paid_until), ownerId: row.owner_id };
}

/** A date as an owner reads it: Ulaanbaatar's, YYYY-MM-DD. */
export function ubDate(d) {
  return new Date(new Date(d).getTime() + 8 * 3_600_000).toISOString().slice(0, 10);
}

const mnt = (n) => `${Math.round(Number(n) || 0).toLocaleString('en-US')}₮`;

/**
 * Reminders, from the sweep: three days before paid_until, and at
 * suspension. Once per stage per period; a payment starts the next period.
 * No link in the SMS, ever — the same rule as every message this system
 * sends an owner.
 */
export async function sendBillingNotices(log = () => {}) {
  const due = await store.billingNoticesDue(BILLING);
  for (const n of due) {
    const until = ubDate(n.out_paid_until);
    const text =
      n.out_stage === 'suspended'
        ? 'Coffeine: Системийн төлбөр төлөгдөөгүй тул машин QPay-ээр зарахаа зогслоо. Самбарын «Төлбөр» хэсгээс төлөхөд шууд сэргэнэ.'
        : `Coffeine: Системийн төлбөр ${until}-нд дуусна (сард ${mnt(n.out_monthly_fee)}). Самбарын «Төлбөр» хэсгээс QPay-ээр төлнө үү.`;
    await pushToOwners(
      [n.out_owner_id],
      { title: 'Системийн төлбөр', body: text.replace(/^Coffeine: /, ''), url: '/billing', tag: 'billing' },
      log
    ).catch(() => {});
    if (smsConfigured()) {
      for (const phone of await store.ownerContactPhones([n.out_owner_id])) {
        const sms = await sendSms(phone, text);
        await store
          .recordSmsSend(localNumber(phone), 'billing', sms.ok, sms.status ?? null,
            sms.ok ? null : String(sms.error ?? '').slice(0, 200), String(sms.reply ?? sms.error ?? '').slice(0, 200))
          .catch(() => {});
      }
    }
    await store.billingNoticeSent(n.out_owner_id, n.out_stage, n.out_paid_until);
    // A suspension starts now for every one of its machines.
    if (n.out_stage === 'suspended') owners.forgetOwner(n.out_owner_id);
    log('billing notice', n.out_stage, n.out_owner_id);
  }
  return due.length;
}
