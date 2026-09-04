import { query } from './db.js';

/**
 * One thin function per statement. No transactions.
 *
 * settle() makes two outbound HTTP calls (QPay, then the machine) and must
 * never hold a pooled connection across them — in transaction-mode pgbouncer
 * that pins a backend for the length of a network round trip, and a handful of
 * concurrent sales would exhaust the pool. Atomicity where it is actually
 * needed lives in the SQL functions from migration 001, each of which is a
 * single statement that claims or releases a row.
 *
 * This module is the write side used during dual-write (phase 2 of
 * docs/multi-tenant-plan.md): the memory Map is still the source of truth for
 * reads, so nothing here can cost a customer their coffee. Every caller wraps
 * these in a try/catch that only logs.
 */

/** deviceNo → machine, owner, and the sealed credential to invoice under. */
export async function resolveMachine(deviceNo) {
  const { rows } = await query(
    `select m.id            as machine_id,
            m.owner_id      as owner_id,
            m.qpay_credential_id,
            m.notify_url,
            m.amount_divisor,
            m.abandon_after_ms,
            m.status        as machine_status,
            m.updated_at    as machine_updated_at,
            o.status        as owner_status,
            c.sealed,
            c.key_id,
            c.status        as credential_status,
            c.is_active     as credential_active,
            c.updated_at    as credential_updated_at
       from public.machines m
       join public.owners o           on o.id = m.owner_id
       join public.qpay_credentials c on c.id = m.qpay_credential_id
      where m.device_no = $1`,
    [deviceNo]
  );
  return rows[0] ?? null;
}

/**
 * Records the order. `on conflict do nothing` is UNTARGETED on purpose: the
 * table carries several unique indexes (machine+order_no, credential+sender
 * invoice no, invoice id, payment id) and naming one of them makes a
 * collision on any OTHER index throw instead of being absorbed — which is
 * exactly the machine-retry case this is meant to survive.
 *
 * Returns the row when it was inserted, or null when an equal-enough order
 * already existed. The caller looks it up rather than assuming.
 */
export async function beginOrder(o) {
  const { rows } = await query(
    `insert into public.orders (
       machine_id, owner_id, qpay_credential_id,
       order_no, device_no, notify_url,
       product_id, product_name,
       raw_order_amount, amount_divisor, amount_mnt,
       qpay_sender_invoice_no, callback_url,
       status, expires_at
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'creating',
               now() + make_interval(secs => $14))
     on conflict do nothing
     returning id`,
    [
      o.machineId,
      o.ownerId,
      o.credentialId,
      o.orderNo,
      o.deviceNo,
      o.notifyUrl,
      o.productId ?? null,
      o.productName ?? null,
      o.rawOrderAmount,
      o.amountDivisor,
      o.amountMnt,
      o.senderInvoiceNo,
      o.callbackUrl,
      Math.round((o.abandonAfterMs ?? 600_000) / 1000),
    ]
  );
  return rows[0] ?? null;
}

export async function findOrderByMachine(machineId, orderNo) {
  const { rows } = await query(
    `select * from public.orders where machine_id = $1 and order_no = $2`,
    [machineId, orderNo]
  );
  return rows[0] ?? null;
}

/**
 * Attaching the invoice is what promotes the order to awaiting_payment.
 *
 * The schema refuses to hold an order in awaiting_payment (or any later state)
 * without a qpay_invoice_id — so an order can never claim to be waiting for a
 * payment that has nowhere to arrive. beginOrder therefore writes 'creating'
 * and this is the second half of the same logical step.
 */
export async function attachInvoice(orderId, { invoiceId, qrCode, qrTextLen }) {
  await query(
    `update public.orders
        set qpay_invoice_id = $2,
            qr_code         = $3,
            qr_text_len     = $4,
            status          = 'awaiting_payment',
            updated_at      = now()
      where id = $1
        and status = 'creating'`,
    [orderId, invoiceId, qrCode, qrTextLen ?? null]
  );
}

/**
 * The single-winner claim. Returns the row only to the caller that won it;
 * everyone else gets null and must not proceed.
 *
 * RETURNS SETOF in SQL, deliberately: a composite return type would hand back
 * one all-NULL row on zero matches, which every driver reports as success —
 * so two concurrent callers would both believe they had the claim, and the
 * customer would get two coffees for one payment.
 */
export async function claimSettle(orderId, { leaseSeconds, instance, notifyGraceSeconds }) {
  const { rows } = await query(
    `select * from app.claim_order_for_settle($1, $2, $3, $4)`,
    [orderId, leaseSeconds ?? 60, instance ?? null, notifyGraceSeconds ?? 120]
  );
  return rows[0] ?? null;
}

/**
 * Every state function below returns `setof public.orders`: the row it changed,
 * or nothing at all when its own WHERE clause refused the transition. Each
 * wrapper therefore returns the row or null, and callers are expected to stop
 * on a null. Swallowing the empty result turns a deliberate refusal — a
 * mismatched amount, a lost lease — into a silent no-op that the next step
 * then builds on.
 */
const one = async (sql, params) => (await query(sql, params)).rows[0] ?? null;

export const markPaymentConfirmed = (orderId, { paymentId, paidAmountMnt, leaseSeconds }) =>
  one(`select * from app.mark_payment_confirmed($1, $2, $3, $4)`, [
    orderId,
    paymentId ?? null,
    paidAmountMnt ?? null,
    leaseSeconds ?? 60,
  ]);

export const markNotifySent = (orderId) => one(`select * from app.mark_notify_sent($1)`, [orderId]);
export const finishSettle = (orderId) => one(`select * from app.finish_settle($1)`, [orderId]);
export const releaseSettle = (orderId, error) =>
  one(`select * from app.release_settle($1, $2)`, [orderId, error ?? null]);
export const giveUp = (orderId, error) =>
  one(`select * from app.give_up($1, $2)`, [orderId, error ?? null]);
export const markCancelled = (orderId) => one(`select * from app.mark_cancelled($1)`, [orderId]);
export const recordProductDone = (orderId, ok) =>
  one(`select * from app.record_product_done($1, $2)`, [orderId, ok]);

/**
 * The owner dashboard's numbers, aggregated in Postgres.
 *
 * `ownerId` must come from a verified JWT, never from a request body: this is
 * the whole of the access control on the query, because app.owner_stats has no
 * other scope. Everything the function reads is joined to this argument.
 */
export async function ownerStats(ownerId, { timezone, now } = {}) {
  const { rows } = await query(
    `select app.owner_stats($1, coalesce($2, 'Asia/Ulaanbaatar'), coalesce($3::timestamptz, now())) as stats`,
    [ownerId, timezone ?? null, now ?? null]
  );
  return rows[0]?.stats ?? null;
}

export async function claimAbandoned({ limit, leaseSeconds, instance } = {}) {
  const { rows } = await query(`select * from app.claim_abandoned_orders($1, $2, $3)`, [
    limit ?? 50,
    leaseSeconds ?? 60,
    instance ?? null,
  ]);
  return rows;
}

/**
 * Ingest errors are their own table because the most important one — a request
 * for a device nobody registered — has no order row to hang off. Without this
 * the machine fails silently and the only trace is a log line that rotates
 * away.
 */
export async function logIngestError({ path, deviceNo, orderNo, reason, payload, remoteIp }) {
  await query(
    `insert into public.ingest_errors (path, device_no, order_no, reason, payload, remote_ip)
     values ($1, $2, $3, $4, $5, $6)`,
    // `payload` is a jsonb column and a tempting place to dump the request
    // body. It must never carry one: bodies on this path are machine traffic
    // today, but the same habit applied to a credential route would persist a
    // merchant password in a table the operator reads casually.
    [path, deviceNo ?? null, orderNo ?? null, reason, payload ?? null, remoteIp ?? null]
  );
}
