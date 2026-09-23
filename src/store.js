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

/** A credential row by id, for rebuilding an order's QPay client on rehydrate. */
export async function getCredentialById(credentialId) {
  const { rows } = await query(
    `select c.id, c.owner_id, c.sealed, c.key_id, c.status, c.is_active
       from public.qpay_credentials c
      where c.id = $1`,
    [credentialId]
  );
  return rows[0] ?? null;
}

/**
 * The restart-recovery read: a live order by its orderNo alone.
 *
 * Used only when the in-memory Map has no entry — the process restarted and a
 * webhook or /check arrived for an order created by the previous life. Only
 * statuses that can still become a coffee qualify; paid and cancelled rows
 * stay finished, and a 'creating' row has no invoice to check against.
 * orderNo is only unique per machine, so ties go to the newest row.
 */
export async function findLiveOrder(orderNo) {
  const { rows } = await query(
    `select o.* from public.orders o
      where o.order_no = $1
        and o.status in ('awaiting_payment','settling','payment_confirmed')
        and o.qpay_invoice_id is not null
      order by o.created_at desc
      limit 1`,
    [orderNo]
  );
  return rows[0] ?? null;
}

/**
 * Flips orders whose settle attempts ran out to needs_human (006). Before 006
 * is applied the function does not exist; that is a missing migration, not a
 * reason to spam the log every sweep tick — hence the 42883 swallow.
 */
export async function giveUpExhausted() {
  try {
    const { rows } = await query(`select app.give_up_exhausted() as n`);
    return rows[0]?.n ?? 0;
  } catch (err) {
    if (err.code === '42883') return 0;
    throw err;
  }
}

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

/**
 * The businesses behind a set of owner ids, for the portal's account switcher.
 *
 * Takes the ids rather than a user id: the caller has already resolved
 * membership from a verified token, and re-deriving it here would put a second
 * copy of that rule in a second place, where the two can drift.
 */
export async function ownersByIds(ownerIds) {
  if (!ownerIds?.length) return [];
  const { rows } = await query(
    // The credential summary never includes `sealed`, `pending_sealed` or any
    // key id. The portal needs to know whether the machine can take money and
    // which account it is pointed at — a masked hint answers both. There is a
    // public.my_qpay_credentials view for exactly this shape, but it filters
    // on auth.uid(), and the bridge connects as service_role with no
    // auth.uid() to read; the owner filter here is the access check instead,
    // and the caller has already proved membership of these ids.
    `select o.id, o.name, o.status,
            count(distinct m.id) filter (where m.status = 'active')::int as active_machines,
            c.status            as credential_status,
            c.is_active         as credential_active,
            c.username_hint     as credential_username_hint,
            c.last_verified_at  as credential_verified_at,
            (c.verify_expires_at is not null and c.verify_expires_at > now())
                                as credential_verification_open
       from public.owners o
       left join public.machines m on m.owner_id = o.id
       left join lateral (
         select qc.status, qc.is_active, qc.username_hint,
                qc.last_verified_at, qc.verify_expires_at
           from public.qpay_credentials qc
          where qc.owner_id = o.id
          order by qc.is_active desc, qc.updated_at desc
          limit 1
       ) c on true
      where o.id = any($1::uuid[])
      group by o.id, c.status, c.is_active, c.username_hint,
               c.last_verified_at, c.verify_expires_at
      order by o.name`,
    [ownerIds]
  );
  return rows;
}

// ===========================================================================
// Owner self-service credentials (migration 003).
//
// Thin wrappers, one per SQL function. The authorisation for every one of
// these lives in SQL — each takes p_actor_user_id and checks admin membership
// on the credential's OWN owner_id — so nothing here may "helpfully" resolve
// an owner on the caller's behalf. Passing an owner id these functions did not
// derive themselves would move the access check into JavaScript, which is
// exactly what migration 003 was written to avoid.
// ===========================================================================

/** Redeems an invite token, creating the owner_members row. */
export async function acceptOwnerInvite(token, userId, sourceIp) {
  const { rows } = await query(`select * from app.accept_owner_invite($1, $2, $3::inet)`, [
    token,
    userId,
    sourceIp ?? null,
  ]);
  return rows[0] ?? { out_status: 'not_found' };
}

/** The credential slot the owner is about to fill, with the admin check applied. */
export async function credentialSlot(credentialId, actorUserId) {
  const { rows } = await query(`select * from app.credential_slot($1, $2)`, [
    credentialId,
    actorUserId,
  ]);
  return rows[0] ?? null;
}

/** Rate limit. Counts only attempts that actually reached QPay. */
export async function credentialVerifyBudget(ownerId, usernameFp, limits = {}) {
  const { rows } = await query(`select * from app.credential_verify_budget($1,$2,$3,$4,$5,$6,$7)`, [
    ownerId,
    usernameFp,
    limits.perHour ?? 5,
    limits.perDay ?? 20,
    limits.distinctUsernamesPerDay ?? 2,
    limits.lockFails ?? 5,
    limits.lockMinutes ?? 60,
  ]);
  return rows[0] ?? { out_allowed: false, out_reason: 'UNAVAILABLE', out_retry_minutes: 60 };
}

export async function recordVerifyAttempt({
  ownerId,
  credentialId,
  actorUserId,
  usernameFp,
  outcome,
  remoteIp,
  userAgent,
}) {
  await query(`select app.record_verify_attempt($1,$2,$3,$4,$5,$6::inet,$7)`, [
    ownerId,
    credentialId,
    actorUserId,
    usernameFp,
    outcome,
    remoteIp ?? null,
    userAgent ?? null,
  ]);
}

/** Circuit breaker: auth failures across ALL owners, for the last N minutes. */
export async function globalAuthFails(minutes = 10) {
  const { rows } = await query(`select app.global_auth_fails($1) as n`, [minutes]);
  return rows[0]?.n ?? 0;
}

export async function recordVerifyFailure(credentialId, actorUserId, failureCode, remoteIp, userAgent) {
  const { rows } = await query(`select app.record_verify_failure($1,$2,$3,$4::inet,$5) as ok`, [
    credentialId,
    actorUserId,
    failureCode,
    remoteIp ?? null,
    userAgent ?? null,
  ]);
  return rows[0]?.ok ?? false;
}

/**
 * Has this owner ever had a credential with this merchant fingerprint?
 *
 * Distinguishes "you mistyped your password" from "that is a different QPay
 * account" — the first is a retry, the second is a question worth asking
 * before an owner's revenue moves.
 */
export async function usernameFpEverConfigured(ownerId, usernameFp) {
  const { rows } = await query(
    `select exists (
       select 1 from public.qpay_credentials c
        where c.owner_id = $1
          and (c.fingerprint = $2 or c.pending_fingerprint = $2)
     ) as seen`,
    [ownerId, usernameFp]
  );
  return rows[0]?.seen ?? false;
}

/** Stages the sealed candidate in pending_*; the live credential keeps serving. */
export async function beginCredentialVerification({
  credentialId,
  actorUserId,
  sealed,
  keyId,
  fp,
  usernameHint,
  invoiceCodeHint,
  nonce,
  invoiceId,
  ttlMinutes,
  remoteIp,
  xff,
  userAgent,
}) {
  const { rows } = await query(
    `select * from app.begin_credential_verification(
       $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::inet,$12,$13)`,
    [
      credentialId,
      actorUserId,
      sealed,
      keyId,
      fp,
      usernameHint,
      invoiceCodeHint,
      nonce,
      invoiceId,
      ttlMinutes ?? 20,
      remoteIp ?? null,
      xff ?? null,
      userAgent ?? null,
    ]
  );
  return rows[0] ?? { out_status: 'not_found' };
}

/** The nonce the owner read out of their own QPay portal. Promotes on success. */
export async function confirmCredentialVerification({
  credentialId,
  actorUserId,
  nonce,
  remoteIp,
  xff,
  userAgent,
}) {
  const { rows } = await query(
    `select * from app.confirm_credential_verification($1,$2,$3,$4::inet,$5,$6)`,
    [credentialId, actorUserId, nonce, remoteIp ?? null, xff ?? null, userAgent ?? null]
  );
  return rows[0] ?? { out_status: 'not_found' };
}

/** Discards the staged candidate. actorUserId may be null for the sweeper. */
export async function abortCredentialVerification(credentialId, actorUserId, reason) {
  const { rows } = await query(`select * from app.abort_credential_verification($1,$2,$3)`, [
    credentialId,
    actorUserId ?? null,
    reason,
  ]);
  return rows[0] ?? { out_status: 'not_found' };
}

export async function setCredentialActive(credentialId, actorUserId, active) {
  const { rows } = await query(`select * from app.set_credential_active($1,$2,$3)`, [
    credentialId,
    actorUserId,
    active,
  ]);
  return rows[0] ?? { out_ok: false, out_affected_machines: 0 };
}

/** Records that this user just proved possession of their phone. */
export async function touchStepUp(userId, source) {
  await query(`select app.touch_step_up($1, $2)`, [userId, source]);
}

/** Seconds since that proof, or null if there has never been one. */
export async function stepUpAgeSeconds(userId) {
  const { rows } = await query(`select app.step_up_age_seconds($1) as s`, [userId]);
  return rows[0]?.s ?? null;
}

/** One credential, for the owner's own screen. Never the sealed blob. */
export async function credentialForOwner(credentialId, actorUserId) {
  const { rows } = await query(
    `select c.id, c.owner_id, c.label, c.status, c.is_active,
            c.username_hint, c.invoice_code_hint, c.source,
            c.last_verified_at, c.last_error_code, c.auth_fail_count,
            c.configured_at, c.acceptance_confirmed_at,
            (c.verify_expires_at is not null and c.verify_expires_at > now()) as verification_open
       from public.qpay_credentials c
      where c.id = $1
        and c.owner_id = any (app.admin_owner_ids_of($2))`,
    [credentialId, actorUserId]
  );
  return rows[0] ?? null;
}

/** Staged verifications past their TTL, for the sweeper to abort. */
export async function expiredVerifications(limit = 20) {
  const { rows } = await query(
    `select c.id, c.owner_id, c.verify_invoice_id
       from public.qpay_credentials c
      where c.verify_expires_at is not null
        and c.verify_expires_at < now()
      order by c.verify_expires_at
      limit $1`,
    [limit]
  );
  return rows;
}

/**
 * Append-only note on a credential's timeline, for events with no SQL
 * function of their own — a verification invoice that could not be cancelled,
 * for instance. Never carries a secret: the caller passes named scalars.
 */
export async function logCredentialEvent(credentialId, action, detail = {}) {
  await query(
    `insert into public.credential_audit (credential_id, owner_id, action, detail)
     select $1, c.owner_id, $2, $3::jsonb
       from public.qpay_credentials c where c.id = $1`,
    [credentialId, action, JSON.stringify(detail)]
  );
}

/**
 * Signs the user out everywhere else after their merchant account changes.
 *
 * Supabase owns the session table, and the bridge connects as service_role,
 * so this is a direct delete of that user's other refresh tokens. If the
 * schema is not reachable the change still stands — this is defence after the
 * fact, not the gate — so a failure is swallowed by the caller.
 */
export async function revokeOtherSessions(userId) {
  await query(`update auth.refresh_tokens set revoked = true where user_id = $1::text`, [userId]);
}

/** The number on the sales paperwork — the one a credential-change alert goes to. */
export async function ownerContactPhone(ownerId) {
  const { rows } = await query(`select contact_phone from public.owners where id = $1`, [ownerId]);
  return rows[0]?.contact_phone ?? null;
}
