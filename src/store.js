import { query, tx } from './db.js';

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
            o.paid_until    as owner_paid_until,
            o.billing_exempt as owner_billing_exempt,
            c.sealed,
            c.key_id,
            c.fingerprint     as credential_fingerprint,
            c.auth_fail_count as credential_auth_fail_count,
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

/**
 * The order, written once and complete: invoice attached, status
 * awaiting_payment, after the invoice exists.
 *
 * beginOrder + attachInvoice wrote it in two steps AFTER the QR was already
 * on the screen. A restart or a failed second statement in between left a
 * 'creating' row that every recovery path skips — and the customer who then
 * paid had no order anywhere. One statement has no in-between.
 *
 * source 'env' is the operator's own merchant (a machine nobody registered):
 * no owner, machine or credential. Returns the row id, whether this call
 * inserted it or an equal row already existed.
 */
export async function insertOrder(o) {
  const { rows } = await query(
    `insert into public.orders (
       source, machine_id, owner_id, qpay_credential_id, merchant_fp,
       order_no, device_no, notify_url,
       product_id, product_name,
       raw_order_amount, amount_divisor, amount_mnt,
       qpay_sender_invoice_no, callback_url,
       qpay_invoice_id, qr_code, qr_text_len,
       status, expires_at
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'awaiting_payment',
               now() + make_interval(secs => $19))
     on conflict do nothing
     returning id`,
    [
      o.source,
      o.machineId ?? null,
      o.ownerId ?? null,
      o.credentialId ?? null,
      o.merchantFp ?? null,
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
      o.invoiceId,
      o.qrCode,
      o.qrTextLen ?? null,
      Math.round((o.abandonAfterMs ?? 600_000) / 1000),
    ]
  );
  if (rows[0]?.id) return rows[0].id;
  return findOrderIdByDevice(o.deviceNo, o.orderNo, o.invoiceId);
}

/**
 * An order's id by the machine's own identifiers. orderNo is unique per
 * machine only; the invoice id, when known, pins the exact row.
 */
export async function findOrderIdByDevice(deviceNo, orderNo, invoiceId) {
  const { rows } = await query(
    `select o.id from public.orders o
      where o.device_no = $1 and o.order_no = $2
        and ($3::text is null or o.qpay_invoice_id = $3)
      order by o.created_at desc
      limit 1`,
    [deviceNo, orderNo, invoiceId ?? null]
  );
  return rows[0]?.id ?? null;
}

/** The state that decides what a refused claim meant. */
export const orderState = (orderId) =>
  one(`select status, notify_sent_at, product_done_at, payment_confirmed_at from public.orders where id = $1`, [orderId]);

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
    `select c.id, c.owner_id, c.sealed, c.key_id, c.status, c.is_active, c.fingerprint
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
export async function findLiveOrderByDevice(deviceNo, orderNo) {
  const { rows } = await query(
    `select o.* from public.orders o
      where o.device_no = $1 and o.order_no = $2
        and o.status in ('awaiting_payment','settling','payment_confirmed')
        and o.qpay_invoice_id is not null
      order by o.created_at desc
      limit 1`,
    [deviceNo, orderNo]
  );
  return rows[0] ?? null;
}

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
export const releaseSettle = (orderId, error, countAttempt = true) =>
  one(`select * from app.release_settle($1, $2, $3)`, [orderId, error ?? null, countAttempt]);
/** After the machine REFUSED the notify: retryable at once, not after the grace window (018). */
export const releaseSettleUndelivered = (orderId, error) =>
  one(`select * from app.release_settle_undelivered($1, $2)`, [orderId, error ?? null]);
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

/** Money confirmed, machine not told (or told and never answered past the grace window). */
export async function claimUnnotified({ limit, leaseSeconds, instance, notifyGraceSeconds } = {}) {
  const { rows } = await query(`select * from app.claim_unnotified_orders($1, $2, $3, $4)`, [
    limit ?? 20,
    leaseSeconds ?? 60,
    instance ?? null,
    notifyGraceSeconds ?? 120,
  ]);
  return rows;
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
    //
    // `machines` is the recognition signal: an owner is taught to stop if the
    // page does not show THEIR machine number, so it must come from here and
    // never from a default. `credential_id` is what the credential form posts
    // back to /owner/v1/credentials/verify.
    `select o.id, o.name, o.status,
            (select count(*)::int from public.machines m
              where m.owner_id = o.id and m.status = 'active') as active_machines,
            coalesce((select json_agg(json_build_object(
                               'device_no', m.device_no, 'label', m.label,
                               'location', m.location, 'status', m.status)
                             order by m.created_at)
                        from public.machines m
                       where m.owner_id = o.id and m.status <> 'retired'), '[]'::json) as machines,
            c.id                as credential_id,
            -- Whether the operator already entered the invoice code, so the
            -- owner's form can say it is optional. The code itself stays here.
            (c.pending_invoice_code is not null) as credential_invoice_code_set,
            c.status            as credential_status,
            c.is_active         as credential_active,
            c.username_hint     as credential_username_hint,
            c.last_verified_at  as credential_verified_at,
            (c.verify_expires_at is not null and c.verify_expires_at > now())
                                as credential_verification_open
       from public.owners o
       left join lateral (
         select qc.id, qc.status, qc.is_active, qc.username_hint,
                qc.last_verified_at, qc.verify_expires_at, qc.pending_invoice_code
           from public.qpay_credentials qc
          where qc.owner_id = o.id
          order by qc.is_active desc, qc.updated_at desc
          limit 1
       ) c on true
      where o.id = any($1::uuid[])
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

/** Migration 012: open invites naming this user's CONFIRMED phone, accepted. */
export async function claimInvitesByPhone(userId, sourceIp) {
  const { rows } = await query(`select * from app.claim_invites_by_phone($1, $2::inet)`, [userId, sourceIp ?? null]);
  return rows;
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

/**
 * The budget, reserved atomically (018): decides and records a 'pending'
 * attempt under a per-owner lock, so parallel requests cannot all pass it.
 * finishVerifyAttempt writes the real outcome once QPay has answered.
 */
export async function reserveVerifyAttempt(
  { ownerId, credentialId, actorUserId, usernameFp, remoteIp, userAgent },
  limits = {}
) {
  const { rows } = await query(
    `select * from app.reserve_verify_attempt($1,$2,$3,$4,$5::inet,$6,$7,$8,$9,$10,$11,$12)`,
    [
      ownerId,
      credentialId,
      actorUserId,
      usernameFp,
      remoteIp ?? null,
      userAgent ?? null,
      limits.perHour ?? 5,
      limits.perDay ?? 20,
      limits.distinctUsernamesPerDay ?? 2,
      limits.lockFails ?? 5,
      limits.lockMinutes ?? 60,
      limits.globalAuthFailsPer10Min ?? 50,
    ]
  );
  return rows[0] ?? { out_allowed: false, out_reason: 'UNAVAILABLE', out_retry_minutes: 60, out_attempt_id: null };
}

export async function finishVerifyAttempt(attemptId, outcome) {
  if (!attemptId) return;
  await query(`select app.finish_verify_attempt($1, $2)`, [attemptId, outcome]);
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
  // The ledger, not qpay_credentials: the credential's fingerprint is taken
  // over username AND invoice code, the attempt's over the username alone,
  // so comparing the two never matched — and every typo paged the operator.
  const { rows } = await query(
    `select exists (
       select 1 from public.credential_verify_attempts a
        where a.owner_id = $1 and a.username_fp = $2 and a.outcome = 'ok'
     ) as seen`,
    [ownerId, usernameFp]
  );
  return rows[0]?.seen ?? false;
}

/** A live merchant failing on the sale path, and recovering (018). */
export const noteSaleAuthFailure = (credentialId, code) =>
  query(`select app.note_sale_auth_failure($1, $2)`, [credentialId, code ?? null]);
export const noteSaleOk = (credentialId) => query(`select app.note_sale_ok($1)`, [credentialId]);

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
    // pending_sealed is read here, while it still exists: the abort that
    // follows clears it, and without it the probe invoice cannot be
    // cancelled — so it never was.
    `select c.id, c.owner_id, c.verify_invoice_id, c.pending_sealed
       from public.qpay_credentials c
      where c.verify_expires_at is not null
        and c.verify_expires_at < now()
      order by c.verify_expires_at
      limit $1`,
    [limit]
  );
  return rows;
}

/** The staged candidate's blob, read before an abort or confirm clears it. */
export async function pendingSealed(credentialId) {
  const { rows } = await query(`select c.pending_sealed from public.qpay_credentials c where c.id = $1`, [credentialId]);
  return rows[0]?.pending_sealed ?? null;
}

/**
 * Append-only note on a credential's timeline, for events with no SQL
 * function of their own — a verification invoice that could not be cancelled,
 * for instance. Never carries a secret: the caller passes named scalars.
 */
export async function logCredentialEvent(credentialId, action, detail = {}) {
  // actor_kind is NOT NULL and the action must be one the table's check
  // knows: this insert used to violate both, and every event was lost.
  await query(
    `insert into public.credential_audit (credential_id, owner_id, action, actor_kind, detail)
     select $1, c.owner_id, $2, 'system', $3::jsonb
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
export async function revokeOtherSessions(userId, keepSessionId) {
  // OTHER sessions: the one that just made the change stays signed in. It
  // was revoked too, and the owner was thrown out within the hour of
  // connecting QPay. Deleting the session rows also stops their push
  // subscriptions (018 session_alive), which revoking tokens alone did not.
  // A token without a session id (none is) leaves nothing to spare.
  await query(
    `update auth.refresh_tokens set revoked = true
      where user_id = $1::text and session_id is distinct from $2::uuid`,
    [userId, keepSessionId ?? null]
  );
  await query(`delete from auth.sessions where user_id = $1::uuid and id is distinct from $2::uuid`, [
    userId,
    keepSessionId ?? null,
  ]);
}

/** The number on the sales paperwork — the one a credential-change alert goes to. */
export async function ownerContactPhone(ownerId) {
  const { rows } = await query(`select contact_phone from public.owners where id = $1`, [ownerId]);
  return rows[0]?.contact_phone ?? null;
}

// ===========================================================================
// Operator console (migration 007).
//
// Every function here reads EVERY owner's revenue. The operator check lives
// in SQL — each takes the actor's user id and verifies membership of
// public.operators itself — so these wrappers deliberately do no checking of
// their own. Adding one here would create a second place the rule lives, and
// the two would drift.
// ===========================================================================

const operatorArgs = (actorUserId, { timezone, now } = {}) => [
  actorUserId,
  timezone ?? 'Asia/Ulaanbaatar',
  now ?? null,
];

/** The one-screen answer. Null when the caller is not an operator. */
export async function operatorOverview(actorUserId, opts) {
  const { rows } = await query(
    `select app.operator_overview($1, $2, coalesce($3::timestamptz, now())) as j`,
    operatorArgs(actorUserId, opts)
  );
  return rows[0]?.j ?? null;
}

export async function operatorOwners(actorUserId, opts) {
  const { rows } = await query(
    `select * from app.operator_owners($1, $2, coalesce($3::timestamptz, now()))`,
    operatorArgs(actorUserId, opts)
  );
  return rows;
}

export async function operatorMachines(actorUserId, opts) {
  const { rows } = await query(
    `select * from app.operator_machines($1, $2, coalesce($3::timestamptz, now()))`,
    operatorArgs(actorUserId, opts)
  );
  return rows;
}

export async function operatorProblems(actorUserId, { limit } = {}) {
  const { rows } = await query(`select * from app.operator_problems($1, $2, now())`, [
    actorUserId,
    Math.min(Math.max(Number(limit) || 50, 1), 200),
  ]);
  return rows;
}

export async function operatorHourly(actorUserId, { days, ownerId, machineId, timezone } = {}) {
  const { rows } = await query(
    `select * from app.operator_hourly($1, $2, $3::uuid, $4, now(), $5::uuid)`,
    [
      actorUserId,
      Math.min(Math.max(Number(days) || 30, 1), 365),
      ownerId ?? null,
      timezone ?? 'Asia/Ulaanbaatar',
      machineId ?? null,
    ]
  );
  return rows;
}

export async function operatorFunnel(actorUserId, { days, ownerId, timezone } = {}) {
  const { rows } = await query(
    `select * from app.operator_funnel($1, $2, $3::uuid, $4, now())`,
    [
      actorUserId,
      Math.min(Math.max(Number(days) || 30, 1), 365),
      ownerId ?? null,
      timezone ?? 'Asia/Ulaanbaatar',
    ]
  );
  return rows;
}

export async function operatorProducts(actorUserId, { days, ownerId } = {}) {
  const { rows } = await query(`select * from app.operator_products($1, $2, $3::uuid, now())`, [
    actorUserId,
    Math.min(Math.max(Number(days) || 30, 1), 365),
    ownerId ?? null,
  ]);
  return rows;
}

export async function operatorOnboarding(actorUserId) {
  const { rows } = await query(`select * from app.operator_onboarding($1)`, [actorUserId]);
  return rows;
}

/** The line-by-line statement an owner holds against their QPay export. */
export async function operatorReconciliation(actorUserId, { ownerId, from, to, timezone }) {
  const { rows } = await query(
    `select * from app.operator_reconciliation($1, $2::uuid, $3::timestamptz, $4::timestamptz, $5)`,
    [actorUserId, ownerId, from, to, timezone ?? 'Asia/Ulaanbaatar']
  );
  return rows;
}

/** True when this user is in public.operators. */
export async function isOperator(userId) {
  const { rows } = await query(`select app.is_operator_user($1) as ok`, [userId]);
  return rows[0]?.ok === true;
}

// ---------------------------------------------------------------------------
// Onboarding (migration 008). Writes, unlike everything above — and still no
// check here: each SQL function verifies operator membership itself.
// ---------------------------------------------------------------------------

/** Owner + first machine + empty credential slot, in one transaction. */
export async function operatorProvisionOwner(actorUserId, {
  credentialId, name, contactPhone, deviceNo, location, invoiceCode,
}) {
  const { rows } = await query(
    `select * from app.operator_provision_owner($1,$2,$3,$4,$5,$6,$7)`,
    [actorUserId, credentialId, name, contactPhone, deviceNo, location ?? null, invoiceCode]
  );
  return rows[0] ?? { out_status: 'error' };
}

/** A further machine for an existing business, on that business's QPay (016). */
export async function operatorAddMachine(actorUserId, { ownerId, deviceNo, location }) {
  const { rows } = await query(`select * from app.operator_add_machine($1,$2,$3,$4)`, [
    actorUserId,
    ownerId,
    deviceNo,
    location ?? null,
  ]);
  return rows[0] ?? { out_status: 'error' };
}

/** Takes the token's DIGEST. The raw token never reaches Postgres. */
export async function operatorCreateInvite(actorUserId, { ownerId, tokenHash, reference, invitedPhone, role }) {
  const { rows } = await query(
    `select * from app.operator_create_invite($1,$2,$3,$4,$5,$6)`,
    [actorUserId, ownerId, tokenHash, reference, invitedPhone, role]
  );
  return rows[0] ?? { out_status: 'error' };
}

export async function operatorSetInvoiceCode(actorUserId, ownerId, invoiceCode) {
  const { rows } = await query(`select app.operator_set_invoice_code($1,$2,$3) as status`, [
    actorUserId,
    ownerId,
    invoiceCode,
  ]);
  return rows[0]?.status ?? 'error';
}

// ---------------------------------------------------------------------------
// The owner's console (migration 014). The caller has already proved
// membership of ownerId; a device filter is matched against that owner's own
// machines inside SQL.
// ---------------------------------------------------------------------------
export async function ownerSummary(ownerId, { from, to, deviceNo }) {
  const { rows } = await query(`select app.owner_summary($1,$2,$3,$4) as s`, [ownerId, from, to, deviceNo ?? null]);
  return rows[0]?.s ?? null;
}

export async function ownerOrders(ownerId, { from, to, deviceNo, bucket, limit, offset }) {
  const { rows } = await query(`select * from app.owner_orders($1,$2,$3,$4,$5,$6,$7)`, [
    ownerId, from, to, deviceNo ?? null, bucket ?? null, limit ?? 50, offset ?? 0,
  ]);
  return rows;
}

export async function ownerMachines(ownerId, { from, to }) {
  const { rows } = await query(`select * from app.owner_machines($1,$2,$3)`, [ownerId, from, to]);
  return rows;
}

export async function ownerHourly(ownerId, { from, to, deviceNo }) {
  const { rows } = await query(`select * from app.owner_hourly($1,$2,$3,$4)`, [ownerId, from, to, deviceNo ?? null]);
  return rows;
}

export async function ownerProducts(ownerId, { from, to, deviceNo }) {
  const { rows } = await query(`select * from app.owner_products($1,$2,$3,$4)`, [ownerId, from, to, deviceNo ?? null]);
  return rows;
}

export async function ownerProblems(ownerId) {
  const { rows } = await query(`select * from app.owner_problems($1)`, [ownerId]);
  return rows;
}

/** Exact per-kind totals over the same windows the list uses (018). */
export async function ownerProblemSummary(ownerId) {
  const { rows } = await query(`select * from app.owner_problem_summary($1)`, [ownerId]);
  return rows;
}

/** Migration 011: invite texts sent to this number in the last day. */
export async function inviteSmsCount24h(phone) {
  const { rows } = await query(
    `select count(*)::int n from public.sms_sends
      where phone = app.norm_phone($1) and purpose = 'invite' and ok and at > now() - interval '24 hours'`,
    [phone]
  );
  return rows[0]?.n ?? 0;
}

/** One row per message, success or failure — the gateway's reply already scrubbed. */
export async function recordSmsSend(phone, purpose, ok, status, error, reply) {
  await query(`select app.record_sms_send($1, $2, $3, $4, $5, $6)`, [phone, purpose, ok, status, error, reply]);
}

/** Migration 015: machine faults exported from Jetinno's SaaS. */
export async function operatorImportFaults(actorUserId, fileName, rows) {
  // Its own transaction with its own timeout: a month's export is thousands
  // of rows, and the pool-wide 800 ms is sized for the machine path.
  return tx(async (q) => {
    await q(`set local statement_timeout = '30s'`);
    const { rows: r } = await q(`select * from app.operator_import_faults($1,$2,$3::jsonb)`, [
      actorUserId, fileName ?? null, JSON.stringify(rows),
    ]);
    return r[0] ?? { out_status: 'error' };
  });
}

export async function operatorFaults(actorUserId, limit) {
  const { rows } = await query(`select * from app.operator_faults($1,$2)`, [actorUserId, limit ?? 200]);
  return rows;
}

export async function operatorFaultImports(actorUserId) {
  const { rows } = await query(`select * from app.operator_fault_imports($1)`, [actorUserId]);
  return rows;
}

/** Migration 010: the slot an operator is about to fill for an owner. */
export async function operatorCredentialSlot(actorUserId, ownerId) {
  const { rows } = await query(`select * from app.operator_credential_slot($1,$2)`, [actorUserId, ownerId]);
  return rows[0] ?? { out_status: 'error' };
}

/** Writes the operator-proved, bridge-sealed credential and switches it on. */
export async function operatorSetCredential(actorUserId, { ownerId, credentialId, sealed, keyId, fp, usernameHint, invoiceCodeHint }) {
  const { rows } = await query(`select app.operator_set_credential($1,$2,$3,$4,$5,$6,$7,$8) as status`, [
    actorUserId, ownerId, credentialId, sealed, keyId, fp, usernameHint, invoiceCodeHint,
  ]);
  return rows[0]?.status ?? 'error';
}

/** Stamped on every signed machine request; throttled to once a minute in SQL. */
export async function touchMachineSeen(deviceNo) {
  await query(`select app.touch_machine_seen($1)`, [deviceNo]);
}

// ---------------------------------------------------------------------------
// Phone notifications (migration 017): Web Push subscriptions, the once-only
// sale push, and the operator's announcements to owners.
// ---------------------------------------------------------------------------

/**
 * One row per browser. A device that signs in as somebody else takes the row
 * with it: the endpoint is the browser's, and it now belongs to whoever is
 * signed in on it.
 */
export async function savePushSubscription(userId, { endpoint, p256dh, auth, notifySales, sessionId }) {
  // 018: remembers the session (a signed-out device stops receiving) and
  // keeps at most ten devices per person.
  const row = await one(`select * from app.save_push_subscription($1, $2, $3, $4, $5, $6::uuid)`, [
    userId, endpoint, p256dh, auth, notifySales, sessionId ?? null,
  ]);
  return row ? { notify_sales: row.out_notify_sales } : null;
}

export async function deletePushSubscription(userId, endpoint) {
  const { rowCount } = await query(
    `delete from public.push_subscriptions where user_id = $1 and endpoint = $2`,
    [userId, endpoint]
  );
  return rowCount > 0;
}

/** null when this browser is not subscribed for this person. */
export const pushSubscriptionState = (userId, endpoint) =>
  one(`select notify_sales from public.push_subscriptions where user_id = $1 and endpoint = $2`, [userId, endpoint]);

export const setPushSales = (userId, endpoint, on) =>
  one(
    `update public.push_subscriptions set notify_sales = $3
      where user_id = $1 and endpoint = $2 returning notify_sales`,
    [userId, endpoint, on]
  );

const SUB_COLUMNS = 's.id, s.endpoint, s.p256dh, s.auth';

/** Everyone who runs this business and wants to hear about its sales. */
export async function saleSubscriptions(ownerId) {
  const { rows } = await query(
    `select distinct ${SUB_COLUMNS}
       from public.push_subscriptions s
       join public.owner_members m on m.user_id = s.user_id
      where m.owner_id = $1 and s.notify_sales and app.session_alive(s.session_id)`,
    [ownerId]
  );
  return rows;
}

/** Every device of everyone who runs one of these businesses. */
export async function ownerSubscriptions(ownerIds) {
  const { rows } = await query(
    `select distinct ${SUB_COLUMNS}
       from public.push_subscriptions s
       join public.owner_members m on m.user_id = s.user_id
      where m.owner_id = any ($1::uuid[]) and app.session_alive(s.session_id)`,
    [ownerIds]
  );
  return rows;
}

export async function userSubscriptions(userId) {
  const { rows } = await query(
    `select ${SUB_COLUMNS} from public.push_subscriptions s where s.user_id = $1 and app.session_alive(s.session_id)`,
    [userId]
  );
  return rows;
}

/** Stamps the devices that took a push; drops the ones the push service has forgotten. */
export async function pushDelivered({ okIds = [], goneIds = [] }) {
  if (okIds.length) {
    await query(`update public.push_subscriptions set last_ok_at = now() where id = any ($1::bigint[])`, [okIds]);
  }
  if (goneIds.length) {
    await query(`delete from public.push_subscriptions where id = any ($1::bigint[])`, [goneIds]);
  }
}

/**
 * Claims the sale push for one confirmed order. The settle path can run more
 * than once for a payment; only the call that sets sale_push_at gets a row.
 */
export const claimSalePush = (orderId) =>
  one(
    `update public.orders o
        set sale_push_at = now()
      where o.id = $1 and o.sale_push_at is null and o.payment_confirmed_at is not null
      returning o.owner_id, coalesce(o.paid_amount_mnt, o.amount_mnt) as amount_mnt,
                o.device_no, o.product_name,
                (select coalesce(m.location, m.label) from public.machines m where m.id = o.machine_id) as place`,
    [orderId]
  );

export async function operatorCreateNotification(actorUserId, { title, body, link, target, channel, ownerIds }) {
  const { rows } = await query(
    `select * from app.operator_create_notification($1, $2, $3, $4, $5, $6, $7::uuid[])`,
    [actorUserId, title, body, link ?? null, target, channel, ownerIds ?? []]
  );
  return rows[0] ?? { out_status: 'error' };
}

export async function operatorNotifications(actorUserId, limit) {
  const { rows } = await query(`select * from app.operator_notifications($1, $2)`, [actorUserId, limit ?? 50]);
  return rows;
}

/** Delivery counts, written back after the sends finish. */
export async function recordNotificationDelivery(id, { pushSent = 0, pushFailed = 0, smsSent = 0, smsFailed = 0 }) {
  await query(
    `update public.notifications
        set push_sent = push_sent + $2, push_failed = push_failed + $3,
            sms_sent = sms_sent + $4, sms_failed = sms_failed + $5
      where id = $1`,
    [id, pushSent, pushFailed, smsSent, smsFailed]
  );
}

/** The contact phones on the paperwork of these businesses, each once. */
export async function ownerContactPhones(ownerIds) {
  const { rows } = await query(
    `select distinct o.contact_phone from public.owners o
      where o.id = any ($1::uuid[]) and o.contact_phone is not null`,
    [ownerIds]
  );
  return rows.map((r) => r.contact_phone);
}

/** An owner's inbox: announcements meant for the app, newest first. */
export async function ownerNotifications(ownerId, userId, limit = 50) {
  const { rows } = await query(
    `select n.id, n.title, n.body, n.link, n.created_at,
            n.created_at > coalesce(s.seen_at, '-infinity'::timestamptz) as unread
       from public.notifications n
       join public.notification_owners x on x.notification_id = n.id and x.owner_id = $1
       left join public.notification_seen s on s.user_id = $2 and s.owner_id = $1
      where n.channel in ('app', 'both')
      order by n.created_at desc
      limit $3`,
    [ownerId, userId, Math.min(Math.max(Number(limit) || 50, 1), 200)]
  );
  return rows;
}

export async function ownerUnreadNotifications(ownerId, userId) {
  const { rows } = await query(
    `select count(*)::int as n
       from public.notifications n
       join public.notification_owners x on x.notification_id = n.id and x.owner_id = $1
       left join public.notification_seen s on s.user_id = $2 and s.owner_id = $1
      where n.channel in ('app', 'both') and n.created_at > coalesce(s.seen_at, '-infinity'::timestamptz)`,
    [ownerId, userId]
  );
  return rows[0]?.n ?? 0;
}

export async function markNotificationsSeen(ownerId, userId) {
  await query(
    `insert into public.notification_seen (user_id, owner_id, seen_at) values ($1, $2, now())
     on conflict (user_id, owner_id) do update set seen_at = now()`,
    [userId, ownerId]
  );
}

// ---------------------------------------------------------------------------
// Members, from the operator's console (018). The operator check is in SQL.
// ---------------------------------------------------------------------------
export async function operatorOwnerMembers(actorUserId, ownerId) {
  const { rows } = await query(`select * from app.operator_owner_members($1, $2)`, [actorUserId, ownerId]);
  return rows;
}

export async function operatorRemoveMember(actorUserId, ownerId, userId) {
  const { rows } = await query(`select app.operator_remove_member($1, $2, $3) as status`, [actorUserId, ownerId, userId]);
  return rows[0]?.status ?? 'error';
}

/** The operator's emergency stop for one business's QPay (018). */
export async function operatorSetCredentialActive(actorUserId, ownerId, active) {
  const { rows } = await query(`select * from app.operator_set_credential_active($1, $2, $3)`, [
    actorUserId, ownerId, active,
  ]);
  return rows[0] ?? { out_status: 'error', out_credential_id: null, out_affected_machines: 0 };
}

// ---------------------------------------------------------------------------
// The portal's auth guard (018): one ledger row per allowed attempt.
// ---------------------------------------------------------------------------
export async function authAttempt(kind, ip, phone) {
  const { rows } = await query(`select * from app.auth_attempt($1, $2::inet, $3)`, [kind, ip ?? null, phone ?? null]);
  return rows[0] ?? { out_allowed: true, out_retry_seconds: 0 };
}

export const pruneAuthAttempts = () => query(`select app.prune_auth_attempts()`);

// ---------------------------------------------------------------------------
// Boot-time checks.
// ---------------------------------------------------------------------------
/** Machines whose recorded divisor disagrees with the one the bridge prices by. */
export async function divisorMismatches(divisor) {
  const { rows } = await query(
    `select count(*)::int n from public.machines m where m.status = 'active' and m.amount_divisor <> $1`,
    [divisor]
  );
  return rows[0]?.n ?? 0;
}

/** One active credential per sealing key, to prove the keyring opens them. */
export async function credentialPerKey() {
  const { rows } = await query(
    `select distinct on (c.key_id) c.id, c.owner_id, c.key_id, c.sealed
       from public.qpay_credentials c
      where c.is_active and c.sealed is not null
      order by c.key_id, c.updated_at desc`
  );
  return rows;
}

// ---------------------------------------------------------------------------
// The system subscription (migration 019). Fees and grace come from the
// bridge's env and are passed in, so one value decides charge and display.
// ---------------------------------------------------------------------------
export async function ownerBilling(ownerId, { fee, graceDays, noticeDays }) {
  const { rows } = await query(`select * from app.owner_billing($1, $2, $3, $4)`, [ownerId, fee, graceDays, noticeDays]);
  return rows[0] ?? null;
}

export async function billingHistory(ownerId, limit = 24) {
  const { rows } = await query(
    `select id, source, months, amount_mnt, status, created_at, paid_at, period_from, period_to, note
       from public.billing_invoices where owner_id = $1
      order by created_at desc limit $2`,
    [ownerId, limit]
  );
  return rows;
}

/** The newest open QPay invoice under a day old, optionally for a number of months. */
export async function openBillingInvoice(ownerId, months = null) {
  return one(
    `select * from public.billing_invoices
      where owner_id = $1 and source = 'qpay' and status = 'open' and qpay_invoice_id is not null
        and created_at > now() - interval '24 hours'
        and ($2::int is null or months = $2)
      order by created_at desc limit 1`,
    [ownerId, months]
  );
}

export async function billingInvoicesLastHour(ownerId) {
  const { rows } = await query(
    `select count(*)::int n from public.billing_invoices
      where owner_id = $1 and source = 'qpay' and created_at > now() - interval '1 hour'`,
    [ownerId]
  );
  return rows[0]?.n ?? 0;
}

export const insertBillingInvoice = ({ ownerId, months, machines, feePerMachine, amount, createdBy }) =>
  one(
    `insert into public.billing_invoices (owner_id, months, machines, fee_per_machine_mnt, amount_mnt, source, created_by)
     values ($1, $2, $3, $4, $5, 'qpay', $6) returning id`,
    [ownerId, months, machines, feePerMachine, amount, createdBy ?? null]
  );

export const attachBillingQpay = (id, { invoiceId, senderInvoiceNo, qrText, qrImage, shortUrl, urls }) =>
  query(
    `update public.billing_invoices
        set qpay_invoice_id = $2, qpay_sender_invoice_no = $3, qr_text = $4, qr_image = $5, short_url = $6, bank_urls = $7::jsonb
      where id = $1`,
    [id, invoiceId, senderInvoiceNo, qrText ?? null, qrImage ?? null, shortUrl ?? null, JSON.stringify(urls ?? [])]
  );

export const cancelBillingInvoice = (id) =>
  query(`update public.billing_invoices set status = 'cancelled' where id = $1 and status = 'open'`, [id]);

export const billingInvoice = (id) => one(`select * from public.billing_invoices where id = $1`, [id]);

export async function billingMarkPaid(id, paymentId, paidAmount) {
  const { rows } = await query(`select * from app.billing_mark_paid($1, $2, $3)`, [id, paymentId ?? null, paidAmount]);
  return rows[0] ?? { out_status: 'error' };
}

export async function operatorBillingOverview(actorUserId, { fee, graceDays, noticeDays }) {
  const { rows } = await query(`select * from app.operator_billing_overview($1, $2, $3, $4)`, [actorUserId, fee, graceDays, noticeDays]);
  return rows;
}

export async function operatorBillingExtend(actorUserId, { ownerId, months, amount, feePerMachine, machines, note }) {
  const { rows } = await query(`select * from app.operator_billing_extend($1, $2, $3, $4, $5, $6, $7)`, [
    actorUserId, ownerId, months, amount, feePerMachine, machines, note ?? null,
  ]);
  return rows[0] ?? { out_status: 'error', out_paid_until: null };
}

export async function operatorBillingSettings(actorUserId, ownerId, { setFee, fee, setExempt, exempt }) {
  const { rows } = await query(`select app.operator_billing_settings($1, $2, $3, $4, $5, $6) as status`, [
    actorUserId, ownerId, setFee, fee, setExempt, exempt,
  ]);
  return rows[0]?.status ?? 'error';
}

export async function billingNoticesDue({ fee, graceDays, noticeDays }) {
  const { rows } = await query(`select * from app.billing_notices_due($1, $2, $3)`, [fee, graceDays, noticeDays]);
  return rows;
}

export const billingNoticeSent = (ownerId, stage, paidUntil) =>
  query(`select app.billing_notice_sent($1, $2, $3)`, [ownerId, stage, paidUntil]);
