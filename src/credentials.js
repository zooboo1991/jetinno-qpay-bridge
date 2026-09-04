/**
 * src/credentials.js — owner self-service QPay credential intake.
 *
 * This is the only network path in the system that ever sees a plaintext QPay
 * merchant password. It supersedes decision #33 of docs/multi-tenant-plan.md
 * ("offline CLI only; no HTTP endpoint accepts a plaintext QPay password"),
 * whose stated condition was "until there is a real session system". This
 * module plus migration 003 plus the Next.js portal are that system. If any of
 * the invariants below stops being true, revert to scripts/add-owner.js.
 *
 * FOUR INVARIANTS, in priority order:
 *
 *  1. PLAINTEXT CONFINEMENT. The password exists in exactly one function scope
 *     (`runVerification`) and inside `seal()`. It is never a property of an
 *     object a logger, an error, or a serializer can reach. This module does
 *     NOT import server.js's log() — it cannot write to the /recent ring even
 *     by accident. safeLog() below has no rest parameter and no object spread,
 *     so it is physically incapable of logging a body.
 *
 *     This is not theoretical. Verified on this repo: with the global
 *     express.json() that server.js:6 installs today, a MALFORMED body reaches
 *     body-parser, which attaches the raw request text to the SyntaxError it
 *     throws as an own enumerable property `err.body` (body-parser
 *     lib/read.js:131). One house-style line — `app.use((err,req,res,next) =>
 *     log('unhandled', err))` — then puts the live merchant password into the
 *     200-line ring that GET /recent serves. That happens on a request which
 *     never reaches this file, so nothing in here can defend against it: the
 *     defence is `delete err.body` in server.js's error handler, and removing
 *     the global parser. See PHASE 0 of the plan.
 *
 *     Also verified: err.message does NOT quote the body on Node 22/26, so
 *     `delete err.body` is the load-bearing control, not a belt-and-braces one.
 *
 *  2. WRITE-ONLY. Nothing here returns a credential, plaintext or sealed.
 *     `open()` is imported for exactly one purpose — cancelling an abandoned
 *     verification invoice — and its result never leaves that function.
 *
 *  3. BOUNDED AUTHORITY. This module can fill or replace the sealed blob of a
 *     credential row that ALREADY EXISTS and is ALREADY WIRED to that owner's
 *     machines by the operator's CLI. It cannot INSERT a credential, create an
 *     owner, or write to `machines` at all. An attacker holding an owner
 *     session therefore cannot re-point a machine — only replace the merchant
 *     behind a machine that is already theirs, which is detected (audit + SMS
 *     to the number on the paperwork + weekly reconciliation), not prevented.
 *
 *  4. AUTHORISATION IS IN SQL. Every write function in migration 003 takes
 *     p_actor_user_id and checks admin membership on the credential's OWN
 *     owner_id. The checks below are the first line, not the only line.
 */
import express from 'express';
import crypto from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { seal, open, fingerprint, merchantIdentity, activeKeyId, credentialAad } from './crypto.js';
import * as qpay from './qpay.js';
import * as store from './store.js';
import * as owners from './owners.js';
import * as alerts from './alerts.js';

function reqEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set — refusing to start`);
  return v;
}

const SUPABASE_URL = reqEnv('SUPABASE_URL').replace(/\/+$/, '');
const PORTAL_ORIGIN = reqEnv('PORTAL_ORIGIN').replace(/\/+$/, ''); // e.g. https://kofe.mn
const JWKS = createRemoteJWKSet(new URL(`${SUPABASE_URL}/auth/v1/.well-known/jwks.json`));

/**
 * Budgets. An owner configures a credential a handful of times in the life of
 * a machine, so limits tight enough to make this a useless credential-testing
 * oracle are still far above honest use.
 *
 * Note what is NOT budgeted: opening the form. Only attempts that actually
 * reached QPay count. Budgeting page loads locks an owner out of connecting
 * their own payment account because they went to look up their password.
 */
const LIMITS = {
  perHour: 5,
  perDay: 20,
  distinctUsernamesPerDay: 2, // an owner has one or two QPay merchants, ever
  lockFails: 5,
  lockMinutes: 60,
  globalAuthFailsPer10Min: 50,
  minResponseMs: 1200, // caps the oracle at ~50 questions/minute and removes timing as a channel
};

const TIMEOUT = { token: 4000, invoice: 6000, cancel: 6000 };
const VERIFY_AMOUNT_MNT = 10; // not 1₮: a merchant-level minimum would fail a CORRECT credential
const VERIFY_TTL_MINUTES = Number(process.env.CRED_VERIFY_TTL_MINUTES ?? 20);

// Step-up. Two levels on purpose.
//   FIRST entry: the invite-redemption OTP is minutes old and the operator is
//   standing in the shop. Charging a SECOND SMS here — through an
//   international A2P route into a Mongolian carrier — is a coin flip on
//   whether onboarding completes at all, defending against a threat (a stolen
//   session) that is not present at an installation.
//   Later CHANGES happen alone, months later, from memory. That is the
//   stolen-session case, and it gets a fresh OTP.
const STEP_UP_FIRST_SECONDS = Number(process.env.CRED_STEP_UP_FIRST_SECONDS ?? 3600);
const STEP_UP_CHANGE_SECONDS = Number(process.env.CRED_STEP_UP_CHANGE_SECONDS ?? 600);

const router = express.Router();

/**
 * The ONLY logger this module may use. Named scalars, nothing else.
 *
 * A logger that accepts an arbitrary object is precisely how a password
 * reaches a log ring: every other handler in server.js opens by stringifying
 * the whole request body into log(), and copy-paste is that file's default
 * behaviour. No rest parameter, no spread, no error object — by construction.
 */
function safeLog({ event, ownerId, credentialId, actorUserId, outcome, status, ms, incident }) {
  process.stdout.write(
    JSON.stringify({
      at: new Date().toISOString(),
      src: 'credentials',
      event,
      ownerId: ownerId ?? null,
      credentialId: credentialId ?? null,
      actorUserId: actorUserId ?? null,
      outcome: outcome ?? null,
      status: status ?? null,
      ms: ms ?? null,
      incident: incident ?? null,
    }) + '\n'
  );
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Fixed enum. The portal owns every Mongolian string; the bridge owns none, so
 * no upstream text can ride out in a response body (decision #28).
 */
function reply(res, httpStatus, code, extra = {}) {
  res.set('Cache-Control', 'no-store');
  res.status(httpStatus).json({ ok: code === 'OK', code, ...extra });
}

// ---------------------------------------------------------------------------
// Transport gate. Bearer-only, exact-origin CORS, no cookies anywhere — so the
// bridge acquires no CSRF surface at all and needs no CSRF machinery.
// ---------------------------------------------------------------------------
router.use((req, res, next) => {
  if (!req.secure && req.get('x-forwarded-proto') !== 'https') return reply(res, 400, 'FORBIDDEN');

  const origin = req.get('origin');
  if (origin) {
    if (origin !== PORTAL_ORIGIN) return reply(res, 403, 'FORBIDDEN');
    res.set('Access-Control-Allow-Origin', PORTAL_ORIGIN);
    res.set('Vary', 'Origin');
    res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    res.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.set('Access-Control-Max-Age', '600');
    // Deliberately NOT Access-Control-Allow-Credentials. Bearer tokens only.
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

// 2kb, and it is only effective because server.js no longer installs a global
// express.json(). body-parser sets req._body before parsing, so a later
// router-scoped parser silently no-ops behind a global one — verified on this
// repo: a 50,040-byte body reached the handler with HTTP 200 while a 2kb cap
// was nominally in force.
router.use(express.json({ limit: '2kb', type: 'application/json' }));

/**
 * Who is calling? Verified here, against Supabase's JWKS, by the bridge
 * itself. The portal never asserts an identity to us and could not be believed
 * if it did.
 */
async function authenticate(req) {
  const jwt = (req.get('authorization') ?? '').replace(/^Bearer\s+/i, '').trim();
  if (!jwt) return null;
  try {
    const { payload } = await jwtVerify(jwt, JWKS, {
      issuer: `${SUPABASE_URL}/auth/v1`,
      audience: 'authenticated',
      clockTolerance: 30,
    });
    return payload.sub ? { userId: payload.sub } : null;
  } catch {
    safeLog({ event: 'jwt_invalid', outcome: 'rejected' });
    return null;
  }
}

// ---------------------------------------------------------------------------
// Input validation. Runs before any QPay contact, so a malformed body can
// never cost a budgeted attempt or a round trip to Ulaanbaatar.
// ---------------------------------------------------------------------------
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PRINTABLE = /^[\x21-\x7e]+$/; // no spaces, no control chars, no unicode lookalikes

function readCredentialFields(body) {
  if (!body || typeof body !== 'object') return { error: 'body' };
  const credentialId = String(body.credentialId ?? '');
  // Trimmed: Android pastes drag whitespace and a leading space in a username
  // is a support call three days later. The PASSWORD is never trimmed —
  // silently altering a password is worse than the typo. The portal warns
  // about surrounding whitespace client-side and lets the owner decide.
  const username = String(body.username ?? '').trim();
  const password = String(body.password ?? '');

  if (!UUID.test(credentialId)) return { error: 'credentialId' };
  if (username.length < 3 || username.length > 64 || !PRINTABLE.test(username)) return { error: 'username' };
  if (password.length < 4 || password.length > 128 || /[\x00-\x1f]/.test(password)) return { error: 'password' };
  return { credentialId, username, password };
}

const maskUsername = (u) => (u.length <= 4 ? '••••' : `${u.slice(0, 2)}••••••${u.slice(-2)}`);
const maskCode = (c) => `••••${String(c).slice(-4)}`;
const usernameFp = (u) => fingerprint(`u:${u.trim().toLowerCase()}`);
const newNonce = () => String(crypto.randomInt(0, 10000)).padStart(4, '0');

/**
 * Classifies a QPay failure into the three things an owner can act on
 * differently.
 *
 * Collapsing "wrong password" into "something went wrong" is the single worst
 * UX decision available here: an owner with correct credentials retries during
 * a QPay outage, is told the password is wrong, concludes they are locked out,
 * and phones the operator — which is the model this whole feature exists to
 * replace. Yes, that distinction is one clean bit of oracle. It is worth it;
 * see the accepted-risk list in the plan.
 */
function classify(err) {
  const status = Number(err?.status ?? NaN);
  if (status === 401 || status === 403) return 'auth_failed';
  if (status >= 500) return 'qpay_unreachable';
  if (status >= 400) return 'client_error';
  const name = err?.name ?? '';
  const code = err?.cause?.code ?? '';
  if (name === 'TimeoutError' || name === 'AbortError') return 'qpay_unreachable';
  if (/ENOTFOUND|ECONNREFUSED|ECONNRESET|EAI_AGAIN|UND_ERR/.test(code)) return 'qpay_unreachable';
  return 'unknown';
}

/**
 * The verification itself. Three proofs, in increasing order of what they buy:
 *
 *   1. token      — proves username + password. Proves nothing about the
 *                   invoice code and nothing about WHOSE account it is.
 *   2. invoice    — proves the invoice code. This is the likelier of the two
 *                   credential typos in general, though the operator now
 *                   supplies the invoice code at invite time so in practice a
 *                   failure here means the OPERATOR typed it wrong, and the
 *                   message must say so rather than blaming the owner.
 *   3. the nonce  — proves the account is the OWNER'S. Steps 1 and 2 answer
 *                   "do these credentials work?", which is a different
 *                   question from "are they yours?". An owner with two
 *                   businesses, or whose QPay account was opened under a
 *                   partner's entity, passes 1 and 2 perfectly and sends every
 *                   coffee sale to the wrong real account, undetected, forever.
 *                   Step 3 is the only thing in the system that catches it,
 *                   and it catches it in seconds with the operator present.
 *
 * The invoice is deliberately NOT cancelled here: the owner has to be able to
 * see it in their own portal. It is cancelled at confirm, at abort, or by the
 * sweeper.
 */
async function runVerification({ credentialId, ownerId, username, password, invoiceCode, nonce }) {
  const client = qpay.forOwner({ ownerId, credentialId, username, password, invoiceCode });

  // Step 1 — auth. Independent deadline: the caller is a human on a phone, not
  // Jetinno's 8-second budget, but a hung socket must still not park a
  // connection for undici's 300s default.
  await client.warmToken(AbortSignal.timeout(TIMEOUT.token));

  // Step 2 + 3 — a real 10₮ invoice on the candidate merchant. sender_invoice_no
  // is shaped so it can never collide with, or be mistaken for, a sale's
  // `${deviceNo}-${orderNo}`. QPay rejects a repeated sender_invoice_no
  // forever, hence the epoch suffix.
  let invoice;
  try {
    invoice = await client.createInvoice({
      senderInvoiceNo: `verify-${credentialId.replace(/-/g, '').slice(0, 12)}-${Date.now()}`,
      amount: VERIFY_AMOUNT_MNT,
      // The owner reads THIS line out of their own QPay portal and types the
      // four digits back. It must be self-explanatory in Mongolian, and the
      // nonce must be the last thing on the line so it survives truncation in
      // a narrow portal column.
      description: `Кофе машин холболт шалгах ${nonce}`,
      // NEVER /qpay/callback/:ref. A paid verification invoice entering the
      // settle path must be impossible, not merely unlikely: settle's
      // ref-is-not-a-uuid branch falls back to lookup by order_no, a namespace
      // a verify sender_invoice_no must never enter.
      callbackUrl: `${process.env.PUBLIC_URL}/qpay/verify-callback`,
      signal: AbortSignal.timeout(TIMEOUT.invoice),
    });
  } catch (err) {
    err.stage = 'invoice';
    throw err;
  }

  const sealed = seal(
    { username, password, invoiceCode },
    { context: credentialAad({ credentialId, ownerId }) }
  );

  return {
    sealed,
    keyId: activeKeyId(),
    fp: fingerprint(merchantIdentity({ username, invoiceCode })),
    usernameHint: maskUsername(username),
    invoiceCodeHint: maskCode(invoiceCode),
    invoiceId: invoice.invoiceId,
  };
}

/** Best effort. A live 10₮ QR nobody will ever see is a trivial loss; an
 *  UNTRACKED one is not, so a failed cancel is recorded and pages the operator. */
async function cancelVerifyInvoice({ credentialId, ownerId, sealedBlob, invoiceId }) {
  if (!invoiceId || !sealedBlob) return;
  try {
    const creds = open(sealedBlob, { context: credentialAad({ credentialId, ownerId }) });
    const client = qpay.forOwner({ ownerId, credentialId, ...creds });
    await client.cancelInvoice(invoiceId, AbortSignal.timeout(TIMEOUT.cancel));
  } catch {
    await store.logCredentialEvent(credentialId, 'VERIFY_CANCEL_FAILED', { invoiceId }).catch(() => {});
    alerts.pageOperator('verify invoice left uncancelled', { credentialId, invoiceId });
  }
}

// ===========================================================================
// POST /owner/v1/invites/redeem   { token }
// ===========================================================================
router.post('/invites/redeem', async (req, res) => {
  const body = req.body;
  req.body = undefined;
  const actor = await authenticate(req);
  if (!actor) return reply(res, 401, 'FORBIDDEN');

  const token = String(body?.token ?? '');
  if (token.length < 20 || token.length > 128) return reply(res, 400, 'INVALID_INPUT', { field: 'token' });

  const r = await store.acceptOwnerInvite(token, actor.userId, req.ip);
  safeLog({ event: 'invite_redeem', actorUserId: actor.userId, outcome: r.out_status });

  if (r.out_status === 'accepted' || r.out_status === 'already_accepted') {
    // THIS is what makes the credential screen openable without a second SMS.
    await store.touchStepUp(actor.userId, 'invite_redeem');
    return reply(res, 200, 'OK', {
      status: r.out_status, ownerId: r.out_owner_id, ownerName: r.out_owner_name, role: r.out_role,
    });
  }
  if (r.out_status === 'phone_mismatch') {
    alerts.pageOperator('invite presented by a non-matching phone', { status: r.out_status });
  }
  return reply(res, 409, 'INVITE_' + String(r.out_status).toUpperCase());
});

// ===========================================================================
// POST /owner/v1/credentials/verify   { credentialId, username, password }
// Phase 1: prove the credentials work, create the 10₮ probe, stage the blob.
// ===========================================================================
router.post('/credentials/verify', async (req, res) => {
  const startedAt = Date.now();
  const incident = crypto.randomBytes(4).toString('hex');

  // Defeats the whole class of "an error handler serialised the request".
  const body = req.body;
  req.body = undefined;

  const pad = async () => {
    const left = LIMITS.minResponseMs - (Date.now() - startedAt);
    if (left > 0) await sleep(left);
  };

  let ownerId = null;
  let credentialId = null;
  let actorUserId = null;
  let fp = null;
  let outcome = 'error';
  let recordAttempt = false;

  try {
    const actor = await authenticate(req);
    if (!actor) { await pad(); return reply(res, 401, 'FORBIDDEN'); }
    actorUserId = actor.userId;

    const fields = readCredentialFields(body);
    if (fields.error) { await pad(); return reply(res, 400, 'INVALID_INPUT', { field: fields.error }); }
    credentialId = fields.credentialId;

    // Resolve the credential FIRST, then check admin membership on ITS owner.
    // Never derive "the" owner from the user: a user can be a member of several
    // owners (one person, two businesses; a shop that changed hands), and
    // picking whichever membership sorted first 404s every credential
    // belonging to the other business — permanently, with no way for the UI to
    // say which one it meant.
    const slot = await store.credentialSlot(credentialId, actor.userId);
    if (!slot || !slot.out_is_admin) {
      safeLog({ event: 'slot_denied', credentialId, actorUserId, outcome: 'rejected' });
      await pad();
      return reply(res, 404, 'FORBIDDEN');
    }
    ownerId = slot.out_owner_id;

    if (!slot.out_pending_invoice_code) {
      // The operator has not filled the invoice code on this slot. An owner
      // cannot fix that and must not be shown a field for it.
      await pad();
      return reply(res, 409, 'SLOT_INCOMPLETE');
    }

    // Step-up. First entry rides the redemption OTP; a change needs a fresh one.
    const isFirstEntry = slot.out_status === 'pending';
    const maxAge = isFirstEntry ? STEP_UP_FIRST_SECONDS : STEP_UP_CHANGE_SECONDS;
    const age = await store.stepUpAgeSeconds(actor.userId);
    if (age > maxAge) {
      // Not an error — the expected response for a returning owner. The portal
      // sends an OTP and resubmits, and the UI presents it as a confirmation
      // step, not a failure. The form fields are NEVER cleared while this
      // happens: they hold a password the owner typed blind on a phone keyboard.
      await pad();
      return reply(res, 401, 'REAUTH_REQUIRED');
    }

    fp = usernameFp(fields.username);
    const budget = await store.credentialVerifyBudget(ownerId, fp, LIMITS);
    if (!budget.out_allowed) {
      await store.recordVerifyAttempt({
        ownerId, credentialId, actorUserId, usernameFp: fp, outcome: 'locked',
        remoteIp: req.ip, userAgent: req.get('user-agent'),
      }).catch(() => {});
      if (budget.out_reason === 'TOO_MANY_MERCHANTS') {
        alerts.pageOperator('third distinct QPay username in 24h', { ownerId });
      }
      safeLog({ event: 'rate_limited', ownerId, credentialId, actorUserId, outcome: budget.out_reason });
      await pad();
      return reply(res, 429, budget.out_reason, { retryAfterMinutes: budget.out_retry_minutes });
    }

    if ((await store.globalAuthFails(10)) > LIMITS.globalAuthFailsPer10Min) {
      alerts.pageOperator('credential verification circuit breaker tripped', {});
      await pad();
      return reply(res, 503, 'RATE_LIMITED', { retryAfterMinutes: 30 });
    }

    recordAttempt = true;
    const nonce = newNonce();
    let v;
    try {
      v = await runVerification({
        credentialId,
        ownerId,
        username: fields.username,
        password: fields.password,
        invoiceCode: slot.out_pending_invoice_code,
        nonce,
      });
    } catch (err) {
      const kind = classify(err);
      if (kind === 'qpay_unreachable') {
        outcome = 'qpay_unreachable';
        recordAttempt = false; // an outage must not lock out every honest owner at once
        safeLog({ event: 'verify_failed', ownerId, credentialId, actorUserId, outcome, incident });
        await pad();
        return reply(res, 502, 'QPAY_UNREACHABLE');
      }
      if (kind === 'auth_failed') {
        outcome = 'auth_failed';
        await store.recordVerifyFailure(credentialId, actorUserId, 'QPAY_AUTH_FAILED', req.ip, req.get('user-agent')).catch(() => {});
        // An owner who fat-fingers retries their OWN username. Someone testing
        // a username this owner has never successfully configured is not a
        // confused shop manager.
        const known = await store.usernameFpEverConfigured(ownerId, fp).catch(() => true);
        if (!known) alerts.pageOperator('auth failure on an unfamiliar QPay username', { ownerId });
        safeLog({ event: 'verify_failed', ownerId, credentialId, actorUserId, outcome, incident });
        await pad();
        return reply(res, 400, 'AUTH_FAILED');
      }
      if (err?.stage === 'invoice') {
        outcome = 'invoice_code_failed';
        await store.recordVerifyFailure(credentialId, actorUserId, 'QPAY_INVOICE_CODE_REJECTED', req.ip, req.get('user-agent')).catch(() => {});
        // The owner never typed this value — the operator did, at invite time.
        // The portal's copy for this code blames the operator and gives his
        // number, and the operator is paged, because the owner cannot fix it.
        alerts.pageOperator('invoice_code rejected by QPay — operator entered it', { ownerId, credentialId });
        safeLog({ event: 'verify_failed', ownerId, credentialId, actorUserId, outcome, incident });
        await pad();
        return reply(res, 400, 'INVOICE_CODE_FAILED');
      }
      // `err` is classified and then dropped. It is NEVER logged: QPay's 401
      // body echoes the merchant username and pg errors echo statement text.
      outcome = 'error';
      safeLog({ event: 'verify_failed', ownerId, credentialId, actorUserId, outcome, incident });
      await pad();
      return reply(res, 500, 'SERVER_ERROR', { incident });
    }

    const begun = await store.beginCredentialVerification({
      credentialId, actorUserId, sealed: v.sealed, keyId: v.keyId, fp: v.fp,
      usernameHint: v.usernameHint, invoiceCodeHint: v.invoiceCodeHint,
      nonce, invoiceId: v.invoiceId, ttlMinutes: VERIFY_TTL_MINUTES,
      remoteIp: req.ip, xff: req.get('x-forwarded-for'), userAgent: req.get('user-agent'),
    });

    if (begun.out_status !== 'ok') {
      outcome = 'rejected';
      // The candidate merchant is real and reachable, so its probe invoice
      // exists and must not be orphaned.
      await cancelVerifyInvoice({ credentialId, ownerId, sealedBlob: v.sealed, invoiceId: v.invoiceId });
      if (begun.out_status === 'duplicate_other_owner') {
        alerts.pageOperator('duplicate merchant across owners', { ownerId, credentialId });
      }
      safeLog({ event: 'verify_rejected', ownerId, credentialId, actorUserId, outcome: begun.out_status });
      await pad();
      return reply(res, 409, begun.out_status.toUpperCase());
    }

    outcome = 'ok';
    safeLog({ event: 'verify_started', ownerId, credentialId, actorUserId, outcome, ms: Date.now() - startedAt });
    await pad();
    return reply(res, 200, 'OK', {
      // The nonce is NOT returned. If the response carried it, the whole step
      // would prove nothing: the page could show the owner a number to type
      // back without them ever opening their portal.
      expiresInMinutes: VERIFY_TTL_MINUTES,
      amountMnt: VERIFY_AMOUNT_MNT,
      usernameHint: v.usernameHint,
    });
  } catch {
    safeLog({ event: 'unhandled', ownerId, credentialId, actorUserId, outcome: 'error', incident });
    await pad();
    return reply(res, 500, 'SERVER_ERROR', { incident });
  } finally {
    if (recordAttempt) {
      await store.recordVerifyAttempt({
        ownerId, credentialId, actorUserId, usernameFp: fp, outcome,
        remoteIp: req.ip, userAgent: req.get('user-agent'),
      }).catch(() => {});
    }
  }
});

// ===========================================================================
// POST /owner/v1/credentials/confirm   { credentialId, nonce }
// Phase 2: the owner read the nonce out of THEIR OWN QPay portal.
// ===========================================================================
router.post('/credentials/confirm', async (req, res) => {
  const startedAt = Date.now();
  const body = req.body;
  req.body = undefined;
  const pad = async () => {
    const left = LIMITS.minResponseMs - (Date.now() - startedAt);
    if (left > 0) await sleep(left);
  };

  const actor = await authenticate(req);
  if (!actor) { await pad(); return reply(res, 401, 'FORBIDDEN'); }

  const credentialId = String(body?.credentialId ?? '');
  const nonce = String(body?.nonce ?? '').trim();
  if (!UUID.test(credentialId)) { await pad(); return reply(res, 400, 'INVALID_INPUT', { field: 'credentialId' }); }
  if (!/^[0-9]{4}$/.test(nonce)) { await pad(); return reply(res, 400, 'INVALID_INPUT', { field: 'nonce' }); }

  const r = await store.confirmCredentialVerification({
    credentialId, actorUserId: actor.userId, nonce,
    remoteIp: req.ip, xff: req.get('x-forwarded-for'), userAgent: req.get('user-agent'),
  });
  safeLog({ event: 'verify_confirm', credentialId, actorUserId: actor.userId, outcome: r.out_status });

  if (r.out_status === 'ok') {
    // Both caches must forget the old merchant or this instance keeps selling
    // on it until its TTL expires. Sibling Render instances self-heal within
    // owners.js's 60s TTL because the cache entry carries updated_at — that is
    // the bound the owner is told about ("1 минутын дотор").
    qpay.evictOwner(r.out_owner_id);
    owners.forgetCredential(credentialId);

    // Detection, not prevention. An attacker holding a stolen session can
    // redirect this owner's future revenue and nothing above stops them.
    // NOTE the recipient: the phone recorded on owners.contact_phone from the
    // sales paperwork, NOT the session's phone — otherwise a hijacked identity
    // silences its own alert. No link in the body, ever (see the no-links rule).
    alerts.notifyOwnerCredentialChanged(r.out_owner_id).catch(() => {});
    await store.revokeOtherSessions(actor.userId).catch(() => {});

    await pad();
    return reply(res, 200, 'OK', {
      usernameHint: r.out_username_hint,
      invoiceCodeHint: r.out_invoice_code_hint,
      liveInSeconds: 60,
    });
  }

  if (r.out_status === 'nonce_wrong') {
    await pad();
    return reply(res, 400, 'NONCE_WRONG', { attemptsLeft: r.out_attempts_left });
  }
  if (r.out_status === 'nonce_exhausted' || r.out_status === 'expired') {
    await cancelVerifyInvoice({
      credentialId, ownerId: r.out_owner_id,
      sealedBlob: null, invoiceId: r.out_invoice_id,
    });
    await pad();
    return reply(res, 409, r.out_status.toUpperCase());
  }
  await pad();
  return reply(res, 409, String(r.out_status).toUpperCase());
});

// ===========================================================================
// POST /owner/v1/credentials/abort   { credentialId }
// "Би энэ нэхэмжлэхийг олж харахгүй байна." A hard stop, on purpose: there is
// no third option that stores the credential anyway, because a third option is
// the one everybody picks.
// ===========================================================================
router.post('/credentials/abort', async (req, res) => {
  const body = req.body;
  req.body = undefined;
  const actor = await authenticate(req);
  if (!actor) return reply(res, 401, 'FORBIDDEN');
  const credentialId = String(body?.credentialId ?? '');
  if (!UUID.test(credentialId)) return reply(res, 400, 'INVALID_INPUT', { field: 'credentialId' });

  const slot = await store.credentialSlot(credentialId, actor.userId);
  if (!slot || !slot.out_is_admin) return reply(res, 404, 'FORBIDDEN');

  const r = await store.abortCredentialVerification(credentialId, actor.userId, 'owner_cannot_see_invoice');
  if (r.out_status === 'ok') {
    await cancelVerifyInvoice({ credentialId, ownerId: r.out_owner_id, sealedBlob: null, invoiceId: r.out_invoice_id });
    // This is the wrong-account signal firing. It is the single most valuable
    // alert in the whole feature, and the operator is on site right now.
    alerts.pageOperator('owner could not see the verification invoice — WRONG MERCHANT ACCOUNT', {
      ownerId: r.out_owner_id, credentialId,
    });
  }
  safeLog({ event: 'verify_abort', credentialId, actorUserId: actor.userId, outcome: r.out_status });
  return reply(res, 200, 'OK');
});

// ===========================================================================
// POST /owner/v1/credentials/:id/active   { active: boolean }
// The owner's emergency stop.
// ===========================================================================
router.post('/credentials/:credentialId/active', async (req, res) => {
  const body = req.body;
  req.body = undefined;
  const actor = await authenticate(req);
  if (!actor) return reply(res, 401, 'FORBIDDEN');
  const { credentialId } = req.params;
  if (!UUID.test(credentialId)) return reply(res, 400, 'INVALID_INPUT', { field: 'credentialId' });
  if (typeof body?.active !== 'boolean') return reply(res, 400, 'INVALID_INPUT', { field: 'active' });

  // Turning a credential back ON is a money-direction change, so it needs the
  // same freshness as one. Turning it OFF must never be gated: a person who
  // believes their password just leaked has to be able to stop it now.
  if (body.active) {
    const age = await store.stepUpAgeSeconds(actor.userId);
    if (age > STEP_UP_CHANGE_SECONDS) return reply(res, 401, 'REAUTH_REQUIRED');
  }

  const r = await store.setCredentialActive(credentialId, actor.userId, body.active);
  if (!r.out_ok) return reply(res, 404, 'FORBIDDEN');
  qpay.evictOwner(r.out_owner_id ?? null);
  owners.forgetCredential(credentialId);
  safeLog({ event: 'set_active', credentialId, actorUserId: actor.userId, outcome: String(body.active) });
  return reply(res, 200, 'OK', { affectedMachines: r.out_affected_machines });
});

// ===========================================================================
// GET /owner/v1/credentials/:id — the ENTIRE read surface.
// There is no other route, no role, no query parameter and no admin flag that
// returns more than this. The operator's own tooling reads the same shape.
// ===========================================================================
router.get('/credentials/:credentialId', async (req, res) => {
  const actor = await authenticate(req);
  if (!actor) return reply(res, 401, 'FORBIDDEN');
  const { credentialId } = req.params;
  if (!UUID.test(credentialId)) return reply(res, 400, 'INVALID_INPUT', { field: 'credentialId' });

  const view = await store.credentialForOwner(credentialId, actor.userId);
  if (!view) return reply(res, 404, 'FORBIDDEN');
  return reply(res, 200, 'OK', {
    label: view.label,
    status: view.status,                     // 'pending' | 'active' | 'disabled'
    usernameHint: view.username_hint,        // 'me••••••23' — display only, never an input
    invoiceCodeHint: view.invoice_code_hint, // '••••4821'
    lastVerifiedAt: view.last_verified_at,
    lastErrorCode: view.last_error_code,     // NEVER last_error: it echoes the merchant username
    verificationOpen: view.verification_open,
    acceptanceConfirmedAt: view.acceptance_confirmed_at,
    machines: view.machines,                 // [{deviceNo, label, location}] — the recognition signal
  });
});

/**
 * The verification invoice's callback. It exists so a verify invoice never
 * shares a URL with a sale: settling one must be impossible, not merely
 * unlikely. Answers QPay the way QPay demands and does nothing else.
 */
export function mountVerifyCallback(app) {
  app.all('/qpay/verify-callback', (req, res) => {
    safeLog({ event: 'verify_callback', outcome: 'ignored' });
    res.status(200).send('SUCCESS');
  });
}

/**
 * Sweeps abandoned verifications: clears the staged candidate and cancels its
 * probe invoice. Without this, an owner who closes the tab leaves a live 10₮
 * QR on their own merchant that nobody will ever reconcile.
 */
export async function sweepAbandonedVerifications() {
  const rows = await store.expiredVerifications(20);
  for (const row of rows) {
    await cancelVerifyInvoice({
      credentialId: row.id, ownerId: row.owner_id,
      sealedBlob: row.pending_sealed, invoiceId: row.verify_invoice_id,
    });
    await store.abortCredentialVerification(row.id, null, 'expired').catch(() => {});
    safeLog({ event: 'verify_swept', ownerId: row.owner_id, credentialId: row.id, outcome: 'expired' });
  }
}

export default router;
