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
// The same resolution server.js uses for sale callbacks. Render sets
// RENDER_EXTERNAL_URL and not PUBLIC_URL; reading PUBLIC_URL alone sent QPay
// "undefined/qpay/verify-callback", which it refuses — and every owner's
// verification failed on a URL they never saw.
const PUBLIC_URL = (process.env.PUBLIC_URL ?? process.env.RENDER_EXTERNAL_URL ?? '').replace(/\/+$/, '');
if (!/^https?:\/\//.test(PUBLIC_URL)) throw new Error('PUBLIC_URL or RENDER_EXTERNAL_URL must be set — QPay needs a callback URL');
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
// Local tests run the bridge on plain http. The escape hatch is refused in
// production so a copied env group cannot open it on Render.
const ALLOW_HTTP = process.env.CRED_ALLOW_HTTP === '1' && process.env.NODE_ENV !== 'production';

router.use((req, res, next) => {
  if (!ALLOW_HTTP && !req.secure && req.get('x-forwarded-proto') !== 'https') return reply(res, 400, 'FORBIDDEN');

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
    return payload.sub ? { userId: payload.sub, otpAt: otpTimestamp(payload) } : null;
  } catch {
    safeLog({ event: 'jwt_invalid', outcome: 'rejected' });
    return null;
  }
}

/**
 * When this session's OTP was actually typed, in epoch seconds, or null.
 *
 * Supabase records it in the token's `amr` claim and carries the ORIGINAL
 * timestamp through every refresh, so a session that has merely been kept
 * alive for a day does not look fresh — which is exactly the property a
 * step-up check needs, and one `iat` does not have.
 */
function otpTimestamp(payload) {
  const amr = Array.isArray(payload.amr) ? payload.amr : [];
  const times = amr
    .filter((e) => e && (e.method === 'otp' || e.method === 'sms'))
    .map((e) => Number(e.timestamp))
    .filter(Number.isFinite);
  return times.length ? Math.max(...times) : null;
}

// ---------------------------------------------------------------------------
// Input validation. Runs before any QPay contact, so a malformed body can
// never cost a budgeted attempt or a round trip to Ulaanbaatar.
// ---------------------------------------------------------------------------
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const INVOICE_CODE = /^[A-Za-z0-9_-]{3,64}$/;
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
 * QPay's own error code from a failed invoice call — `INVOICE_CODE_INVALID`
 * and the like — and nothing else from its body.
 *
 * The body is never logged (QPay echoes the merchant username), but its code
 * is the one thing that tells "the invoice code is wrong" apart from every
 * other refusal, and without it every refusal was reported as a wrong code.
 * Only an all-caps token survives; anything else is dropped.
 */
function qpayErrorCode(err) {
  const raw = String(err?.message ?? '');
  const body = raw.slice(raw.indexOf(': ') + 2);
  let code = '';
  try {
    const j = JSON.parse(body);
    code = String(j?.error ?? j?.code ?? j?.message ?? '');
  } catch {
    code = /\b([A-Z][A-Z_]{2,38})\b/.exec(body)?.[1] ?? '';
  }
  code = code.trim().toUpperCase();
  return /^[A-Z_]{3,34}$/.test(code) ? code : null;
}

/**
 * QPay's refusal as the operator needs to read it: status and the first
 * 160 characters of its body, with the username and password cut out of it
 * wherever they appear. Goes to the operator's alert list only — never to a
 * response and never to the log.
 */
function qpayRefusalForOperator(err, { username, password }) {
  const raw = String(err?.message ?? '');
  let text = raw.replace(/^qpay invoice /, '').slice(0, 200);
  for (const secret of [username, password]) {
    if (secret && secret.length >= 3) text = text.split(secret).join('***');
  }
  return text.replace(/\s+/g, ' ').slice(0, 160);
}

/** Codes that mean the invoice code itself is what QPay refused. */
const INVOICE_CODE_ERRORS = /INVOICE_CODE|INVOICE_NOT_FOUND|MERCHANT_INVOICE|INVALID_INVOICE/;

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
      callbackUrl: `${PUBLIC_URL}/qpay/verify-callback`,
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
    // THIS is what makes the credential screen openable without a second SMS
    // — but only for a session that has just proved the phone by SMS. An old
    // invite link re-redeemed from a password session (already_accepted
    // answers forever) must not stand in for that code.
    const now = Math.floor(Date.now() / 1000);
    if (actor.otpAt && now - actor.otpAt <= STEP_UP_RECORD_WINDOW_SECONDS) await store.touchStepUp(actor.userId, 'invite_redeem');
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
// POST /owner/v1/invites/claim
// Accepts every open invite that names the phone this user just proved.
//
// The operator registered a number; the person proved that number with an
// SMS code; the two match — that IS the invitation, whichever way they
// arrived. Only within minutes of the code (the token's own amr time), so a
// session that has been open for a day cannot pick up an invite issued since.
// ===========================================================================
const CLAIM_WINDOW_SECONDS = 600;

router.post('/invites/claim', async (req, res) => {
  req.body = undefined;
  const actor = await authenticate(req);
  if (!actor) return reply(res, 401, 'FORBIDDEN');
  const now = Math.floor(Date.now() / 1000);
  if (!actor.otpAt || now - actor.otpAt > CLAIM_WINDOW_SECONDS) return reply(res, 401, 'REAUTH_REQUIRED');

  const claimed = await store.claimInvitesByPhone(actor.userId, req.ip);
  if (claimed.length) await store.touchStepUp(actor.userId, 'invite_redeem');
  safeLog({ event: 'invite_claim', actorUserId: actor.userId, outcome: String(claimed.length) });
  return reply(res, 200, 'OK', {
    owners: claimed.map((c) => ({ ownerId: c.out_owner_id, ownerName: c.out_owner_name, role: c.out_role })),
  });
});

// ===========================================================================
// GET  /owner/v1/step-up   — how fresh is this user's last OTP, and how fresh
//                            does it need to be.
// POST /owner/v1/step-up   — record an OTP the session JUST completed.
//
// The portal calls POST straight after every successful login, and GET before
// it shows the credential form: an owner must never type a merchant password
// blind on a phone keyboard only to be told afterwards that they needed an SMS
// code first.
// ===========================================================================
const STEP_UP_RECORD_WINDOW_SECONDS = 300;

router.get('/step-up', async (req, res) => {
  const actor = await authenticate(req);
  if (!actor) return reply(res, 401, 'FORBIDDEN');
  const age = await store.stepUpAgeSeconds(actor.userId);
  return reply(res, 200, 'OK', {
    ageSeconds: age,
    firstEntryMaxSeconds: STEP_UP_FIRST_SECONDS,
    changeMaxSeconds: STEP_UP_CHANGE_SECONDS,
  });
});

router.post('/step-up', async (req, res) => {
  req.body = undefined;
  const actor = await authenticate(req);
  if (!actor) return reply(res, 401, 'FORBIDDEN');
  // The proof is the token's own OTP timestamp, not the portal's say-so: a
  // portal that could stamp step-up at will would make the check decorative.
  const now = Math.floor(Date.now() / 1000);
  if (!actor.otpAt || now - actor.otpAt > STEP_UP_RECORD_WINDOW_SECONDS) {
    return reply(res, 401, 'REAUTH_REQUIRED');
  }
  await store.touchStepUp(actor.userId, 'step_up');
  safeLog({ event: 'step_up', actorUserId: actor.userId, outcome: 'ok' });
  return reply(res, 200, 'OK');
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

    // QPay hands the owner three things together: username, password and
    // invoice code. The owner may type the code; if they leave it blank the
    // one the operator entered at registration is used. Theirs wins when both
    // exist, so a wrong operator entry is something the owner can fix.
    const typedCode = String(body?.invoiceCode ?? '').trim();
    if (typedCode && !INVOICE_CODE.test(typedCode)) {
      await pad();
      return reply(res, 400, 'INVALID_INPUT', { field: 'invoiceCode' });
    }
    const invoiceCode = typedCode || slot.out_pending_invoice_code;
    const codeFrom = typedCode ? 'owner' : 'operator';
    if (!invoiceCode) {
      await pad();
      return reply(res, 400, 'INVALID_INPUT', { field: 'invoiceCode' });
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
        invoiceCode,
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
        const qpayCode = qpayErrorCode(err);
        const codeProblem = !qpayCode || INVOICE_CODE_ERRORS.test(qpayCode);
        outcome = codeProblem ? 'invoice_code_failed' : 'invoice_failed';
        await store.recordVerifyFailure(
          credentialId, actorUserId,
          qpayCode ? `QPAY_${qpayCode}`.slice(0, 40) : 'QPAY_INVOICE_CODE_REJECTED',
          req.ip, req.get('user-agent')
        ).catch(() => {});
        safeLog({ event: 'verify_failed', ownerId, credentialId, actorUserId, outcome, status: qpayCode, incident });
        // Without QPay's own words every refusal here looked the same — and
        // was misreported as a wrong code. The operator gets them, scrubbed.
        alerts.pageOperator(`QPay verification invoice refused: ${qpayRefusalForOperator(err, fields)}`, { ownerId, credentialId });
        if (!codeProblem) {
          // QPay accepted the login and refused the invoice for some other
          // reason. Saying "wrong invoice code" here sends the owner to retype
          // a code that was right; say what QPay said instead.
          await pad();
          return reply(res, 400, 'INVOICE_FAILED', { qpayError: qpayCode });
        }
        // Whose typo it was decides the message: the owner can retype their
        // own code, but only the operator can fix one entered at registration
        // — and is paged for it.
        if (codeFrom === 'operator') {
          alerts.pageOperator('invoice_code rejected by QPay — operator entered it', { ownerId, credentialId });
        }
        await pad();
        return reply(res, 400, 'INVOICE_CODE_FAILED', { enteredBy: codeFrom, qpayError: qpayCode });
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

    // No read-back step. The business decided the owner's first sale is the
    // check that the money lands where it should, so the staged credential is
    // promoted at once — through the same SQL confirm the read-back used,
    // with the nonce the bridge itself just generated. Every check that
    // function makes (admin, duplicate merchant, state) still runs.
    const conf = await store.confirmCredentialVerification({
      credentialId, actorUserId, nonce,
      remoteIp: req.ip, xff: req.get('x-forwarded-for'), userAgent: req.get('user-agent'),
    });
    // The probe invoice proved the invoice code; nobody needs to read it.
    await cancelVerifyInvoice({ credentialId, ownerId, sealedBlob: v.sealed, invoiceId: v.invoiceId });
    if (conf.out_status !== 'ok') {
      outcome = 'rejected';
      safeLog({ event: 'verify_rejected', ownerId, credentialId, actorUserId, outcome: conf.out_status });
      await pad();
      return reply(res, 409, String(conf.out_status).toUpperCase());
    }

    // Both caches forget the old merchant, as on a confirm.
    qpay.evictOwner(conf.out_owner_id ?? ownerId);
    owners.forgetCredential(credentialId);
    // Detection, not prevention: the number on the sales paperwork hears
    // about every change, whoever made it.
    alerts.notifyOwnerCredentialChanged(ownerId).catch(() => {});
    await store.revokeOtherSessions(actorUserId).catch(() => {});

    outcome = 'ok';
    safeLog({ event: 'verify_activated', ownerId, credentialId, actorUserId, outcome, ms: Date.now() - startedAt });
    await pad();
    return reply(res, 200, 'OK', {
      activated: true,
      usernameHint: conf.out_username_hint ?? v.usernameHint,
      liveInSeconds: 60,
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

// ===========================================================================
// POST /admin/v1/owners/:ownerId/credentials
//   { username, password, invoiceCode, confirmOwnership: true }
//
// The operator configures an owner's QPay from the console — the fallback
// for an owner who cannot do it themselves. Same proofs against QPay as the
// owner path (token, then a probe invoice that exercises the invoice code),
// same sealing, same single place the plaintext lives.
//
// Differences, all deliberate:
//   * no 4-digit read-back: the operator vouches, and must say so
//     (confirmOwnership) — the probe invoice is cancelled at once;
//   * the operator's OWN SMS code must be from the last ten minutes, whatever
//     their session age: this re-points a business's revenue;
//   * the owner is told by SMS at the number on the sales paperwork.
//
// Mounted on /admin/v1 AFTER the console's read router, whose operator gate
// passes a verified operator through to here; this route checks again itself.
// ===========================================================================
const OPERATOR_STEP_UP_SECONDS = 600;

export const operatorRouter = express.Router();

operatorRouter.use((req, res, next) => {
  if (!ALLOW_HTTP && !req.secure && req.get('x-forwarded-proto') !== 'https') return reply(res, 400, 'FORBIDDEN');
  next();
});
operatorRouter.use(express.json({ limit: '2kb', type: 'application/json' }));

operatorRouter.post('/owners/:ownerId/credentials', async (req, res) => {
  const incident = crypto.randomBytes(4).toString('hex');
  // Defeats the whole class of "an error handler serialised the request".
  const body = req.body;
  req.body = undefined;

  let ownerId = null;
  let credentialId = null;
  let actorUserId = null;
  try {
    const actor = await authenticate(req);
    if (!actor || !(await store.isOperator(actor.userId))) return reply(res, 401, 'FORBIDDEN');
    actorUserId = actor.userId;

    const now = Math.floor(Date.now() / 1000);
    if (!actor.otpAt || now - actor.otpAt > OPERATOR_STEP_UP_SECONDS) return reply(res, 401, 'REAUTH_REQUIRED');

    if (!UUID.test(req.params.ownerId)) return reply(res, 400, 'INVALID_INPUT', { field: 'ownerId' });
    ownerId = req.params.ownerId;
    if (body?.confirmOwnership !== true) return reply(res, 400, 'INVALID_INPUT', { field: 'confirmOwnership' });

    const slot = await store.operatorCredentialSlot(actorUserId, ownerId);
    if (slot.out_status !== 'ok') {
      return reply(res, slot.out_status === 'verification_open' ? 409 : 404, String(slot.out_status).toUpperCase());
    }
    credentialId = slot.out_credential_id;

    const fields = readCredentialFields({ ...(body ?? {}), credentialId });
    if (fields.error) return reply(res, 400, 'INVALID_INPUT', { field: fields.error });
    const invoiceCode = String(body?.invoiceCode ?? '').trim();
    if (!INVOICE_CODE.test(invoiceCode)) return reply(res, 400, 'INVALID_INPUT', { field: 'invoiceCode' });

    let v;
    try {
      v = await runVerification({
        credentialId, ownerId,
        username: fields.username, password: fields.password,
        invoiceCode, nonce: newNonce(),
      });
    } catch (err) {
      const kind = classify(err);
      safeLog({ event: 'operator_verify_failed', ownerId, credentialId, actorUserId, outcome: kind, incident });
      if (kind === 'qpay_unreachable') return reply(res, 502, 'QPAY_UNREACHABLE');
      if (kind === 'auth_failed') return reply(res, 400, 'AUTH_FAILED');
      if (err?.stage === 'invoice') {
        const qpayCode = qpayErrorCode(err);
        if (qpayCode && !INVOICE_CODE_ERRORS.test(qpayCode)) return reply(res, 400, 'INVOICE_FAILED', { qpayError: qpayCode });
        return reply(res, 400, 'INVOICE_CODE_FAILED', { qpayError: qpayCode });
      }
      return reply(res, 500, 'SERVER_ERROR', { incident });
    }

    // The probe proved the invoice code; nobody needs to read it.
    await cancelVerifyInvoice({ credentialId, ownerId, sealedBlob: v.sealed, invoiceId: v.invoiceId });

    const status = await store.operatorSetCredential(actorUserId, {
      ownerId, credentialId, sealed: v.sealed, keyId: v.keyId, fp: v.fp,
      usernameHint: v.usernameHint, invoiceCodeHint: v.invoiceCodeHint,
    });
    if (status !== 'ok') {
      if (status === 'duplicate_other_owner') alerts.pageOperator('duplicate merchant across owners', { ownerId, credentialId });
      safeLog({ event: 'operator_configure_rejected', ownerId, credentialId, actorUserId, outcome: status });
      return reply(res, 409, String(status).toUpperCase());
    }

    // Both caches forget the old merchant, as on the owner's confirm.
    qpay.evictOwner(ownerId);
    owners.forgetCredential(credentialId);
    alerts.notifyOwnerCredentialChanged(ownerId).catch(() => {});
    safeLog({ event: 'operator_configured', ownerId, credentialId, actorUserId, outcome: 'ok' });
    return reply(res, 200, 'OK', { usernameHint: v.usernameHint, invoiceCodeHint: v.invoiceCodeHint, liveInSeconds: 60 });
  } catch {
    safeLog({ event: 'operator_configure_unhandled', ownerId, credentialId, actorUserId, outcome: 'error', incident });
    return reply(res, 500, 'SERVER_ERROR', { incident });
  }
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
