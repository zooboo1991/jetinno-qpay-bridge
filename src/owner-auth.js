import { createRemoteJWKSet, jwtVerify, decodeProtectedHeader } from 'jose';
import { query } from './db.js';

/**
 * Turns a Supabase access token into "which owners may this request read or
 * write", and nothing else.
 *
 * The bridge talks to Postgres as service_role, which can see every owner's
 * rows. That is the whole reason this file is small and strict: service_role
 * plus a mis-scoped request is one owner reading another's revenue. So the
 * owner id used by every /owner/v1 route comes from here — derived from a
 * signed token and a membership table — and never from a path, query or body
 * parameter the caller controls.
 */

const SUPABASE_URL = (process.env.SUPABASE_URL ?? '').replace(/\/+$/, '');

/** The routes refuse to mount without this, rather than serving unauthenticated. */
export function authConfigured() {
  return Boolean(SUPABASE_URL);
}

/*
 * Supabase signs with an asymmetric key and publishes the public half at
 * /auth/v1/.well-known/jwks.json. Verifying against that means the bridge
 * never holds a secret that could also MINT tokens — a bridge compromise
 * cannot forge a session for an owner it has never seen.
 *
 * createRemoteJWKSet caches the key set and re-fetches on an unknown `kid`,
 * with its own cooldown, so a key rotation heals without a deploy and a
 * stream of junk tokens cannot turn into a stream of outbound requests.
 */
let jwks = null;
function keySet() {
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`${SUPABASE_URL}/auth/v1/.well-known/jwks.json`), {
      cooldownDuration: 30_000,
      timeoutDuration: 3_000,
    });
  }
  return jwks;
}

/**
 * Verifies the token and returns its subject.
 *
 * `algorithms` is pinned. Without it a token whose header says `alg: none` —
 * or HS256 signed with the public JWKS key, which is public — verifies
 * against a JWKS meant for ES256, and the signature check becomes decoration.
 *
 * `audience: 'authenticated'` is Supabase's own claim for a signed-in user;
 * it rejects the anon key, which is a valid JWT from the same issuer that
 * every visitor to the portal already has in their browser.
 */
export async function verifyAccessToken(token) {
  const header = decodeProtectedHeader(token);
  if (!header.alg || header.alg === 'none' || header.alg.startsWith('HS')) {
    throw new Error('BAD_ALG');
  }
  const { payload } = await jwtVerify(token, keySet(), {
    issuer: `${SUPABASE_URL}/auth/v1`,
    audience: 'authenticated',
    algorithms: ['ES256', 'RS256'],
    clockTolerance: 5,
  });
  if (!payload.sub) throw new Error('NO_SUBJECT');
  return { userId: payload.sub, sessionId: payload.session_id ?? null };
}

/** Owner ids this user administers. Empty array means "no access to anything". */
export async function adminOwnerIds(userId) {
  const { rows } = await query(`select app.admin_owner_ids_of($1) as ids`, [userId]);
  return rows[0]?.ids ?? [];
}

const BEARER = /^Bearer\s+([A-Za-z0-9._~+/-]+=*)$/;

/**
 * Express middleware. Populates `req.owner = { userId, ownerIds }`.
 *
 * Every failure answers the same body. Distinguishing "bad signature" from
 * "expired" from "not a member" tells an attacker which half of a guess was
 * right, and tells a legitimate owner nothing they can act on — the portal
 * shows its own message and sends them back to the login screen either way.
 * The reason is logged, not returned.
 */
export function requireOwner(log = () => {}) {
  return async (req, res, next) => {
    const deny = (why) => {
      log('owner auth denied', req.path, why);
      res.status(401).json({ error: 'UNAUTHORIZED' });
    };
    const match = BEARER.exec(req.get('authorization') ?? '');
    if (!match) return deny('no bearer token');
    try {
      const { userId, sessionId } = await verifyAccessToken(match[1]);
      const ownerIds = await adminOwnerIds(userId);
      if (!ownerIds.length) return deny(`user ${userId} administers no owner`);
      req.owner = { userId, sessionId, ownerIds };
      next();
    } catch (err) {
      deny(err.message.split('\n')[0]);
    }
  };
}

/**
 * Resolves which owner a request is about.
 *
 * A user may administer more than one business — the plan calls this out
 * explicitly, because the owner who buys a second machine for a second company
 * is a customer we want. So an owner id MAY be named in the query string, but
 * it is only ever accepted after being checked against the membership list
 * this request already proved. Naming an id you do not administer is a 404,
 * not a 403: it does not confirm the id exists.
 */
export function resolveOwnerId(req, res) {
  const asked = req.query.ownerId;
  if (!asked) return req.owner.ownerIds[0];
  if (!req.owner.ownerIds.includes(asked)) {
    res.status(404).json({ error: 'NOT_FOUND' });
    return null;
  }
  return asked;
}
