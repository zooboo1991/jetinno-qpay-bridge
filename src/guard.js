import express from 'express';
import { isIP } from 'node:net';
import { timingSafeEqual } from 'node:crypto';
import * as store from './store.js';

/**
 * The portal's login guard, and the one key the portal holds for the bridge.
 *
 * The login actions are public server actions, and every one of them reaches
 * Supabase from Vercel's addresses — so Supabase's per-IP limits saw a few
 * shared IPs, not the people behind them. Anyone could request SMS codes for a
 * known owner's number until the per-phone budget ran out (locking the owner
 * out of SMS login for a day), or try passwords without limit. The portal now
 * asks here first, passing the caller's real IP, and the ledger lives in
 * Postgres (018 app.auth_attempt) so it holds across instances and restarts.
 *
 * GUARD_SECRET is shared with the portal. The same key is what lets the
 * portal vouch for the end user's IP and user agent on other calls
 * (trustedClient below): without it, those headers are anybody's to set.
 */

const SECRET = process.env.GUARD_SECRET ?? '';

export const guardConfigured = () => SECRET.length >= 16;

function keyMatches(candidate) {
  if (!guardConfigured() || typeof candidate !== 'string') return false;
  const a = Buffer.from(candidate);
  const b = Buffer.from(SECRET);
  return a.length === b.length && timingSafeEqual(a, b);
}

const KINDS = new Set(['otp_request', 'otp_verify', 'password', 'password_change']);

/**
 * The end user's IP and user agent as the portal saw them — only when the
 * portal proved it is the portal. Otherwise null, and callers use what the
 * bridge itself observed.
 */
export function trustedClient(req) {
  if (!keyMatches(req.get('x-guard-key'))) return null;
  const ip = String(req.get('x-client-ip') ?? '').trim();
  const ua = String(req.get('x-client-ua') ?? '').slice(0, 300);
  return { ip: isIP(ip) ? ip : null, userAgent: ua || null };
}

export function guardApi({ log = () => {} } = {}) {
  const router = express.Router();
  router.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  router.post('/attempt', express.json({ limit: '1kb', type: 'application/json' }), async (req, res) => {
    if (!keyMatches(req.get('x-guard-key'))) return res.status(401).json({ error: 'UNAUTHORIZED' });
    const kind = String(req.body?.kind ?? '');
    if (!KINDS.has(kind)) return res.status(400).json({ error: 'INVALID_KIND' });
    const rawIp = String(req.body?.ip ?? '').trim();
    const ip = isIP(rawIp) ? rawIp : null;
    const digits = String(req.body?.phone ?? '').replace(/\D/g, '');
    const phone = digits.length >= 8 && digits.length <= 15 ? digits : null;
    try {
      const r = await store.authAttempt(kind, ip, phone);
      if (!r.out_allowed) log('auth guard refused', kind, `retry=${r.out_retry_seconds}s`);
      return res.json(
        r.out_allowed ? { allowed: true } : { allowed: false, retryAfterSeconds: r.out_retry_seconds ?? 60 }
      );
    } catch (err) {
      // The portal fails open on anything but a 200: the guard is defence in
      // depth, and a database hiccup must not stop owners logging in.
      log('auth guard failed', err.message.split('\n')[0]);
      return res.status(503).json({ error: 'UNAVAILABLE' });
    }
  });

  return router;
}
