import express from 'express';
import * as store from './store.js';
import { requireOwner, resolveOwnerId, authConfigured } from './owner-auth.js';

/**
 * The owner portal's read API.
 *
 * Mounted only when SUPABASE_URL is set. A router that silently serves
 * unauthenticated because an environment variable was forgotten on a new
 * deploy is worse than no router: nothing looks broken.
 *
 * The browser calls this directly with a bearer token — no cookies, so there
 * is no CSRF surface here and none of the machinery that would otherwise be
 * needed to defend one.
 */
export function ownerApi({ log = () => {}, portalOrigin = '' } = {}) {
  const router = express.Router();

  /*
   * CORS, allow-listed to the portal's exact origin.
   *
   * `*` would be wrong even for a read API: the token travels in a header the
   * page's own script sets, so any origin permitted here can be handed a
   * borrowed token by a malicious page and read an owner's revenue with it.
   * Credentials are explicitly NOT allowed, because nothing here uses cookies
   * and allowing them would let a future cookie become an ambient credential.
   */
  router.use((req, res, next) => {
    const origin = req.get('origin');
    if (portalOrigin && origin === portalOrigin) {
      res.setHeader('Access-Control-Allow-Origin', portalOrigin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Max-Age', '600');
    }
    if (req.method === 'OPTIONS') return res.status(204).end();
    next();
  });

  // Revenue is money: a cache between here and the owner is a stale number
  // someone will act on, and a shared cache is one owner's money in another
  // owner's browser.
  router.use((req, res, next) => {
    res.setHeader('Cache-Control', 'private, no-store');
    next();
  });

  router.use(requireOwner(log));

  /**
   * Everything the dashboard draws, in one call.
   *
   * The aggregation lives in app.owner_stats, so this handler cannot widen
   * the scope even by accident — it passes an owner id and returns what comes
   * back. `timezone` is deliberately not a request parameter: it would change
   * which day a sale is filed under, and the answer for every machine we have
   * is Ulaanbaatar.
   */
  router.get('/stats', async (req, res) => {
    const ownerId = resolveOwnerId(req, res);
    if (!ownerId) return;
    try {
      const stats = await store.ownerStats(ownerId);
      res.json({ ownerId, ...stats });
    } catch (err) {
      log('owner stats failed', ownerId, err.message.split('\n')[0]);
      res.status(500).json({ error: 'SYSTEM_ERROR' });
    }
  });

  /** Who am I, and which businesses can I switch between. */
  router.get('/me', async (req, res) => {
    try {
      const owners = await store.ownersByIds(req.owner.ownerIds);
      res.json({ userId: req.owner.userId, owners });
    } catch (err) {
      log('owner me failed', err.message.split('\n')[0]);
      res.status(500).json({ error: 'SYSTEM_ERROR' });
    }
  });

  return router;
}

export { authConfigured };
