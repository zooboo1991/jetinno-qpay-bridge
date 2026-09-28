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

  // Per route, NOT router.use(). This router and the credentials router share
  // the /owner/v1 prefix, and a router-wide gate here answered 401 to every
  // path under it — including /owner/v1/invites/redeem, which by definition
  // is called by somebody who is not a member yet. The invite path was dead
  // on arrival and no test noticed, because every test seeded owner_members
  // directly. Unmatched paths must fall through.
  const auth = requireOwner(log);

  /**
   * Everything the dashboard draws, in one call.
   *
   * The aggregation lives in app.owner_stats, so this handler cannot widen
   * the scope even by accident — it passes an owner id and returns what comes
   * back. `timezone` is deliberately not a request parameter: it would change
   * which day a sale is filed under, and the answer for every machine we have
   * is Ulaanbaatar.
   */
  router.get('/stats', auth, async (req, res) => {
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

  // -------------------------------------------------------------------------
  // The owner's console (migration 014). Periods arrive as local dates,
  // YYYY-MM-DD, `to` inclusive; they become [from 00:00, to+1 00:00) in
  // Ulaanbaatar time. Anything malformed falls back to the last 30 days
  // rather than failing — a bad bookmark should still show a report.
  // -------------------------------------------------------------------------
  const DAY = /^\d{4}-\d{2}-\d{2}$/;
  const UB_OFFSET = '+08:00';
  function period(q) {
    const todayUb = new Date(Date.now() + 8 * 3600e3).toISOString().slice(0, 10);
    let to = DAY.test(String(q.to ?? '')) ? String(q.to) : todayUb;
    let from = DAY.test(String(q.from ?? '')) ? String(q.from) : null;
    const toEnd = new Date(`${to}T00:00:00${UB_OFFSET}`);
    if (Number.isNaN(toEnd.getTime())) to = todayUb;
    const end = new Date(new Date(`${to}T00:00:00${UB_OFFSET}`).getTime() + 86400e3);
    let start = from ? new Date(`${from}T00:00:00${UB_OFFSET}`) : new Date(end.getTime() - 30 * 86400e3);
    if (Number.isNaN(start.getTime()) || start >= end) start = new Date(end.getTime() - 30 * 86400e3);
    // A year and a bit at most: the day series is one row per day.
    if (end - start > 400 * 86400e3) start = new Date(end.getTime() - 400 * 86400e3);
    return { from: start.toISOString(), to: end.toISOString() };
  }
  const device = (q) => {
    const d = String(q.machine ?? '');
    return /^[A-Za-z0-9_-]{1,40}$/.test(d) ? d : null;
  };
  const BUCKETS = new Set(['paid', 'unpaid', 'failed', 'pending', 'no_cup']);

  /** Wraps a read so a query failure never leaks a pg message. */
  const read = (name, fn) => [auth, async (req, res) => {
    const ownerId = resolveOwnerId(req, res);
    if (!ownerId) return;
    try {
      res.json(await fn(ownerId, req.query));
    } catch (err) {
      log(`owner ${name} failed`, ownerId, err.message.split('\n')[0]);
      res.status(500).json({ error: 'SYSTEM_ERROR' });
    }
  }];

  router.get('/summary', ...read('summary', async (ownerId, q) => {
    const p = period(q);
    return { ...p, machine: device(q), summary: await store.ownerSummary(ownerId, { ...p, deviceNo: device(q) }) };
  }));

  router.get('/orders', ...read('orders', async (ownerId, q) => {
    const p = period(q);
    const limit = Math.min(Math.max(Number(q.limit) || 50, 1), 500);
    const offset = Math.max(Number(q.offset) || 0, 0);
    const bucket = BUCKETS.has(String(q.status)) ? String(q.status) : null;
    const rows = await store.ownerOrders(ownerId, { ...p, deviceNo: device(q), bucket, limit, offset });
    return {
      ...p,
      total: Number(rows[0]?.total_count ?? 0),
      orders: rows.map(({ total_count, ...r }) => r),
    };
  }));

  router.get('/machines', ...read('machines', async (ownerId, q) => {
    const p = period(q);
    return { ...p, machines: await store.ownerMachines(ownerId, p) };
  }));

  router.get('/hourly', ...read('hourly', async (ownerId, q) => {
    const p = period(q);
    return { ...p, hours: await store.ownerHourly(ownerId, { ...p, deviceNo: device(q) }) };
  }));

  router.get('/products', ...read('products', async (ownerId, q) => {
    const p = period(q);
    return { ...p, products: await store.ownerProducts(ownerId, { ...p, deviceNo: device(q) }) };
  }));

  router.get('/problems', ...read('problems', async (ownerId) => ({
    problems: await store.ownerProblems(ownerId),
  })));

  /** Who am I, and which businesses can I switch between. */
  router.get('/me', auth, async (req, res) => {
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
