import express from 'express';
import * as store from './store.js';
import { verifyAccessToken } from './owner-auth.js';

/**
 * The operator console's read API.
 *
 * Everything here crosses every tenant boundary in the system: one call
 * returns every owner's revenue, every machine's takings, and the phone
 * number of every customer. That is the whole point of an operator console
 * and also the reason this file is short and has exactly one shape.
 *
 * TWO CHECKS, DELIBERATELY. This router verifies the Supabase JWT and then
 * confirms the subject is in public.operators before any handler runs; every
 * SQL function it calls ALSO takes the actor's id and checks membership
 * itself. The duplication is not an oversight — the bridge connects as
 * service_role, so if this middleware were ever bypassed by a routing change
 * the database would still refuse, and if the SQL check were ever relaxed the
 * router would still refuse.
 *
 * Read-only. Nothing here writes, so there is no operator action that can be
 * triggered by a forged request — the worst outcome of a bypass is disclosure,
 * which is bad enough to be worth the double check and not bad enough to
 * justify a second authentication scheme.
 */

const TZ = 'Asia/Ulaanbaatar';
const BEARER = /^Bearer\s+([A-Za-z0-9._~+/-]+=*)$/;

function requireOperator(log = () => {}) {
  return async (req, res, next) => {
    const deny = (why) => {
      log('admin auth denied', req.path, why);
      // The same body whatever the reason. Distinguishing "not an operator"
      // from "bad token" tells a caller which half of a guess was right, and
      // tells a legitimate operator nothing they can act on.
      res.status(401).json({ error: 'UNAUTHORIZED' });
    };
    const match = BEARER.exec(req.get('authorization') ?? '');
    if (!match) return deny('no bearer token');
    try {
      const { userId } = await verifyAccessToken(match[1]);
      if (!(await store.isOperator(userId))) return deny(`user ${userId} is not an operator`);
      req.operator = { userId };
      next();
    } catch (err) {
      deny(err.message.split('\n')[0]);
    }
  };
}

export function adminApi({ log = () => {}, portalOrigin = '' } = {}) {
  const router = express.Router();

  router.use((req, res, next) => {
    const origin = req.get('origin');
    if (portalOrigin && origin === portalOrigin) {
      res.setHeader('Access-Control-Allow-Origin', portalOrigin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
      res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    }
    if (req.method === 'OPTIONS') return res.status(204).end();
    // Every response here is one operator's view of live money. A shared
    // cache anywhere between here and the browser is another operator's
    // dashboard in somebody's tab.
    res.setHeader('Cache-Control', 'private, no-store');
    next();
  });

  router.use(requireOperator(log));

  /** Wraps a handler so a query failure never leaks a pg message to the caller. */
  const handler = (name, fn) => async (req, res) => {
    try {
      res.json(await fn(req));
    } catch (err) {
      log(`admin ${name} failed`, err.message.split('\n')[0]);
      res.status(500).json({ error: 'SYSTEM_ERROR' });
    }
  };

  const uuidOrNull = (v) =>
    typeof v === 'string' && /^[0-9a-f-]{36}$/i.test(v) ? v : null;

  router.get('/overview', handler('overview', (req) =>
    store.operatorOverview(req.operator.userId, { timezone: TZ })
  ));

  router.get('/owners', handler('owners', async (req) => ({
    owners: await store.operatorOwners(req.operator.userId, { timezone: TZ }),
  })));

  router.get('/machines', handler('machines', async (req) => ({
    machines: await store.operatorMachines(req.operator.userId, { timezone: TZ }),
  })));

  router.get('/problems', handler('problems', async (req) => ({
    problems: await store.operatorProblems(req.operator.userId, { limit: req.query.limit }),
  })));

  router.get('/onboarding', handler('onboarding', async (req) => ({
    machines: await store.operatorOnboarding(req.operator.userId),
  })));

  router.get('/hourly', handler('hourly', async (req) => ({
    hours: await store.operatorHourly(req.operator.userId, {
      days: req.query.days,
      ownerId: uuidOrNull(req.query.ownerId),
      machineId: uuidOrNull(req.query.machineId),
      timezone: TZ,
    }),
  })));

  router.get('/funnel', handler('funnel', async (req) => ({
    machines: await store.operatorFunnel(req.operator.userId, {
      days: req.query.days,
      ownerId: uuidOrNull(req.query.ownerId),
      timezone: TZ,
    }),
  })));

  router.get('/products', handler('products', async (req) => ({
    products: await store.operatorProducts(req.operator.userId, {
      days: req.query.days,
      ownerId: uuidOrNull(req.query.ownerId),
    }),
  })));

  /**
   * The statement an owner holds against their own QPay export.
   *
   * ownerId is required and validated: without it this would silently become
   * "every owner's payment lines", which is a different and much larger
   * disclosure than the endpoint's name suggests.
   */
  router.get('/reconciliation', handler('reconciliation', async (req) => {
    const ownerId = uuidOrNull(req.query.ownerId);
    if (!ownerId) return { error: 'ownerId required', rows: [] };
    const now = new Date();
    const from = req.query.from ? new Date(String(req.query.from)) : new Date(now.getFullYear(), now.getMonth(), 1);
    const to = req.query.to ? new Date(String(req.query.to)) : now;
    if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) {
      return { error: 'bad date range', rows: [] };
    }
    return {
      ownerId,
      from: from.toISOString(),
      to: to.toISOString(),
      rows: await store.operatorReconciliation(req.operator.userId, {
        ownerId,
        from: from.toISOString(),
        to: to.toISOString(),
        timezone: TZ,
      }),
    };
  }));

  /** Am I an operator? The portal asks this to decide whether to show the link. */
  router.get('/me', (req, res) => res.json({ userId: req.operator.userId, isOperator: true }));

  return router;
}
