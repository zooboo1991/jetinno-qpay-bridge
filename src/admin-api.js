import express from 'express';
import crypto from 'node:crypto';
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
 * Almost read-only. The writes are onboarding and nothing else — register a
 * business with an empty credential slot, issue its invite, correct its
 * invoice code — and none of them can touch a sealed credential or make
 * anybody a member. The owner still has to present the invite from the right
 * phone and type their own QPay password; the operator can hand over the key
 * but cannot turn it.
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

// No 0/O or 1/I: the reference is read aloud over the phone.
const REF_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function inviteReference() {
  const pick = () => REF_ALPHABET[crypto.randomInt(REF_ALPHABET.length)];
  const part = () => Array.from({ length: 4 }, pick).join('');
  return `${part()}-${part()}`;
}

export function adminApi({ log = () => {}, portalOrigin = '' } = {}) {
  const router = express.Router();

  router.use((req, res, next) => {
    const origin = req.get('origin');
    if (portalOrigin && origin === portalOrigin) {
      res.setHeader('Access-Control-Allow-Origin', portalOrigin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
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

  // -------------------------------------------------------------------------
  // Onboarding writes (migration 008).
  // -------------------------------------------------------------------------
  const json = express.json({ limit: '4kb', type: 'application/json' });
  const str = (v) => (typeof v === 'string' ? v : '');

  /** A business, its first machine and an empty credential slot. */
  router.post('/owners', json, handler('provision', async (req) => {
    const b = req.body ?? {};
    const r = await store.operatorProvisionOwner(req.operator.userId, {
      // Generated here, not in SQL: the credential id is bound into the AEAD
      // additional data the owner's password will be sealed under.
      credentialId: crypto.randomUUID(),
      name: str(b.name),
      contactPhone: str(b.contactPhone),
      deviceNo: str(b.deviceNo),
      location: str(b.location),
      invoiceCode: str(b.invoiceCode),
    });
    log('admin provision', r.out_status, r.out_owner_id ?? '');
    return { status: r.out_status, ownerId: r.out_owner_id ?? null };
  }));

  /**
   * The invite link's secret half.
   *
   * 32 random bytes, returned exactly once, to the operator's own session —
   * Postgres keeps only the sha256, so nothing stored can mint a working
   * link. The reference is the non-secret handle for talking about an invite
   * on the phone.
   */
  router.post('/owners/:ownerId/invite', json, handler('invite', async (req) => {
    const ownerId = uuidOrNull(req.params.ownerId);
    if (!ownerId) return { status: 'not_found' };
    const b = req.body ?? {};
    const role = b.role === 'admin' || b.role === 'viewer' ? b.role : null;
    if (!role) return { status: 'invalid_role' };

    for (let attempt = 0; attempt < 3; attempt++) {
      const token = crypto.randomBytes(32).toString('base64url');
      const tokenHash = crypto.createHash('sha256').update(token, 'utf8').digest();
      try {
        const r = await store.operatorCreateInvite(req.operator.userId, {
          ownerId,
          tokenHash,
          reference: inviteReference(),
          invitedPhone: str(b.invitedPhone),
          role,
        });
        log('admin invite', r.out_status, r.out_reference ?? '');
        if (r.out_status !== 'ok') return { status: r.out_status };
        return { status: 'ok', token, reference: r.out_reference, expiresAt: r.out_expires_at, role };
      } catch (err) {
        // A reference collision (one in a trillion) gets a fresh draw; any
        // other error is a real failure.
        if (err.code !== '23505') throw err;
      }
    }
    throw new Error('invite reference collided three times');
  }));

  router.post('/owners/:ownerId/invoice-code', json, handler('invoice-code', async (req) => {
    const ownerId = uuidOrNull(req.params.ownerId);
    if (!ownerId) return { status: 'not_found' };
    const status = await store.operatorSetInvoiceCode(req.operator.userId, ownerId, str(req.body?.invoiceCode));
    log('admin invoice code', status, ownerId);
    return { status };
  }));

  /** Am I an operator? The portal asks this to decide whether to show the link. */
  router.get('/me', (req, res) => res.json({ userId: req.operator.userId, isOperator: true }));

  return router;
}
