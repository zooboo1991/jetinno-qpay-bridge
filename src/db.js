import pg from 'pg';

/**
 * Postgres against the Supabase transaction pooler (port 6543).
 *
 * Two things here are not style choices:
 *
 * 1. Short timeouts. Jetinno gives the whole getQrCode request 8 seconds. A
 *    database that hangs must fail fast and let the request continue, because
 *    a lock wait looks exactly like QPay being slow and eats the same budget.
 *
 * 2. No named prepared statements, ever. Transaction-mode pgbouncer hands a
 *    different backend to every statement, so a prepared name created on one
 *    is missing on the next. Plain parameterised queries only — which `pg`
 *    does by default as long as nothing passes a `name` field.
 *
 * Also: no supabase-js / PostgREST on the request path. It is an HTTP hop with
 * its own latency budget in front of a database we can reach directly.
 */
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  max: Number(process.env.PG_POOL_MAX ?? 5),
  connectionTimeoutMillis: 1500,
  idleTimeoutMillis: 30_000,
  // Set at connection time by the driver rather than with a `set` inside a
  // pool.on('connect') handler: that handler's query is not awaited by the
  // pool, so it races the caller's first statement — the connection can serve
  // a query before its own timeout is in place, which is precisely the query
  // most likely to be the one that hangs.
  statement_timeout: Number(process.env.PG_STATEMENT_TIMEOUT_MS ?? 800),
});

// Without a listener, a dropped pooled connection raises an unhandled 'error'
// event and takes the whole process down — including the machine's ability to
// sell coffee, over a database this phase does not even read from.
pool.on('error', () => {});

export const configured = () => Boolean(process.env.DATABASE_URL);

export const query = (text, params) => pool.query(text, params);

/**
 * One transaction on one client. Used only OFF the request path (owner
 * registration), never where the machine's 8-second budget lives: a
 * transaction pins a pooled connection for its whole span, and the comment at
 * the top of store.js explains why the hot path never does that.
 */
export async function tx(fn) {
  const client = await pool.connect();
  try {
    await client.query('begin');
    const result = await fn((text, params) => client.query(text, params));
    await client.query('commit');
    return result;
  } catch (err) {
    await client.query('rollback').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/**
 * A lane for the portal's APIs, so they can never take every connection.
 *
 * The pool is five connections, and /jetinno/getQrCode needs one inside
 * Jetinno's 8 seconds. One owner opening the reports page fires a dozen and
 * more API calls at once; a few owners together queued the machine's lookup
 * behind them past the pool's 1.5 s wait, and the customer saw an error.
 * Portal requests run at most (pool - 2) at a time; the rest wait here, in
 * memory, not in the pool's queue.
 */
const API_SLOTS = Math.max(1, Number(process.env.PG_POOL_MAX ?? 5) - 2);
let apiBusy = 0;
const apiWaiting = [];

export function apiGate(req, res, next) {
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    const waiter = apiWaiting.shift();
    if (waiter) waiter();
    else apiBusy -= 1;
  };
  const start = () => {
    res.once('finish', release);
    res.once('close', release);
    next();
  };
  if (apiBusy < API_SLOTS) {
    apiBusy += 1;
    start();
  } else {
    // A slot handed over directly keeps apiBusy unchanged.
    apiWaiting.push(start);
  }
}

export const healthy = () =>
  pool
    .query('select 1')
    .then(() => true)
    .catch(() => false);

export const close = () => pool.end();
