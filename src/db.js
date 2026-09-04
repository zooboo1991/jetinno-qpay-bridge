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

export const healthy = () =>
  pool
    .query('select 1')
    .then(() => true)
    .catch(() => false);

export const close = () => pool.end();
