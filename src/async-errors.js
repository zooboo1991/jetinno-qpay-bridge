import Layer from 'express/lib/router/layer.js';

/**
 * Express 4 does not look at what a handler returns. An async handler whose
 * database call rejects — a statement timeout, a dropped pooler connection —
 * becomes an unhandled rejection, and Node's default for that is to exit.
 * One slow query on /owner/v1/invites/redeem took the whole bridge down with
 * it: every machine's sales and every in-flight order in memory.
 *
 * This is the same patch express-async-errors applies: a rejected promise is
 * passed to next(err), where server.js's error handler answers it. Express 5
 * does this natively; this file goes when the bridge moves to it.
 */
Layer.prototype.handle_request = function handle(req, res, next) {
  const fn = this.handle;
  if (fn.length > 3) return next();
  try {
    const result = fn(req, res, next);
    if (result && typeof result.then === 'function') result.then(undefined, next);
  } catch (err) {
    next(err);
  }
};
