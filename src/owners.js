import * as store from './store.js';

/**
 * A short-lived cache in front of the device → owner → credential lookup.
 *
 * WHY IT EXISTS: that lookup sits on the getQrCode hot path, inside Jetinno's
 * 8-second budget, and it is the same three-table join for every cup a
 * machine sells. One round trip to Supabase's pooler per coffee is a round
 * trip that buys nothing — the answer changes a few times in the life of a
 * machine.
 *
 * WHY THE TTL IS SHORT: it is also the window in which a machine keeps
 * selling on a merchant the owner has just replaced. Sixty seconds is the
 * number the owner is told about ("1 минутын дотор"), and it is what bounds
 * the other Render instances, which never see the local invalidation below.
 *
 * WHAT IS CACHED: the row, sealed blob and all — exactly what the database
 * returned. NOT an unsealed credential and NOT a QPay client: those close
 * over a plaintext merchant password, and keeping one alive for a minute to
 * save a few milliseconds of AES is a poor trade.
 */

const TTL_MS = Number(process.env.OWNER_CACHE_TTL_MS ?? 60_000);

/** deviceNo -> { row, at } */
const byDevice = new Map();

// Counted, not inferred. A cache whose hit rate nobody measures is a cache
// nobody knows is working — and this one is measurable from /health, where a
// hit rate near zero would say the TTL is shorter than the gap between sales.
let hits = 0;
let misses = 0;

export async function resolveMachine(deviceNo) {
  const hit = byDevice.get(deviceNo);
  if (hit && Date.now() - hit.at < TTL_MS) {
    hits += 1;
    return hit.row;
  }
  misses += 1;

  const row = await store.resolveMachine(deviceNo);
  // A miss is cached too. An unregistered device is exactly the case that
  // repeats — a machine nobody has seeded sells all day — and without this
  // every one of those sales pays for the same negative lookup.
  byDevice.set(deviceNo, { row, at: Date.now() });
  return row;
}

/**
 * Drops every entry pointing at this credential.
 *
 * Called the moment a verification promotes a new merchant. The map is keyed
 * by device, so the sweep is over its values — there are as many entries as
 * there are machines that have sold since the last minute, and this runs a
 * handful of times in the life of a machine.
 */
export function forgetCredential(credentialId) {
  for (const [deviceNo, entry] of byDevice) {
    if (entry.row?.qpay_credential_id === credentialId) byDevice.delete(deviceNo);
  }
}

/** Drops one device's entry — for the registration CLI and for tests. */
export function forgetDevice(deviceNo) {
  byDevice.delete(deviceNo);
}

/** Empties the cache. Used by tests; never on a request path. */
export function forgetAll() {
  byDevice.clear();
  hits = 0;
  misses = 0;
}

/** For /health: how much is being held, how often it answers, and the TTL. */
export function cacheStats() {
  return { entries: byDevice.size, ttlMs: TTL_MS, hits, misses };
}
