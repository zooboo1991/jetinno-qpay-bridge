import * as store from './store.js';
import * as qpay from './qpay.js';
import * as alerts from './alerts.js';
import { open, credentialAad } from './crypto.js';

/**
 * The operator's own merchant ("the house"), as one of the businesses in the
 * system.
 *
 * OPERATOR_MERCHANT_OWNER_ID names a business — Coffeine's own — whose
 * connected QPay account takes the operator's money: the system subscription
 * (billing.js) and every sale on a machine nobody has registered. Unset, both
 * stay on the env QPAY_* account, as before; set, they never touch it again,
 * and a house that cannot be used refuses rather than falls back — the env
 * account may be somebody's test merchant.
 *
 * The credential is read from the database, never from the environment: it
 * is the one the business connected in the portal, and a new password or a
 * re-verified merchant there applies here within the minute (at once on this
 * instance, through owners.forgetCredential).
 *
 * Each order and invoice the house issues carries a marker naming the
 * credential and its merchant fingerprint, so a check always goes to the
 * merchant that issued the invoice: orders and invoices made before the
 * switch finish on the env account, later ones here.
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RAW_ID = (process.env.OPERATOR_MERCHANT_OWNER_ID ?? '').trim();
export const HOUSE_OWNER_ID = UUID.test(RAW_ID) ? RAW_ID.toLowerCase() : null;
/** Set to something, but not to a business id: a typo must not fall back silently. */
export const HOUSE_MISCONFIGURED = RAW_ID !== '' && !HOUSE_OWNER_ID;
export const houseConfigured = () => Boolean(HOUSE_OWNER_ID) || HOUSE_MISCONFIGURED;

export class HouseUnavailable extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

/*
 * The ROW is cached, sealed blob and all — not an unsealed credential or a
 * client, which close over a plaintext password (the rule owners.js keeps).
 * Unsealing per use costs microseconds; the query is what the cache saves.
 */
const TTL_MS = Number(process.env.OWNER_CACHE_TTL_MS ?? 60_000);
let cached = null; // { at, row }
let lastState = HOUSE_OWNER_ID ? 'unknown' : HOUSE_MISCONFIGURED ? 'misconfigured' : 'unset';

/** What a marker looks like: `house:<credential id>:<merchant fingerprint>`. */
const MARKER = /^house:([0-9a-f-]{36}):([0-9a-f]{64})$/;
export const markerFor = (row) => `house:${row.id}:${row.fingerprint}`;
export function parseMarker(text) {
  const m = typeof text === 'string' ? MARKER.exec(text) : null;
  return m ? { credentialId: m[1], fingerprint: m[2] } : null;
}

/** The house's credential row, through the cache. Throws HouseUnavailable. */
async function houseRow() {
  if (HOUSE_MISCONFIGURED) {
    lastState = 'misconfigured';
    throw new HouseUnavailable('OPERATOR_MERCHANT_OWNER_ID_INVALID');
  }
  if (cached && Date.now() - cached.at < TTL_MS) return cached.row;
  let row;
  try {
    row = await store.houseCredential(HOUSE_OWNER_ID);
  } catch {
    // The database is slow or down: the account seen a minute ago is still
    // the house's — the same rule owners.js keeps for an owner's machine.
    if (cached?.row) return cached.row;
    lastState = 'db_error';
    throw new HouseUnavailable('OPERATOR_MERCHANT_DB_UNAVAILABLE');
  }
  if (!row) {
    cached = null;
    lastState = 'not_connected';
    throw new HouseUnavailable('OPERATOR_MERCHANT_NOT_CONNECTED');
  }
  cached = { at: Date.now(), row };
  return row;
}

/**
 * The house merchant: { client, credentialId, marker }, or null when no house
 * is configured (the env account is the operator's merchant). Throws
 * HouseUnavailable when one is configured but cannot take money right now.
 */
export async function houseMerchant() {
  if (!houseConfigured()) return null;
  const row = await houseRow();
  let plain;
  try {
    plain = open(row.sealed, { context: credentialAad({ credentialId: row.id, ownerId: row.owner_id }) });
  } catch {
    cached = null;
    lastState = 'unseal_failed';
    throw new HouseUnavailable('OPERATOR_MERCHANT_UNSEAL_FAILED');
  }
  lastState = 'ok';
  // Keyed by credential id like every owner client, so the house shares one
  // QPay token with that business's own machines.
  return { client: qpay.clientForSealed(plain, row.id), credentialId: row.id, marker: markerFor(row) };
}

/**
 * The marker new invoices are issued under right now, without unsealing
 * anything: null for the env account. Throws HouseUnavailable.
 */
export async function currentMarker() {
  if (!houseConfigured()) return null;
  return markerFor(await houseRow());
}

/**
 * The client that can check or cancel what a credential issued: rebuilt even
 * if it has since been deactivated (settling an existing sale is not a new
 * one), but only while it still names the merchant that issued the invoice.
 * { client } or { error }.
 */
export async function clientForCredential(credentialId, fingerprint) {
  const cred = await store.getCredentialById(credentialId);
  if (!cred?.sealed) return { error: 'CREDENTIAL_MISSING' };
  if (fingerprint && cred.fingerprint && cred.fingerprint !== fingerprint) return { error: 'MERCHANT_CHANGED' };
  try {
    const plain = open(cred.sealed, { context: credentialAad({ credentialId, ownerId: cred.owner_id }) });
    return { client: qpay.clientForSealed(plain, credentialId) };
  } catch (err) {
    // The crypto module's own words (wrong key, tampered row) — never the blob.
    return { error: 'CREDENTIAL_UNSEAL_FAILED', detail: String(err?.message ?? err).split('\n')[0].slice(0, 120) };
  }
}

/**
 * The client for whatever a marker names: the env account for none (made
 * before the switch, or with no house configured), the house credential that
 * issued it otherwise. { client: null } means the env client.
 */
export async function issuerClient(marker) {
  if (!marker) return { client: null };
  const h = parseMarker(marker);
  if (!h) return { error: 'MERCHANT_MARKER_INVALID' };
  return clientForCredential(h.credentialId, h.fingerprint);
}

/*
 * The operator hears about an unusable house once per reason per hour: every
 * billing page and every unregistered machine's sale would otherwise page
 * them again.
 */
const paged = new Map();
export function reportDown(err, log = () => {}) {
  const code = String(err?.code ?? err?.message ?? 'OPERATOR_MERCHANT_UNAVAILABLE').slice(0, 60);
  log('operator merchant unavailable', code);
  const now = Date.now();
  if (now - (paged.get(code) ?? 0) < 3_600_000) return;
  paged.set(code, now);
  alerts.pageOperator('operator QPay account unusable: subscription and unregistered sales stopped', { code });
}

/** Forgets the cached row — whenever any credential changes. */
export function forget() {
  cached = null;
}

/** For /health: which merchant takes the operator's money, and whether it works. */
export const status = () => (HOUSE_OWNER_ID || HOUSE_MISCONFIGURED ? lastState : 'unset');
