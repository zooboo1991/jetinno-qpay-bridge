/**
 * src/crypto.js — authenticated encryption for owner QPay credentials at rest.
 *
 * ONE sealed blob per credential row, AES-256-GCM, fresh random 96-bit IV per
 * write, full 128-bit tag, and the row identity (credential id + owner id)
 * bound in as AAD so a ciphertext can never be relocated to another row.
 *
 * Threat model: this protects against someone who obtains the DATABASE and
 * nothing else — a Supabase breach, a leaked read-only DB credential, a stolen
 * pg_dump, an RLS misconfiguration. It protects against nothing else. See
 * section 8 of the implementation plan.
 *
 * Decryption is ~15µs. It is free against Jetinno's 8-second budget; the
 * network hops around it are what need caching, not this.
 */
import { createCipheriv, createDecipheriv, randomBytes, hkdfSync, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';

const ALGO = 'aes-256-gcm';
const IV_BYTES = 12;  // 96 bits: the only IV length AES-GCM is properly specified for.
const TAG_BYTES = 16; // 128 bits. Never truncated.
const FORMAT = 'v1';
const INFO_ENC = 'jetinno-qpay-bridge/owner-credentials/v1';
const INFO_FP = 'jetinno-qpay-bridge/credential-fingerprint/v1';
const KEY_ID_RE = /^[a-z0-9][a-z0-9_-]{0,15}$/;

const b64u = (buf) => buf.toString('base64url');
const canonB64 = (s) => s.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');

export class CredentialCryptoError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'CredentialCryptoError';
    this.code = code; // NO_KEYRING | UNKNOWN_KEY | BAD_FORMAT | AUTH_FAILED | BAD_PAYLOAD
  }
}

const fail = (code, message) => {
  throw new CredentialCryptoError(code, message);
};

/**
 * Decode 32 bytes of base64 key material, refusing anything that does not
 * round-trip. Buffer.from(str,'base64') NEVER throws: it silently skips
 * characters it does not recognise and stops at the first padding run, so a
 * truncated paste becomes a short key and — the nastier case — a key with
 * trailing junk still decodes to exactly 32 bytes and sails past a length
 * check, quietly encrypting under a key nobody can reproduce tomorrow.
 */
function decodeKey(label, b64) {
  const raw = Buffer.from(b64, 'base64');
  if (raw.length !== 32) fail('NO_KEYRING', `${label} decoded to ${raw.length} bytes, need 32`);
  if (canonB64(raw.toString('base64')) !== canonB64(b64)) {
    fail('NO_KEYRING', `${label} is not clean base64 — check for a truncated or padded paste`);
  }
  return raw;
}

/** hkdfSync returns an ArrayBuffer in Node, not a Buffer. createCipheriv throws on it. */
const derive = (master, info) => Buffer.from(hkdfSync('sha256', master, Buffer.alloc(0), info, 32));

const SECRET_FILE = process.env.CRED_KEYS_FILE ?? '/etc/secrets/cred_keys';

/**
 * Two sources, and NEVER a silent preference between them. An operator who
 * rotates the secret file but leaves a stale env var behind would otherwise
 * start encrypting under the wrong key with no signal at all.
 */
function readSource(filePath, envName) {
  let fromFile = null;
  try {
    fromFile = readFileSync(filePath, 'utf8').trim();
  } catch {
    fromFile = null;
  }
  const fromEnv = (process.env[envName] ?? '').trim();

  if (fromFile && fromEnv && fromFile !== fromEnv) {
    fail('NO_KEYRING', `${envName} and ${filePath} are both set and disagree — remove one`);
  }
  const value = fromFile || fromEnv;
  if (!value) fail('NO_KEYRING', `${envName} is not set — refusing to start`);
  return { value, source: fromFile ? `file:${filePath}` : `env:${envName}` };
}

function buildKeyring() {
  const { value, source } = readSource(SECRET_FILE, 'CRED_KEYS');

  const keys = new Map();
  for (const entry of value.split(/[,\n]/)) {
    const line = entry.trim();
    if (!line || line.startsWith('#')) continue;

    const at = line.indexOf(':');
    if (at < 1) fail('NO_KEYRING', 'CRED_KEYS entry is not <keyId>:<base64>');
    const keyId = line.slice(0, at).trim();
    const b64 = line.slice(at + 1).trim();

    // The key id travels inside every ciphertext string, so keep it to a
    // charset that can never collide with the '.' separator.
    if (!KEY_ID_RE.test(keyId)) fail('NO_KEYRING', `bad key id: ${keyId}`);
    if (keys.has(keyId)) fail('NO_KEYRING', `duplicate key id: ${keyId}`);

    const master = decodeKey(`key ${keyId}`, b64);
    // HKDF so this master is only ever used for this one purpose. If the same
    // secret is later reused to sign webhooks or cookies, each purpose gets its
    // own subkey and no two share raw key bytes. Microseconds, once, at boot.
    const enc = derive(master, `${INFO_ENC}#${keyId}`);
    master.fill(0);
    keys.set(keyId, enc);
  }
  if (keys.size === 0) fail('NO_KEYRING', 'CRED_KEYS contained no usable entries');

  const activeId = (process.env.CRED_KEY_ACTIVE ?? '').trim() || [...keys.keys()][0];
  if (!keys.has(activeId)) fail('NO_KEYRING', `CRED_KEY_ACTIVE=${activeId} is not in CRED_KEYS`);

  // Fingerprints use their own key, deliberately OUTSIDE the rotating keyring:
  // a fingerprint must stay stable across a master-key rotation or the unique
  // index that stops two owners registering the same merchant silently splits
  // into two namespaces mid-rotation.
  const fpSource = readSource(process.env.CRED_FP_KEY_FILE ?? '/etc/secrets/cred_fp_key', 'CRED_FP_KEY');
  const fpMaster = decodeKey('CRED_FP_KEY', fpSource.value);
  const fpKey = derive(fpMaster, INFO_FP);
  fpMaster.fill(0);

  return { keys, activeId, fpKey, source, fpKeySource: fpSource.source };
}

let keyring = null;

/**
 * Parsed once at module load, never re-read. Rotating keys means a redeploy,
 * which is the correct blast radius: a live process must never switch keys
 * underneath an in-flight request.
 */
function ring() {
  if (!keyring) keyring = buildKeyring();
  return keyring;
}

/**
 * Call once at boot, before app.listen. A bad or missing key must fail the
 * deploy loudly, not the first customer of the morning.
 */
export function assertCryptoUsable() {
  const r = ring();
  const context = credentialAad({
    credentialId: '00000000-0000-4000-8000-000000000000',
    ownerId: '00000000-0000-4000-8000-000000000001',
  });
  const probe = seal({ probe: true }, { context });
  if (open(probe, { context }).probe !== true) fail('AUTH_FAILED', 'keyring self-test failed');
  if (fingerprint('selftest').length !== 64) fail('AUTH_FAILED', 'fingerprint self-test failed');
  return {
    activeKeyId: r.activeId,
    keyIds: [...r.keys.keys()],
    keyringSource: r.source,
    fpKeySource: r.fpKeySource,
  };
}

export const activeKeyId = () => ring().activeId;

/**
 * The additional authenticated data for a credential row.
 *
 * Binding BOTH ids matters. Without the credential id, blobs are swappable
 * between one owner's own rows; without the owner id, an attacker with UPDATE
 * re-parents a credential row to themselves. With both bound, either move
 * fails authentication instead of silently redirecting an owner's revenue.
 * Changing either id on a live row therefore requires a deliberate rewrap —
 * that is the intent, not an inconvenience.
 */
export function credentialAad({ credentialId, ownerId }) {
  if (!credentialId || !ownerId) fail('BAD_PAYLOAD', 'credentialAad needs credentialId and ownerId');
  return `qpay_credentials:${credentialId}|owner:${ownerId}`;
}

function aadFor(context) {
  if (typeof context !== 'string' || context.length === 0 || context.length > 200) {
    fail('BAD_PAYLOAD', 'context must be a short non-empty string');
  }
  return Buffer.from(`${FORMAT}|${context}`, 'utf8');
}

/**
 * Seals an object into `v1.<keyId>.<iv>.<tag>.<ciphertext>` (base64url parts).
 *
 * Self-describing on purpose: the key id travels with the ciphertext, so a row
 * can never disagree with a separate "which key" column. The key_id column in
 * Postgres is a denormalised copy for `WHERE key_id <> $active` during
 * rotation — this string is the authority.
 */
export function seal(value, { context }) {
  const { keys, activeId } = ring();
  const aad = aadFor(context);
  const plaintext = Buffer.from(JSON.stringify(value), 'utf8');

  // Fresh random IV on EVERY call, including a re-save of unchanged values.
  // Never derived from an id, never a counter, never an IV column reused on
  // update. A repeated (key, IV) pair under GCM leaks the XOR of both
  // plaintexts AND the GHASH subkey, which yields forged tags under that key
  // forever. 96 random bits is safe well past the seals this system will make.
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGO, keys.get(activeId), iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad, { plaintextLength: plaintext.length }); // must precede update()
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag(); // only valid after final()

  plaintext.fill(0);
  return [FORMAT, activeId, b64u(iv), b64u(tag), b64u(ct)].join('.');
}

/** Opens a sealed string. Throws on tampering, wrong context, or unknown key. */
export function open(sealed, { context }) {
  if (typeof sealed !== 'string') fail('BAD_FORMAT', 'sealed value is not a string');
  const parts = sealed.split('.');
  if (parts.length !== 5 || parts[0] !== FORMAT) fail('BAD_FORMAT', 'sealed value is not a v1 blob');

  const [, keyId, ivB64, tagB64, ctB64] = parts;
  const key = ring().keys.get(keyId);
  // A missing key is an operational error, not an attack: a key was retired
  // from CRED_KEYS before every row had been rewrapped. Say so plainly.
  if (!key) fail('UNKNOWN_KEY', `no key "${keyId}" in keyring — was it retired too early?`);

  const iv = Buffer.from(ivB64, 'base64url');
  const tag = Buffer.from(tagB64, 'base64url');
  const ct = Buffer.from(ctB64, 'base64url');
  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) fail('BAD_FORMAT', 'bad iv or tag length');

  const decipher = createDecipheriv(ALGO, key, iv, { authTagLength: TAG_BYTES });
  decipher.setAAD(aadFor(context));
  decipher.setAuthTag(tag); // must be set before final()

  let plaintext;
  try {
    // final() is what verifies the tag. Skipping it — or catching its throw and
    // using the update() output anyway — silently downgrades this to
    // unauthenticated CTR mode. No manual timingSafeEqual: OpenSSL's GCM tag
    // check is already constant-time, and a hand-rolled one is a bug waiting.
    plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    // Deliberately opaque: never echo iv/tag/ciphertext into logs or HTTP.
    fail('AUTH_FAILED', `ciphertext failed authentication (key ${keyId})`);
  }

  try {
    return JSON.parse(plaintext.toString('utf8'));
  } finally {
    // Narrows the window; does not close it. The JSON.stringify intermediate is
    // an immutable GC-managed string that cannot be wiped, and the decrypted
    // object lives in the credential cache by design. A heap dump of this
    // process contains plaintext credentials.
    plaintext.fill(0);
  }
}

export const sealedKeyId = (sealed) => (typeof sealed === 'string' ? sealed.split('.')[1] : null);
export const needsRewrap = (sealed) => sealedKeyId(sealed) !== ring().activeId;

/**
 * Rotation primitive: open with whatever key sealed it, re-seal under the
 * active key, and verify the new blob before the caller writes it back. The
 * verify is cheap and turns "rewrap silently corrupted 40 owners" into a
 * failed job.
 */
export function rewrap(sealed, { context }) {
  const value = open(sealed, { context });
  const resealed = seal(value, { context });
  if (JSON.stringify(open(resealed, { context })) !== JSON.stringify(value)) {
    fail('AUTH_FAILED', 'rewrap verification failed');
  }
  return resealed;
}

/**
 * Keyed fingerprint of a merchant identity. A plain SHA-256 would be
 * brute-forceable — QPay usernames are short and structured — which would hand
 * a database reader half the Basic auth pair from a dump with no key at all.
 */
export function fingerprint(text) {
  if (typeof text !== 'string' || !text) fail('BAD_PAYLOAD', 'fingerprint needs a non-empty string');
  return createHmac('sha256', ring().fpKey).update(text, 'utf8').digest('hex');
}

/** The canonical identity string a merchant fingerprint is taken over. */
export const merchantIdentity = ({ username, invoiceCode }) =>
  `${String(username).trim().toLowerCase()}:${String(invoiceCode).trim()}`;
