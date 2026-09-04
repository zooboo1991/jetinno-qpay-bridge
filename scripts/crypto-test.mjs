/**
 * Assertions for src/crypto.js — the module that decides whether a database
 * breach hands the attacker every owner's QPay password.
 *
 * Run with: npm run test:crypto
 *
 * The two that matter most are "relocate blocked" and "reparent blocked". They
 * are what stops `update qpay_credentials set owner_id = <me>` from turning
 * someone else's sealed credential into one this system will happily use. The
 * AAD binds both ids into the tag, so a moved row simply fails to open.
 */
import { randomBytes } from 'node:crypto';

process.env.CRED_KEYS ??= `k1:${randomBytes(32).toString('base64')}`;
process.env.CRED_KEY_ACTIVE ??= 'k1';
process.env.CRED_FP_KEY ??= randomBytes(32).toString('base64');

const c = await import('../src/crypto.js');
c.assertCryptoUsable();

const A = c.credentialAad({ credentialId: 'cred_1', ownerId: 'own_1' });
const B = c.credentialAad({ credentialId: 'cred_2', ownerId: 'own_1' });
const C = c.credentialAad({ credentialId: 'cred_1', ownerId: 'own_2' });

// A trailing space is deliberate: password managers paste them, the form flags
// them rather than stripping them, and the crypto must carry them byte-exact.
const secret = { username: 'coffeine', password: 'p@ss w0rd ', invoice_code: 'INV_123' };
const blob = c.seal(secret, { context: A });

const refuses = (fn) => {
  try {
    fn();
    return false;
  } catch (err) {
    return err.code === 'AUTH_FAILED';
  }
};

const id = (username, invoiceCode) => c.fingerprint(c.merchantIdentity({ username, invoiceCode }));

const checks = [
  ['round trip', () => JSON.stringify(c.open(blob, { context: A })) === JSON.stringify(secret)],
  ['self-describing key id', () => blob.startsWith('v1.k1.') && c.sealedKeyId(blob) === 'k1'],
  ['fresh IV on every seal', () => blob !== c.seal(secret, { context: A })],
  ['relocate to another credential blocked', () => refuses(() => c.open(blob, { context: B }))],
  ['reparent to another owner blocked', () => refuses(() => c.open(blob, { context: C }))],
  [
    'single-character tamper blocked',
    () => {
      const p = blob.split('.');
      p[4] = p[4].slice(0, -1) + (p[4].endsWith('A') ? 'B' : 'A');
      return refuses(() => c.open(p.join('.'), { context: A }));
    },
  ],
  ['trailing space preserved byte-exact', () => c.open(blob, { context: A }).password === 'p@ss w0rd '],
  ['fingerprint stable', () => id('coffeine', 'INV_123') === id('coffeine', 'INV_123')],
  ['fingerprint separates invoice codes', () => id('coffeine', 'INV_123') !== id('coffeine', 'INV_124')],
  ['fingerprint separates usernames', () => id('coffeine', 'INV_123') !== id('other', 'INV_123')],
  ['fingerprint case-insensitive on username', () => id('Coffeine', 'INV_123') === id('coffeine', 'INV_123')],
  ['fingerprint trims surrounding space', () => id(' coffeine ', 'INV_123') === id('coffeine', 'INV_123')],
  ['fingerprint is keyed, not a bare hash', () => id('coffeine', 'INV_123').length === 64],
];

let passed = 0;
for (const [name, fn] of checks) {
  let ok = false;
  let detail = '';
  try {
    ok = fn();
  } catch (err) {
    detail = ` — ${err.code ?? err.message}`;
  }
  console.log(`  ${ok ? '✓' : '✗'} ${name}${ok ? '' : detail}`);
  if (ok) passed += 1;
}

console.log('');
console.log(`  ${passed}/${checks.length} давлаа · sealed blob ${blob.length} тэмдэгт`);
process.exit(passed === checks.length ? 0 : 1);
