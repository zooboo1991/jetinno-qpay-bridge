/**
 * The owner cache: that it exists, and that it cannot outlive a credential
 * change made through the API. Run: npm run test:cache
 *
 * The cache sits on the money path — it decides which merchant a sale is
 * invoiced under — so both halves matter. A cache that never hits buys
 * nothing; a cache that holds a replaced merchant sends an owner's coffee
 * money to the account they just disconnected.
 */
import { randomUUID } from 'node:crypto';
import { query, close } from '../src/db.js';
import * as owners from '../src/owners.js';

const results = [];
const check = async (name, fn) => {
  try {
    const ok = await fn();
    results.push([Boolean(ok), name, typeof ok === 'string' ? ` — ${ok}` : '']);
  } catch (err) {
    results.push([false, name, ` — ${err.message.split('\n')[0]}`]);
  }
};

// Measured from the cache's own counters, not inferred from timing. ESM
// exports are frozen, so monkey-patching store.resolveMachine is not an
// option — and a counter the module exports is better anyway: /health reads
// the same number in production.
const missesSince = (() => {
  let base = 0;
  return {
    reset() { base = owners.cacheStats().misses; },
    count() { return owners.cacheStats().misses - base; },
  };
})();

const ownerId = randomUUID();
const credId = randomUUID();
const machineId = randomUUID();
const deviceNo = `C${Math.floor(Math.random() * 1e9)}`;

await query(`insert into public.owners (id, name, contact_phone) values ($1,'Кэш ХХК','99110001')`, [ownerId]);
await query(
  `insert into public.qpay_credentials (id, owner_id, label, sealed, key_id, fingerprint, status, is_active, source)
   values ($1,$2,'Үндсэн','v1.k1.a.b.c','k1',$3,'active',true,'cli')`,
  [credId, ownerId, 'c'.repeat(64)]
);
await query(
  `insert into public.machines (id, owner_id, qpay_credential_id, device_no, label, status)
   values ($1,$2,$3,$4,'Кэш','active')`,
  [machineId, ownerId, credId, deviceNo]
);

await check('хоёр дахь дуудлага санд очихгүй — кэш ажиллаж байна', async () => {
  owners.forgetAll();
  missesSince.reset();
  await owners.resolveMachine(deviceNo);
  await owners.resolveMachine(deviceNo);
  await owners.resolveMachine(deviceNo);
  return missesSince.count() === 1;
});

await check('бүртгэлгүй машины хариу ч кэшлэгдэнэ — давтагдах хайлт үнэтэй', async () => {
  owners.forgetAll();
  missesSince.reset();
  const a = await owners.resolveMachine('GHOST-NOBODY');
  const b = await owners.resolveMachine('GHOST-NOBODY');
  return a === null && b === null && missesSince.count() === 1;
});

await check('forgetCredential нь тэр credential-ийн БҮХ машиныг мартана', async () => {
  // A second machine on the same credential — the case where forgetting only
  // the device that triggered the change would leave the others stale.
  const second = randomUUID();
  const secondDevice = `C${Math.floor(Math.random() * 1e9)}`;
  await query(
    `insert into public.machines (id, owner_id, qpay_credential_id, device_no, label, status)
     values ($1,$2,$3,$4,'Хоёр дахь','active')`,
    [second, ownerId, credId, secondDevice]
  );
  owners.forgetAll();
  await owners.resolveMachine(deviceNo);
  await owners.resolveMachine(secondDevice);
  missesSince.reset();
  owners.forgetCredential(credId);
  await owners.resolveMachine(deviceNo);
  await owners.resolveMachine(secondDevice);
  return missesSince.count() === 2;
});

await check('өөр credential-ыг мартуулахад энэ нь кэшдээ үлдэнэ', async () => {
  owners.forgetAll();
  await owners.resolveMachine(deviceNo);
  missesSince.reset();
  owners.forgetCredential(randomUUID());
  await owners.resolveMachine(deviceNo);
  return missesSince.count() === 0;
});

await check('кэш дэх мөр нь credential-ийн ТӨЛӨВИЙГ агуулна', async () => {
  // The status flags merchantFor gates on must be in the cached row, or the
  // gate would need its own lookup and the cache would buy nothing.
  owners.forgetAll();
  const row = await owners.resolveMachine(deviceNo);
  return (
    row.credential_status === 'active' &&
    row.credential_active === true &&
    row.machine_status === 'active' &&
    row.owner_status === 'active'
  );
});

await check('SQL-ээр шууд унтраахад кэш дуусах хүртэл хуучин хэвээр', async () => {
  // Documented behaviour, asserted so it stays documented: disabling through
  // the API invalidates, a raw SQL disable waits out the TTL. The emergency
  // stop is removing DATABASE_URL, not this.
  owners.forgetAll();
  await owners.resolveMachine(deviceNo);
  await query(`update public.qpay_credentials set status='disabled', is_active=false where id=$1`, [credId]);
  const stale = await owners.resolveMachine(deviceNo);
  owners.forgetCredential(credId);
  const fresh = await owners.resolveMachine(deviceNo);
  await query(`update public.qpay_credentials set status='active', is_active=true where id=$1`, [credId]);
  return stale.credential_active === true && fresh.credential_active === false;
});

await close();
const passed = results.filter(([ok]) => ok).length;
for (const [ok, name, extra] of results) console.log(`  ${ok ? '✓' : '✗'} ${name}${extra}`);
console.log(`\n  ${passed}/${results.length} давлаа`);
process.exit(passed === results.length ? 0 : 1);
