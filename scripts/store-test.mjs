/**
 * Integration test for src/store.js against a real Postgres carrying the real
 * migrations. Run with: npm run test:store
 *
 * Needs DATABASE_URL. scripts/store-test.sh starts a throwaway container,
 * applies migrations/000..003, and points this at it — so it never touches
 * Supabase and never needs a production credential.
 *
 * The assertion that matters is "only one settle claim wins". Until orders
 * moved to Postgres, that guarantee was a synchronous flag in one process;
 * from here it is a SQL predicate, and Render runs the old and new instance
 * together for ~30 seconds on every deploy, so two processes racing for one
 * payment is not hypothetical.
 */
import { randomUUID, createHash } from 'node:crypto';
import { query, close } from '../src/db.js';
import * as store from '../src/store.js';

const results = [];
const check = async (name, fn) => {
  try {
    const ok = await fn();
    results.push([Boolean(ok), name, '']);
  } catch (err) {
    results.push([false, name, ` — ${err.message.split('\n')[0]}`]);
  }
};

// ---- seed one owner, one credential, one machine -------------------------
const ownerId = randomUUID();
const credId = randomUUID();
const machineId = randomUUID();
const deviceNo = `TEST${Math.floor(Math.random() * 100000)}`;

await query(`insert into public.owners (id, name, contact_phone) values ($1,$2,$3)`, [
  ownerId,
  'Тест Оффис ХХК',
  '99112233',
]);
await query(
  `insert into public.qpay_credentials (id, owner_id, label, sealed, key_id, fingerprint, status, is_active)
   values ($1,$2,$3,$4,'k1',$5,'active',true)`,
  // The fingerprint column is shape-checked as 64 lowercase hex — the exact
  // output of the keyed HMAC in src/crypto.js. Seed something of that shape.
  [credId, ownerId, 'Үндсэн данс', 'v1.k1.aaa.bbb.ccc', createHash('sha256').update(credId).digest('hex')]
);
await query(
  `insert into public.machines (id, owner_id, qpay_credential_id, device_no, notify_url, status)
   values ($1,$2,$3,$4,'http://localhost:4000/notify','active')`,
  [machineId, ownerId, credId, deviceNo]
);

// ---- resolveMachine ------------------------------------------------------
let resolved;
await check('resolveMachine finds the machine, owner and sealed credential', async () => {
  resolved = await store.resolveMachine(deviceNo);
  return (
    resolved &&
    resolved.owner_id === ownerId &&
    resolved.qpay_credential_id === credId &&
    resolved.sealed === 'v1.k1.aaa.bbb.ccc'
  );
});

await check('resolveMachine returns null for an unregistered device', async () => {
  return (await store.resolveMachine('NOPE-NOT-REGISTERED')) === null;
});

// ---- beginOrder ----------------------------------------------------------
const orderNo = `T${Date.now()}`;
const newOrder = (no) => ({
  machineId,
  ownerId,
  credentialId: credId,
  orderNo: no,
  deviceNo,
  notifyUrl: 'http://localhost:4000/notify',
  productId: '1',
  productName: 'Латте',
  rawOrderAmount: '10000',
  amountDivisor: 100,
  amountMnt: 100,
  senderInvoiceNo: no,
  callbackUrl: `http://localhost/qpay/callback/${no}`,
  abandonAfterMs: 600_000,
});

let orderId;
await check("beginOrder inserts in 'creating' and returns the id", async () => {
  const row = await store.beginOrder(newOrder(orderNo));
  orderId = row?.id;
  const stored = await store.findOrderByMachine(machineId, orderNo);
  // An order has no invoice yet at this point; the schema refuses to let it
  // claim awaiting_payment until attachInvoice supplies one.
  return Boolean(orderId) && stored.status === 'creating';
});

await check('beginOrder absorbs the machine retry instead of throwing', async () => {
  // The machine re-sends the same orderNo when our 8s budget is missed. This
  // must be a no-op, not a duplicate-key error.
  return (await store.beginOrder(newOrder(orderNo))) === null;
});

await check('the same orderNo on a different machine is a separate order', async () => {
  const otherMachine = randomUUID();
  await query(
    `insert into public.machines (id, owner_id, qpay_credential_id, device_no, notify_url, status)
     values ($1,$2,$3,$4,'http://localhost:4000/notify','active')`,
    [otherMachine, ownerId, credId, `${deviceNo}B`]
  );
  // Jetinno's orderNo is unique per machine only, so a global key would let
  // one machine's order number block another owner's sale.
  const row = await store.beginOrder({
    ...newOrder(orderNo),
    machineId: otherMachine,
    deviceNo: `${deviceNo}B`,
    senderInvoiceNo: `${orderNo}-B`,
  });
  return Boolean(row?.id);
});

await check('attachInvoice stores the invoice and promotes to awaiting_payment', async () => {
  await store.attachInvoice(orderId, {
    invoiceId: `inv_${orderId}`,
    qrCode: 'https://s.qpay.mn/abc',
    qrTextLen: 242,
  });
  const row = await store.findOrderByMachine(machineId, orderNo);
  return (
    row.qpay_invoice_id === `inv_${orderId}` &&
    row.qr_text_len === 242 &&
    row.status === 'awaiting_payment'
  );
});

// ---- the claim: exactly one winner --------------------------------------
await check('five concurrent settle claims produce exactly one winner', async () => {
  const claims = await Promise.all(
    Array.from({ length: 5 }, (_, i) =>
      store.claimSettle(orderId, { leaseSeconds: 60, instance: `worker-${i}` })
    )
  );
  return claims.filter(Boolean).length === 1;
});

await check('a second claim while the lease is held is refused', async () => {
  return (await store.claimSettle(orderId, { leaseSeconds: 60, instance: 'late' })) === null;
});

// ---- settle through to paid ---------------------------------------------
// A refusal has to be visible to the caller. The wrapper returning nothing at
// all let a wrong amount pass silently, and the next step then drove the row
// to 'paid' with no confirmation behind it.
await check('markPaymentConfirmed refuses a mismatched amount and says so', async () => {
  const refused = await store.markPaymentConfirmed(orderId, {
    paymentId: 'pay_wrong',
    paidAmountMnt: 99,
  });
  const row = await store.findOrderByMachine(machineId, orderNo);
  return refused === null && row.payment_confirmed_at === null && row.status === 'settling';
});

await check('markPaymentConfirmed → markNotifySent → finishSettle reaches paid', async () => {
  const confirmed = await store.markPaymentConfirmed(orderId, {
    paymentId: 'pay_1',
    paidAmountMnt: 100,
  });
  const notified = await store.markNotifySent(orderId);
  const finished = await store.finishSettle(orderId);
  const row = await store.findOrderByMachine(machineId, orderNo);
  return (
    confirmed !== null &&
    notified !== null &&
    finished !== null &&
    row.status === 'paid' &&
    row.payment_confirmed_at !== null
  );
});

await check('recordProductDone marks the cup as dispensed', async () => {
  await store.recordProductDone(orderId, true);
  const row = await store.findOrderByMachine(machineId, orderNo);
  return row.product_done_ok === true && row.product_done_at !== null;
});

// ---- abandoned sweep -----------------------------------------------------
await check('claimAbandoned picks up an expired unpaid order exactly once', async () => {
  const staleNo = `S${Date.now()}`;
  const row = await store.beginOrder({ ...newOrder(staleNo), senderInvoiceNo: staleNo });
  await store.attachInvoice(row.id, { invoiceId: `inv_${staleNo}`, qrCode: 'https://s.qpay.mn/x' });
  await query(`update public.orders set expires_at = now() - interval '1 hour' where id = $1`, [
    row.id,
  ]);
  const [a, b] = await Promise.all([
    store.claimAbandoned({ limit: 50, instance: 'sweeper-a' }),
    store.claimAbandoned({ limit: 50, instance: 'sweeper-b' }),
  ]);
  const claimedTwice = a.filter((x) => b.some((y) => y.id === x.id));
  return a.concat(b).some((x) => x.id === row.id) && claimedTwice.length === 0;
});

// ---- 006: the review fixes ----------------------------------------------
await check('006: a cancelled order whose payment landed late is claimable again', async () => {
  const no = `C${Date.now()}`;
  const row = await store.beginOrder({ ...newOrder(no), senderInvoiceNo: no });
  await store.attachInvoice(row.id, { invoiceId: `inv_${no}`, qrCode: 'https://s.qpay.mn/x' });
  // Sweep path: claim, cancel — then QPay says INVOICE_PAID after all.
  await store.claimSettle(row.id, { leaseSeconds: 60, instance: 'sweeper' });
  await store.markCancelled(row.id);
  const reclaimed = await store.claimSettle(row.id, { leaseSeconds: 60, instance: 'settler' });
  if (!reclaimed) return 'cancelled мөрийг claim хийж чадсангүй';
  await store.markPaymentConfirmed(row.id, { paymentId: `pay_${no}`, paidAmountMnt: 100 });
  await store.markNotifySent(row.id);
  await store.finishSettle(row.id);
  const after = await store.findOrderByMachine(machineId, no);
  return after.status === 'paid' && after.cancelled_at !== null;
});

await check('006: an invoice-less creating order fails alone instead of wedging the sweeper', async () => {
  const stuckNo = `W${Date.now()}`;
  const goodNo = `G${Date.now()}`;
  const stuck = await store.beginOrder({ ...newOrder(stuckNo), senderInvoiceNo: stuckNo });
  const good = await store.beginOrder({ ...newOrder(goodNo), senderInvoiceNo: goodNo });
  await store.attachInvoice(good.id, { invoiceId: `inv_${goodNo}`, qrCode: 'https://s.qpay.mn/x' });
  await query(`update public.orders set expires_at = now() - interval '1 hour' where id = any($1::uuid[])`, [
    [stuck.id, good.id],
  ]);
  // Before 006 this whole batch aborted on the constraint and NOTHING was
  // ever claimed again — the poisoned oldest row was re-selected forever.
  const claimed = await store.claimAbandoned({ limit: 50, instance: 'sweeper' });
  const stuckRow = await store.findOrderByMachine(machineId, stuckNo);
  return (
    claimed.some((x) => x.id === good.id) &&
    stuckRow.status === 'failed' &&
    stuckRow.last_error === 'NO_INVOICE'
  );
});

await check('006: productdone is accepted for a needs_human order', async () => {
  const no = `H${Date.now()}`;
  const row = await store.beginOrder({ ...newOrder(no), senderInvoiceNo: no });
  await store.attachInvoice(row.id, { invoiceId: `inv_${no}`, qrCode: 'https://s.qpay.mn/x' });
  await store.claimSettle(row.id, { leaseSeconds: 60, instance: 'settler' });
  await store.markPaymentConfirmed(row.id, { paymentId: `pay_${no}`, paidAmountMnt: 100 });
  await store.giveUp(row.id, 'test: machine unreachable');
  const done = await store.recordProductDone(row.id, true);
  const after = await store.findOrderByMachine(machineId, no);
  return done !== null && after.product_done_at !== null && after.status === 'needs_human';
});

await check('006: giveUpExhausted flips run-out orders to needs_human', async () => {
  const no = `E${Date.now()}`;
  const row = await store.beginOrder({ ...newOrder(no), senderInvoiceNo: no });
  await store.attachInvoice(row.id, { invoiceId: `inv_${no}`, qrCode: 'https://s.qpay.mn/x' });
  await query(`update public.orders set settle_attempts = 10 where id = $1`, [row.id]);
  const n = await store.giveUpExhausted();
  const after = await store.findOrderByMachine(machineId, no);
  return n >= 1 && after.status === 'needs_human' && after.last_error === 'SETTLE_ATTEMPTS_EXHAUSTED';
});

await check('findLiveOrder returns a live row by orderNo and skips finished ones', async () => {
  const liveNo = `L${Date.now()}`;
  const row = await store.beginOrder({ ...newOrder(liveNo), senderInvoiceNo: liveNo });
  await store.attachInvoice(row.id, { invoiceId: `inv_${liveNo}`, qrCode: 'https://s.qpay.mn/x' });
  const live = await store.findLiveOrder(liveNo);
  const finished = await store.findLiveOrder(orderNo); // paid earlier in this file
  return live?.id === row.id && live.notify_url && finished === null;
});

// ---- ingest errors -------------------------------------------------------
await check('logIngestError records an unregistered device', async () => {
  await store.logIngestError({
    path: '/jetinno/getQrCode',
    deviceNo: 'GHOST-DEVICE',
    orderNo: 'X1',
    reason: 'DEVICE_NOT_REGISTERED',
  });
  const { rows } = await query(
    `select count(*)::int as n from public.ingest_errors where device_no = 'GHOST-DEVICE'`
  );
  return rows[0].n === 1;
});

// ---- report --------------------------------------------------------------
let passed = 0;
for (const [ok, name, detail] of results) {
  console.log(`  ${ok ? '✓' : '✗'} ${name}${detail}`);
  if (ok) passed += 1;
}
console.log('');
console.log(`  ${passed}/${results.length} давлаа`);

await close();
process.exit(passed === results.length ? 0 : 1);
