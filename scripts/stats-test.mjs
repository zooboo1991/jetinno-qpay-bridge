/**
 * Integration test for app.owner_stats against a real Postgres carrying the
 * real migrations. Run with: npm run test:stats
 *
 * Two things are being defended here, and both have been wrong in shipped
 * dashboards before:
 *
 *   Scope. The function's only access control is its p_owner_id argument, so
 *   a second owner is seeded with a deliberately enormous sale. If any figure
 *   for the first owner moves, the query leaks across tenants.
 *
 *   The day boundary. Mongolia is UTC+8. A sale at 00:30 Ulaanbaatar happened
 *   at 16:30 UTC the previous day, so a UTC-bucketed "today" files it under
 *   yesterday — and every owner in the country sees an empty dashboard until
 *   08:00 while their morning money is on the wrong row. The seed below puts
 *   a sale in exactly that window on purpose.
 */
import { randomUUID } from 'node:crypto';
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

const TZ = 'Asia/Ulaanbaatar';

/**
 * A pinned clock. Every assertion below is about a calendar boundary, and a
 * test that reads the real clock is a test that passes for twenty-nine days
 * and fails on the first of the month — or between midnight and 10am, when a
 * sale seeded at "10:00 today" has not happened yet. app.owner_stats takes
 * `now` as a parameter for exactly this; the bridge never passes it.
 *
 * 2026-09-15 05:00 UTC is 13:00 on the 15th in Ulaanbaatar: mid-month, mid-
 * afternoon, so "two days ago" and "the 1st of this month" are unambiguous.
 */
const NOW = '2026-09-15T05:00:00Z';

async function seedOwner(name, phone) {
  const ownerId = randomUUID();
  const credId = randomUUID();
  const machineId = randomUUID();
  await query(`insert into public.owners (id, name, contact_phone) values ($1,$2,$3)`, [
    ownerId,
    name,
    phone,
  ]);
  await query(
    `insert into public.qpay_credentials
       (id, owner_id, label, sealed, key_id, fingerprint, status, is_active, source)
     values ($1,$2,'Үндсэн данс','v1.k1.a.b.c','k1',$3,'active',true,'cli')`,
    [credId, ownerId, randomUUID().replace(/-/g, '').padEnd(64, '0')]
  );
  await query(
    `insert into public.machines (id, owner_id, qpay_credential_id, device_no, label, status)
     values ($1,$2,$3,$4,$5,'active')`,
    [machineId, ownerId, credId, `T${Math.floor(Math.random() * 1e9)}`, name]
  );
  return { ownerId, credId, machineId };
}

/**
 * Inserts a settled sale at a given LOCAL wall-clock moment.
 *
 * `localTime` is a time-of-day on a day offset from today in Ulaanbaatar —
 * expressed that way because the whole point of these tests is what the local
 * calendar says, and converting by hand in JS would reintroduce the bug being
 * tested.
 */
async function sale(who, { orderNo, amount, productId, productName, dayOffset, localTime, done, atMonthStart }) {
  // `atMonthStart` pins the sale to the 1st of the current month instead of an
  // offset from today. A fixed negative offset is not month-stable: run on the
  // 4th, "eight days ago" is last month, and an assertion about the month total
  // silently changes meaning depending on the day the test runs.
  await query(
    `insert into public.orders (
       machine_id, owner_id, qpay_credential_id, order_no, device_no, notify_url,
       product_id, product_name, raw_order_amount, amount_divisor, amount_mnt,
       paid_amount_mnt, qpay_sender_invoice_no, qpay_invoice_id, callback_url,
       status, payment_confirmed_at, notified_at, notify_sent_at,
       product_done_at, product_done_ok, created_at)
     select $1::uuid,$2::uuid,$3::uuid,$4,'DEV','http://x/notify',
            $5,$6,($7*100)::text,100,$7,
            $7,$4,'inv_'||$4,'http://x/cb',
            'paid', m.at, m.at, m.at,
            case when $10 then m.at end, case when $10 then true end, m.at
       from (select (
              (case when $12 then date_trunc('month', $13::timestamptz at time zone $11)::date
                    else ($13::timestamptz at time zone $11)::date + $8::int end)
              + $9::time) at time zone $11 as at) m`,
    [
      who.machineId,
      who.ownerId,
      who.credId,
      orderNo,
      productId,
      productName,
      amount,
      dayOffset,
      localTime,
      done,
      TZ,
      Boolean(atMonthStart),
      NOW,
    ]
  );
}

const a = await seedOwner('А эзэмшигч', '99110001');
const b = await seedOwner('Б эзэмшигч', '99110002');

// 00:30 Ulaanbaatar today — 16:30 UTC yesterday. The boundary case.
await sale(a, { orderNo: 'EARLY', amount: 5000, productId: '1', productName: 'Латте', dayOffset: 0, localTime: '00:30', done: true });
await sale(a, { orderNo: 'T1', amount: 4000, productId: '1', productName: 'Латте', dayOffset: 0, localTime: '09:00', done: true });
// Money taken, no cup.
await sale(a, { orderNo: 'T2', amount: 3000, productId: '2', productName: 'Американо', dayOffset: 0, localTime: '10:00', done: false });
// Two days back, leaving yesterday empty.
await sale(a, { orderNo: 'D2', amount: 7000, productId: '1', productName: 'Латте', dayOffset: -2, localTime: '14:00', done: true });
// Pinned to the 1st of this month, so it is always inside the month total
// whatever day the test runs — and outside the rolling week whenever there is
// a day to be outside of.
await sale(a, { orderNo: 'OLD', amount: 50, productId: '1', productName: 'Латте', atMonthStart: true, localTime: '12:00', done: true });
// The other owner's money. Must never appear in A's figures.
await sale(b, { orderNo: 'OTHER', amount: 999000, productId: '1', productName: 'Латте', dayOffset: 0, localTime: '11:00', done: true });

const stats = await store.ownerStats(a.ownerId, { now: NOW });

// The same data bucketed in UTC. Asserted rather than merely computed: if the
// two ever agree, the timezone argument has stopped doing anything and the
// test above would pass without testing anything.
const utc = await store.ownerStats(a.ownerId, { now: NOW, timezone: 'UTC' });

await check('UTC-гээр бүлэглэвэл өөр хариу — цагийн бүс үнэхээр нөлөөлж байна', () => {
  return utc.today.amount === 7000 && utc.today.cups === 2;
});

await check("өнөөдрийн дүн УБ-ын хуанлиар — 00:30-ын борлуулалт өнөөдөрт орсон", () => {
  // 5000 + 4000 + 3000. Under UTC bucketing EARLY lands on yesterday and this
  // is 7000 with two cups.
  return stats.today.amount === 12000 && stats.today.cups === 3;
});

await check('өөр эзэмшигчийн 999,000₮ хаана ч гараагүй', () => {
  return !JSON.stringify(stats).includes('999000');
});

await check('7 хоногийн график яг 7 өдөр, өнөөдрөөр төгсөнө', () => {
  const days = stats.week.map((d) => d.date);
  return days.length === 7 && days[6] === stats.today_date && days[6] > days[0];
});

await check('борлуулалтгүй өдөр тэг багана болж үлдэнэ', () => {
  const yesterday = stats.week[5];
  const twoBack = stats.week[4];
  return yesterday.amount === 0 && yesterday.cups === 0 && twoBack.amount === 7000;
});

await check('огноо тогтмол — 2026-09-15, УБ-аар', () => {
  return stats.today_date === '2026-09-15' && stats.monthStart === '2026-09-01';
});

await check('сарын дүн 7 хоногийн цонхноос гадуурх борлуулалтыг ч тооцно', () => {
  // 12000 өнөөдөр + 7000 хоёр хоногийн өмнө + 50 сарын 1-нд.
  // Сарын 1 нь 7 хоногийн цонхны гадна (9-р сарын 9-15) байгаа нь чухал.
  return stats.month.amount === 19050 && stats.month.cups === 5;
});

await check('мөнгө авсан ч кофе гараагүй нь тоологдоно', () => {
  return stats.failedThisMonth === 1;
});

await check('бүтээгдэхүүн productId-аар бүлэглэгдэж, дүнгээр эрэмбэлэгдэнэ', () => {
  const [first, second] = stats.products;
  return (
    stats.products.length === 2 &&
    first.productId === '1' &&
    first.cups === 4 &&
    first.amount === 16050 &&
    second.productId === '2' &&
    second.amount === 3000 &&
    first.amount > second.amount
  );
});

await check('шинэ эзэмшигчид тэг үзүүлэлт буцаана, алдаа биш', async () => {
  const fresh = await seedOwner('Шинэ эзэмшигч', '99110003');
  const empty = await store.ownerStats(fresh.ownerId, { now: NOW });
  return (
    empty.today.amount === 0 &&
    empty.month.cups === 0 &&
    empty.week.length === 7 &&
    empty.products.length === 0 &&
    empty.failedThisMonth === 0
  );
});

await check('006: мөнгө нь баталгаажсан ч дуусаагүй захиалга failed-д тоологдоно', async () => {
  // The worst failure never reaches 'paid': payment confirmed, notify never
  // finished. It has no notified_at, so it buckets by payment_confirmed_at.
  await query(
    `insert into public.orders (
       machine_id, owner_id, qpay_credential_id, order_no, device_no, notify_url,
       raw_order_amount, amount_divisor, amount_mnt, paid_amount_mnt,
       qpay_sender_invoice_no, qpay_invoice_id, callback_url,
       status, payment_confirmed_at, settle_attempts, last_error)
     select $1,$2,$3,'STUCK','DEV','http://x/notify',
            '500000',100,5000,5000,'STUCK','inv_stuck_1','http://x/cb',
            'needs_human', m.at, 10, 'machine unreachable'
       from (select ($4::timestamptz - interval '2 hours') as at) m`,
    [a.machineId, a.ownerId, a.credId, NOW]
  );
  const after = await store.ownerStats(a.ownerId, { now: NOW });
  // 1 paid-but-no-cup (T2) + 1 stuck = 2; the stuck 5000₮ is NOT revenue.
  return after.failedThisMonth === 2 && after.month.amount === 19050;
});

await check('төлөгдөөгүй захиалга орлогод ороогүй', async () => {
  await query(
    `insert into public.orders (
       machine_id, owner_id, qpay_credential_id, order_no, device_no, notify_url,
       raw_order_amount, amount_divisor, amount_mnt, qpay_sender_invoice_no,
       qpay_invoice_id, callback_url, status)
     values ($1,$2,$3,'UNPAID','DEV','http://x/notify',
             '4444400',100,44444,'UNPAID','inv_unpaid','http://x/cb','awaiting_payment')`,
    [a.machineId, a.ownerId, a.credId]
  );
  const after = await store.ownerStats(a.ownerId, { now: NOW });
  return after.month.amount === 19050 && !JSON.stringify(after).includes('44444');
});

await close();

const passed = results.filter(([ok]) => ok).length;
for (const [ok, name, extra] of results) console.log(`  ${ok ? '✓' : '✗'} ${name}${extra}`);
console.log(`\n  ${passed}/${results.length} давлаа`);
process.exit(passed === results.length ? 0 : 1);
