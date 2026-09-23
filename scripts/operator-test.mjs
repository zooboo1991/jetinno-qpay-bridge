/**
 * The operator console's reports. Run: npm run test:operator
 *
 * Two things are being defended. The first is the boundary: every function
 * here reads EVERY owner's revenue, so a caller who is not in public.operators
 * must get nothing from any of them — and the check lives in SQL, not in the
 * bridge's HTTP layer, because an authorisation check that exists only in a
 * route handler is one refactor away from being skipped.
 *
 * The second is arithmetic. An owner's revenue is a number they will compare
 * against their own bank statement, and the shape of these queries makes one
 * specific error easy: joining machines and orders in the same GROUP BY
 * multiplies every sale by the machine count, so a customer's revenue doubles
 * the day they buy a second machine. That is asserted directly.
 */
import { randomUUID } from 'node:crypto';
import { query, close } from '../src/db.js';

const results = [];
const check = async (name, fn) => {
  try {
    const ok = await fn();
    results.push([Boolean(ok), name, typeof ok === 'string' ? ` — ${ok}` : '']);
  } catch (err) {
    results.push([false, name, ` — ${err.message.split('\n')[0]}`]);
  }
};

const OPERATOR = randomUUID();
const STRANGER = randomUUID();
const ownerA = randomUUID();
const ownerB = randomUUID();
const credA = randomUUID();
const credB = randomUUID();
const m1 = randomUUID();
const m2 = randomUUID();
const m3 = randomUUID();
const dev1 = `D${Math.floor(Math.random() * 1e8)}`;
const dev2 = `D${Math.floor(Math.random() * 1e8)}`;
const dev3 = `D${Math.floor(Math.random() * 1e8)}`;

await query(`insert into auth.users (id, phone) values ($1,'97699110000'),($2,'97699110002')`, [OPERATOR, STRANGER]);
await query(`insert into public.operators (user_id, label) values ($1,'Тест админ')`, [OPERATOR]);
await query(`insert into public.owners (id,name,contact_phone) values ($1,'А ХХК','99110001'),($2,'Б ХХК','99110002')`, [ownerA, ownerB]);
await query(
  `insert into public.qpay_credentials (id,owner_id,label,sealed,key_id,fingerprint,username_hint,status,is_active,source,acceptance_confirmed_at)
   values ($1,$2,'A','v1.k1.a.b.c','k1',$3,'cof••••ne','active',true,'cli',now())`,
  [credA, ownerA, 'a'.repeat(64)]
);
// 'pending' means an operator-created empty slot, and the schema requires
// sealed/key_id/fingerprint to be NULL for it — that IS the state.
await query(
  `insert into public.qpay_credentials (id,owner_id,label,status,is_active,source)
   values ($1,$2,'B','pending',false,'cli')`,
  [credB, ownerB]
);
await query(
  `insert into public.machines (id,owner_id,qpay_credential_id,device_no,label,status) values
     ($1,$2,$3,$4,'1-р давхар','active'),
     ($5,$2,$3,$6,'2-р давхар','active'),
     ($7,$8,$9,$10,'Шинэ','active')`,
  [m1, ownerA, credA, dev1, m2, dev2, m3, ownerB, credB, dev3]
);

const sale = (machineId, ownerId, credentialId, deviceNo, amount, hoursAgo, status, done, productId = '1') =>
  query(
    `insert into public.orders (machine_id,owner_id,qpay_credential_id,order_no,device_no,notify_url,
       product_id,product_name,raw_order_amount,amount_divisor,amount_mnt,paid_amount_mnt,
       qpay_sender_invoice_no,qpay_invoice_id,qpay_payment_id,callback_url,status,
       payment_confirmed_at,notified_at,notify_sent_at,product_done_at,product_done_ok,created_at)
     select $1,$2,$3,$4,$5,'http://x/n',$6,'Латте',($7*100)::text,100,$7,
            case when $9='paid' then $7 end,
            $4,'inv_'||$4, case when $9='paid' then 'pay_'||$4 end,'http://x/cb',$9,
            case when $9='paid' then m.at end, case when $9='paid' then m.at end,
            case when $9='paid' then m.at end,
            case when $10 then m.at end, case when $10 then true end, m.at
       from (select now() - ($8 * interval '1 hour') as at) m`,
    [machineId, ownerId, credentialId, `O${randomUUID().slice(0, 12)}`, deviceNo, productId, amount, hoursAgo, status, done]
  );

// Owner A, machine 1: eight paid, five abandoned, one paid-without-a-cup.
for (let i = 1; i <= 8; i += 1) await sale(m1, ownerA, credA, dev1, 4500, i, 'paid', true);
for (let i = 2; i <= 6; i += 1) await sale(m1, ownerA, credA, dev1, 4500, i, 'cancelled', false);
await sale(m1, ownerA, credA, dev1, 4500, 3, 'paid', false);
// Owner A, machine 2: one sale, 80 hours ago — silent.
await sale(m2, ownerA, credA, dev2, 4000, 80, 'paid', true);

await check('оператор бүх тайланг харна', async () => {
  const { rows } = await query(`select app.operator_overview($1) as j`, [OPERATOR]);
  return rows[0].j?.machines?.total === 3 && rows[0].j?.owners?.total >= 2;
});

await check('оператор БИШ хүн юу ч харахгүй — 8 функц тус бүрд', async () => {
  const empty = [];
  const { rows: ov } = await query(`select app.operator_overview($1) as j`, [STRANGER]);
  if (ov[0].j !== null) empty.push('overview');
  for (const [name, sql] of [
    ['owners', 'select * from app.operator_owners($1)'],
    ['machines', 'select * from app.operator_machines($1)'],
    ['problems', 'select * from app.operator_problems($1)'],
    ['funnel', 'select * from app.operator_funnel($1)'],
    ['products', 'select * from app.operator_products($1)'],
    ['onboarding', 'select * from app.operator_onboarding($1)'],
    ['hourly', 'select * from app.operator_hourly($1)'],
  ]) {
    const { rows } = await query(sql, [STRANGER]);
    if (rows.length) empty.push(name);
  }
  return empty.length === 0 || `задарсан: ${empty.join(', ')}`;
});

await check('эзэмшигчийн орлого машины тоогоор ҮРЖИХГҮЙ', async () => {
  // Owner A has two machines. The fan-out bug doubles this number.
  const { rows: o } = await query(
    `select total_amount::int as t from app.operator_owners($1) where owner_id = $2`,
    [OPERATOR, ownerA]
  );
  const { rows: m } = await query(
    `select coalesce(sum(month_amount),0)::int as t from app.operator_machines($1) where owner_id = $2`,
    [OPERATOR, ownerA]
  );
  // 8×4500 + 1×4500 (paid, no cup) + 1×4000 = 44500
  return o[0].t === 44500 && m[0].t === 44500;
});

await check('чимээгүй машин илэрнэ, хэзээ ч зараагүй нь NULL', async () => {
  const { rows } = await query(`select device_no, silent_hours from app.operator_machines($1)`, [OPERATOR]);
  const silent = rows.find((r) => r.device_no === dev2);
  const never = rows.find((r) => r.device_no === dev3);
  return Number(silent.silent_hours) > 24 && never.silent_hours === null;
});

await check('конверси: QR гарсан 14, төлсөн 9, орхисон 5', async () => {
  const { rows } = await query(`select * from app.operator_funnel($1) where device_no = $2`, [OPERATOR, dev1]);
  const r = rows[0];
  return r.qr_shown === 14 && r.paid === 9 && r.abandoned === 5 && Number(r.conversion_pct) === 64.3;
});

await check('асуудлын жагсаалтад мөнгө авсан ч кофе гараагүй нь орно', async () => {
  const { rows } = await query(`select kind, amount_mnt from app.operator_problems($1)`, [OPERATOR]);
  return rows.some((r) => r.kind === 'paid_no_cup' && r.amount_mnt === 4500);
});

await check('онбординг: тохируулаагүй эзэмшигч "invited" шатанд', async () => {
  const { rows } = await query(`select device_no, stage from app.operator_onboarding($1)`, [OPERATOR]);
  return rows.find((r) => r.device_no === dev3)?.stage === 'invited';
});

await check('цагийн задаргаа 24 мөр, машинаар шүүгдэнэ', async () => {
  const { rows: all } = await query(`select * from app.operator_hourly($1)`, [OPERATOR]);
  const { rows: one } = await query(
    `select coalesce(sum(cups),0)::int as c from app.operator_hourly($1, 30, null, 'Asia/Ulaanbaatar', now(), $2)`,
    [OPERATOR, m2]
  );
  return all.length === 24 && one[0].c === 1;
});

await check('бүтээгдэхүүний үнийн задаргаа', async () => {
  const { rows } = await query(`select * from app.operator_products($1) where device_no = $2`, [OPERATOR, dev1]);
  return rows[0]?.cups === 9 && rows[0]?.min_price === 4500 && rows[0]?.max_price === 4500;
});

await check('QPay-тай тулгах хуулга нэхэмжлэх/төлбөрийн дугаартай', async () => {
  const { rows } = await query(
    `select * from app.operator_reconciliation($1, $2, now() - interval '30 days', now())`,
    [OPERATOR, ownerA]
  );
  return (
    rows.length === 10 &&
    rows.every((r) => r.qpay_invoice_id && r.qpay_payment_id && r.local_time) &&
    rows.every((r) => r.paid_amount_mnt === r.amount_mnt)
  );
});

await check('тулгах хуулгыг оператор БИШ хүн авахгүй', async () => {
  const { rows } = await query(
    `select * from app.operator_reconciliation($1, $2, now() - interval '30 days', now())`,
    [STRANGER, ownerA]
  );
  return rows.length === 0;
});

await check('touch_machine_seen нь last_seen_at бичнэ', async () => {
  await query(`select app.touch_machine_seen($1)`, [dev1]);
  const { rows } = await query(`select last_seen_at from public.machines where device_no = $1`, [dev1]);
  return rows[0].last_seen_at !== null;
});

await close();
const passed = results.filter(([ok]) => ok).length;
for (const [ok, name, extra] of results) console.log(`  ${ok ? '✓' : '✗'} ${name}${extra}`);
console.log(`\n  ${passed}/${results.length} давлаа`);
process.exit(passed === results.length ? 0 : 1);
