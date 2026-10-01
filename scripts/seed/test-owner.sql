-- =====================================================================
-- TEST DATA — a pretend owner with three machines and 90 days of sales,
-- so the dashboards have something to show before real customers do.
--
-- Everything here is tagged and removable in one go:
--   owner       7e570000-0000-4000-8000-000000000001  «Туршилтын Кофе ХХК (тест)»
--   credential  7e570000-0000-4000-8000-000000000002  (sealed value is NOT a key)
--   machines    TEST-0001, TEST-0002, TEST-0003
--   orders      order_no starting with 'TST'
--   faults      device_no starting with 'TEST-'
-- Remove with scripts/seed/test-owner-cleanup.sql.
--
-- Safe by construction:
--   - No real Jetinno machine sends a deviceNo starting with "TEST-", so no
--     sale can ever be routed here.
--   - The credential's sealed value is not an encryption of anything; if it
--     were ever opened, the bridge would refuse (CREDENTIAL_UNSEAL_FAILED),
--     and nothing here touches QPay.
--   - The orders are finished (paid / cancelled / failed / needs_human); the
--     sweeper only looks at live ones.
--
-- ⚠ The one line to check: MY_PHONE below — the 8-digit number you log in
--   with. That account becomes an admin member of the test owner, so the
--   owner pages can show it (switch businesses in the header).
-- =====================================================================
begin;

create temp table seed_cfg on commit drop as
select '99066835'::text as my_phone;   -- ⚠ MY_PHONE

-- ---- owner, credential, machines -------------------------------------------
insert into public.owners (id, name, contact_phone, status, notes)
values ('7e570000-0000-4000-8000-000000000001', 'Туршилтын Кофе ХХК (тест)', '90000001', 'active',
        'TEST-SEED: туршилтын өгөгдөл. Устгах: scripts/seed/test-owner-cleanup.sql')
on conflict (id) do nothing;

insert into public.qpay_credentials
  (id, owner_id, label, sealed, key_id, fingerprint, invoice_code_hint, is_active, status,
   last_verified_at, username_hint, configured_at, source, acceptance_confirmed_at)
values ('7e570000-0000-4000-8000-000000000002', '7e570000-0000-4000-8000-000000000001', 'Үндсэн',
        'v1.test-seed.not-a-key.not-a-key.not-a-key', 'test-seed', md5('test-seed-a') || md5('test-seed-b'),
        'TEST', true, 'active', now(), 'test••••', now(), 'cli', now() - interval '89 days')
on conflict (id) do nothing;

insert into public.machines (id, owner_id, qpay_credential_id, device_no, label, location, status, installed_at, last_seen_at)
values
  ('7e570000-0000-4000-8000-000000000011', '7e570000-0000-4000-8000-000000000001', '7e570000-0000-4000-8000-000000000002',
   'TEST-0001', 'Төв оффис', 'СБД, Тест төв оффис, 1-р давхар', 'active', now() - interval '90 days', now() - interval '20 minutes'),
  ('7e570000-0000-4000-8000-000000000012', '7e570000-0000-4000-8000-000000000001', '7e570000-0000-4000-8000-000000000002',
   'TEST-0002', 'Их сургууль', 'СХД, Тест их сургууль, хоолны танхим', 'active', now() - interval '90 days', now() - interval '2 hours'),
  ('7e570000-0000-4000-8000-000000000013', '7e570000-0000-4000-8000-000000000001', '7e570000-0000-4000-8000-000000000002',
   'TEST-0003', 'Эмнэлэг', 'БЗД, Тест эмнэлэг, хүлээлгийн танхим', 'active', now() - interval '60 days', now() - interval '30 hours')
on conflict (id) do nothing;

-- ---- 90 days of orders ----------------------------------------------------------
-- Deterministic (hash-based), so re-running gives the same history:
--   - busier on weekdays, office machine busiest, hospital started 60 days ago
--     and has been quiet since yesterday (shows as a silent machine)
--   - morning and lunch peaks, Ulaanbaatar time
--   - ~85% paid, ~9% abandoned QR, ~3% failed, a few paid-but-no-cup, one
--     needs_human
with
mach(id, dev, weight, menu, since_days, quiet_hours) as (values
  ('7e570000-0000-4000-8000-000000000011'::uuid, 'TEST-0001', 1.0,
     array['1:Латте:4500', '2:Американо:3500', '3:Каппучино:4500', '4:Халуун шоколад:4000', '5:Эспрессо:3000'], 89, 0),
  ('7e570000-0000-4000-8000-000000000012'::uuid, 'TEST-0002', 0.8,
     array['1:Американо:3000', '2:Латте:4000', '3:Цай:2000', '4:Какао:3500'], 89, 0),
  ('7e570000-0000-4000-8000-000000000013'::uuid, 'TEST-0003', 0.35,
     array['1:Латте:4500', '2:Цай:2500', '3:Американо:3500'], 59, 30)
),
days as (
  select m.*, d,
         ((now() at time zone 'Asia/Ulaanbaatar')::date - d) as day
    from mach m, generate_series(0, 89) d
   where d <= m.since_days
),
counts as (
  select *,
         greatest(0, round(weight * (
           8 + abs(hashtext(dev || day::text)::bigint) % 9            -- 8..16 a day
           + case when extract(isodow from day) in (6, 7) then -6 else 0 end
           + (89 - d) / 30                                     -- slow growth
         )))::int as n
    from days
),
slots as (
  select c.*, i,
         abs(hashtext(c.dev || c.day::text || ':' || i)::bigint) as h
    from counts c, generate_series(1, c.n) i
),
timed as (
  select s.*,
         ((s.day::timestamp
           + make_interval(hours => (array[8,8,9,9,9,10,10,11,12,13,13,14,15,16,17,18])[1 + s.h % 16],
                           mins  => ((s.h / 16) % 60)::int))
           at time zone 'Asia/Ulaanbaatar') as at,
         split_part(s.menu[1 + (s.h / 7) % array_length(s.menu, 1)], ':', 1) as pid,
         split_part(s.menu[1 + (s.h / 7) % array_length(s.menu, 1)], ':', 2) as pname,
         split_part(s.menu[1 + (s.h / 7) % array_length(s.menu, 1)], ':', 3)::int as price,
         (s.h / 1000) % 100 as roll
    from slots s
),
rows as (
  select t.*,
         'TST' || to_char(t.at at time zone 'Asia/Ulaanbaatar', 'YYMMDDHH24MISS') || right(t.dev, 1) || lpad(t.i::text, 2, '0') as order_no,
         case
           when t.roll < 3 then 'failed'
           when t.roll < 12 then 'cancelled'
           when t.roll = 12 and t.d < 25 then 'needs_human'
           else 'paid'
         end as st
    from timed t
   where t.at < now() - make_interval(hours => t.quiet_hours)
)
insert into public.orders
  (machine_id, owner_id, qpay_credential_id, order_no, device_no, notify_url, product_id, product_name,
   raw_order_amount, amount_divisor, amount_mnt, paid_amount_mnt, qpay_sender_invoice_no, qpay_invoice_id,
   qpay_payment_id, callback_url, status, notify_sent_at, payment_confirmed_at, notified_at,
   product_done_at, product_done_ok, cancelled_at, last_error, last_error_at, expires_at, created_at)
select r.id, '7e570000-0000-4000-8000-000000000001', '7e570000-0000-4000-8000-000000000002',
       r.order_no, r.dev, 'https://test.invalid/notify', r.pid, r.pname,
       (r.price * 100)::text, 100, r.price,
       case when r.st = 'paid' then r.price end,
       r.order_no,
       case when r.st <> 'failed' then 'TESTINV-' || r.order_no end,
       case when r.st in ('paid', 'needs_human') then 'TESTPAY-' || r.order_no end,
       'https://test.invalid/qpay/callback/' || r.order_no,
       r.st,
       case when r.st = 'paid' then r.at + interval '44 seconds' end,
       case when r.st = 'paid' then r.at + interval '40 seconds' end,
       case when r.st = 'paid' then r.at + interval '45 seconds' end,
       case when r.st = 'paid' then r.at + interval '95 seconds' end,
       -- A few paid orders where the machine reported no cup (shows on Асуудал).
       case when r.st = 'paid' then not (r.roll = 13 and r.d < 28) end,
       case when r.st = 'cancelled' then r.at + interval '10 minutes' end,
       case r.st when 'failed' then 'TEST: QR үүсгэж чадсангүй'
                 when 'needs_human' then 'TEST: төлбөр орсон, машин хариу өгөөгүй' end,
       case when r.st in ('failed', 'needs_human') then r.at + interval '1 minute' end,
       r.at + interval '10 minutes',
       r.at
  from rows r
on conflict on constraint orders_machine_order_no_key do nothing;

-- ---- machine faults, as if imported from Jetinno SaaS --------------------------
insert into public.machine_faults (device_no, code, description, occurred_at, resolved_at, status_text, source)
select f.dev, f.code, f.descr,
       now() - make_interval(hours => f.ago_h),
       case when f.open then null else now() - make_interval(hours => f.ago_h) + make_interval(mins => f.fix_m) end,
       case when f.open then 'Uncleared' else 'Cleared' end,
       'saas_import'
  from (values
    ('TEST-0001', 'ERROR:5900', 'Bucket lack of water',          5, 12, false),
    ('TEST-0001', 'ERROR:5700', 'no beans',                       30, 95, false),
    ('TEST-0001', 'ERROR:5B00', 'drip trey not well-installed',   52,  4, false),
    ('TEST-0001', 'WARNING:Z0040', 'Waste barrel full warning',   75, 140, false),
    ('TEST-0001', 'ERROR:5900', 'Bucket lack of water',          170, 25, false),
    ('TEST-0001', 'ERROR:5300', 'lack of cups',                  260, 50, false),
    ('TEST-0002', 'ERROR:5700', 'no beans',                       14, 0, true),
    ('TEST-0002', 'WARNING:10009', 'Coffee beans low warning',    40, 300, false),
    ('TEST-0002', 'ERROR:5A00', 'Waste bin (or drip tray) full',  98, 35, false),
    ('TEST-0002', 'ERROR:5900', 'Bucket lack of water',          200, 18, false),
    ('TEST-0003', 'WARNING:0A', 'Door open',                      31, 0, true),
    ('TEST-0003', 'ERROR:7100', 'Boiler filling timeout',         60, 240, false),
    ('TEST-0003', 'ERROR:5900', 'Bucket lack of water',          150, 60, false)
  ) as f(dev, code, descr, ago_h, fix_m, open)
 -- Times are relative to now, so a second run would add a second set.
 where not exists (select 1 from public.machine_faults where device_no like 'TEST-%')
on conflict on constraint machine_faults_identity_key do nothing;

-- ---- your account sees the test owner too ----------------------------------------
insert into public.owner_members (owner_id, user_id, role)
select '7e570000-0000-4000-8000-000000000001', u.id, 'admin'
  from auth.users u, seed_cfg c
 where right(u.phone, 8) = c.my_phone
on conflict (owner_id, user_id) do nothing;

-- What was written. "members 0" means MY_PHONE matched no account.
select (select count(*) from public.machines where owner_id = '7e570000-0000-4000-8000-000000000001') as machines,
       (select count(*) from public.orders where owner_id = '7e570000-0000-4000-8000-000000000001') as orders,
       (select count(*) from public.orders where owner_id = '7e570000-0000-4000-8000-000000000001' and status = 'paid') as paid,
       (select coalesce(sum(amount_mnt), 0) from public.orders where owner_id = '7e570000-0000-4000-8000-000000000001' and status = 'paid') as revenue_mnt,
       (select count(*) from public.machine_faults where device_no like 'TEST-%') as faults,
       (select count(*) from public.owner_members where owner_id = '7e570000-0000-4000-8000-000000000001') as members;

commit;
