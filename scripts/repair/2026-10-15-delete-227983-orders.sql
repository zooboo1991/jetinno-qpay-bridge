-- =====================================================================
-- Deletes the coffee sales (public.orders) of machine 227983, the test
-- machine, at the operator's request on 2026-10-15.
--
-- Kept on purpose:
--   - public.machine_faults (its fault history)
--   - public.ingest_errors (the bridge's error log for it)
--   - the machine itself, its owner and its QPay credential
--   - orders still in flight (creating / awaiting_payment / settling /
--     payment_confirmed): the bridge may still owe the customer a cup.
--     Run again later if any are reported left.
--
-- A copy of every deleted row goes to backup.orders_227983_20261015 first.
-- That schema is not exposed to the API and anon/authenticated get no
-- grant on it. Once you are sure, remove it with:
--   drop table backup.orders_227983_20261015;
--
-- Safe to run twice: the second run stops at "already exists" and changes
-- nothing (the whole script is one transaction).
-- ASCII only, so a non-UTF-8 clipboard cannot corrupt it.
-- =====================================================================
begin;

create schema if not exists backup;
revoke all on schema backup from public, anon, authenticated;

create table backup.orders_227983_20261015 as
select o.*
  from public.orders o
 where o.device_no = '227983'
   and o.status not in ('creating', 'awaiting_payment', 'settling', 'payment_confirmed');
alter table backup.orders_227983_20261015 enable row level security;
revoke all on backup.orders_227983_20261015 from public, anon, authenticated;

-- order_events rows of these orders go with them (on delete cascade).
with gone as (
  delete from public.orders o
   using backup.orders_227983_20261015 b
   where o.id = b.id
  returning o.status, o.amount_mnt, o.created_at
)
select count(*) as deleted_orders,
       count(*) filter (where status = 'paid') as deleted_paid,
       coalesce(sum(amount_mnt) filter (where status = 'paid'), 0) as deleted_paid_mnt,
       min(created_at) as first_deleted_at,
       max(created_at) as last_deleted_at,
       (select count(*) from public.orders where device_no = '227983') as in_flight_left,
       (select count(*) from public.machine_faults where device_no = '227983') as faults_kept,
       (select count(*) from public.machines where device_no = '227983') as machine_found
  from gone;

commit;
