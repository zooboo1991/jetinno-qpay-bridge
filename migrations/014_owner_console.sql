-- =====================================================================
-- 014  The owner's console.
--
-- The reports 007 gave the operator, scoped to ONE business, plus the
-- order-by-order list an owner needs to hold their QPay statement against.
--
-- Scoping: every function takes p_owner_id and returns nothing outside it.
-- Membership is checked by the bridge before the call (requireOwner +
-- resolveOwnerId, the same gate app.owner_stats sits behind); a machine
-- filter is matched against machines OF THAT OWNER, so naming someone
-- else's device number returns an empty report rather than their sales.
--
-- Periods are [p_from, p_to) in absolute time; the bridge turns the owner's
-- local dates into those bounds. Days are bucketed in p_tz.
--
-- Status buckets, used by every function the same way:
--   paid     status = 'paid'
--   unpaid   status in ('cancelled','orphaned')   QR shown, nobody paid
--   failed   status in ('failed','needs_human')    our side went wrong
--   pending  creating / awaiting_payment / settling / payment_confirmed
--   no_cup   paid, but the machine never reported a cup (after 5 minutes)
-- =====================================================================
begin;

create or replace function app.owner_order_bucket(p_status text) returns text
language sql immutable as $$
  select case
    when p_status = 'paid' then 'paid'
    when p_status in ('cancelled','orphaned') then 'unpaid'
    when p_status in ('failed','needs_human') then 'failed'
    else 'pending'
  end;
$$;

/* The machine a filter names, only if it belongs to this owner. */
create or replace function app.owner_machine_id(p_owner_id uuid, p_device_no text)
returns uuid
language sql stable security definer set search_path = '' as $$
  select m.id from public.machines m where m.owner_id = p_owner_id and m.device_no = p_device_no;
$$;

/*
 * The period at a glance: money, cups, how many QRs became sales, and one
 * row per local day for the chart.
 */
create or replace function app.owner_summary(
  p_owner_id  uuid,
  p_from      timestamptz,
  p_to        timestamptz,
  p_device_no text default null,
  p_tz        text default 'Asia/Ulaanbaatar',
  p_now       timestamptz default now()
) returns jsonb
language sql stable security definer set search_path = '' as $$
with scope as (
  -- A device filter that is not this owner's resolves to no machine at all.
  select case when p_device_no is null then null
              else coalesce(app.owner_machine_id(p_owner_id, p_device_no), '00000000-0000-0000-0000-000000000000'::uuid)
         end as machine_id
),
o as (
  select r.* from public.orders r, scope s
   where r.owner_id = p_owner_id
     and r.created_at >= p_from and r.created_at < p_to
     and r.status <> 'creating'
     and (s.machine_id is null or r.machine_id = s.machine_id)
),
paid as (
  select r.amount_mnt, r.product_done_ok, r.notified_at,
         (r.notified_at at time zone p_tz)::date as local_day
    from public.orders r, scope s
   where r.owner_id = p_owner_id and r.status = 'paid'
     and r.notified_at >= p_from and r.notified_at < p_to
     and (s.machine_id is null or r.machine_id = s.machine_id)
),
days as (
  select d::date as day
    from generate_series((p_from at time zone p_tz)::date,
                         ((p_to at time zone p_tz) - interval '1 second')::date,
                         interval '1 day') d
)
select jsonb_build_object(
  'amount',      (select coalesce(sum(amount_mnt), 0) from paid),
  'cups',        (select count(*) from paid),
  'qrShown',     (select count(*) from o),
  'paid',        (select count(*) from o where o.status = 'paid'),
  'unpaid',      (select count(*) from o where app.owner_order_bucket(o.status) = 'unpaid'),
  'failed',      (select count(*) from o where app.owner_order_bucket(o.status) = 'failed'),
  'noCup',       (select count(*) from paid
                   where product_done_ok is distinct from true and notified_at < p_now - interval '5 minutes'),
  'conversionPct', (select case when count(*) = 0 then null
                                else round(100.0 * count(*) filter (where o.status = 'paid') / count(*), 1) end
                      from o),
  'avgTicket',   (select case when count(*) = 0 then null else round(avg(amount_mnt))::int end from paid),
  'days',        (select coalesce(jsonb_agg(jsonb_build_object(
                     'date', to_char(d.day, 'YYYY-MM-DD'),
                     'amount', coalesce((select sum(p.amount_mnt) from paid p where p.local_day = d.day), 0),
                     'cups',   (select count(*) from paid p where p.local_day = d.day))
                   order by d.day), '[]'::jsonb)
                   from days d)
);
$$;

/*
 * Every order in the period, newest first, with the QPay ids an owner
 * matches against their own merchant statement.
 */
create or replace function app.owner_orders(
  p_owner_id  uuid,
  p_from      timestamptz,
  p_to        timestamptz,
  p_device_no text default null,
  p_bucket    text default null,
  p_limit     integer default 50,
  p_offset    integer default 0,
  p_tz        text default 'Asia/Ulaanbaatar',
  p_now       timestamptz default now()
) returns table (
  order_no text, created_at timestamptz, local_time text, device_no text,
  product_name text, amount_mnt integer, status text, bucket text,
  cup_dispensed boolean, qpay_payment_id text, total_count bigint
)
language sql stable security definer set search_path = '' as $$
  with scope as (
    select case when p_device_no is null then null
                else coalesce(app.owner_machine_id(p_owner_id, p_device_no), '00000000-0000-0000-0000-000000000000'::uuid)
           end as machine_id
  ),
  rows as (
    select r.*, app.owner_order_bucket(r.status) as b
      from public.orders r, scope s
     where r.owner_id = p_owner_id
       and r.created_at >= p_from and r.created_at < p_to
       and r.status <> 'creating'
       and (s.machine_id is null or r.machine_id = s.machine_id)
  )
  select r.order_no, r.created_at,
         to_char(r.created_at at time zone p_tz, 'YYYY-MM-DD HH24:MI'),
         r.device_no, r.product_name, r.amount_mnt, r.status, r.b,
         r.product_done_ok, r.qpay_payment_id,
         count(*) over ()
    from rows r
   where p_bucket is null
      or r.b = p_bucket
      or (p_bucket = 'no_cup' and r.status = 'paid' and r.product_done_ok is distinct from true
          and r.notified_at < p_now - interval '5 minutes')
   order by r.created_at desc
   limit least(greatest(coalesce(p_limit, 50), 1), 500)
  offset greatest(coalesce(p_offset, 0), 0);
$$;

/* One row per machine of this owner, for the period. */
create or replace function app.owner_machines(
  p_owner_id uuid,
  p_from     timestamptz,
  p_to       timestamptz,
  p_tz       text default 'Asia/Ulaanbaatar',
  p_now      timestamptz default now()
) returns table (
  device_no text, machine_label text, location text, machine_status text,
  amount bigint, cups int, qr_shown int, conversion_pct numeric,
  today_amount bigint, last_sale_at timestamptz, silent_hours numeric, last_seen_at timestamptz,
  credential_active boolean
)
language sql stable security definer set search_path = '' as $$
  select m.device_no, m.label, m.location, m.status,
         (select coalesce(sum(r.amount_mnt), 0)::bigint from public.orders r
           where r.machine_id = m.id and r.status = 'paid'
             and r.notified_at >= p_from and r.notified_at < p_to),
         (select count(*)::int from public.orders r
           where r.machine_id = m.id and r.status = 'paid'
             and r.notified_at >= p_from and r.notified_at < p_to),
         (select count(*)::int from public.orders r
           where r.machine_id = m.id and r.status <> 'creating'
             and r.created_at >= p_from and r.created_at < p_to),
         (select case when count(*) = 0 then null
                      else round(100.0 * count(*) filter (where r.status = 'paid') / count(*), 1) end
            from public.orders r
           where r.machine_id = m.id and r.status <> 'creating'
             and r.created_at >= p_from and r.created_at < p_to),
         (select coalesce(sum(r.amount_mnt), 0)::bigint from public.orders r
           where r.machine_id = m.id and r.status = 'paid'
             and (r.notified_at at time zone p_tz)::date = (p_now at time zone p_tz)::date),
         (select max(r.notified_at) from public.orders r where r.machine_id = m.id and r.status = 'paid'),
         (select case when max(r.created_at) is null then null
                      else round(extract(epoch from (p_now - max(r.created_at))) / 3600.0, 1) end
            from public.orders r where r.machine_id = m.id),
         m.last_seen_at,
         c.is_active
    from public.machines m
    join public.qpay_credentials c on c.id = m.qpay_credential_id
   where m.owner_id = p_owner_id and m.status <> 'retired'
   order by 5 desc, m.device_no;
$$;

/* Cups by local hour of day. */
create or replace function app.owner_hourly(
  p_owner_id  uuid,
  p_from      timestamptz,
  p_to        timestamptz,
  p_device_no text default null,
  p_tz        text default 'Asia/Ulaanbaatar'
) returns table (hour_of_day int, cups int, amount bigint)
language sql stable security definer set search_path = '' as $$
  with scope as (
    select case when p_device_no is null then null
                else coalesce(app.owner_machine_id(p_owner_id, p_device_no), '00000000-0000-0000-0000-000000000000'::uuid)
           end as machine_id
  )
  select h::int, count(r.id)::int, coalesce(sum(r.amount_mnt), 0)::bigint
    from generate_series(0, 23) h
    cross join scope s
    left join public.orders r
      on r.owner_id = p_owner_id
     and r.status = 'paid'
     and r.notified_at >= p_from and r.notified_at < p_to
     and (s.machine_id is null or r.machine_id = s.machine_id)
     and extract(hour from (r.notified_at at time zone p_tz))::int = h
   group by h
   order by h;
$$;

/* What sold, and the price each machine actually charged for it. */
create or replace function app.owner_products(
  p_owner_id  uuid,
  p_from      timestamptz,
  p_to        timestamptz,
  p_device_no text default null
) returns table (
  device_no text, product_id text, product_name text,
  cups int, amount bigint, min_price int, max_price int
)
language sql stable security definer set search_path = '' as $$
  with scope as (
    select case when p_device_no is null then null
                else coalesce(app.owner_machine_id(p_owner_id, p_device_no), '00000000-0000-0000-0000-000000000000'::uuid)
           end as machine_id
  )
  select r.device_no, coalesce(r.product_id, '?'),
         (array_agg(r.product_name order by r.notified_at desc)
            filter (where r.product_name is not null))[1],
         count(*)::int, sum(r.amount_mnt)::bigint,
         min(r.amount_mnt)::int, max(r.amount_mnt)::int
    from public.orders r, scope s
   where r.owner_id = p_owner_id and r.status = 'paid'
     and r.notified_at >= p_from and r.notified_at < p_to
     and (s.machine_id is null or r.machine_id = s.machine_id)
   group by r.device_no, coalesce(r.product_id, '?')
   order by 5 desc;
$$;

/*
 * Everything about this business that needs someone, newest first. Each
 * kind maps to one sentence and one action on the owner's screen.
 */
create or replace function app.owner_problems(
  p_owner_id uuid,
  p_limit    integer default 100,
  p_now      timestamptz default now()
) returns table (
  kind text, at timestamptz, device_no text, amount_mnt integer, detail text, reference text
)
language sql stable security definer set search_path = '' as $$
  -- The customer paid and the sale never completed on our side.
  select 'needs_human'::text, r.created_at, r.device_no, r.amount_mnt,
         null::text, r.order_no
    from public.orders r
   where r.owner_id = p_owner_id and r.status = 'needs_human'
  union all
  -- Paid, the machine was told, no cup reported.
  select 'paid_no_cup', r.notified_at, r.device_no, r.amount_mnt, r.product_name, r.order_no
    from public.orders r
   where r.owner_id = p_owner_id and r.status = 'paid' and r.product_done_ok is distinct from true
     and r.notified_at > p_now - interval '30 days'
     and r.notified_at < p_now - interval '5 minutes'
  union all
  -- A customer chose a coffee and the QR could not be made.
  select 'order_failed', r.created_at, r.device_no, r.amount_mnt, r.product_name, r.order_no
    from public.orders r
   where r.owner_id = p_owner_id and r.status = 'failed'
     and r.created_at > p_now - interval '7 days'
  union all
  -- A machine of this owner asked to sell and was refused (QPay not ready,
  -- account switched off, machine disabled).
  select 'machine_refused', e.at, e.device_no, null, e.reason, e.order_no
    from public.ingest_errors e
    join public.machines m on m.device_no = e.device_no and m.owner_id = p_owner_id
   where e.at > p_now - interval '7 days'
  union all
  -- The QPay account has started refusing the bridge.
  select 'qpay_failing', c.updated_at, null, null, c.last_error_code, c.username_hint
    from public.qpay_credentials c
   where c.owner_id = p_owner_id and c.auth_fail_count > 0
  union all
  -- A machine that sold before and has not for a day.
  select 'machine_silent', max(r.created_at), m.device_no, null, null, null
    from public.machines m
    join public.orders r on r.machine_id = m.id
   where m.owner_id = p_owner_id and m.status = 'active'
   group by m.device_no
  having max(r.created_at) < p_now - interval '24 hours'
  order by 2 desc
  limit least(greatest(coalesce(p_limit, 100), 1), 500);
$$;

revoke all on function app.owner_order_bucket(text) from public;
revoke all on function app.owner_machine_id(uuid, text) from public, anon, authenticated;
revoke all on function app.owner_summary(uuid, timestamptz, timestamptz, text, text, timestamptz) from public, anon, authenticated;
revoke all on function app.owner_orders(uuid, timestamptz, timestamptz, text, text, integer, integer, text, timestamptz) from public, anon, authenticated;
revoke all on function app.owner_machines(uuid, timestamptz, timestamptz, text, timestamptz) from public, anon, authenticated;
revoke all on function app.owner_hourly(uuid, timestamptz, timestamptz, text, text) from public, anon, authenticated;
revoke all on function app.owner_products(uuid, timestamptz, timestamptz, text) from public, anon, authenticated;
revoke all on function app.owner_problems(uuid, integer, timestamptz) from public, anon, authenticated;

grant execute on function app.owner_order_bucket(text) to service_role;
grant execute on function app.owner_machine_id(uuid, text) to service_role;
grant execute on function app.owner_summary(uuid, timestamptz, timestamptz, text, text, timestamptz) to service_role;
grant execute on function app.owner_orders(uuid, timestamptz, timestamptz, text, text, integer, integer, text, timestamptz) to service_role;
grant execute on function app.owner_machines(uuid, timestamptz, timestamptz, text, timestamptz) to service_role;
grant execute on function app.owner_hourly(uuid, timestamptz, timestamptz, text, text) to service_role;
grant execute on function app.owner_products(uuid, timestamptz, timestamptz, text) to service_role;
grant execute on function app.owner_problems(uuid, integer, timestamptz) to service_role;

create index if not exists orders_owner_notified_all_idx on public.orders (owner_id, notified_at desc);

commit;
