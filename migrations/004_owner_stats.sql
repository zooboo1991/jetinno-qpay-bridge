-- =====================================================================
-- 004  Owner-facing revenue aggregates
--
-- The portal's dashboard reads exactly one function. It is defined here
-- rather than assembled in the bridge for two reasons:
--
--   1. Scope is a parameter, not a filter someone can forget. Every branch
--      below is joined to p_owner_id. There is no code path in this file
--      that can read across owners, so no future edit to the bridge's HTTP
--      layer can widen the query by accident.
--   2. It is one round trip. The dashboard is the first screen after login;
--      six separate aggregate queries over a pooled connection is how that
--      screen becomes slow on the day it matters.
--
-- The bridge calls this as service_role, having already verified the
-- caller's Supabase JWT and resolved which owners that user administers.
-- p_owner_id NEVER comes from a request body.
-- =====================================================================

-- Supports every aggregate below: owner first, then the timestamp we bucket
-- by. Partial, because unpaid orders are not revenue and there is no reason
-- to carry them in a revenue index.
create index if not exists orders_owner_paid_idx
  on public.orders (owner_id, notified_at desc)
  where status = 'paid';

/*
 * Everything the owner dashboard shows, in one object.
 *
 * WHY notified_at AND NOT created_at OR payment_confirmed_at:
 * notified_at is the moment we told the machine to brew — the instant the
 * sale became real for both sides. created_at is when a QR was drawn, which
 * includes every customer who walked away; payment_confirmed_at is when QPay
 * answered, which drifts when QPay is slow. Only one of the three is the
 * event the owner would recognise as "a coffee was sold at that time".
 *
 * WHY THE TIMEZONE IS A PARAMETER AND DEFAULTS TO ULAANBAATAR:
 * Mongolia is UTC+8, so a UTC "today" is Ulaanbaatar's yesterday until 08:00
 * local — a third of the working day would be filed under the wrong date, and
 * the owner would see their morning sales appear only at lunchtime. The
 * default is correct for every machine we have; the parameter exists so that
 * fact is stated somewhere rather than assumed everywhere.
 *
 * WHY "NOW" IS ALSO A PARAMETER:
 * so the tests can pin it. Every branch here is a calendar boundary, and a
 * test that reads the real clock passes for twenty-nine days and fails on the
 * first of the month — which is the one morning nobody wants to be debugging
 * a revenue query. p_now cannot widen scope or leak anything; the bridge never
 * passes it and the default is the real clock.
 */
create or replace function app.owner_stats(
  p_owner_id uuid,
  p_tz       text default 'Asia/Ulaanbaatar',
  p_now      timestamptz default now()
) returns jsonb
language sql stable as $$
with bounds as (
  select
    (p_now at time zone p_tz)::date                      as today,
    date_trunc('month', (p_now at time zone p_tz))::date as month_start
),
-- Paid orders only, with each sale's LOCAL calendar day attached once so
-- every aggregate below buckets on the same value.
sales as (
  select o.amount_mnt,
         o.product_id,
         o.product_name,
         o.product_done_ok,
         o.notified_at,
         (o.notified_at at time zone p_tz)::date as local_day
    from public.orders o
   where o.owner_id = p_owner_id
     and o.status = 'paid'
     and o.notified_at is not null
),
today_agg as (
  select coalesce(sum(s.amount_mnt), 0)::bigint as amount, count(*)::int as cups
    from sales s, bounds b
   where s.local_day = b.today
),
month_agg as (
  select coalesce(sum(s.amount_mnt), 0)::bigint as amount, count(*)::int as cups
    from sales s, bounds b
   where s.local_day >= b.month_start
),
-- A rolling seven days ending today, not a calendar week: the owner is
-- comparing this morning to the last few mornings, and a Monday that shows
-- one bar is not a useful chart. generate_series supplies the empty days —
-- a day with no sales must appear as a zero bar, not vanish and let the
-- neighbouring days slide together into a shape that never happened.
week as (
  select d::date as day,
         coalesce(sum(s.amount_mnt), 0)::bigint as amount,
         count(s.*)::int as cups
    from bounds b
    cross join generate_series(b.today - 6, b.today, interval '1 day') as d
    left join sales s on s.local_day = d::date
   group by d
   order by d
),
-- Grouped by the product id the machine reports, because product_name is
-- whatever string the machine's menu holds — today that is Chinese, and it
-- can be re-labelled on the machine without warning. The id is the stable
-- half; the most recent name is carried along for display.
products as (
  select coalesce(s.product_id, '?') as product_id,
         (array_agg(s.product_name order by s.notified_at desc)
            filter (where s.product_name is not null))[1] as product_name,
         count(*)::int as cups,
         sum(s.amount_mnt)::bigint as amount
    from sales s, bounds b
   where s.local_day >= b.month_start
   group by 1
   order by 4 desc
),
-- Money taken, no cup. Reported rather than hidden: an owner who finds this
-- out from a customer trusts nothing else on the page. The five-minute grace
-- keeps a sale that is merely still brewing out of the count — productdone
-- arrives seconds after the notify, so anything older than that is not late,
-- it is missing.
failed as (
  select count(*)::int as n
    from sales s, bounds b
   where s.local_day >= b.month_start
     and s.product_done_ok is distinct from true
     and s.notified_at < p_now - interval '5 minutes'
)
select jsonb_build_object(
  'today',      (select jsonb_build_object('amount', amount, 'cups', cups) from today_agg),
  'month',      (select jsonb_build_object('amount', amount, 'cups', cups) from month_agg),
  'monthStart', (select month_start from bounds),
  'today_date', (select today from bounds),
  'week',       (select coalesce(jsonb_agg(jsonb_build_object(
                    'date', day, 'amount', amount, 'cups', cups) order by day), '[]'::jsonb)
                  from week),
  'products',   (select coalesce(jsonb_agg(jsonb_build_object(
                    'productId', product_id, 'name', product_name,
                    'cups', cups, 'amount', amount) order by amount desc), '[]'::jsonb)
                  from products),
  'failedThisMonth', (select n from failed),
  'timezone',   p_tz
);
$$;

comment on function app.owner_stats(uuid, text, timestamptz) is
  'Owner dashboard aggregates. Scope is the p_owner_id argument, resolved by '
  'the bridge from a verified JWT — never from a request body. Buckets by '
  'notified_at (the moment the machine was told to brew) in the owner''s '
  'local timezone.';

-- Callable only by the bridge. The portal never reaches Postgres directly:
-- an owner-scoped aggregate handed to a browser-reachable role is one JWT
-- forgery away from being every owner's aggregate.
revoke all on function app.owner_stats(uuid, text, timestamptz) from public, anon, authenticated;
grant execute on function app.owner_stats(uuid, text, timestamptz) to service_role;
