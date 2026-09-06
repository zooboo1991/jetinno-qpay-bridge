-- =====================================================================
-- 006  Fixes found by review: the sweeper wedge, the cancelled dead-end,
--      exhausted orders vanishing, and two smaller state-machine holes.
--
-- Everything here is CREATE OR REPLACE over 001/004 functions, so it is
-- safe on a database that already ran them and equally safe on a fresh one.
-- =====================================================================
begin;

/*
 * THE WEDGE. claim_abandoned_orders promoted every expired row — including
 * 'creating' rows that never got an invoice — to 'settling' in one multi-row
 * UPDATE. But orders_live_needs_invoice forbids 'settling' with a NULL
 * qpay_invoice_id, so one invoice-less row aborts the whole batch; and since
 * candidates are ordered by expires_at, the same poisoned oldest row is
 * re-selected on every run. One crash between insert and invoice creation
 * would have wedged the phase-3 sweeper permanently.
 *
 * Invoice-less rows now go straight to 'failed': there is no invoice to
 * cancel and no QR anyone could have paid, so there is nothing to settle —
 * 'failed' is the truth, not a workaround.
 */
create or replace function app.claim_abandoned_orders(
  p_limit integer default 50,
  p_lease_seconds integer default 60,
  p_instance text default null,
  p_max_attempts integer default 10
) returns setof public.orders
language sql volatile as $$
  update public.orders o
     set status = 'failed',
         last_error = 'NO_INVOICE',
         last_error_at = now(),
         updated_at = now()
   where o.expires_at < now()
     and o.status = 'creating'
     and o.qpay_invoice_id is null;

  with candidate as (
    select o.id from public.orders o
     where o.expires_at < now()
       and o.status in ('creating','awaiting_payment','settling')
       and o.qpay_invoice_id is not null
       and o.settle_attempts < p_max_attempts
       and (o.status <> 'settling' or o.settle_lease_until < now())
     order by o.expires_at
     limit p_limit
     for update skip locked
  )
  update public.orders o
     set status = 'settling',
         settle_lease_until = now() + make_interval(secs => p_lease_seconds),
         settle_lease_owner = p_instance,
         settle_attempts = o.settle_attempts + 1,
         updated_at = now()
    from candidate c
   where o.id = c.id
  returning o.*;
$$;

/*
 * A payment can land AFTER the sweep cancelled the invoice — QPay reports it
 * as INVOICE_PAID on the cancel call, and the bridge then settles. The claim
 * refused 'cancelled' rows, so that settle could never be mirrored: the
 * customer had coffee, the database said cancelled, forever. 'cancelled' is
 * now claimable; cancelled_at is kept as history of the detour.
 */
create or replace function app.claim_order_for_settle(
  p_order_id             uuid,
  p_lease_seconds        integer default 60,
  p_instance             text    default null,
  p_notify_grace_seconds integer default 120,
  p_max_attempts         integer default 10
) returns setof public.orders
language sql volatile as $$
  update public.orders o
     set status             = 'settling',
         settle_lease_until = now() + make_interval(secs => p_lease_seconds),
         settle_lease_owner = p_instance,
         settle_attempts    = o.settle_attempts + 1,
         updated_at         = now()
   where o.id = p_order_id
     and o.product_done_at is null
     and o.settle_attempts < p_max_attempts
     and (o.notify_sent_at is null
          or o.notify_sent_at < now() - make_interval(secs => p_notify_grace_seconds))
     and (o.status in ('awaiting_payment','payment_confirmed','cancelled')
          or (o.status = 'settling' and o.settle_lease_until < now()))
  returning o.*;
$$;

/*
 * The cup coming out is evidence, whatever state the row is in. A row that
 * went needs_human (attempts ran out) and then received productdone was
 * refusing the one fact that resolves it — the machine DID brew. Recording
 * product_done_at also permanently blocks every future settle claim, which
 * is exactly right for a cup that exists.
 */
create or replace function app.record_product_done(p_order_id uuid, p_ok boolean)
returns setof public.orders
language sql volatile as $$
  update public.orders o
     set product_done_at = coalesce(o.product_done_at, now()),
         product_done_ok = coalesce(o.product_done_ok, p_ok),
         updated_at = now()
   where o.id = p_order_id
     and o.status in ('settling','payment_confirmed','paid','needs_human')
  returning o.*;
$$;

/*
 * Orders whose settle_attempts reached the cap drop out of every claim
 * function's WHERE clause — money possibly confirmed, machine never told,
 * and no worker will ever look again. This flips them to needs_human, the
 * status that exists precisely so a person looks. Called by the bridge's
 * sweep tick; cheap when there is nothing to do.
 */
create or replace function app.give_up_exhausted(p_max_attempts integer default 10)
returns integer
language sql volatile as $$
  with flipped as (
    update public.orders o
       set status = 'needs_human',
           settle_lease_until = null,
           settle_lease_owner = null,
           last_error = coalesce(o.last_error, 'SETTLE_ATTEMPTS_EXHAUSTED'),
           last_error_at = coalesce(o.last_error_at, now()),
           updated_at = now()
     where o.status in ('awaiting_payment','settling','payment_confirmed')
       and o.settle_attempts >= p_max_attempts
       and o.product_done_at is null
       and (o.status <> 'settling' or o.settle_lease_until < now())
    returning 1
  )
  select count(*)::integer from flipped;
$$;

/*
 * owner_stats counted "money taken, no cup" only among PAID orders. The worst
 * case never reaches 'paid' at all: payment confirmed, notify never finished,
 * row stuck in settling/payment_confirmed/needs_human. The owner is the one
 * person who will hear about that cup — from the customer standing at the
 * machine — so it belongs in their failed count, not only in the operator's.
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
-- Paid and notified, but the machine never confirmed a cup.
failed_paid as (
  select count(*)::int as n
    from sales s, bounds b
   where s.local_day >= b.month_start
     and s.product_done_ok is distinct from true
     and s.notified_at < p_now - interval '5 minutes'
),
-- Money confirmed, sale never completed: stuck before 'paid'. These rows
-- have no notified_at, so they bucket by when the money was confirmed.
failed_stuck as (
  select count(*)::int as n
    from public.orders o, bounds b
   where o.owner_id = p_owner_id
     and o.status in ('settling','payment_confirmed','needs_human')
     and o.payment_confirmed_at is not null
     and (o.payment_confirmed_at at time zone p_tz)::date >= b.month_start
     and o.payment_confirmed_at < p_now - interval '5 minutes'
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
  'failedThisMonth', (select (select n from failed_paid) + (select n from failed_stuck)),
  'timezone',   p_tz
);
$$;

revoke all on function app.give_up_exhausted(integer) from public, anon, authenticated;
grant execute on function app.give_up_exhausted(integer) to service_role;
-- owner_stats grants carry over from 004 (same signature), but re-asserting
-- costs nothing and survives a signature drift.
revoke all on function app.owner_stats(uuid, text, timestamptz) from public, anon, authenticated;
grant execute on function app.owner_stats(uuid, text, timestamptz) to service_role;

commit;
