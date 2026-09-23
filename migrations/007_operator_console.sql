-- =====================================================================
-- 007  The operator console.
--
-- Everything the person running the business needs to see, as functions the
-- bridge calls with service_role. The operator VIEWS in 003 cannot serve
-- this: they filter on app.is_operator(), which reads auth.uid(), and the
-- bridge has no auth.uid() — it verifies a Supabase JWT itself and then
-- connects as service_role.
--
-- So each function takes the actor's user id and checks operator membership
-- ITSELF. That is the same rule 003 set for the credential functions, and it
-- holds for the same reason: an authorisation check that lives only in the
-- HTTP layer is one refactor away from being skipped, and what it guards here
-- is every owner's revenue.
--
-- Timezone and clock are parameters for the same reason they are on
-- app.owner_stats: Mongolia is UTC+8, and a test that reads the wall clock
-- passes for twenty-nine days.
-- =====================================================================
begin;

/*
 * Operator check for a caller the bridge has already authenticated.
 *
 * Deliberately NOT app.is_operator() with an argument bolted on: that one
 * reads auth.uid() and is what the RLS views use. Two functions, two callers,
 * neither pretending to be the other.
 */
create or replace function app.is_operator_user(p_user_id uuid)
returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.operators o where o.user_id = p_user_id);
$$;

/*
 * The one-screen answer to "how is the business doing, and what needs me".
 *
 * Every number is fleet-wide. `silent_machines` is the one that earns a phone
 * call: a machine that sold every day and has sold nothing for 24 hours is
 * either out of beans, unplugged, or offline — and none of those fix
 * themselves. It is NOT uptime; the bridge only hears from a machine when
 * somebody buys a coffee, so a genuinely idle lobby looks the same.
 */
create or replace function app.operator_overview(
  p_actor_user_id uuid,
  p_tz            text default 'Asia/Ulaanbaatar',
  p_now           timestamptz default now()
) returns jsonb
language sql stable security definer set search_path = '' as $$
with guard as (select app.is_operator_user(p_actor_user_id) as ok),
bounds as (
  select (p_now at time zone p_tz)::date                      as today,
         date_trunc('month', (p_now at time zone p_tz))::date as month_start
),
sales as (
  select o.amount_mnt, o.owner_id, o.machine_id, o.product_done_ok,
         (o.notified_at at time zone p_tz)::date as local_day
    from public.orders o, guard g
   where g.ok and o.status = 'paid' and o.notified_at is not null
),
today_agg as (
  select coalesce(sum(s.amount_mnt),0)::bigint amount, count(*)::int cups
    from sales s, bounds b where s.local_day = b.today
),
month_agg as (
  select coalesce(sum(s.amount_mnt),0)::bigint amount, count(*)::int cups,
         count(distinct s.owner_id)::int earning_owners,
         count(distinct s.machine_id)::int earning_machines
    from sales s, bounds b where s.local_day >= b.month_start
),
fleet as (
  select count(*)::int total,
         count(*) filter (where m.status = 'active')::int active,
         count(*) filter (where m.status <> 'active')::int inactive
    from public.machines m, guard g where g.ok
),
-- Last sale per machine, which is as close to "is it alive" as this data gets.
silence as (
  select count(*)::int as silent
    from public.machines m, guard g
   where g.ok and m.status = 'active'
     and coalesce(
           (select max(o.created_at) from public.orders o where o.machine_id = m.id),
           m.created_at
         ) < p_now - interval '24 hours'
),
owner_counts as (
  select count(*)::int total,
         count(*) filter (where o.status = 'active')::int active
    from public.owners o, guard g where g.ok
),
problems as (
  select
    (select count(*) from public.orders o, guard g
      where g.ok and o.status = 'needs_human')::int as needs_human,
    (select count(*) from public.orders o, guard g
      where g.ok and o.status = 'paid' and o.product_done_ok is distinct from true
        and o.notified_at > p_now - interval '30 days'
        and o.notified_at < p_now - interval '5 minutes')::int as paid_no_cup_30d,
    (select count(*) from public.ingest_errors e, guard g
      where g.ok and e.at > p_now - interval '24 hours')::int as ingest_errors_24h,
    (select count(*) from public.sms_sends s, guard g
      where g.ok and not s.ok and s.at > p_now - interval '24 hours')::int as sms_failures_24h,
    (select count(*) from public.qpay_credentials c, guard g
      where g.ok and c.auth_fail_count > 0)::int as credentials_failing
),
onboarding as (
  select count(*) filter (where c.status = 'pending')::int as not_configured,
         count(*) filter (where c.status = 'active' and c.acceptance_confirmed_at is null)::int as never_sold
    from public.machines m
    join public.qpay_credentials c on c.id = m.qpay_credential_id,
    guard g
   where g.ok
)
select case when (select ok from guard) then jsonb_build_object(
  'today',      (select jsonb_build_object('amount', amount, 'cups', cups) from today_agg),
  'month',      (select jsonb_build_object('amount', amount, 'cups', cups,
                    'earningOwners', earning_owners, 'earningMachines', earning_machines) from month_agg),
  'machines',   (select jsonb_build_object('total', total, 'active', active,
                    'inactive', inactive, 'silent24h', (select silent from silence)) from fleet),
  'owners',     (select jsonb_build_object('total', total, 'active', active) from owner_counts),
  'onboarding', (select jsonb_build_object('notConfigured', not_configured, 'neverSold', never_sold) from onboarding),
  'problems',   (select to_jsonb(p) from problems p),
  'today_date', (select today from bounds),
  'monthStart', (select month_start from bounds),
  'timezone',   p_tz
) else null end;
$$;

/*
 * Every owner, one row each: what they earn, whether their account works, and
 * whether they have ever sold anything. The operator's customer list.
 */
create or replace function app.operator_owners(
  p_actor_user_id uuid,
  p_tz            text default 'Asia/Ulaanbaatar',
  p_now           timestamptz default now()
) returns table (
  owner_id uuid, owner_name text, contact_phone text, owner_status text,
  machines int, active_machines int,
  month_amount bigint, month_cups int, total_amount bigint,
  last_sale_at timestamptz,
  credential_status text, credential_active boolean, credential_fail_count int,
  has_member boolean, stage text
)
language sql stable security definer set search_path = '' as $$
  -- Each aggregate is its own scalar subquery rather than one grouped join.
  -- Joining machines AND orders AND credentials in a single GROUP BY
  -- multiplies every order row by the number of machines the owner has, and
  -- the owner's revenue silently doubles the day they buy a second machine —
  -- which is exactly the customer you least want to hand a wrong number.
  with bounds as (select date_trunc('month', (p_now at time zone p_tz))::date as month_start)
  select o.id, o.name, o.contact_phone, o.status,
         (select count(*)::int from public.machines m where m.owner_id = o.id),
         (select count(*)::int from public.machines m
           where m.owner_id = o.id and m.status = 'active'),
         (select coalesce(sum(r.amount_mnt),0)::bigint from public.orders r, bounds b
           where r.owner_id = o.id and r.status = 'paid'
             and (r.notified_at at time zone p_tz)::date >= b.month_start),
         (select count(*)::int from public.orders r, bounds b
           where r.owner_id = o.id and r.status = 'paid'
             and (r.notified_at at time zone p_tz)::date >= b.month_start),
         (select coalesce(sum(r.amount_mnt),0)::bigint from public.orders r
           where r.owner_id = o.id and r.status = 'paid'),
         (select max(r.notified_at) from public.orders r
           where r.owner_id = o.id and r.status = 'paid'),
         c.status, c.is_active, c.auth_fail_count::int,
         exists (select 1 from public.owner_members mm where mm.owner_id = o.id),
         case
           when c.status = 'pending'
             and not exists (select 1 from public.owner_members mm where mm.owner_id = o.id) then 'invited'
           when c.status = 'pending' then 'account_created'
           when not exists (select 1 from public.orders r
                             where r.owner_id = o.id and r.status = 'paid') then 'credentials_verified'
           else 'earning'
         end
    from public.owners o
    -- The owner's live credential, or their most recent one. An owner has one
    -- or two in practice; picking here keeps the row count at one per owner.
    left join lateral (
      select qc.status, qc.is_active, qc.auth_fail_count
        from public.qpay_credentials qc
       where qc.owner_id = o.id
       order by qc.is_active desc, qc.updated_at desc
       limit 1
    ) c on true
   where app.is_operator_user(p_actor_user_id)
   order by 7 desc, o.name;
$$;

/*
 * Every machine, one row each — the league table. `silent_hours` is what the
 * operator sorts by when deciding who to phone.
 */
create or replace function app.operator_machines(
  p_actor_user_id uuid,
  p_tz            text default 'Asia/Ulaanbaatar',
  p_now           timestamptz default now()
) returns table (
  machine_id uuid, device_no text, machine_label text, location text, machine_status text,
  owner_id uuid, owner_name text,
  today_amount bigint, today_cups int,
  month_amount bigint, month_cups int,
  last_sale_at timestamptz, silent_hours numeric,
  credential_status text, credential_active boolean
)
language sql stable security definer set search_path = '' as $$
  with bounds as (
    select (p_now at time zone p_tz)::date                      as today,
           date_trunc('month', (p_now at time zone p_tz))::date as month_start
  )
  select m.id, m.device_no, m.label, m.location, m.status,
         o.id, o.name,
         coalesce(sum(r.amount_mnt) filter (
           where r.status='paid' and (r.notified_at at time zone p_tz)::date = b.today),0)::bigint,
         count(r.id) filter (
           where r.status='paid' and (r.notified_at at time zone p_tz)::date = b.today)::int,
         coalesce(sum(r.amount_mnt) filter (
           where r.status='paid' and (r.notified_at at time zone p_tz)::date >= b.month_start),0)::bigint,
         count(r.id) filter (
           where r.status='paid' and (r.notified_at at time zone p_tz)::date >= b.month_start)::int,
         max(r.notified_at) filter (where r.status='paid'),
         -- NULL, not zero, for a machine that has never sold: a brand-new
         -- machine and one that stopped selling an hour ago are different
         -- problems, and zero would sort them together.
         case when count(r.id) = 0 then null
              else round(extract(epoch from (p_now - max(r.created_at))) / 3600.0, 1)
         end,
         c.status, c.is_active
    from public.machines m
    cross join bounds b
    join public.owners o on o.id = m.owner_id
    join public.qpay_credentials c on c.id = m.qpay_credential_id
    left join public.orders r on r.machine_id = m.id
   where app.is_operator_user(p_actor_user_id)
   group by m.id, m.device_no, m.label, m.location, m.status,
            o.id, o.name, c.status, c.is_active, b.today, b.month_start
   order by 13 desc nulls last, m.device_no;
$$;

/*
 * When people actually buy coffee, by local hour.
 *
 * The one report an owner will thank you for unprompted: "your machine sells
 * hardest between 09:00 and 11:00, fill it before nine". Fleet-wide when
 * p_owner_id is null.
 */
create or replace function app.operator_hourly(
  p_actor_user_id uuid,
  p_days          integer default 30,
  p_owner_id      uuid default null,
  p_tz            text default 'Asia/Ulaanbaatar',
  p_now           timestamptz default now(),
  p_machine_id    uuid default null
) returns table (hour_of_day int, cups int, amount bigint)
language sql stable security definer set search_path = '' as $$
  select h::int,
         count(r.id)::int,
         coalesce(sum(r.amount_mnt),0)::bigint
    from generate_series(0, 23) as h
    left join public.orders r
      on extract(hour from (r.notified_at at time zone p_tz))::int = h
     and r.status = 'paid'
     and r.notified_at > p_now - make_interval(days => p_days)
     and (p_owner_id is null or r.owner_id = p_owner_id)
     and (p_machine_id is null or r.machine_id = p_machine_id)
   where app.is_operator_user(p_actor_user_id)
   group by h
   order by h;
$$;

/*
 * Everything that needs a human, in one list.
 *
 * Each row carries enough to act on without a second query: which machine,
 * whose, how much money, and what went wrong. Ordered newest first.
 */
create or replace function app.operator_problems(
  p_actor_user_id uuid,
  p_limit         integer default 50,
  p_now           timestamptz default now()
) returns table (
  kind text, at timestamptz, device_no text, owner_name text,
  amount_mnt integer, detail text, reference text
)
language sql stable security definer set search_path = '' as $$
  with guard as (select app.is_operator_user(p_actor_user_id) as ok)
  -- Money confirmed, sale never completed. The worst kind: the customer paid.
  select 'needs_human'::text, r.created_at, r.device_no, o.name, r.amount_mnt,
         coalesce(r.last_error, 'settle attempts exhausted'), r.order_no
    from public.orders r join public.owners o on o.id = r.owner_id, guard g
   where g.ok and r.status = 'needs_human'
  union all
  -- Paid, machine told, no cup reported.
  select 'paid_no_cup', r.notified_at, r.device_no, o.name, r.amount_mnt,
         'мөнгө авсан, кофе гараагүй', r.order_no
    from public.orders r join public.owners o on o.id = r.owner_id, guard g
   where g.ok and r.status = 'paid' and r.product_done_ok is distinct from true
     and r.notified_at > p_now - interval '30 days'
     and r.notified_at < p_now - interval '5 minutes'
  union all
  -- A machine tried to sell and we refused, or could not place it.
  select 'ingest_error', e.at, e.device_no, null, null, e.reason, e.order_no
    from public.ingest_errors e, guard g
   where g.ok and e.at > p_now - interval '7 days'
  union all
  -- A login code that never arrived.
  select 'sms_failed', s.at, null, null, null,
         coalesce(s.error, 'gateway refused'), s.phone
    from public.sms_sends s, guard g
   where g.ok and not s.ok and s.at > p_now - interval '7 days'
  union all
  -- A merchant account that has started refusing us.
  select 'credential_failing', c.updated_at, null, o.name, null,
         coalesce(c.last_error_code, 'auth failing') || ' (' || c.auth_fail_count || ')', c.username_hint
    from public.qpay_credentials c join public.owners o on o.id = c.owner_id, guard g
   where g.ok and c.auth_fail_count > 0
  order by 2 desc
  limit p_limit;
$$;

/*
 * Which machines are not finished being sold. Wraps 003's view's logic in a
 * function the bridge can call — the view itself needs auth.uid().
 */
create or replace function app.operator_onboarding(p_actor_user_id uuid)
returns table (
  machine_id uuid, device_no text, machine_label text, location text,
  owner_id uuid, owner_name text, contact_phone text,
  credential_status text, last_verified_at timestamptz,
  invite_expires_at timestamptz, has_member boolean, paid_orders int, stage text
)
language sql stable security definer set search_path = '' as $$
  select m.id, m.device_no, m.label, m.location,
         o.id, o.name, o.contact_phone,
         c.status, c.last_verified_at,
         (select max(i.expires_at) from public.owner_invites i
           where i.owner_id = o.id and i.accepted_at is null and i.revoked_at is null),
         exists (select 1 from public.owner_members mm where mm.owner_id = o.id),
         (select count(*) from public.orders r
           where r.machine_id = m.id and r.status = 'paid')::int,
         case
           when c.status = 'pending' and not exists
                (select 1 from public.owner_members mm where mm.owner_id = o.id) then 'invited'
           when c.status = 'pending' then 'account_created'
           when c.acceptance_confirmed_at is null then 'credentials_verified'
           else 'earning'
         end
    from public.machines m
    join public.owners o on o.id = m.owner_id
    join public.qpay_credentials c on c.id = m.qpay_credential_id
   where app.is_operator_user(p_actor_user_id)
   order by 13, m.device_no;
$$;

/*
 * QR shown, money not taken. The abandonment rate.
 *
 * Every getQrCode that reached an invoice is a customer who chose a coffee.
 * The ones that never became 'paid' are customers who looked at the QR and
 * walked away — the single most actionable number for an owner, because it
 * separates "nobody comes here" from "people come and then give up". A high
 * rate points at price, at the QR being hard to scan, or at the machine
 * standing somewhere people pass but do not stop.
 *
 * Deliberately counts from 'awaiting_payment' onward, not from 'creating':
 * an order that never got an invoice was our failure, not an abandonment,
 * and it is reported separately as an ingest error.
 */
create or replace function app.operator_funnel(
  p_actor_user_id uuid,
  p_days          integer default 30,
  p_owner_id      uuid default null,
  p_tz            text default 'Asia/Ulaanbaatar',
  p_now           timestamptz default now()
) returns table (
  device_no text, owner_name text,
  qr_shown int, paid int, abandoned int, failed int,
  conversion_pct numeric
)
language sql stable security definer set search_path = '' as $$
  select m.device_no, o.name,
         count(r.id)::int,
         count(r.id) filter (where r.status = 'paid')::int,
         count(r.id) filter (where r.status = 'cancelled')::int,
         count(r.id) filter (where r.status in ('failed','needs_human','orphaned'))::int,
         case when count(r.id) = 0 then null
              else round(100.0 * count(r.id) filter (where r.status='paid') / count(r.id), 1)
         end
    from public.machines m
    join public.owners o on o.id = m.owner_id
    left join public.orders r
      on r.machine_id = m.id
     and r.created_at > p_now - make_interval(days => p_days)
     and r.status <> 'creating'
   where app.is_operator_user(p_actor_user_id)
     and (p_owner_id is null or m.owner_id = p_owner_id)
   group by m.device_no, o.name
   order by 7 nulls last, 3 desc;
$$;

/*
 * The line-by-line statement an owner can hold against their QPay account.
 *
 * This is what settles "where is my money". Every paid order carries the
 * QPay invoice id and payment id it was settled under, so each row here
 * matches exactly one row in the owner's own QPay export. The schema already
 * refuses to mark an order paid when the amount differs from the invoice, so
 * an underpayment can never quietly reconcile — it would sit in the problems
 * list instead.
 */
create or replace function app.operator_reconciliation(
  p_actor_user_id uuid,
  p_owner_id      uuid,
  p_from          timestamptz,
  p_to            timestamptz,
  p_tz            text default 'Asia/Ulaanbaatar'
) returns table (
  notified_at timestamptz, local_time text, device_no text,
  order_no text, product_name text,
  amount_mnt integer, paid_amount_mnt integer,
  qpay_invoice_id text, qpay_payment_id text, cup_dispensed boolean
)
language sql stable security definer set search_path = '' as $$
  select r.notified_at,
         to_char(r.notified_at at time zone p_tz, 'YYYY-MM-DD HH24:MI'),
         r.device_no, r.order_no, r.product_name,
         r.amount_mnt, r.paid_amount_mnt,
         r.qpay_invoice_id, r.qpay_payment_id,
         r.product_done_ok
    from public.orders r
   where app.is_operator_user(p_actor_user_id)
     and r.owner_id = p_owner_id
     and r.status = 'paid'
     and r.notified_at >= p_from
     and r.notified_at < p_to
   order by r.notified_at;
$$;

/*
 * Product mix and the price each machine actually charges.
 *
 * min/max price per product id is the interesting column: the same menu slot
 * earning different amounts on different machines is a price difference
 * somebody set on the machine itself, and nobody would otherwise notice.
 */
create or replace function app.operator_products(
  p_actor_user_id uuid,
  p_days          integer default 30,
  p_owner_id      uuid default null,
  p_now           timestamptz default now()
) returns table (
  device_no text, owner_name text, product_id text, product_name text,
  cups int, amount bigint, min_price int, max_price int
)
language sql stable security definer set search_path = '' as $$
  select r.device_no, o.name, coalesce(r.product_id, '?'),
         (array_agg(r.product_name order by r.notified_at desc)
            filter (where r.product_name is not null))[1],
         count(*)::int, sum(r.amount_mnt)::bigint,
         min(r.amount_mnt)::int, max(r.amount_mnt)::int
    from public.orders r
    join public.owners o on o.id = r.owner_id
   where app.is_operator_user(p_actor_user_id)
     and r.status = 'paid'
     and r.notified_at > p_now - make_interval(days => p_days)
     and (p_owner_id is null or r.owner_id = p_owner_id)
   group by r.device_no, o.name, coalesce(r.product_id, '?')
   order by 6 desc;
$$;

/*
 * Stamped on every signed machine request.
 *
 * machines.last_seen_at has existed since 001 and nothing has ever written
 * it. Without it there is no way to tell a machine that is powered off from
 * one standing in a quiet lobby — "last sale" conflates the two, and the
 * operator ends up phoning the wrong customer.
 */
create or replace function app.touch_machine_seen(p_device_no text)
returns void
language sql volatile security definer set search_path = '' as $$
  update public.machines set last_seen_at = now()
   where device_no = p_device_no
     and (last_seen_at is null or last_seen_at < now() - interval '1 minute');
$$;

revoke all on function app.is_operator_user(uuid) from public, anon, authenticated;
revoke all on function app.operator_overview(uuid, text, timestamptz) from public, anon, authenticated;
revoke all on function app.operator_owners(uuid, text, timestamptz) from public, anon, authenticated;
revoke all on function app.operator_machines(uuid, text, timestamptz) from public, anon, authenticated;
revoke all on function app.operator_hourly(uuid, integer, uuid, text, timestamptz, uuid) from public, anon, authenticated;
revoke all on function app.operator_funnel(uuid, integer, uuid, text, timestamptz) from public, anon, authenticated;
revoke all on function app.operator_reconciliation(uuid, uuid, timestamptz, timestamptz, text) from public, anon, authenticated;
revoke all on function app.operator_products(uuid, integer, uuid, timestamptz) from public, anon, authenticated;
revoke all on function app.operator_problems(uuid, integer, timestamptz) from public, anon, authenticated;
revoke all on function app.operator_onboarding(uuid) from public, anon, authenticated;
revoke all on function app.touch_machine_seen(text) from public, anon, authenticated;

grant execute on function app.is_operator_user(uuid) to service_role;
grant execute on function app.operator_overview(uuid, text, timestamptz) to service_role;
grant execute on function app.operator_owners(uuid, text, timestamptz) to service_role;
grant execute on function app.operator_machines(uuid, text, timestamptz) to service_role;
grant execute on function app.operator_hourly(uuid, integer, uuid, text, timestamptz, uuid) to service_role;
grant execute on function app.operator_funnel(uuid, integer, uuid, text, timestamptz) to service_role;
grant execute on function app.operator_reconciliation(uuid, uuid, timestamptz, timestamptz, text) to service_role;
grant execute on function app.operator_products(uuid, integer, uuid, timestamptz) to service_role;
grant execute on function app.operator_problems(uuid, integer, timestamptz) to service_role;
grant execute on function app.operator_onboarding(uuid) to service_role;
grant execute on function app.touch_machine_seen(text) to service_role;

-- Sorting the fleet by silence and by month revenue are the two reads the
-- console does on every load.
create index if not exists orders_machine_created_idx on public.orders (machine_id, created_at desc);
create index if not exists orders_owner_notified_idx on public.orders (owner_id, notified_at desc)
  where status = 'paid';

commit;
