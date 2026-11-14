-- =====================================================================
-- 022 — a reminder on the day the subscription runs out
--
-- 019 told a business twice: three days before paid_until ('due_soon') and
-- when its machines stopped ('suspended'). On the day the period ran out —
-- the start of the three grace days — nothing went to the phone, only a
-- banner to whoever opened the portal. Now that day sends its own notice
-- ('overdue'): the period is over, the machines stop on <date>.
--
-- One notice per stage per period, never going back: a business that is
-- told it is overdue is not told again that it is due soon, and one that
-- reaches a stage without the earlier ones (the bridge was down for days)
-- gets only the stage it is in.
--
-- And a fix: billing_notice_sent never recorded a notice for a paid_until
-- with microseconds — every one from now() (a new business's first month,
-- a payment after the period ran out). The value comes back from
-- JavaScript to the millisecond, the exact comparison failed, and the same
-- SMS would have gone out again on every hourly run.
--
-- Idempotent; safe to run twice.
-- =====================================================================
begin;

alter table public.owners drop constraint if exists owners_billing_notice_check;
alter table public.owners add constraint owners_billing_notice_check
  check (billing_notice_stage is null or billing_notice_stage in ('due_soon', 'overdue', 'suspended'));

create or replace function app.billing_notices_due(
  p_default_fee integer,
  p_grace_days  integer default 3,
  p_notice_days integer default 3
) returns table (out_owner_id uuid, out_stage text, out_paid_until timestamptz, out_grace_until timestamptz,
                 out_monthly_fee integer)
language sql stable security definer set search_path = '' as $$
  select o.id, s.stage, b.out_paid_until, b.out_grace_until, b.out_monthly_fee
    from public.owners o
    cross join lateral app.owner_billing(o.id, p_default_fee, p_grace_days, p_notice_days) b
    cross join lateral (select case when b.out_state in ('due_soon', 'overdue', 'suspended') then b.out_state end as stage) s
   where s.stage is not null
     and o.status = 'active'
     and (
       -- A new period (a payment cleared the marker, or moved paid_until).
       o.billing_notice_for is distinct from o.paid_until
       -- The same period, a later stage than the one already sent.
       or (case s.stage when 'due_soon' then 1 when 'overdue' then 2 else 3 end)
          > (case o.billing_notice_stage when 'due_soon' then 1 when 'overdue' then 2 when 'suspended' then 3 else 0 end)
     );
$$;

/*
 * Marks a notice sent for the period it was about. That period is matched
 * to the millisecond — what survives the trip through JavaScript — and the
 * marker takes the database's own value, so billing_notices_due's equality
 * holds. A payment that moved paid_until in between leaves it unmarked:
 * the new period gets its own notices.
 */
create or replace function app.billing_notice_sent(p_owner_id uuid, p_stage text, p_paid_until timestamptz)
returns void
language sql volatile security definer set search_path = '' as $$
  update public.owners o
     set billing_notice_stage = p_stage, billing_notice_for = o.paid_until
   where o.id = p_owner_id
     and abs(extract(epoch from (o.paid_until - p_paid_until))) < 0.001;
$$;

revoke all on function app.billing_notices_due(integer, integer, integer) from public, anon, authenticated;
revoke all on function app.billing_notice_sent(uuid, text, timestamptz) from public, anon, authenticated;
grant execute on function app.billing_notices_due(integer, integer, integer) to service_role;
grant execute on function app.billing_notice_sent(uuid, text, timestamptz) to service_role;

commit;
