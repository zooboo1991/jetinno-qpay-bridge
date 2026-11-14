-- =====================================================================
-- 019  The system subscription.
--
-- Every business pays a monthly fee per active machine, through QPay on the
-- operator's own merchant. Each payment extends owners.paid_until by the
-- months bought. Three days after paid_until lapses the business is
-- suspended: its machines refuse QPay sales and its portal shows only the
-- billing page, until it pays — which restores everything at once.
--
-- The fee and the grace period are not stored here. The bridge passes them
-- in (BILLING_FEE_PER_MACHINE_MNT, BILLING_GRACE_DAYS) so one value decides
-- both what is charged and what is shown.
--
-- Additive: the bridge running when this is applied ignores it.
-- =====================================================================
begin;

alter table public.owners
  add column if not exists paid_until timestamptz,
  add column if not exists billing_exempt boolean not null default false,
  add column if not exists billing_fee_per_machine_mnt integer,
  add column if not exists billing_notice_stage text,
  add column if not exists billing_notice_for timestamptz;

do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'owners_billing_fee_check') then
    alter table public.owners add constraint owners_billing_fee_check
      check (billing_fee_per_machine_mnt is null or billing_fee_per_machine_mnt between 0 and 10000000);
  end if;
  if not exists (select 1 from pg_constraint where conname = 'owners_billing_notice_check') then
    alter table public.owners add constraint owners_billing_notice_check
      check (billing_notice_stage is null or billing_notice_stage in ('due_soon', 'suspended'));
  end if;
end $$;

-- Every business that exists today: the first month free, to 2026-12-14
-- 00:00 in Ulaanbaatar. A business created later gets its own first month.
update public.owners set paid_until = '2026-12-14 00:00:00+08' where paid_until is null;
alter table public.owners alter column paid_until set default (now() + interval '1 month');
alter table public.owners alter column paid_until set not null;

comment on column public.owners.paid_until is
  'The subscription is paid up to here. Sales stop BILLING_GRACE_DAYS after it (bridge env).';

-- 017's list, plus the reminders this migration sends.
alter table public.sms_sends drop constraint if exists sms_sends_purpose_check;
alter table public.sms_sends add constraint sms_sends_purpose_check
  check (purpose in ('otp', 'invite', 'announcement', 'billing'));

create table if not exists public.billing_invoices (
  id                     uuid primary key default gen_random_uuid(),
  owner_id               uuid not null references public.owners(id) on delete cascade,
  months                 integer not null check (months between 1 and 24),
  machines               integer not null check (machines >= 0),
  fee_per_machine_mnt    integer not null check (fee_per_machine_mnt >= 0),
  amount_mnt             integer not null check (amount_mnt >= 0),
  source                 text not null check (source in ('qpay', 'manual')),
  status                 text not null default 'open' check (status in ('open', 'paid', 'cancelled')),
  qpay_invoice_id        text,
  qpay_sender_invoice_no text,
  qpay_payment_id        text,
  qr_text                text,
  qr_image               text check (qr_image is null or char_length(qr_image) <= 200000),
  short_url              text,
  bank_urls              jsonb,
  paid_amount_mnt        integer,
  period_from            timestamptz,
  period_to              timestamptz,
  note                   text check (note is null or char_length(note) <= 300),
  created_by             uuid,
  created_at             timestamptz not null default now(),
  paid_at                timestamptz,
  constraint billing_invoices_paid_shape check (status <> 'paid' or (paid_at is not null and period_to is not null))
);
create unique index if not exists billing_invoices_qpay_invoice_key on public.billing_invoices (qpay_invoice_id) where qpay_invoice_id is not null;
create unique index if not exists billing_invoices_sender_key on public.billing_invoices (qpay_sender_invoice_no) where qpay_sender_invoice_no is not null;
create unique index if not exists billing_invoices_payment_key on public.billing_invoices (qpay_payment_id) where qpay_payment_id is not null;
create index if not exists billing_invoices_owner_idx on public.billing_invoices (owner_id, created_at desc);
alter table public.billing_invoices enable row level security;
revoke all on public.billing_invoices from anon, authenticated;

/*
 * Where a business stands. The single source of the state names the portal
 * and the sale path both use.
 */
create or replace function app.owner_billing(
  p_owner_id    uuid,
  p_default_fee integer,
  p_grace_days  integer default 3,
  p_notice_days integer default 3,
  p_now         timestamptz default now()
) returns table (
  out_state text, out_paid_until timestamptz, out_grace_until timestamptz,
  out_machines integer, out_fee_per_machine integer, out_monthly_fee integer,
  out_exempt boolean, out_fee_override boolean
)
language sql stable security definer set search_path = '' as $$
  with o as (
    select o.id, o.paid_until, o.billing_exempt, o.billing_fee_per_machine_mnt,
           (select count(*)::integer from public.machines m where m.owner_id = o.id and m.status = 'active') as machines
      from public.owners o
     where o.id = p_owner_id
  )
  select case
           when o.billing_exempt then 'exempt'
           when o.machines = 0 then 'no_machines'
           when p_now >= o.paid_until + make_interval(days => p_grace_days) then 'suspended'
           when p_now >= o.paid_until then 'overdue'
           when p_now >= o.paid_until - make_interval(days => p_notice_days) then 'due_soon'
           else 'active'
         end,
         o.paid_until,
         o.paid_until + make_interval(days => p_grace_days),
         o.machines,
         coalesce(o.billing_fee_per_machine_mnt, p_default_fee),
         o.machines * coalesce(o.billing_fee_per_machine_mnt, p_default_fee),
         o.billing_exempt,
         o.billing_fee_per_machine_mnt is not null
    from o;
$$;

/*
 * Credits a payment. Idempotent: a callback, a check and the sweep may all
 * arrive for one payment, and only the first extends. An invoice that was
 * cancelled and paid anyway is still credited — the money arrived.
 */
create or replace function app.billing_mark_paid(
  p_invoice_id  uuid,
  p_payment_id  text,
  p_paid_amount integer
) returns table (out_status text, out_owner_id uuid, out_paid_until timestamptz)
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_inv   public.billing_invoices;
  v_from  timestamptz;
  v_to    timestamptz;
begin
  select * into v_inv from public.billing_invoices i where i.id = p_invoice_id for update;
  if not found then
    return query select 'not_found'::text, null::uuid, null::timestamptz; return;
  end if;
  if v_inv.status = 'paid' then
    return query select 'already'::text, v_inv.owner_id, (select o.paid_until from public.owners o where o.id = v_inv.owner_id);
    return;
  end if;
  if p_paid_amount is null or p_paid_amount < v_inv.amount_mnt then
    return query select 'underpaid'::text, v_inv.owner_id, null::timestamptz; return;
  end if;

  select greatest(o.paid_until, now()) into v_from from public.owners o where o.id = v_inv.owner_id for update;
  v_to := v_from + make_interval(months => v_inv.months);

  update public.owners o
     set paid_until = v_to, billing_notice_stage = null, billing_notice_for = null
   where o.id = v_inv.owner_id;
  update public.billing_invoices i
     set status = 'paid', paid_at = now(), qpay_payment_id = coalesce(i.qpay_payment_id, p_payment_id),
         paid_amount_mnt = p_paid_amount, period_from = v_from, period_to = v_to
   where i.id = p_invoice_id;

  return query select 'ok'::text, v_inv.owner_id, v_to;
end $$;

/* Payment by other means (cash, bank transfer), entered by the operator. */
create or replace function app.operator_billing_extend(
  p_actor_user_id uuid,
  p_owner_id      uuid,
  p_months        integer,
  p_amount_mnt    integer,
  p_fee_per_machine integer,
  p_machines      integer,
  p_note          text
) returns table (out_status text, out_paid_until timestamptz)
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_from timestamptz;
  v_to   timestamptz;
begin
  if not app.is_operator_user(p_actor_user_id) then
    return query select 'forbidden'::text, null::timestamptz; return;
  end if;
  if p_months is null or p_months < 1 or p_months > 12 or coalesce(p_amount_mnt, 0) < 0
     or char_length(coalesce(p_note, '')) > 300 then
    return query select 'invalid'::text, null::timestamptz; return;
  end if;
  select greatest(o.paid_until, now()) into v_from from public.owners o where o.id = p_owner_id for update;
  if v_from is null then
    return query select 'not_found'::text, null::timestamptz; return;
  end if;
  v_to := v_from + make_interval(months => p_months);

  update public.owners o
     set paid_until = v_to, billing_notice_stage = null, billing_notice_for = null
   where o.id = p_owner_id;
  insert into public.billing_invoices
    (owner_id, months, machines, fee_per_machine_mnt, amount_mnt, source, status,
     paid_amount_mnt, period_from, period_to, note, created_by, paid_at)
  values
    (p_owner_id, p_months, greatest(coalesce(p_machines, 0), 0), greatest(coalesce(p_fee_per_machine, 0), 0),
     coalesce(p_amount_mnt, 0), 'manual', 'paid', coalesce(p_amount_mnt, 0), v_from, v_to,
     nullif(btrim(coalesce(p_note, '')), ''), p_actor_user_id, now());
  return query select 'ok'::text, v_to;
end $$;

/*
 * The per-machine fee (null: the default) and the exemption. Each argument
 * is applied only when its "set" flag is true, so the console can change one
 * without restating the other.
 */
create or replace function app.operator_billing_settings(
  p_actor_user_id uuid,
  p_owner_id      uuid,
  p_set_fee       boolean,
  p_fee           integer,
  p_set_exempt    boolean,
  p_exempt        boolean
) returns text
language plpgsql volatile security definer set search_path = '' as $$
begin
  if not app.is_operator_user(p_actor_user_id) then return 'forbidden'; end if;
  if p_set_fee and p_fee is not null and (p_fee < 0 or p_fee > 10000000) then return 'invalid'; end if;
  update public.owners o
     set billing_fee_per_machine_mnt = case when p_set_fee then p_fee else o.billing_fee_per_machine_mnt end,
         billing_exempt = case when p_set_exempt and p_exempt is not null then p_exempt else o.billing_exempt end
   where o.id = p_owner_id;
  if not found then return 'not_found'; end if;
  return 'ok';
end $$;

/* Every business, for the console's list. */
create or replace function app.operator_billing_overview(
  p_actor_user_id uuid,
  p_default_fee   integer,
  p_grace_days    integer default 3,
  p_notice_days   integer default 3
) returns table (
  out_owner_id uuid, out_state text, out_paid_until timestamptz, out_machines integer,
  out_fee_per_machine integer, out_monthly_fee integer, out_exempt boolean, out_fee_override boolean
)
language sql stable security definer set search_path = '' as $$
  select o.id, b.out_state, b.out_paid_until, b.out_machines, b.out_fee_per_machine,
         b.out_monthly_fee, b.out_exempt, b.out_fee_override
    from public.owners o
    cross join lateral app.owner_billing(o.id, p_default_fee, p_grace_days, p_notice_days) b
   where app.is_operator_user(p_actor_user_id)
   order by o.name;
$$;

/*
 * Businesses that have entered a stage they have not been told about yet:
 * three days before paid_until ('due_soon') and at suspension. A payment
 * clears the marker, so the next period is announced again.
 */
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
    cross join lateral (select case when b.out_state = 'suspended' then 'suspended'
                                    when b.out_state in ('due_soon', 'overdue') then 'due_soon' end as stage) s
   where s.stage is not null
     and o.status = 'active'
     and (o.billing_notice_for is distinct from o.paid_until
          or o.billing_notice_stage is distinct from s.stage)
     -- A suspension notice is the last word for a period; due_soon never follows it.
     -- (coalesce: with no notice yet both sides are null, and `not null` is null.)
     and not coalesce(o.billing_notice_for = o.paid_until and o.billing_notice_stage = 'suspended', false);
$$;

create or replace function app.billing_notice_sent(p_owner_id uuid, p_stage text, p_paid_until timestamptz)
returns void
language sql volatile security definer set search_path = '' as $$
  update public.owners o
     set billing_notice_stage = p_stage, billing_notice_for = p_paid_until
   where o.id = p_owner_id and o.paid_until = p_paid_until;
$$;

revoke all on function app.owner_billing(uuid, integer, integer, integer, timestamptz) from public, anon, authenticated;
revoke all on function app.billing_mark_paid(uuid, text, integer) from public, anon, authenticated;
revoke all on function app.operator_billing_extend(uuid, uuid, integer, integer, integer, integer, text) from public, anon, authenticated;
revoke all on function app.operator_billing_settings(uuid, uuid, boolean, integer, boolean, boolean) from public, anon, authenticated;
revoke all on function app.operator_billing_overview(uuid, integer, integer, integer) from public, anon, authenticated;
revoke all on function app.billing_notices_due(integer, integer, integer) from public, anon, authenticated;
revoke all on function app.billing_notice_sent(uuid, text, timestamptz) from public, anon, authenticated;

grant execute on function app.owner_billing(uuid, integer, integer, integer, timestamptz) to service_role;
grant execute on function app.billing_mark_paid(uuid, text, integer) to service_role;
grant execute on function app.operator_billing_extend(uuid, uuid, integer, integer, integer, integer, text) to service_role;
grant execute on function app.operator_billing_settings(uuid, uuid, boolean, integer, boolean, boolean) to service_role;
grant execute on function app.operator_billing_overview(uuid, integer, integer, integer) to service_role;
grant execute on function app.billing_notices_due(integer, integer, integer) to service_role;
grant execute on function app.billing_notice_sent(uuid, text, timestamptz) to service_role;

commit;
