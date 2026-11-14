-- =====================================================================
-- 021 — the operator's payments ledger («Төлбөр» in the console)
--
-- Every subscription payment in one list, whichever way it came:
--   * QPay, confirmed by the bridge as before;
--   * cash or a bank transfer the operator confirms by hand;
--   * months given free.
-- And a way back for a payment confirmed by mistake: the NEWEST manual
-- payment of a business can be cancelled, which returns its paid-until to
-- exactly what it was before.
--
-- 019's operator_billing_extend is left as it is (a bridge that is still
-- deploying calls it); the bridge after this migration calls
-- operator_billing_record instead.
--
-- Idempotent; safe to run twice.
-- =====================================================================
begin;

alter table public.billing_invoices add column if not exists method          text;
alter table public.billing_invoices add column if not exists prev_paid_until timestamptz;
alter table public.billing_invoices add column if not exists cancelled_at    timestamptz;
alter table public.billing_invoices add column if not exists cancelled_by    uuid;
alter table public.billing_invoices add column if not exists cancel_reason   text;

-- Rows before this migration: QPay is QPay; a manual row of 0₮ was free
-- months; any other manual row is not known to have been cash or transfer.
update public.billing_invoices
   set method = case when source = 'qpay' then 'qpay' when amount_mnt = 0 then 'free' else 'other' end
 where method is null;

do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'billing_invoices_method_check') then
    alter table public.billing_invoices add constraint billing_invoices_method_check
      check (method is null or method in ('qpay', 'cash', 'bank', 'free', 'other'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'billing_invoices_method_source') then
    alter table public.billing_invoices add constraint billing_invoices_method_source
      check (method is null or (source = 'qpay') = (method = 'qpay'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'billing_invoices_cancel_reason_len') then
    alter table public.billing_invoices add constraint billing_invoices_cancel_reason_len
      check (cancel_reason is null or char_length(cancel_reason) <= 300);
  end if;
end $$;

comment on column public.billing_invoices.method is
  'How it was paid: qpay | cash | bank (transfer) | free (months given) | other. NULL only on QPay rows written by a bridge older than 021.';
comment on column public.billing_invoices.prev_paid_until is
  'owners.paid_until just before this manual payment: where a cancellation puts it back.';

/*
 * A payment confirmed by the operator: cash, a bank transfer, free months.
 * Extends paid-until from the later of it and now, like a QPay payment.
 * Free months are 0₮; cash and a transfer are more than that.
 */
create or replace function app.operator_billing_record(
  p_actor_user_id   uuid,
  p_owner_id        uuid,
  p_months          integer,
  p_amount_mnt      integer,
  p_fee_per_machine integer,
  p_machines        integer,
  p_method          text,
  p_note            text
) returns table (out_status text, out_paid_until timestamptz, out_invoice_id uuid)
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_prev timestamptz;
  v_from timestamptz;
  v_to   timestamptz;
  v_id   uuid;
begin
  if not app.is_operator_user(p_actor_user_id) then
    return query select 'forbidden'::text, null::timestamptz, null::uuid; return;
  end if;
  if p_months is null or p_months < 1 or p_months > 12
     or p_amount_mnt is null or p_amount_mnt < 0 or p_amount_mnt > 100000000
     or p_method is null or p_method not in ('cash', 'bank', 'free', 'other')
     or (p_method = 'free' and p_amount_mnt <> 0)
     or (p_method in ('cash', 'bank') and p_amount_mnt = 0)
     or char_length(coalesce(p_note, '')) > 300 then
    return query select 'invalid'::text, null::timestamptz, null::uuid; return;
  end if;
  select o.paid_until into v_prev from public.owners o where o.id = p_owner_id for update;
  if not found then
    return query select 'not_found'::text, null::timestamptz, null::uuid; return;
  end if;
  v_from := greatest(v_prev, now());
  v_to   := v_from + make_interval(months => p_months);

  update public.owners o
     set paid_until = v_to, billing_notice_stage = null, billing_notice_for = null
   where o.id = p_owner_id;
  insert into public.billing_invoices
    (owner_id, months, machines, fee_per_machine_mnt, amount_mnt, source, status, method,
     paid_amount_mnt, period_from, period_to, prev_paid_until, note, created_by, paid_at)
  values
    (p_owner_id, p_months, greatest(coalesce(p_machines, 0), 0), greatest(coalesce(p_fee_per_machine, 0), 0),
     p_amount_mnt, 'manual', 'paid', p_method, p_amount_mnt, v_from, v_to, v_prev,
     nullif(btrim(coalesce(p_note, '')), ''), p_actor_user_id, now())
  returning id into v_id;
  return query select 'ok'::text, v_to, v_id;
end $$;

/*
 * Cancels a payment confirmed by mistake. Only a manual one — QPay money is
 * refunded in QPay, not here — and only the newest: the business's
 * paid-until must still be the end of this payment's period, so taking it
 * back cannot undo a later payment. Paid-until returns to what it was.
 * Locks the invoice, then the business: billing_mark_paid's order.
 */
create or replace function app.operator_billing_void(
  p_actor_user_id uuid,
  p_invoice_id    uuid,
  p_reason        text
) returns table (out_status text, out_owner_id uuid, out_paid_until timestamptz)
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_inv  public.billing_invoices;
  v_paid timestamptz;
  v_back timestamptz;
begin
  if not app.is_operator_user(p_actor_user_id) then
    return query select 'forbidden'::text, null::uuid, null::timestamptz; return;
  end if;
  if char_length(coalesce(p_reason, '')) > 300 then
    return query select 'invalid'::text, null::uuid, null::timestamptz; return;
  end if;
  select * into v_inv from public.billing_invoices i where i.id = p_invoice_id for update;
  if not found then
    return query select 'not_found'::text, null::uuid, null::timestamptz; return;
  end if;
  if v_inv.source <> 'manual' then
    return query select 'not_manual'::text, v_inv.owner_id, null::timestamptz; return;
  end if;
  if v_inv.status = 'cancelled' then
    return query select 'already'::text, v_inv.owner_id, null::timestamptz; return;
  end if;
  select o.paid_until into v_paid from public.owners o where o.id = v_inv.owner_id for update;
  if v_inv.status <> 'paid' or v_paid is distinct from v_inv.period_to then
    return query select 'not_latest'::text, v_inv.owner_id, v_paid; return;
  end if;
  v_back := coalesce(v_inv.prev_paid_until, v_inv.period_from);

  update public.owners o
     set paid_until = v_back, billing_notice_stage = null, billing_notice_for = null
   where o.id = v_inv.owner_id;
  update public.billing_invoices i
     set status = 'cancelled', cancelled_at = now(), cancelled_by = p_actor_user_id,
         cancel_reason = nullif(btrim(coalesce(p_reason, '')), '')
   where i.id = v_inv.id;
  return query select 'ok'::text, v_inv.owner_id, v_back;
end $$;

/*
 * The ledger: every invoice and payment of every business between two
 * instants (by when it was paid, or made if never paid), newest first.
 * `voidable` is exactly the condition operator_billing_void checks.
 */
create or replace function app.operator_billing_payments(
  p_actor_user_id uuid,
  p_from          timestamptz,
  p_to            timestamptz
) returns table (
  out_id uuid, out_owner_id uuid, out_owner_name text, out_source text, out_method text, out_status text,
  out_months integer, out_machines integer, out_amount_mnt integer, out_paid_amount_mnt integer,
  out_created_at timestamptz, out_paid_at timestamptz, out_period_from timestamptz, out_period_to timestamptz,
  out_note text, out_recorded_by text, out_cancelled_at timestamptz, out_cancel_reason text, out_voidable boolean
)
language sql stable security definer set search_path = '' as $$
  select i.id, i.owner_id, o.name, i.source,
         coalesce(i.method, case when i.source = 'qpay' then 'qpay' when i.amount_mnt = 0 then 'free' else 'other' end),
         i.status, i.months, i.machines, i.amount_mnt, i.paid_amount_mnt,
         i.created_at, i.paid_at, i.period_from, i.period_to, i.note,
         (select op.label from public.operators op where op.user_id = i.created_by limit 1),
         i.cancelled_at, i.cancel_reason,
         (i.source = 'manual' and i.status = 'paid' and o.paid_until = i.period_to)
    from public.billing_invoices i
    join public.owners o on o.id = i.owner_id
   where app.is_operator_user(p_actor_user_id)
     and coalesce(i.paid_at, i.created_at) >= p_from
     and coalesce(i.paid_at, i.created_at) <  p_to
   order by coalesce(i.paid_at, i.created_at) desc, i.id desc
   limit 2000;
$$;

revoke all on function app.operator_billing_record(uuid, uuid, integer, integer, integer, integer, text, text) from public, anon, authenticated;
revoke all on function app.operator_billing_void(uuid, uuid, text) from public, anon, authenticated;
revoke all on function app.operator_billing_payments(uuid, timestamptz, timestamptz) from public, anon, authenticated;
grant execute on function app.operator_billing_record(uuid, uuid, integer, integer, integer, integer, text, text) to service_role;
grant execute on function app.operator_billing_void(uuid, uuid, text) to service_role;
grant execute on function app.operator_billing_payments(uuid, timestamptz, timestamptz) to service_role;

commit;
