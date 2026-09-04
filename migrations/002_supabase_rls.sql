-- =====================================================================
-- jetinno-qpay-bridge — migration 002_supabase_rls.sql
-- SUPABASE ONLY (needs auth.users, anon, authenticated). Never run in the e2e.
-- The bridge connects as service_role and bypasses all of this; everything
-- here exists for the future owner dashboard and is READ-ONLY by design.
-- =====================================================================

begin;

create table public.owner_members (
  owner_id   uuid not null references public.owners(id) on delete cascade,
  user_id    uuid not null references auth.users(id) on delete cascade,
  role       text not null default 'viewer' check (role in ('admin','viewer')),
  created_at timestamptz not null default now(),
  primary key (owner_id, user_id)
);
create index owner_members_user_idx on public.owner_members (user_id);

-- STABLE so the planner calls it once per statement, not once per row.
-- SECURITY DEFINER so the policies below do not recurse into owner_members' RLS.
create or replace function app.my_owner_ids() returns uuid[]
language sql stable security definer set search_path = '' as $$
  select coalesce(array_agg(m.owner_id), '{}'::uuid[])
    from public.owner_members m
   where m.user_id = (select auth.uid());
$$;

alter table public.owners              enable row level security;
alter table public.owner_members       enable row level security;
alter table public.qpay_credentials    enable row level security;
alter table public.machines            enable row level security;
alter table public.machine_assignments enable row level security;
alter table public.orders              enable row level security;
alter table public.order_events        enable row level security;
alter table public.ingest_errors       enable row level security;
alter table public.admin_audit         enable row level security;

create policy owners_read_own on public.owners
  for select to authenticated using (id = any (app.my_owner_ids()));
create policy owner_members_read_own on public.owner_members
  for select to authenticated using (owner_id = any (app.my_owner_ids()));
create policy machines_read_own on public.machines
  for select to authenticated using (owner_id = any (app.my_owner_ids()));
create policy machine_assignments_read_own on public.machine_assignments
  for select to authenticated using (owner_id = any (app.my_owner_ids()));
create policy orders_read_own on public.orders
  for select to authenticated using (owner_id = any (app.my_owner_ids()));
create policy order_events_read_own on public.order_events
  for select to authenticated using (owner_id = any (app.my_owner_ids()));

-- qpay_credentials, ingest_errors and admin_audit get RLS with ZERO policies,
-- plus an explicit REVOKE. Two layers on purpose: RLS alone makes PostgREST
-- return a confusing empty array; the REVOKE returns a clear permission error.
revoke all on public.qpay_credentials from anon, authenticated;
revoke all on public.ingest_errors    from anon, authenticated;
revoke all on public.admin_audit      from anon, authenticated;

grant usage on schema public to anon, authenticated;
grant select on public.owners, public.owner_members, public.machines,
                public.machine_assignments, public.orders, public.order_events
  to authenticated;

grant usage on schema app to authenticated;
grant execute on function app.my_owner_ids() to authenticated;

-- The settle/claim helpers belong to the bridge alone.
revoke all on function app.claim_order_for_settle(uuid,integer,text,integer,integer) from public;
revoke all on function app.mark_payment_confirmed(uuid,text,integer,integer)          from public;
revoke all on function app.mark_notify_sent(uuid)                                     from public;
revoke all on function app.finish_settle(uuid)                                        from public;
revoke all on function app.release_settle(uuid,text,boolean)                          from public;
revoke all on function app.give_up(uuid,text)                                         from public;
revoke all on function app.claim_abandoned_orders(integer,integer,text,integer)        from public;
revoke all on function app.claim_unnotified_orders(integer,integer,text,integer,integer) from public;
revoke all on function app.record_product_done(uuid,boolean)                          from public;
revoke all on function app.mark_cancelled(uuid)                                       from public;
revoke all on function app.audit_row()                                                from public;

-- security_invoker so RLS evaluates as the caller. A view without it is the
-- classic Supabase RLS bypass.
create view public.owner_orders with (security_invoker = true) as
  select o.id, o.owner_id, o.machine_id, m.device_no, m.label as machine_label,
         o.order_no, o.product_name, o.amount_mnt, o.paid_amount_mnt, o.status,
         o.created_at, o.payment_confirmed_at, o.notified_at, o.product_done_at
    from public.orders o
    join public.machines m on m.id = o.machine_id;
grant select on public.owner_orders to authenticated;

commit;
