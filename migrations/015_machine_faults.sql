-- =====================================================================
-- 015  Machine faults, imported from Jetinno's SaaS.
--
-- The payment interface (A5) never carries a machine's own faults — out of
-- water, grinder jammed, door open. Jetinno's SaaS has them (故障列表) and
-- exports them to Excel, but offers no documented API. Until it does, the
-- operator uploads that export and the rows land here; when an API arrives
-- it writes the same rows and nothing downstream changes.
--
-- A fault is identified by (device, code, time it happened), so the same
-- export uploaded twice — or two overlapping exports — adds nothing twice.
-- Faults for machines we do not have are kept (device_no only): the machine
-- may be registered next week, and the operator should still see them.
-- =====================================================================
begin;

create table if not exists public.machine_faults (
  id           bigint generated always as identity primary key,
  device_no    text not null check (char_length(device_no) between 1 and 40),
  code         text not null default '' check (char_length(code) <= 60),
  description  text check (description is null or char_length(description) <= 300),
  occurred_at  timestamptz not null,
  resolved_at  timestamptz,
  status_text  text check (status_text is null or char_length(status_text) <= 60),
  source       text not null default 'saas_import' check (source in ('saas_import', 'api')),
  import_id    uuid,
  created_at   timestamptz not null default now(),
  constraint machine_faults_identity_key unique (device_no, code, occurred_at)
);
create index if not exists machine_faults_device_idx on public.machine_faults (device_no, occurred_at desc);

alter table public.machine_faults enable row level security;
revoke all on public.machine_faults from anon, authenticated;

create table if not exists public.fault_imports (
  id          uuid primary key default gen_random_uuid(),
  imported_by uuid,
  file_name   text,
  rows_read   integer not null default 0,
  rows_added  integer not null default 0,
  rows_updated integer not null default 0,
  created_at  timestamptz not null default now()
);
alter table public.fault_imports enable row level security;
revoke all on public.fault_imports from anon, authenticated;

/*
 * Takes the parsed rows as JSON. A row seen before is updated only where the
 * new export knows more — a resolution time, a status — never erased.
 */
create or replace function app.operator_import_faults(
  p_actor_user_id uuid,
  p_file_name     text,
  p_rows          jsonb
) returns table (out_status text, out_import_id uuid, out_read int, out_added int, out_updated int)
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_import uuid := gen_random_uuid();
  v_read   int := 0;
  v_added  int := 0;
  v_upd    int := 0;
  r        jsonb;
  v_new    boolean;
begin
  if not app.is_operator_user(p_actor_user_id) then
    return query select 'forbidden'::text, null::uuid, 0, 0, 0;
    return;
  end if;
  if jsonb_typeof(p_rows) <> 'array' or jsonb_array_length(p_rows) > 20000 then
    return query select 'invalid'::text, null::uuid, 0, 0, 0;
    return;
  end if;

  insert into public.fault_imports (id, imported_by, file_name) values (v_import, p_actor_user_id, left(p_file_name, 200));

  for r in select * from jsonb_array_elements(p_rows) loop
    v_read := v_read + 1;
    continue when coalesce(r->>'deviceNo', '') = '' or coalesce(r->>'occurredAt', '') = '';
    insert into public.machine_faults as f
      (device_no, code, description, occurred_at, resolved_at, status_text, source, import_id)
    values
      (left(r->>'deviceNo', 40), left(coalesce(r->>'code', ''), 60), left(r->>'description', 300),
       (r->>'occurredAt')::timestamptz, nullif(r->>'resolvedAt', '')::timestamptz,
       left(r->>'status', 60), 'saas_import', v_import)
    on conflict on constraint machine_faults_identity_key do update
       set resolved_at = coalesce(excluded.resolved_at, f.resolved_at),
           status_text = coalesce(excluded.status_text, f.status_text),
           description = coalesce(excluded.description, f.description)
    returning (xmax = 0) into v_new;
    if v_new then v_added := v_added + 1; else v_upd := v_upd + 1; end if;
  end loop;

  update public.fault_imports set rows_read = v_read, rows_added = v_added, rows_updated = v_upd
   where id = v_import;
  return query select 'ok'::text, v_import, v_read, v_added, v_upd;
end $$;

/* The operator's list: newest first, with whose machine it is. */
create or replace function app.operator_faults(p_actor_user_id uuid, p_limit integer default 200)
returns table (
  occurred_at timestamptz, resolved_at timestamptz, device_no text, owner_name text,
  code text, description text, status_text text
)
language sql stable security definer set search_path = '' as $$
  select f.occurred_at, f.resolved_at, f.device_no, o.name, f.code, f.description, f.status_text
    from public.machine_faults f
    left join public.machines m on m.device_no = f.device_no
    left join public.owners o on o.id = m.owner_id
   where app.is_operator_user(p_actor_user_id)
   order by f.occurred_at desc
   limit least(greatest(coalesce(p_limit, 200), 1), 1000);
$$;

create or replace function app.operator_fault_imports(p_actor_user_id uuid)
returns table (created_at timestamptz, file_name text, rows_read int, rows_added int, rows_updated int)
language sql stable security definer set search_path = '' as $$
  select i.created_at, i.file_name, i.rows_read, i.rows_added, i.rows_updated
    from public.fault_imports i
   where app.is_operator_user(p_actor_user_id)
   order by i.created_at desc
   limit 10;
$$;

/*
 * 014's owner problems, plus the machine's own faults: unresolved ones from
 * the last 7 days, on this owner's machines only.
 */
create or replace function app.owner_problems(
  p_owner_id uuid,
  p_limit    integer default 100,
  p_now      timestamptz default now()
) returns table (
  kind text, at timestamptz, device_no text, amount_mnt integer, detail text, reference text
)
language sql stable security definer set search_path = '' as $$
  select 'needs_human'::text, r.created_at, r.device_no, r.amount_mnt,
         null::text, r.order_no
    from public.orders r
   where r.owner_id = p_owner_id and r.status = 'needs_human'
  union all
  select 'paid_no_cup', r.notified_at, r.device_no, r.amount_mnt, r.product_name, r.order_no
    from public.orders r
   where r.owner_id = p_owner_id and r.status = 'paid' and r.product_done_ok is distinct from true
     and r.notified_at > p_now - interval '30 days'
     and r.notified_at < p_now - interval '5 minutes'
  union all
  select 'order_failed', r.created_at, r.device_no, r.amount_mnt, r.product_name, r.order_no
    from public.orders r
   where r.owner_id = p_owner_id and r.status = 'failed'
     and r.created_at > p_now - interval '7 days'
  union all
  select 'machine_refused', e.at, e.device_no, null, e.reason, e.order_no
    from public.ingest_errors e
    join public.machines m on m.device_no = e.device_no and m.owner_id = p_owner_id
   where e.at > p_now - interval '7 days'
  union all
  select 'qpay_failing', c.updated_at, null, null, c.last_error_code, c.username_hint
    from public.qpay_credentials c
   where c.owner_id = p_owner_id and c.auth_fail_count > 0
  union all
  select 'machine_silent', max(r.created_at), m.device_no, null, null, null
    from public.machines m
    join public.orders r on r.machine_id = m.id
   where m.owner_id = p_owner_id and m.status = 'active'
   group by m.device_no
  having max(r.created_at) < p_now - interval '24 hours'
  union all
  -- The machine's own fault, as Jetinno's SaaS reported it.
  select 'machine_fault', f.occurred_at, f.device_no, null,
         nullif(concat_ws(' · ', nullif(f.code, ''), f.description), ''), f.status_text
    from public.machine_faults f
    join public.machines m on m.device_no = f.device_no and m.owner_id = p_owner_id
   where f.resolved_at is null and f.occurred_at > p_now - interval '7 days'
  order by 2 desc
  limit least(greatest(coalesce(p_limit, 100), 1), 500);
$$;

revoke all on function app.operator_import_faults(uuid, text, jsonb) from public, anon, authenticated;
revoke all on function app.operator_faults(uuid, integer) from public, anon, authenticated;
revoke all on function app.operator_fault_imports(uuid) from public, anon, authenticated;
grant execute on function app.operator_import_faults(uuid, text, jsonb) to service_role;
grant execute on function app.operator_faults(uuid, integer) to service_role;
grant execute on function app.operator_fault_imports(uuid) to service_role;

commit;
