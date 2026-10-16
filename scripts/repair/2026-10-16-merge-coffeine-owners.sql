-- =====================================================================
-- 2026-10-16, at the operator's request: two businesses ended up with the
-- contact phone 99147668 — «Coffeine» (QPay connected, formerly Хаан тауэр)
-- and «coffeine» (invited, no QPay yet). Merge them into the connected one:
--
--   - the duplicate's machine(s) move to the connected business and its
--     active QPay credential, so their revenue lands there;
--   - the duplicate's unpaid attempts (failed / cancelled orders) are
--     deleted; anything paid or still in flight stops the whole script;
--   - anyone who joined the duplicate joins the connected business;
--   - the duplicate's pending credential, invites and the business itself
--     are deleted;
--   - the connected business's contact phone becomes 90777400, and its open
--     invites (sent to 99147668) are revoked.
--
-- One transaction: any check that fails changes nothing.
-- Copy it from chat or the file, not through pbcopy (Cyrillic messages).
-- =====================================================================
begin;

create temp table merge_result (keeper uuid, dup_name text, moved_machines int, deleted_orders int)
  on commit drop;

do $$
declare
  v_phone    text := app.norm_phone('99147668');
  n          int;
  v_keeper   uuid;
  v_cred     uuid;
  v_dup      uuid;
  v_dup_name text;
  n_orders   int;
  n_machines int;
begin
  select count(*) into n from public.owners where app.norm_phone(contact_phone) = v_phone;
  if n <> 2 then
    raise exception '99147668 утастай % эзэмшигч олдлоо, 2 байх ёстой. Юу ч өөрчлөгдсөнгүй.', n;
  end if;

  -- The keeper is the one whose QPay is connected; exactly one may be.
  select count(distinct o.id) into n
    from public.owners o
    join public.qpay_credentials c on c.owner_id = o.id and c.status = 'active'
   where app.norm_phone(o.contact_phone) = v_phone;
  if n <> 1 then
    raise exception 'QPay холбогдсон эзэмшигч % олдлоо, 1 байх ёстой. Юу ч өөрчлөгдсөнгүй.', n;
  end if;

  select o.id into v_keeper
    from public.owners o
    join public.qpay_credentials c on c.owner_id = o.id and c.status = 'active'
   where app.norm_phone(o.contact_phone) = v_phone
   limit 1;

  -- The credential its machines already sell through, if it has several.
  select c.id into v_cred
    from public.qpay_credentials c
   where c.owner_id = v_keeper and c.status = 'active'
   order by exists (select 1 from public.machines m where m.qpay_credential_id = c.id) desc,
            c.last_verified_at desc nulls last
   limit 1;

  select o.id, o.name into v_dup, v_dup_name
    from public.owners o
   where app.norm_phone(o.contact_phone) = v_phone and o.id <> v_keeper;

  select count(*) into n
    from public.orders r
   where r.owner_id = v_dup and r.status not in ('failed', 'cancelled');
  if n > 0 then
    raise exception 'Давхардсан эзэмшигч % төлөгдсөн/явж буй захиалгатай. Юу ч өөрчлөгдсөнгүй.', n;
  end if;

  delete from public.orders where owner_id = v_dup;
  get diagnostics n_orders = row_count;

  delete from public.machine_assignments where owner_id = v_dup;

  update public.machines
     set owner_id = v_keeper, qpay_credential_id = v_cred
   where owner_id = v_dup;
  get diagnostics n_machines = row_count;

  insert into public.owner_members (owner_id, user_id, role)
  select v_keeper, m.user_id, m.role from public.owner_members m where m.owner_id = v_dup
  on conflict (owner_id, user_id) do nothing;

  -- Invites, members and verify attempts go with the owner (on delete cascade).
  delete from public.qpay_credentials where owner_id = v_dup;
  delete from public.owners where id = v_dup;

  perform app.revoke_owner_invite(i.id, 'contact_phone_changed')
     from public.owner_invites i
    where i.owner_id = v_keeper and i.accepted_at is null and i.revoked_at is null;

  update public.owners set contact_phone = app.norm_phone('90777400') where id = v_keeper;

  insert into merge_result values (v_keeper, v_dup_name, n_machines, n_orders);
end $$;

select o.name,
       o.contact_phone,
       (select string_agg(m.device_no, ', ' order by m.device_no)
          from public.machines m where m.owner_id = o.id) as machines,
       (select count(*) from public.owner_members mm where mm.owner_id = o.id) as members,
       r.dup_name as merged_from,
       r.moved_machines,
       r.deleted_orders
  from merge_result r
  join public.owners o on o.id = r.keeper;

commit;
