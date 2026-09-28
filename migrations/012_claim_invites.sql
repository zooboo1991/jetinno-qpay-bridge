-- =====================================================================
-- 012  An invite is claimed by the phone it names.
--
-- The rule the business set: the operator registers a number, the person
-- proves that number by SMS code, and when the two match the account
-- exists. The link in the invite SMS is a convenience, not a second key.
--
-- Before this, only the link's token could redeem an invite. An owner who
-- reached the portal any other way — the link's domain not live yet, a
-- bookmark, "нууц үгээ мартсан" — proved their phone and was told they were
-- not registered, while an open invite for that exact number sat unclaimed.
--
-- What still has to hold, and does:
--   * the phone must be CONFIRMED on auth.users — Supabase sets that only
--     when the SMS code is right;
--   * the invite must be open (not accepted, revoked or expired);
--   * the bridge only calls this within minutes of an SMS code, so a stale
--     session cannot claim an invite issued after it logged in.
-- =====================================================================
begin;

create or replace function app.claim_invites_by_phone(
  p_user_id   uuid,
  p_source_ip inet default null
) returns table (out_owner_id uuid, out_owner_name text, out_role text)
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_phone text;
  v_ok    timestamptz;
  r       record;
begin
  select app.norm_phone(u.phone), u.phone_confirmed_at into v_phone, v_ok
    from auth.users u where u.id = p_user_id;
  if v_phone is null or v_ok is null then return; end if;

  for r in
    select i.id, i.owner_id, i.role, i.reference
      from public.owner_invites i
     where i.invited_phone = v_phone
       and i.accepted_at is null
       and i.revoked_at is null
       and i.expires_at > now()
     order by i.created_at
     for update
  loop
    update public.owner_invites i
       set accepted_at = now(), accepted_by = p_user_id, accepted_ip = p_source_ip,
           attempt_count = i.attempt_count + 1, last_attempt_at = now(), last_attempt_ip = p_source_ip
     where i.id = r.id and i.accepted_at is null;
    if not found then continue; end if;

    -- ON CONFLICT names the constraint — see 003's accept_owner_invite for
    -- why bare column names blow up inside a function with OUT parameters.
    insert into public.owner_members (owner_id, user_id, role)
    values (r.owner_id, p_user_id, r.role)
    on conflict on constraint owner_members_pkey do nothing;

    insert into public.credential_audit
      (owner_id, action, actor_user_id, actor_kind, source_ip, detail)
    values
      (r.owner_id, 'member_joined', p_user_id, 'owner', p_source_ip,
       jsonb_build_object('invite_reference', r.reference, 'role', r.role, 'via', 'phone_match'));

    return query select r.owner_id, o.name, r.role from public.owners o where o.id = r.owner_id;
  end loop;
end $$;

revoke all on function app.claim_invites_by_phone(uuid, inet) from public, anon, authenticated;
grant execute on function app.claim_invites_by_phone(uuid, inet) to service_role;

commit;
