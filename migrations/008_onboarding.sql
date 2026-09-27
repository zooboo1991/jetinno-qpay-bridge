-- =====================================================================
-- 008  Onboarding from the operator console.
--
-- 003 built every piece of the self-service path — the pending credential
-- slot, the operator-typed invoice code, the phone-bound single-use invite,
-- the owner's two-phase credential write — and left the operator's half to
-- "the CLI". That CLI was never written; scripts/add-owner.js instead asks
-- the OPERATOR for the owner's QPay password, which is the opposite of the
-- decision the business made (the owner types it, nobody else sees it).
--
-- These are the operator's half, as functions the bridge calls with
-- service_role on behalf of a JWT it has already verified. Each checks
-- operator membership itself, for the reason 007 gives: an authorisation
-- check that exists only in the HTTP layer is one refactor from skipped.
--
-- What they can NOT do is as important: none of them touches `sealed`, and
-- none can create an owner_members row. The owner becomes an admin only by
-- presenting the invite from a phone that matches, through
-- app.accept_owner_invite — the operator can hand over the key, not turn it.
-- =====================================================================
begin;

-- Two new audit actions. The constraint is replaced, not altered: Postgres
-- has no way to widen a CHECK in place.
alter table public.credential_audit drop constraint if exists credential_audit_action_check;
alter table public.credential_audit add constraint credential_audit_action_check check (action in (
  'invite_created','invite_revoked','invite_mismatch','member_joined',
  'verify_started','verify_confirmed','verify_aborted','verify_failed',
  'rejected_duplicate','rejected_not_admin',
  'deactivated','reactivated','label_changed','acceptance_confirmed',
  'owner_provisioned','invoice_code_set'));

/*
 * Registers a business, its first machine, and an EMPTY credential slot.
 *
 * The machine is wired to the slot immediately, so from this moment the
 * machine resolves to its owner and src/owners.js answers MERCHANT_NOT_READY
 * for it — the machine refuses to sell rather than selling on the operator's
 * own merchant. Money never goes to the wrong account while the owner is
 * still finding their password.
 *
 * p_credential_id comes from the bridge because the credential id is part of
 * the AEAD additional data the owner's password will later be sealed under
 * (001 deliberately gives the column no default).
 */
create or replace function app.operator_provision_owner(
  p_actor_user_id uuid,
  p_credential_id uuid,
  p_name          text,
  p_contact_phone text,
  p_device_no     text,
  p_location      text,
  p_invoice_code  text
) returns table (out_status text, out_owner_id uuid, out_machine_id uuid)
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_owner   uuid := gen_random_uuid();
  v_machine uuid := gen_random_uuid();
  v_name    text := btrim(coalesce(p_name, ''));
  v_device  text := btrim(coalesce(p_device_no, ''));
  v_code    text := btrim(coalesce(p_invoice_code, ''));
  v_phone   text := app.norm_phone(p_contact_phone);
begin
  if not app.is_operator_user(p_actor_user_id) then
    return query select 'forbidden'::text, null::uuid, null::uuid;
    return;
  end if;
  if p_credential_id is null or length(v_name) < 2 or length(v_name) > 120 then
    return query select 'invalid_name'::text, null::uuid, null::uuid;
    return;
  end if;
  -- A Mongolian mobile: 976 + 8 digits. Anything else is a typo, and a typo
  -- here is the phone a future invite will be checked against.
  if v_phone is null or v_phone !~ '^976[0-9]{8}$' then
    return query select 'invalid_phone'::text, null::uuid, null::uuid;
    return;
  end if;
  if v_device !~ '^[A-Za-z0-9_-]{3,40}$' then
    return query select 'invalid_device'::text, null::uuid, null::uuid;
    return;
  end if;
  if v_code !~ '^[A-Za-z0-9_-]{3,64}$' then
    return query select 'invalid_invoice_code'::text, null::uuid, null::uuid;
    return;
  end if;
  if exists (select 1 from public.machines m where m.device_no = v_device) then
    return query select 'device_taken'::text, null::uuid, null::uuid;
    return;
  end if;

  insert into public.owners (id, name, contact_phone, status)
  values (v_owner, v_name, v_phone, 'active');

  -- 'pending' with no sealed blob: the shape 003's state-machine CHECK
  -- requires. is_active must be false — the same CHECK derives it.
  insert into public.qpay_credentials
    (id, owner_id, label, status, is_active, source, pending_invoice_code, invoice_code_hint)
  values
    (p_credential_id, v_owner, 'Үндсэн данс', 'pending', false, 'cli', v_code, right(v_code, 4));

  -- notify_url stays NULL until the machine's first signed getQrCode pins it.
  insert into public.machines
    (id, owner_id, qpay_credential_id, device_no, label, location, notify_url, status, installed_at)
  values
    (v_machine, v_owner, p_credential_id, v_device, null, nullif(btrim(coalesce(p_location, '')), ''),
     null, 'active', now());

  insert into public.credential_audit (owner_id, credential_id, action, actor_kind, actor_user_id, detail)
  values (v_owner, p_credential_id, 'owner_provisioned', 'operator', p_actor_user_id,
          jsonb_build_object('device_no', v_device, 'invoice_code_hint', right(v_code, 4)));

  return query select 'ok'::text, v_owner, v_machine;
exception
  -- Two operators registering the same machine at once: the unique
  -- constraint decides, and the loser is told plainly.
  when unique_violation then
    return query select 'device_taken'::text, null::uuid, null::uuid;
end $$;

/*
 * Issues the link the owner scans at installation.
 *
 * The raw token never reaches Postgres — the bridge generates it and passes
 * the sha256. Any earlier unaccepted invite for the same owner is revoked
 * first: the operator re-issues when a link was lost or mistyped, and two
 * live links for one business is one more than anyone can account for.
 *
 * The phone must be typed AGAIN and must equal owners.contact_phone —
 * app.create_owner_invite enforces that, and it is the point: one wrong digit
 * at the end of a long installation would otherwise hand the power to redirect
 * a business's revenue to a stranger whose identity genuinely matches.
 */
create or replace function app.operator_create_invite(
  p_actor_user_id uuid,
  p_owner_id      uuid,
  p_token_hash    bytea,
  p_reference     text,
  p_invited_phone text,
  p_role          text
) returns table (out_status text, out_reference text, out_expires_at timestamptz)
language plpgsql volatile security definer set search_path = '' as $$
declare
  r record;
begin
  if not app.is_operator_user(p_actor_user_id) then
    return query select 'forbidden'::text, null::text, null::timestamptz;
    return;
  end if;
  if p_role not in ('admin', 'viewer') then
    return query select 'invalid_role'::text, null::text, null::timestamptz;
    return;
  end if;
  if not exists (select 1 from public.owners o where o.id = p_owner_id) then
    return query select 'not_found'::text, null::text, null::timestamptz;
    return;
  end if;
  if app.norm_phone(p_invited_phone) is distinct from
     (select app.norm_phone(o.contact_phone) from public.owners o where o.id = p_owner_id) then
    return query select 'phone_mismatch'::text, null::text, null::timestamptz;
    return;
  end if;

  for r in
    select i.id from public.owner_invites i
     where i.owner_id = p_owner_id and i.accepted_at is null and i.revoked_at is null
  loop
    perform app.revoke_owner_invite(r.id, 'superseded');
  end loop;

  return query
    select 'ok'::text, c.out_reference, c.out_expires_at
      from app.create_owner_invite(p_owner_id, p_token_hash, p_reference, p_invited_phone,
                                   p_role, 7, p_actor_user_id) c;
end $$;

/*
 * Fills (or corrects) the invoice code on an owner's credential slot.
 *
 * Two callers need it. When QPay rejects the code at verification, the owner
 * is told the operator typed it wrong — and this is how the operator fixes
 * it. And an ACTIVE credential has its code sealed inside the blob, with
 * pending_invoice_code NULL, so an owner changing their password is refused
 * SLOT_INCOMPLETE until the operator puts the code back here.
 *
 * Refused while a verification is open: the staged candidate was sealed with
 * the old code, and swapping it underneath would confirm a credential that
 * no longer matches what was proved.
 */
create or replace function app.operator_set_invoice_code(
  p_actor_user_id uuid,
  p_owner_id      uuid,
  p_invoice_code  text
) returns text
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_code text := btrim(coalesce(p_invoice_code, ''));
  v_cred public.qpay_credentials;
begin
  if not app.is_operator_user(p_actor_user_id) then return 'forbidden'; end if;
  if v_code !~ '^[A-Za-z0-9_-]{3,64}$' then return 'invalid_invoice_code'; end if;

  -- The slot the owner's machines are wired to. An owner with none has
  -- nothing to configure.
  select c.* into v_cred
    from public.qpay_credentials c
   where c.owner_id = p_owner_id
     and exists (select 1 from public.machines m where m.qpay_credential_id = c.id)
   order by c.is_active desc, c.updated_at desc
   limit 1
   for update;
  if not found then return 'not_found'; end if;
  if v_cred.verify_expires_at is not null and v_cred.verify_expires_at > now() then
    return 'verification_open';
  end if;

  update public.qpay_credentials c
     set pending_invoice_code = v_code,
         -- A pending slot shows the code it will use; an active one keeps
         -- the hint of the code actually sealed until the change completes.
         invoice_code_hint = case when c.status = 'pending' then right(v_code, 4) else c.invoice_code_hint end
   where c.id = v_cred.id;

  insert into public.credential_audit (owner_id, credential_id, action, actor_kind, actor_user_id, detail)
  values (p_owner_id, v_cred.id, 'invoice_code_set', 'operator', p_actor_user_id,
          jsonb_build_object('invoice_code_hint', right(v_code, 4), 'credential_status', v_cred.status));
  return 'ok';
end $$;

revoke all on function app.operator_provision_owner(uuid, uuid, text, text, text, text, text) from public, anon, authenticated;
revoke all on function app.operator_create_invite(uuid, uuid, bytea, text, text, text) from public, anon, authenticated;
revoke all on function app.operator_set_invoice_code(uuid, uuid, text) from public, anon, authenticated;
grant execute on function app.operator_provision_owner(uuid, uuid, text, text, text, text, text) to service_role;
grant execute on function app.operator_create_invite(uuid, uuid, bytea, text, text, text) to service_role;
grant execute on function app.operator_set_invoice_code(uuid, uuid, text) to service_role;

commit;
