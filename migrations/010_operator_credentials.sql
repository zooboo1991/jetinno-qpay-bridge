-- =====================================================================
-- 010  The operator configures an owner's QPay account.
--
-- For the owner who cannot do it themselves — no smartphone to hand, a
-- merchant password they only remember on paper, an accountant who holds
-- the login. The owner still CAN do it themselves; this is the fallback, and
-- it is louder than the owner's own path in three ways:
--
--   * the bridge requires the operator's SMS code from the last ten minutes;
--   * the change is audited as the operator's, never the owner's;
--   * the owner gets an SMS at the number on the sales paperwork.
--
-- What it does NOT do is the owner path's 4-digit read-back. That check
-- proves the account is the OWNER's by making the owner look inside it; here
-- the operator is vouching instead, having the credentials in hand, and the
-- console makes them say so.
--
-- Like 008, the sealed blob is produced by the bridge; Postgres never sees a
-- plaintext password.
-- =====================================================================
begin;

alter table public.credential_audit drop constraint if exists credential_audit_action_check;
alter table public.credential_audit add constraint credential_audit_action_check check (action in (
  'invite_created','invite_revoked','invite_mismatch','member_joined',
  'verify_started','verify_confirmed','verify_aborted','verify_failed',
  'rejected_duplicate','rejected_not_admin',
  'deactivated','reactivated','label_changed','acceptance_confirmed',
  'owner_provisioned','invoice_code_set','operator_configured'));

/*
 * The slot the operator is about to fill: the credential this owner's
 * machines are wired to. Its id is needed BEFORE sealing — it is part of the
 * AEAD additional data.
 */
create or replace function app.operator_credential_slot(p_actor_user_id uuid, p_owner_id uuid)
returns table (out_status text, out_credential_id uuid)
language plpgsql stable security definer set search_path = '' as $$
declare v_cred public.qpay_credentials;
begin
  if not app.is_operator_user(p_actor_user_id) then
    return query select 'forbidden'::text, null::uuid;
    return;
  end if;
  select c.* into v_cred
    from public.qpay_credentials c
   where c.owner_id = p_owner_id
     and exists (select 1 from public.machines m where m.qpay_credential_id = c.id)
   order by c.is_active desc, c.updated_at desc
   limit 1;
  if not found then
    return query select 'not_found'::text, null::uuid;
    return;
  end if;
  -- The owner is in the middle of doing it themselves. Overwriting the slot
  -- under them would confirm a credential that no longer matches what they
  -- are about to read back.
  if v_cred.verify_expires_at is not null and v_cred.verify_expires_at > now() then
    return query select 'verification_open'::text, v_cred.id;
    return;
  end if;
  return query select 'ok'::text, v_cred.id;
end $$;

/*
 * Writes the sealed credential and switches it on, in one statement.
 *
 * The bridge has already proved it against QPay (token + a probe invoice
 * that exercises the invoice code) before calling this.
 */
create or replace function app.operator_set_credential(
  p_actor_user_id     uuid,
  p_owner_id          uuid,
  p_credential_id     uuid,
  p_sealed            text,
  p_key_id            text,
  p_fingerprint       text,
  p_username_hint     text,
  p_invoice_code_hint text
) returns text
language plpgsql volatile security definer set search_path = '' as $$
declare v_cred public.qpay_credentials;
begin
  if not app.is_operator_user(p_actor_user_id) then return 'forbidden'; end if;

  select c.* into v_cred from public.qpay_credentials c
   where c.id = p_credential_id and c.owner_id = p_owner_id
   for update;
  if not found then return 'not_found'; end if;
  if v_cred.verify_expires_at is not null and v_cred.verify_expires_at > now() then
    return 'verification_open';
  end if;

  -- Two owners on one merchant means one of them receives the other's money.
  if exists (
    select 1 from public.qpay_credentials c
     where c.owner_id <> p_owner_id
       and (c.fingerprint = p_fingerprint or c.pending_fingerprint = p_fingerprint)
  ) then
    insert into public.credential_audit (owner_id, credential_id, action, actor_kind, actor_user_id, detail)
    values (p_owner_id, p_credential_id, 'rejected_duplicate', 'operator', p_actor_user_id,
            jsonb_build_object('via', 'operator_console'));
    return 'duplicate_other_owner';
  end if;

  update public.qpay_credentials c
     set sealed = p_sealed,
         key_id = p_key_id,
         fingerprint = p_fingerprint,
         username_hint = p_username_hint,
         invoice_code_hint = p_invoice_code_hint,
         status = 'active',
         is_active = true,
         pending_invoice_code = null,
         last_verified_at = now(),
         last_error_code = null,
         last_error = null,
         auth_fail_count = 0,
         configured_by = p_actor_user_id,
         configured_at = now(),
         source = 'cli'
   where c.id = p_credential_id;

  insert into public.credential_audit (owner_id, credential_id, action, actor_kind, actor_user_id, key_id, detail)
  values (p_owner_id, p_credential_id, 'operator_configured', 'operator', p_actor_user_id, p_key_id,
          jsonb_build_object('username_hint', p_username_hint, 'invoice_code_hint', p_invoice_code_hint,
                             'previous_status', v_cred.status));
  return 'ok';
exception
  -- The active-fingerprint unique index: the same merchant is live elsewhere.
  when unique_violation then return 'duplicate_other_owner';
end $$;

revoke all on function app.operator_credential_slot(uuid, uuid) from public, anon, authenticated;
revoke all on function app.operator_set_credential(uuid, uuid, uuid, text, text, text, text, text) from public, anon, authenticated;
grant execute on function app.operator_credential_slot(uuid, uuid) to service_role;
grant execute on function app.operator_set_credential(uuid, uuid, uuid, text, text, text, text, text) to service_role;

commit;
