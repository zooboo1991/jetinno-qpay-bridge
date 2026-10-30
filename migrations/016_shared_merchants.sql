-- =====================================================================
-- 016  One QPay merchant for many machines and many businesses.
--
-- Until now a QPay merchant could be live for ONE business only (the
-- active-fingerprint unique index from 001, and the duplicate checks in 003
-- and 010). The operator now sells to businesses that share a merchant — a
-- company with several legal entities, or machines whose takings all go to
-- one account — so:
--
--   * the same merchant may be active for any number of businesses. Each
--     business keeps its own sealed copy (the AEAD binds a blob to its row and
--     owner), its own machines and its own dashboard; only the account the
--     money lands in is shared. The audit row of every configuration records
--     how many other businesses already sell through that merchant;
--   * within ONE business a merchant is still active once: a second slot on
--     the same account buys nothing and is what the index still refuses;
--   * the operator can add a machine to a business that already exists
--     (app.operator_add_machine). It sells through that business's QPay, the
--     same slot its other machines use.
--
-- The three credential functions are re-created from 003 and 010 with only
-- the duplicate rule changed; signatures and grants are unchanged.
-- =====================================================================
begin;

drop index if exists public.qpay_credentials_active_fingerprint_key;
create unique index if not exists qpay_credentials_owner_active_fingerprint_key
  on public.qpay_credentials (owner_id, fingerprint) where is_active;

create or replace function app.begin_credential_verification(
  p_credential_id     uuid,
  p_actor_user_id     uuid,
  p_sealed            text,
  p_key_id            text,
  p_fingerprint       text,
  p_username_hint     text,
  p_invoice_code_hint text,
  p_verify_nonce      text,
  p_verify_invoice_id text,
  p_ttl_minutes       integer default 20,
  p_source_ip         inet    default null,
  p_source_xff        text    default null,
  p_user_agent        text    default null
) returns table (out_status text, out_owner_id uuid)
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_owner   uuid;
  v_admin   boolean;
  v_clash   uuid;
  v_shared  integer;
begin
  if p_sealed is null or p_sealed !~ '^v1\.' then
    raise exception 'BAD_SEALED' using errcode = '22023';
  end if;
  if p_fingerprint is null or p_fingerprint !~ '^[0-9a-f]{64}$' then
    raise exception 'BAD_FINGERPRINT' using errcode = '22023';
  end if;
  if p_verify_nonce is null or p_verify_nonce !~ '^[0-9]{4}$' then
    raise exception 'BAD_NONCE' using errcode = '22023';
  end if;

  select c.owner_id, c.owner_id = any (app.admin_owner_ids_of(p_actor_user_id))
    into v_owner, v_admin
    from public.qpay_credentials c where c.id = p_credential_id
     for update;

  if not found then
    return query select 'not_found'::text, null::uuid; return;
  end if;
  if not v_admin then
    insert into public.credential_audit
      (owner_id, credential_id, action, actor_user_id, actor_kind, source_ip, source_xff, user_agent, detail)
    values (v_owner, p_credential_id, 'rejected_not_admin', p_actor_user_id, 'owner',
            p_source_ip, left(coalesce(p_source_xff,''),300), left(coalesce(p_user_agent,''),300), '{}'::jsonb);
    return query select 'not_admin'::text, null::uuid; return;
  end if;

  -- The same merchant already live on another slot of THIS business, checked
  -- early so the owner is never told "success" and then "duplicate". The
  -- partial unique index (owner_id, fingerprint) catches the race at confirm.
  select c.owner_id into v_clash
    from public.qpay_credentials c
   where c.fingerprint = p_fingerprint and c.is_active and c.id <> p_credential_id
     and c.owner_id = v_owner
   limit 1;
  if v_clash is not null then
    insert into public.credential_audit
      (owner_id, credential_id, action, actor_user_id, actor_kind, source_ip, source_xff, user_agent, detail)
    values (v_owner, p_credential_id, 'rejected_duplicate', p_actor_user_id, 'owner',
            p_source_ip, left(coalesce(p_source_xff,''),300), left(coalesce(p_user_agent,''),300),
            jsonb_build_object('same_owner', true));
    return query select 'duplicate_same_owner'::text, v_owner;
    return;
  end if;

  -- Other businesses on this merchant are allowed (016). Counted for the
  -- audit row, so a shared account can always be traced afterwards.
  select count(distinct c.owner_id)::integer into v_shared
    from public.qpay_credentials c
   where c.fingerprint = p_fingerprint and c.is_active and c.owner_id <> v_owner;

  update public.qpay_credentials c
     set pending_sealed            = p_sealed,
         pending_key_id            = p_key_id,
         pending_fingerprint       = p_fingerprint,
         pending_username_hint     = p_username_hint,
         pending_invoice_code_hint = p_invoice_code_hint,
         verify_nonce              = p_verify_nonce,
         verify_invoice_id         = p_verify_invoice_id,
         verify_started_at         = now(),
         verify_expires_at         = now() + make_interval(mins => greatest(p_ttl_minutes, 5)),
         verify_attempts           = 0,
         updated_at                = now()
   where c.id = p_credential_id;

  insert into public.credential_audit
    (owner_id, credential_id, action, actor_user_id, actor_kind,
     source_ip, source_xff, user_agent, key_id, detail)
  values
    (v_owner, p_credential_id, 'verify_started', p_actor_user_id, 'owner',
     p_source_ip, left(coalesce(p_source_xff,''),300), left(coalesce(p_user_agent,''),300),
     p_key_id, jsonb_build_object('invoice_code_hint', p_invoice_code_hint,
                                  'shared_with_owners', v_shared));

  return query select 'ok'::text, v_owner;
end $$;

create or replace function app.confirm_credential_verification(
  p_credential_id uuid,
  p_actor_user_id uuid,
  p_nonce         text,
  p_source_ip     inet default null,
  p_source_xff    text default null,
  p_user_agent    text default null
) returns table (out_status text, out_owner_id uuid, out_attempts_left integer,
                 out_invoice_id text, out_username_hint text, out_invoice_code_hint text)
language plpgsql volatile security definer set search_path = '' as $$
declare
  c        public.qpay_credentials;
  v_admin  boolean;
  v_conf   text;
begin
  select * into c from public.qpay_credentials q where q.id = p_credential_id for update;
  if not found then
    return query select 'not_found'::text, null::uuid, null::integer, null::text, null::text, null::text; return;
  end if;

  v_admin := c.owner_id = any (app.admin_owner_ids_of(p_actor_user_id));
  if not v_admin then
    return query select 'not_admin'::text, null::uuid, null::integer, null::text, null::text, null::text; return;
  end if;

  if c.pending_sealed is null or c.verify_expires_at is null then
    return query select 'no_pending'::text, c.owner_id, null::integer, null::text, null::text, null::text; return;
  end if;
  if c.verify_expires_at <= now() then
    return query select 'expired'::text, c.owner_id, null::integer, c.verify_invoice_id, null::text, null::text; return;
  end if;

  -- Five guesses at a 4-digit code, then the staged candidate is discarded and
  -- the owner starts over. The nonce is not a password; it is evidence that
  -- the owner can see the invoice. Brute-forcing it means the credentials were
  -- for an account the caller cannot read, which is exactly the thing being
  -- caught.
  if c.verify_nonce is distinct from p_nonce then
    update public.qpay_credentials q
       set verify_attempts = q.verify_attempts + 1, updated_at = now()
     where q.id = p_credential_id;
    if c.verify_attempts + 1 >= 5 then
      update public.qpay_credentials q
         set pending_sealed = null, pending_key_id = null, pending_fingerprint = null,
             pending_username_hint = null, pending_invoice_code_hint = null,
             verify_nonce = null, verify_expires_at = null, updated_at = now()
       where q.id = p_credential_id;
      insert into public.credential_audit
        (owner_id, credential_id, action, actor_user_id, actor_kind, source_ip, detail)
      values (c.owner_id, p_credential_id, 'verify_aborted', p_actor_user_id, 'owner', p_source_ip,
              jsonb_build_object('reason', 'nonce_attempts_exhausted'));
      return query select 'nonce_exhausted'::text, c.owner_id, 0, c.verify_invoice_id, null::text, null::text;
    else
      return query select 'nonce_wrong'::text, c.owner_id, 5 - (c.verify_attempts + 1),
                          null::text, null::text, null::text;
    end if;
    return;
  end if;

  -- Promote the candidate. The credential id is unchanged, so the AAD is
  -- unchanged and machines.qpay_credential_id still points where it pointed
  -- before. No machine is ever re-pointed by this function; it cannot write
  -- to `machines` at all.
  begin
    update public.qpay_credentials q
       set sealed            = q.pending_sealed,
           key_id            = q.pending_key_id,
           fingerprint       = q.pending_fingerprint,
           username_hint     = q.pending_username_hint,
           invoice_code_hint = q.pending_invoice_code_hint,
           status            = 'active',
           is_active         = true,
           source            = 'self_service',
           last_verified_at  = now(),
           last_error        = null,
           last_error_at     = null,
           last_error_code   = null,
           auth_fail_count   = 0,
           configured_by     = p_actor_user_id,
           configured_at     = now(),
           pending_sealed = null, pending_key_id = null, pending_fingerprint = null,
           pending_username_hint = null, pending_invoice_code_hint = null,
           pending_invoice_code = null,      -- consumed: it is inside `sealed` now
           verify_nonce = null, verify_invoice_id = null,
           verify_expires_at = null, verify_attempts = 0,
           updated_at = now()
     where q.id = p_credential_id
    returning q.* into c;
  exception when unique_violation then
    -- Since 016 the fingerprint index is per business: a clash here is this
    -- business's own other slot, never another business.
    get stacked diagnostics v_conf = constraint_name;
    return query select case when v_conf = 'qpay_credentials_owner_label_key'
                             then 'duplicate_label' else 'duplicate_same_owner' end,
                        c.owner_id, null::integer, c.verify_invoice_id, null::text, null::text;
    return;
  end;

  insert into public.credential_audit
    (owner_id, credential_id, action, actor_user_id, actor_kind,
     source_ip, source_xff, user_agent, key_id, detail)
  values
    (c.owner_id, p_credential_id, 'verify_confirmed', p_actor_user_id, 'owner',
     p_source_ip, left(coalesce(p_source_xff,''),300), left(coalesce(p_user_agent,''),300),
     c.key_id, jsonb_build_object('invoice_code_hint', c.invoice_code_hint,
                                  'username_hint', c.username_hint));

  return query select 'ok'::text, c.owner_id, null::integer, null::text,
                      c.username_hint, c.invoice_code_hint;
end $$;

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
declare v_cred public.qpay_credentials; v_shared integer;
begin
  if not app.is_operator_user(p_actor_user_id) then return 'forbidden'; end if;

  select c.* into v_cred from public.qpay_credentials c
   where c.id = p_credential_id and c.owner_id = p_owner_id
   for update;
  if not found then return 'not_found'; end if;
  if v_cred.verify_expires_at is not null and v_cred.verify_expires_at > now() then
    return 'verification_open';
  end if;

  -- Other businesses on this merchant are allowed (016); the operator is
  -- routing this business's takings there on purpose. Counted for the audit.
  select count(distinct c.owner_id)::integer into v_shared
    from public.qpay_credentials c
   where c.owner_id <> p_owner_id and c.fingerprint = p_fingerprint and c.is_active;

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
                             'previous_status', v_cred.status, 'shared_with_owners', v_shared));
  return 'ok';
exception
  -- The per-business fingerprint index: this merchant is already live on
  -- another slot of the same business.
  when unique_violation then return 'duplicate_same_owner';
end $$;

/*
 * A further machine for a business that already exists.
 *
 * It sells through the slot the business's other machines are wired to — the
 * same choice operator_credential_slot makes — so "one QPay for many
 * machines" is the default, and the business's own QPay change later moves
 * every machine at once. A business with no machine yet takes its newest slot.
 * notify_url stays NULL until the machine's first signed getQrCode, as in
 * operator_provision_owner. The machines_audit trigger records the insert.
 */
create or replace function app.operator_add_machine(
  p_actor_user_id uuid,
  p_owner_id      uuid,
  p_device_no     text,
  p_location      text
) returns table (out_status text, out_machine_id uuid)
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_device  text := btrim(coalesce(p_device_no, ''));
  v_cred    uuid;
  v_machine uuid := gen_random_uuid();
begin
  if not app.is_operator_user(p_actor_user_id) then
    return query select 'forbidden'::text, null::uuid;
    return;
  end if;
  if v_device !~ '^[A-Za-z0-9_-]{3,40}$' then
    return query select 'invalid_device'::text, null::uuid;
    return;
  end if;
  if not exists (select 1 from public.owners o where o.id = p_owner_id) then
    return query select 'not_found'::text, null::uuid;
    return;
  end if;
  if exists (select 1 from public.machines m where m.device_no = v_device) then
    return query select 'device_taken'::text, null::uuid;
    return;
  end if;

  select c.id into v_cred
    from public.qpay_credentials c
   where c.owner_id = p_owner_id
   order by exists (select 1 from public.machines m where m.qpay_credential_id = c.id) desc,
            c.is_active desc, c.updated_at desc
   limit 1;
  if v_cred is null then
    return query select 'no_credential'::text, null::uuid;
    return;
  end if;

  insert into public.machines
    (id, owner_id, qpay_credential_id, device_no, label, location, notify_url, status, installed_at)
  values
    (v_machine, p_owner_id, v_cred, v_device, null, nullif(btrim(coalesce(p_location, '')), ''),
     null, 'active', now());

  return query select 'ok'::text, v_machine;
exception
  -- Two operators adding the same machine at once: the unique constraint
  -- decides, and the loser is told plainly.
  when unique_violation then
    return query select 'device_taken'::text, null::uuid;
end $$;

revoke all on function app.operator_add_machine(uuid, uuid, text, text) from public, anon, authenticated;
grant execute on function app.operator_add_machine(uuid, uuid, text, text) to service_role;

commit;
