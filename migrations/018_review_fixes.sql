-- =====================================================================
-- 018  Fixes from the 2026-11-12 code review.
--
-- Additive and backward compatible: the bridge that is running when this is
-- applied keeps working against it. Apply it BEFORE deploying the bridge
-- commit that uses it.
--
--   1. Phone aliases: Supabase compares phones as exact strings, norm_phone()
--      reads 8 digits as 976 + digits. Phone-based grants now require the
--      stored phone to be canonical already.
--   2. Orders: the operator's own (unregistered-machine) sales get a row too,
--      every order remembers the merchant that issued its invoice, and a
--      refused notify can be retried without waiting out the grace window.
--   3. Credential-verify budget: reserved atomically, so parallel requests
--      cannot all pass it; its own refusals no longer count against it.
--   4. Audit hygiene: no staged blob or invoice code in admin_audit; an
--      invite whose user was deleted no longer blocks that delete.
--   5. Operator: list and remove a business's members.
--   6. Push: subscriptions remember their session and are capped per user.
--   7. Owner problems: capped per kind, with exact per-kind totals.
--   8. Fault import: one statement instead of a row-by-row loop.
--   9. A login-attempt ledger for the portal's auth guard.
--  10. owner_orders: a stable order and the paid time.
-- =====================================================================
begin;

-- ---------------------------------------------------------------------
-- 1. PHONE ALIASES
--
-- A user can set their Supabase phone to the bare 8 digits of a number
-- somebody else owns: no account holds that exact string, so Supabase
-- accepts it. norm_phone() then turns it into 976 + digits, and every check
-- below took it for the real owner of that number — an open invite, or an
-- operator_phones entry. A canonical phone is one norm_phone() leaves alone.
-- ---------------------------------------------------------------------
create or replace function app.phone_is_canonical(p text) returns boolean
language sql immutable set search_path = '' as $$
  select p is not null and p <> '' and p = app.norm_phone(p);
$$;

create or replace function app.is_operator_user(p_user_id uuid)
returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.operators o where o.user_id = p_user_id)
      or exists (
        select 1
          from auth.users u
          join public.operator_phones op on op.phone = app.norm_phone(u.phone)
         where u.id = p_user_id
           and u.phone_confirmed_at is not null
           and app.phone_is_canonical(u.phone)
      );
$$;

/*
 * The send-SMS gate. Supabase hands the hook the phone exactly as it stored
 * it, so a code requested for the bare 8 digits of an operator's or owner's
 * number is refused here before anything is sent — that is the step that
 * would have created the alias account in the first place.
 */
create or replace function app.phone_may_receive_otp(p_phone text)
returns boolean
language sql stable security definer set search_path = '' as $$
  select app.phone_is_canonical(regexp_replace(coalesce(p_phone, ''), '[^0-9]', '', 'g'))
     and (
       exists (
         select 1
           from public.owner_members m
           join auth.users u on u.id = m.user_id
          where app.norm_phone(u.phone) = app.norm_phone(p_phone)
            and app.phone_is_canonical(u.phone)
       ) or exists (
         select 1
           from public.owner_invites i
          where app.norm_phone(i.invited_phone) = app.norm_phone(p_phone)
            and i.accepted_at is null
            and i.revoked_at is null
            and i.expires_at > now()
       ) or exists (
         select 1 from public.operator_phones op where op.phone = app.norm_phone(p_phone)
       )
     );
$$;

/*
 * 012's claim, unchanged except that an alias phone claims nothing.
 */
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
    from auth.users u where u.id = p_user_id and app.phone_is_canonical(u.phone);
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

/*
 * 003's acceptance, unchanged except that an alias phone counts as unconfirmed
 * (and so as a phone mismatch, audited like any other).
 */
create or replace function app.accept_owner_invite(
  p_token     text,
  p_user_id   uuid,
  p_source_ip inet default null
) returns table (out_status text, out_owner_id uuid, out_owner_name text, out_role text)
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_inv    public.owner_invites;
  v_name   text;
  v_phone  text;
  v_ok     timestamptz;
begin
  if p_user_id is null then
    raise exception 'AUTH_REQUIRED' using errcode = '28000';
  end if;
  if p_token is null or length(p_token) < 20 then
    return query select 'invalid'::text, null::uuid, null::text, null::text;
    return;
  end if;

  select * into v_inv
    from public.owner_invites i
   where i.token_hash = sha256(convert_to(p_token, 'utf8'))
   for update;

  if not found then
    return query select 'invalid'::text, null::uuid, null::text, null::text;
    return;
  end if;

  -- Record the presentation BEFORE deciding anything, so a mismatch is durable.
  update public.owner_invites i
     set attempt_count   = i.attempt_count + 1,
         last_attempt_at = now(),
         last_attempt_ip = p_source_ip
   where i.id = v_inv.id;

  if v_inv.revoked_at is not null then
    return query select 'revoked'::text, null::uuid, null::text, null::text;
    return;
  end if;

  if v_inv.accepted_at is not null then
    if v_inv.accepted_by = p_user_id then
      select o.name into v_name from public.owners o where o.id = v_inv.owner_id;
      return query select 'already_accepted'::text, v_inv.owner_id, v_name, v_inv.role;
    else
      return query select 'used'::text, null::uuid, null::text, null::text;
    end if;
    return;
  end if;

  if v_inv.expires_at <= now() then
    return query select 'expired'::text, null::uuid, null::text, null::text;
    return;
  end if;

  select u.phone, u.phone_confirmed_at into v_phone, v_ok
    from auth.users u where u.id = p_user_id;
  -- 018: an alias phone (the bare 8 digits of someone else's number) proves
  -- nothing, and is treated like an unconfirmed one.
  if not app.phone_is_canonical(v_phone) then v_ok := null; end if;

  if v_ok is null
     or app.norm_phone(v_phone) is null
     or app.norm_phone(v_phone) is distinct from app.norm_phone(v_inv.invited_phone) then
    insert into public.credential_audit
      (owner_id, action, actor_user_id, actor_kind, source_ip, detail)
    values
      (v_inv.owner_id, 'invite_mismatch', p_user_id, 'owner', p_source_ip,
       jsonb_build_object('invite_reference', v_inv.reference,
                          'attempt', v_inv.attempt_count + 1));
    return query select 'phone_mismatch'::text, null::uuid, null::text, null::text;
    return;
  end if;

  -- Single use, atomically: the same shape as the settle lease in section 2.
  update public.owner_invites i
     set accepted_at = now(), accepted_by = p_user_id, accepted_ip = p_source_ip
   where i.id = v_inv.id and i.accepted_at is null;
  if not found then
    return query select 'used'::text, null::uuid, null::text, null::text;
    return;
  end if;

  -- ON CONFLICT names the CONSTRAINT, not the columns. An inference list of
  -- bare column names inside a function with same-named OUT parameters raises
  -- "column reference is ambiguous" AT RUNTIME — a failure that appears only
  -- on the happy path, i.e. on the first real owner who signs up. The OUT
  -- parameters here are all out_-prefixed for the same reason; keep it that way.
  insert into public.owner_members (owner_id, user_id, role)
  values (v_inv.owner_id, p_user_id, v_inv.role)
  on conflict on constraint owner_members_pkey do nothing;

  select o.name into v_name from public.owners o where o.id = v_inv.owner_id;

  insert into public.credential_audit
    (owner_id, action, actor_user_id, actor_kind, source_ip, detail)
  values
    (v_inv.owner_id, 'member_joined', p_user_id, 'owner', p_source_ip,
     jsonb_build_object('invite_reference', v_inv.reference, 'role', v_inv.role));

  return query select 'accepted'::text, v_inv.owner_id, v_name, v_inv.role;
end $$;

-- ---------------------------------------------------------------------
-- 2. ORDERS
-- ---------------------------------------------------------------------
/*
 * The operator's own merchant (a machine nobody registered) sold without a
 * row: after a restart its paid orders were unknown, answered 503 to every
 * QPay retry, and only QPay remembered the money. source='env' rows carry no
 * owner, machine or credential — the composite foreign keys are not checked
 * while their columns are null — and the shape check keeps each kind whole.
 */
alter table public.orders
  alter column machine_id drop not null,
  alter column owner_id drop not null,
  alter column qpay_credential_id drop not null;

alter table public.orders add column if not exists source text not null default 'owner';
do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'orders_source_check') then
    alter table public.orders add constraint orders_source_check check (source in ('owner', 'env'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'orders_source_shape') then
    alter table public.orders add constraint orders_source_shape check (
      (source = 'owner' and machine_id is not null and owner_id is not null and qpay_credential_id is not null)
      or (source = 'env' and machine_id is null and owner_id is null and qpay_credential_id is null));
  end if;
end $$;
-- What (machine_id, order_no) is for owner rows. Jetinno's orderNo is unique
-- per machine only.
create unique index if not exists orders_env_device_order_key
  on public.orders (device_no, order_no) where source = 'env';

/*
 * The merchant that issued the invoice, as the credential's fingerprint at
 * the time. A credential can be re-pointed at another merchant in place,
 * under the same id; an order created before that must not be checked or
 * cancelled with the new merchant's login.
 */
alter table public.orders add column if not exists merchant_fp text;

comment on column public.orders.notify_url is
  'From the signed Jetinno request. Jetinno''s own notify endpoint; the bridge refuses private and loopback hosts.';

/*
 * Release after the machine REFUSED the notify (a definite no, not a lost
 * answer). Clears notify_sent_at, which otherwise holds the order for the
 * whole grace window in case a cup is already brewing: a refusal means none
 * is, and the customer is still standing there.
 */
create or replace function app.release_settle_undelivered(p_order_id uuid, p_error text)
returns setof public.orders
language sql volatile security definer set search_path = '' as $$
  update public.orders o
     set status = case when o.payment_confirmed_at is not null
                       then 'payment_confirmed' else 'awaiting_payment' end,
         notify_sent_at     = null,
         settle_lease_until = null,
         settle_lease_owner = null,
         last_error    = coalesce(p_error, o.last_error),
         last_error_at = case when p_error is null then o.last_error_at else now() end,
         updated_at    = now()
   where o.id = p_order_id and o.status = 'settling'
  returning o.*;
$$;

/*
 * The abandoned-QR sweep must never touch a payment that is on record. Such
 * a row is the unnotified drain's: that one waits out the grace window after
 * a notify, and this one did not — after a crash mid-settle it could claim
 * the row, find INVOICE_PAID and tell the machine to brew a second time.
 */
create or replace function app.claim_abandoned_orders(
  p_limit integer default 50,
  p_lease_seconds integer default 60,
  p_instance text default null,
  p_max_attempts integer default 10
) returns setof public.orders
language sql volatile as $$
  update public.orders o
     set status = 'failed',
         last_error = 'NO_INVOICE',
         last_error_at = now(),
         updated_at = now()
   where o.expires_at < now()
     and o.status = 'creating'
     and o.qpay_invoice_id is null;

  with candidate as (
    select o.id from public.orders o
     where o.expires_at < now()
       and o.status in ('creating','awaiting_payment','settling')
       and o.qpay_invoice_id is not null
       and o.payment_confirmed_at is null
       and o.notify_sent_at is null
       and o.settle_attempts < p_max_attempts
       and (o.status <> 'settling' or o.settle_lease_until < now())
     order by o.expires_at
     limit p_limit
     for update skip locked
  )
  update public.orders o
     set status = 'settling',
         settle_lease_until = now() + make_interval(secs => p_lease_seconds),
         settle_lease_owner = p_instance,
         settle_attempts = o.settle_attempts + 1,
         updated_at = now()
    from candidate c
   where o.id = c.id
  returning o.*;
$$;

/*
 * The drain: money in, machine not told. It waited 30 seconds after the
 * payment before looking, a guard against racing the settle that had just
 * confirmed it — but that settle holds the row's lease, which the WHERE
 * already respects. A customer whose machine refused the first notify now
 * waits seconds, not half a minute plus a sweep tick.
 */
create or replace function app.claim_unnotified_orders(
  p_limit integer default 20,
  p_lease_seconds integer default 60,
  p_instance text default null,
  p_notify_grace_seconds integer default 120,
  p_max_attempts integer default 10
) returns setof public.orders
language sql volatile as $$
  with candidate as (
    select o.id from public.orders o
     where o.status in ('payment_confirmed','settling')
       and o.product_done_at is null
       and o.settle_attempts < p_max_attempts
       and o.payment_confirmed_at < now() - interval '5 seconds'
       and (o.notify_sent_at is null
            or o.notify_sent_at < now() - make_interval(secs => p_notify_grace_seconds))
       and (o.status <> 'settling' or o.settle_lease_until < now())
     order by o.payment_confirmed_at
     limit p_limit
     for update skip locked
  )
  update public.orders o
     set status = 'settling',
         settle_lease_until = now() + make_interval(secs => p_lease_seconds),
         settle_lease_owner = p_instance,
         settle_attempts = o.settle_attempts + 1,
         updated_at = now()
    from candidate c
   where o.id = c.id
  returning o.*;
$$;

-- Machine amounts are divided by the bridge's AMOUNT_DIVISOR for every
-- machine; these two columns are recorded per order but never read.
comment on column public.machines.amount_divisor is
  'NOT READ by the bridge: AMOUNT_DIVISOR (env) prices every machine. Kept for the record; the bridge warns at boot when a machine''s value differs.';
comment on column public.machines.abandon_after_ms is
  'NOT READ by the bridge: ABANDON_AFTER_MS (env) applies to every machine.';

-- ---------------------------------------------------------------------
-- 3. CREDENTIAL-VERIFY BUDGET
-- ---------------------------------------------------------------------
alter table public.credential_verify_attempts
  drop constraint if exists credential_verify_attempts_outcome_check;
alter table public.credential_verify_attempts
  add constraint credential_verify_attempts_outcome_check check (outcome in
    ('ok','auth_failed','invoice_code_failed','invoice_failed','nonce_failed','rejected',
     'locked','error','qpay_unreachable','pending'));

/*
 * The budget, reserved rather than read.
 *
 * app.credential_verify_budget only READ the ledger, and the attempt was
 * written after QPay answered — so forty requests sent at once all saw an
 * empty ledger and all reached QPay. This takes a per-owner lock, decides,
 * and writes a 'pending' row in the same transaction; the bridge updates
 * that row's outcome when QPay answers.
 *
 * Its own refusals ('locked' rows, kept for the record) no longer count:
 * they made RATE_LIMITED extend itself on every retry, and reset the
 * failure streak so LOCKED lasted one request.
 */
create or replace function app.reserve_verify_attempt(
  p_owner_id      uuid,
  p_credential_id uuid,
  p_actor_user_id uuid,
  p_username_fp   text,
  p_remote_ip     inet    default null,
  p_user_agent    text    default null,
  p_per_hour      integer default 5,
  p_per_day       integer default 20,
  p_distinct      integer default 2,
  p_lock_fails    integer default 5,
  p_lock_min      integer default 60,
  p_global_fails  integer default 50
) returns table (out_allowed boolean, out_reason text, out_retry_minutes integer, out_attempt_id bigint)
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_hour      integer;
  v_day       integer;
  v_distinct  integer;
  v_streak    integer;
  v_last_fail timestamptz;
  v_reason    text;
  v_retry     integer;
  v_id        bigint;
begin
  perform pg_advisory_xact_lock(hashtextextended('verify-budget:' || p_owner_id::text, 0));

  if (select count(*) from public.credential_verify_attempts a
       where a.outcome = 'auth_failed' and a.at > now() - interval '10 minutes') > p_global_fails then
    v_reason := 'BREAKER'; v_retry := 30;
  else
    select count(*) into v_hour from public.credential_verify_attempts a
     where a.owner_id = p_owner_id and a.at > now() - interval '1 hour'
       and a.outcome not in ('qpay_unreachable', 'locked');
    select count(*) into v_day from public.credential_verify_attempts a
     where a.owner_id = p_owner_id and a.at > now() - interval '24 hours'
       and a.outcome not in ('qpay_unreachable', 'locked');
    select count(distinct a.username_fp) into v_distinct
      from public.credential_verify_attempts a
     where a.owner_id = p_owner_id and a.at > now() - interval '24 hours'
       and a.outcome not in ('qpay_unreachable', 'locked');

    select count(*), max(a.at) into v_streak, v_last_fail
      from public.credential_verify_attempts a
     where a.owner_id = p_owner_id
       and a.outcome = 'auth_failed'
       and a.at > coalesce((select max(b.at) from public.credential_verify_attempts b
                             where b.owner_id = p_owner_id
                               and b.outcome not in ('auth_failed','qpay_unreachable','locked','pending')),
                           'epoch'::timestamptz);

    if v_streak >= p_lock_fails and v_last_fail > now() - make_interval(mins => p_lock_min) then
      v_reason := 'LOCKED';
      v_retry := ceil(extract(epoch from (v_last_fail + make_interval(mins => p_lock_min) - now())) / 60)::integer;
    elsif v_hour >= p_per_hour then
      v_reason := 'RATE_LIMITED'; v_retry := 60;
    elsif v_day >= p_per_day then
      v_reason := 'RATE_LIMITED'; v_retry := 240;
    elsif v_distinct >= p_distinct
          and not exists (select 1 from public.credential_verify_attempts a
                           where a.owner_id = p_owner_id and a.at > now() - interval '24 hours'
                             and a.outcome not in ('qpay_unreachable', 'locked')
                             and a.username_fp = p_username_fp) then
      v_reason := 'TOO_MANY_MERCHANTS'; v_retry := 1440;
    end if;
  end if;

  insert into public.credential_verify_attempts
    (owner_id, credential_id, actor_user_id, username_fp, outcome, remote_ip, user_agent)
  values (p_owner_id, p_credential_id, p_actor_user_id, p_username_fp,
          case when v_reason is null then 'pending' else 'locked' end,
          p_remote_ip, left(coalesce(p_user_agent, ''), 300))
  returning id into v_id;

  if v_reason is null then
    return query select true, null::text, null::integer, v_id;
  else
    return query select false, v_reason, v_retry, null::bigint;
  end if;
end $$;

create or replace function app.finish_verify_attempt(p_attempt_id bigint, p_outcome text)
returns void
language sql volatile security definer set search_path = '' as $$
  update public.credential_verify_attempts a
     set outcome = p_outcome
   where a.id = p_attempt_id and a.outcome = 'pending';
$$;

/*
 * A candidate's failure is the CANDIDATE's. Writing it to last_error_code and
 * auth_fail_count marked the live, earning merchant as failing in both
 * consoles after a single typo during a password change. Those columns now
 * move only for a slot that has no live merchant yet; everything is audited
 * as before.
 */
create or replace function app.record_verify_failure(
  p_credential_id uuid,
  p_actor_user_id uuid,
  p_failure_code  text,
  p_source_ip     inet default null,
  p_user_agent    text default null
) returns boolean
language plpgsql volatile security definer set search_path = '' as $$
declare v_owner uuid;
begin
  select q.owner_id into v_owner from public.qpay_credentials q where q.id = p_credential_id;
  if v_owner is null then return false; end if;

  update public.qpay_credentials q
     set last_error_code = p_failure_code,
         last_error_at   = now(),
         auth_fail_count = case when p_failure_code = 'QPAY_AUTH_FAILED'
                                then q.auth_fail_count + 1 else q.auth_fail_count end,
         updated_at = now()
   where q.id = p_credential_id and q.status = 'pending';

  insert into public.credential_audit
    (owner_id, credential_id, action, actor_user_id, actor_kind, source_ip, user_agent, detail)
  values (v_owner, p_credential_id, 'verify_failed', p_actor_user_id, 'owner',
          p_source_ip, left(coalesce(p_user_agent,''),300),
          jsonb_build_object('failure_code', p_failure_code));
  return true;
end $$;

/*
 * The other half: a live merchant whose password was changed in QPay's own
 * portal failed every sale with 401 and nothing recorded it. The sale path
 * now does, and clears it again on the next invoice that succeeds.
 */
create or replace function app.note_sale_auth_failure(p_credential_id uuid, p_code text)
returns void
language sql volatile security definer set search_path = '' as $$
  update public.qpay_credentials q
     set last_error_code = left(coalesce(p_code, 'QPAY_AUTH_FAILED'), 40),
         last_error_at   = now(),
         auth_fail_count = q.auth_fail_count + 1,
         updated_at      = now()
   where q.id = p_credential_id and q.status = 'active';
$$;

create or replace function app.note_sale_ok(p_credential_id uuid)
returns void
language sql volatile security definer set search_path = '' as $$
  update public.qpay_credentials q
     set auth_fail_count = 0,
         last_error_code = null,
         updated_at      = now()
   where q.id = p_credential_id and q.auth_fail_count > 0;
$$;

-- ---------------------------------------------------------------------
-- 4. AUDIT HYGIENE
-- ---------------------------------------------------------------------
alter table public.credential_audit drop constraint if exists credential_audit_action_check;
-- 010's list, plus two.
alter table public.credential_audit add constraint credential_audit_action_check check (action in (
  'invite_created','invite_revoked','invite_mismatch','member_joined',
  'verify_started','verify_confirmed','verify_aborted','verify_failed',
  'rejected_duplicate','rejected_not_admin',
  'deactivated','reactivated','label_changed','acceptance_confirmed',
  'owner_provisioned','invoice_code_set','operator_configured',
  'member_removed','verify_cancel_failed'));

/*
 * admin_audit stripped only `sealed`. Every credential write also copied the
 * staged blob (pending_sealed), the plaintext pending invoice code, the
 * read-back nonce and the merchant fingerprints into a table that is kept
 * forever — so a blob sealed under a key later rotated for being leaked
 * stayed readable here.
 */
create or replace function app.audit_row() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
  hidden text[] := array['sealed','pending_sealed','pending_invoice_code','verify_nonce',
                         'fingerprint','pending_fingerprint'];
  b jsonb := case when tg_op = 'INSERT' then null else to_jsonb(old) end;
  a jsonb := case when tg_op = 'DELETE' then null else to_jsonb(new) end;
begin
  insert into public.admin_audit (table_name, op, row_id, before, after, sealed_changed)
  values (
    tg_table_name, tg_op,
    coalesce(a ->> 'id', b ->> 'id'),
    b - hidden, a - hidden,
    coalesce(b ->> 'sealed', '') is distinct from coalesce(a ->> 'sealed', '')
      or coalesce(b ->> 'pending_sealed', '') is distinct from coalesce(a ->> 'pending_sealed', '')
  );
  return null;
end $$;

-- The copies already written.
update public.admin_audit
   set before = before - array['sealed','pending_sealed','pending_invoice_code','verify_nonce',
                               'fingerprint','pending_fingerprint'],
       after  = after  - array['sealed','pending_sealed','pending_invoice_code','verify_nonce',
                               'fingerprint','pending_fingerprint']
 where table_name = 'qpay_credentials'
   and (before ?| array['pending_sealed','pending_invoice_code','verify_nonce','fingerprint','pending_fingerprint']
        or after ?| array['pending_sealed','pending_invoice_code','verify_nonce','fingerprint','pending_fingerprint']);

/*
 * accepted_by is ON DELETE SET NULL, and the shape check demanded that it be
 * set whenever accepted_at is — so deleting the login of anyone who joined by
 * invite failed. An accepted invite may outlive the user who accepted it.
 */
alter table public.owner_invites drop constraint if exists owner_invites_accept_shape;
alter table public.owner_invites add constraint owner_invites_accept_shape
  check (accepted_by is null or accepted_at is not null);

-- ---------------------------------------------------------------------
-- 5. MEMBERS, FROM THE OPERATOR'S CONSOLE
--
-- The console could invite but never see or remove anyone. A business that
-- changed hands kept its previous admin, password and all, with full control
-- of its QPay account, until somebody wrote SQL.
-- ---------------------------------------------------------------------
create or replace function app.operator_owner_members(p_actor_user_id uuid, p_owner_id uuid)
returns table (out_user_id uuid, out_role text, out_phone_masked text,
               out_joined_at timestamptz, out_last_sign_in_at timestamptz)
language sql stable security definer set search_path = '' as $$
  select m.user_id, m.role,
         case when app.norm_phone(u.phone) is null then null
              else left(right(app.norm_phone(u.phone), 8), 4) || '••' || right(app.norm_phone(u.phone), 2)
         end,
         m.created_at, u.last_sign_in_at
    from public.owner_members m
    left join auth.users u on u.id = m.user_id
   where app.is_operator_user(p_actor_user_id)
     and m.owner_id = p_owner_id
   order by m.created_at;
$$;

create or replace function app.operator_remove_member(p_actor_user_id uuid, p_owner_id uuid, p_user_id uuid)
returns text
language plpgsql volatile security definer set search_path = '' as $$
declare v_role text;
begin
  if not app.is_operator_user(p_actor_user_id) then return 'forbidden'; end if;

  delete from public.owner_members m
   where m.owner_id = p_owner_id and m.user_id = p_user_id
  returning m.role into v_role;
  if v_role is null then return 'not_found'; end if;

  -- Somebody with no business left has no business seeing its sales on their
  -- lock screen. With another membership, the push queries' join on
  -- owner_members already keeps this business's sales away from them.
  if not exists (select 1 from public.owner_members m where m.user_id = p_user_id) then
    delete from public.push_subscriptions s where s.user_id = p_user_id;
  end if;

  insert into public.credential_audit (owner_id, action, actor_user_id, actor_kind, detail)
  values (p_owner_id, 'member_removed', p_actor_user_id, 'operator',
          jsonb_build_object('user_id', p_user_id, 'role', v_role));
  return 'ok';
end $$;

/*
 * The operator's emergency stop for one business's QPay. The README used to
 * prescribe removing DATABASE_URL instead — which sent EVERY owner's sales
 * to the operator's own merchant. This stops exactly one business: its
 * machines refuse sales until the credential is switched back on.
 */
create or replace function app.operator_set_credential_active(
  p_actor_user_id uuid, p_owner_id uuid, p_active boolean
) returns table (out_status text, out_credential_id uuid, out_affected_machines integer)
language plpgsql volatile security definer set search_path = '' as $$
declare v_cred uuid; v_n integer;
begin
  if not app.is_operator_user(p_actor_user_id) then
    return query select 'forbidden'::text, null::uuid, 0; return;
  end if;
  if not exists (select 1 from public.owners o where o.id = p_owner_id) then
    return query select 'not_found'::text, null::uuid, 0; return;
  end if;

  -- The slot the owner's machines are wired to, as operator_set_invoice_code
  -- finds it.
  select c.id into v_cred
    from public.qpay_credentials c
   where c.owner_id = p_owner_id
     and c.status <> 'pending'
     and exists (select 1 from public.machines m where m.qpay_credential_id = c.id)
   order by c.is_active desc, c.updated_at desc
   limit 1;
  if v_cred is null then
    return query select 'no_credential'::text, null::uuid, 0; return;
  end if;

  update public.qpay_credentials c
     set is_active  = p_active,
         status     = case when p_active then 'active' else 'disabled' end,
         updated_at = now()
   where c.id = v_cred;

  select count(*)::integer into v_n from public.machines m
   where m.qpay_credential_id = v_cred and m.status = 'active';

  insert into public.credential_audit (owner_id, credential_id, action, actor_user_id, actor_kind, detail)
  values (p_owner_id, v_cred, case when p_active then 'reactivated' else 'deactivated' end,
          p_actor_user_id, 'operator', jsonb_build_object('affected_machines', v_n));

  return query select 'ok'::text, v_cred, v_n;
end $$;

-- ---------------------------------------------------------------------
-- 6. PUSH SUBSCRIPTIONS
-- ---------------------------------------------------------------------
/*
 * The Supabase session a subscription was made in. Signing out (or the
 * bridge revoking a stolen session) ends the session; the push queries skip
 * a subscription whose session is gone, so the device stops showing sales.
 */
alter table public.push_subscriptions add column if not exists session_id uuid;

create or replace function app.session_alive(p_session_id uuid) returns boolean
language plpgsql stable security definer set search_path = '' as $$
begin
  if p_session_id is null then return true; end if;
  return exists (select 1 from auth.sessions s where s.id = p_session_id);
exception when insufficient_privilege or undefined_table then
  -- A project where this role cannot read Supabase's sessions: deliver as
  -- before rather than silence every phone.
  return true;
end $$;

/*
 * One row per browser, and at most ten per person. Without the cap one
 * signed-in account could register thousands of endpoints and make every
 * push — and the single bridge instance with it — stall on them.
 */
create or replace function app.save_push_subscription(
  p_user_id      uuid,
  p_endpoint     text,
  p_p256dh       text,
  p_auth         text,
  p_notify_sales boolean,
  p_session_id   uuid default null
) returns table (out_notify_sales boolean)
language plpgsql volatile security definer set search_path = '' as $$
declare v_id bigint;
begin
  insert into public.push_subscriptions as s (user_id, endpoint, p256dh, auth, notify_sales, session_id)
  values (p_user_id, p_endpoint, p_p256dh, p_auth, p_notify_sales, p_session_id)
  on conflict on constraint push_subscriptions_endpoint_key do update
     set user_id = excluded.user_id, p256dh = excluded.p256dh, auth = excluded.auth,
         notify_sales = excluded.notify_sales, session_id = excluded.session_id,
         created_at = now()
  returning s.id into v_id;

  delete from public.push_subscriptions s
   where s.user_id = p_user_id
     and s.id not in (select x.id from public.push_subscriptions x
                       where x.user_id = p_user_id
                       order by greatest(x.created_at, coalesce(x.last_ok_at, x.created_at)) desc, x.id desc
                       limit 10);

  return query select s.notify_sales from public.push_subscriptions s where s.id = v_id;
end $$;

-- ---------------------------------------------------------------------
-- 7. OWNER PROBLEMS
--
-- One `limit 100` over the union of every kind: a day of refused scans took
-- all hundred places, and the owner's home page silently lost its
-- "paid, no cup" money and its stuck payments. The rows are now capped per
-- kind, and the totals come exact from owner_problem_summary.
-- ---------------------------------------------------------------------
create or replace function app.owner_problem_rows(p_owner_id uuid, p_now timestamptz default now())
returns table (kind text, at timestamptz, device_no text, amount_mnt integer, detail text, reference text)
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
  select 'machine_fault', f.occurred_at, f.device_no, null,
         nullif(concat_ws(' · ', nullif(f.code, ''), f.description), ''), f.status_text
    from public.machine_faults f
    join public.machines m on m.device_no = f.device_no and m.owner_id = p_owner_id
   where f.resolved_at is null and f.occurred_at > p_now - interval '7 days';
$$;

create or replace function app.owner_problems(
  p_owner_id uuid,
  p_limit    integer default 500,
  p_now      timestamptz default now()
) returns table (
  kind text, at timestamptz, device_no text, amount_mnt integer, detail text, reference text
)
language sql stable security definer set search_path = '' as $$
  select x.kind, x.at, x.device_no, x.amount_mnt, x.detail, x.reference
    from (select p.*, row_number() over (partition by p.kind order by p.at desc) as rn
            from app.owner_problem_rows(p_owner_id, p_now) p) x
   where x.rn <= 100
   order by x.at desc
   limit least(greatest(coalesce(p_limit, 500), 1), 500);
$$;

create or replace function app.owner_problem_summary(p_owner_id uuid, p_now timestamptz default now())
returns table (kind text, problem_count integer, devices integer, amount_mnt bigint, last_at timestamptz)
language sql stable security definer set search_path = '' as $$
  select p.kind, count(*)::integer, count(distinct p.device_no)::integer,
         coalesce(sum(p.amount_mnt), 0)::bigint, max(p.at)
    from app.owner_problem_rows(p_owner_id, p_now) p
   group by p.kind;
$$;

-- ---------------------------------------------------------------------
-- 8. FAULT IMPORT, IN ONE STATEMENT
--
-- The row-by-row loop over a month's export ran past the pool's statement
-- timeout and rolled the whole import back. The bridge now also gives this
-- call its own, longer timeout.
-- ---------------------------------------------------------------------
create or replace function app.operator_import_faults(
  p_actor_user_id uuid,
  p_file_name     text,
  p_rows          jsonb
) returns table (out_status text, out_import_id uuid, out_read int, out_added int, out_updated int)
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_import uuid := gen_random_uuid();
  v_read   int;
  v_added  int := 0;
  v_upd    int := 0;
begin
  if not app.is_operator_user(p_actor_user_id) then
    return query select 'forbidden'::text, null::uuid, 0, 0, 0;
    return;
  end if;
  if jsonb_typeof(p_rows) <> 'array' or jsonb_array_length(p_rows) > 20000 then
    return query select 'invalid'::text, null::uuid, 0, 0, 0;
    return;
  end if;
  v_read := jsonb_array_length(p_rows);

  insert into public.fault_imports (id, imported_by, file_name) values (v_import, p_actor_user_id, left(p_file_name, 200));

  -- DISTINCT ON: one statement may not update the same fault twice, and an
  -- export can list a fault on two lines. The line that knows a resolution
  -- time wins.
  with src as (
    select distinct on (d.device_no, d.code, d.occurred_at) d.*
      from (select left(e->>'deviceNo', 40) as device_no,
                   left(coalesce(e->>'code', ''), 60) as code,
                   left(e->>'description', 300) as description,
                   (e->>'occurredAt')::timestamptz as occurred_at,
                   nullif(e->>'resolvedAt', '')::timestamptz as resolved_at,
                   left(e->>'status', 60) as status_text
              from jsonb_array_elements(p_rows) e
             where coalesce(e->>'deviceNo', '') <> '' and coalesce(e->>'occurredAt', '') <> '') d
     order by d.device_no, d.code, d.occurred_at, d.resolved_at desc nulls last
  ), up as (
    insert into public.machine_faults as f
      (device_no, code, description, occurred_at, resolved_at, status_text, source, import_id)
    select s.device_no, s.code, s.description, s.occurred_at, s.resolved_at, s.status_text, 'saas_import', v_import
      from src s
    on conflict on constraint machine_faults_identity_key do update
       set resolved_at = coalesce(excluded.resolved_at, f.resolved_at),
           status_text = coalesce(excluded.status_text, f.status_text),
           description = coalesce(excluded.description, f.description)
    returning (xmax = 0) as inserted
  )
  select count(*) filter (where u.inserted)::int, count(*) filter (where not u.inserted)::int
    into v_added, v_upd
    from up u;

  update public.fault_imports set rows_read = v_read, rows_added = v_added, rows_updated = v_upd
   where id = v_import;
  return query select 'ok'::text, v_import, v_read, v_added, v_upd;
end $$;

-- ---------------------------------------------------------------------
-- 9. LOGIN ATTEMPTS (the portal's auth guard)
--
-- The login actions are public, and every request reaches Supabase from
-- Vercel's addresses, so Supabase's per-IP limits cannot tell one caller
-- from another. The portal asks the bridge first, with the real client IP.
-- Per-phone limits are deliberately loose: a strict one is a way for a
-- stranger to lock a known owner out.
-- ---------------------------------------------------------------------
create table if not exists public.auth_attempts (
  id    bigint generated always as identity primary key,
  at    timestamptz not null default now(),
  kind  text not null check (kind in ('otp_request','otp_verify','password','password_change')),
  ip    inet,
  phone text check (phone is null or phone ~ '^[0-9]{8,15}$')
);
create index if not exists auth_attempts_ip_idx on public.auth_attempts (kind, ip, at desc) where ip is not null;
create index if not exists auth_attempts_phone_idx on public.auth_attempts (kind, phone, at desc) where phone is not null;
create index if not exists auth_attempts_at_idx on public.auth_attempts (at);
alter table public.auth_attempts enable row level security;
revoke all on public.auth_attempts from anon, authenticated;

create or replace function app.auth_attempt(p_kind text, p_ip inet, p_phone text)
returns table (out_allowed boolean, out_retry_seconds integer)
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_phone   text := app.norm_phone(p_phone);
  -- {window minutes, max} per IP, a second per-IP day cap, and per phone.
  v_ip_win  integer;  v_ip_max  integer;
  v_day_max integer;
  v_ph_win  integer;  v_ph_max  integer;
  v_oldest  timestamptz;
  v_n       integer;
begin
  case p_kind
    when 'otp_request'     then v_ip_win := 15; v_ip_max := 5;  v_day_max := 20; v_ph_win := null; v_ph_max := null;
    when 'otp_verify'      then v_ip_win := 15; v_ip_max := 20; v_day_max := 100; v_ph_win := 15;  v_ph_max := 10;
    when 'password'        then v_ip_win := 15; v_ip_max := 10; v_day_max := 50; v_ph_win := 60;  v_ph_max := 20;
    when 'password_change' then v_ip_win := 15; v_ip_max := 10; v_day_max := 50; v_ph_win := null; v_ph_max := null;
    else return query select false, 60; return;
  end case;

  if p_ip is not null then
    perform pg_advisory_xact_lock(hashtextextended('auth-ip:' || p_kind || ':' || host(p_ip), 0));
  end if;
  if v_phone is not null and v_ph_win is not null then
    perform pg_advisory_xact_lock(hashtextextended('auth-phone:' || p_kind || ':' || v_phone, 0));
  end if;

  if p_ip is not null then
    select count(*), min(a.at) into v_n, v_oldest from public.auth_attempts a
     where a.kind = p_kind and a.ip = p_ip and a.at > now() - make_interval(mins => v_ip_win);
    if v_n >= v_ip_max then
      return query select false, greatest(1, ceil(extract(epoch from (v_oldest + make_interval(mins => v_ip_win) - now())))::integer);
      return;
    end if;
    select count(*), min(a.at) into v_n, v_oldest from public.auth_attempts a
     where a.kind = p_kind and a.ip = p_ip and a.at > now() - interval '24 hours';
    if v_n >= v_day_max then
      return query select false, greatest(1, ceil(extract(epoch from (v_oldest + interval '24 hours' - now())))::integer);
      return;
    end if;
  end if;

  if v_phone is not null and v_ph_win is not null then
    select count(*), min(a.at) into v_n, v_oldest from public.auth_attempts a
     where a.kind = p_kind and a.phone = v_phone and a.at > now() - make_interval(mins => v_ph_win);
    if v_n >= v_ph_max then
      return query select false, greatest(1, ceil(extract(epoch from (v_oldest + make_interval(mins => v_ph_win) - now())))::integer);
      return;
    end if;
  end if;

  insert into public.auth_attempts (kind, ip, phone) values (p_kind, p_ip, v_phone);
  return query select true, 0;
end $$;

create or replace function app.prune_auth_attempts() returns integer
language sql volatile security definer set search_path = '' as $$
  with gone as (delete from public.auth_attempts a where a.at < now() - interval '2 days' returning 1)
  select count(*)::integer from gone;
$$;

-- ---------------------------------------------------------------------
-- 10. OWNER ORDERS: a stable order, and when each was paid
--
-- created_at alone does not order two rows from the same instant, so pages
-- requested one after another could repeat or skip a row; the export pages
-- through thousands. paid_at is what the on-screen totals count by.
-- Return type changes, so drop and recreate (grants restated below).
-- ---------------------------------------------------------------------
drop function if exists app.owner_orders(uuid, timestamptz, timestamptz, text, text, integer, integer, text, timestamptz);
create function app.owner_orders(
  p_owner_id  uuid,
  p_from      timestamptz,
  p_to        timestamptz,
  p_device_no text default null,
  p_bucket    text default null,
  p_limit     integer default 50,
  p_offset    integer default 0,
  p_tz        text default 'Asia/Ulaanbaatar',
  p_now       timestamptz default now()
) returns table (
  order_no text, created_at timestamptz, local_time text, device_no text,
  product_name text, amount_mnt integer, status text, bucket text,
  cup_dispensed boolean, qpay_payment_id text, paid_at timestamptz, total_count bigint
)
language sql stable security definer set search_path = '' as $$
  with scope as (
    select case when p_device_no is null then null
                else coalesce(app.owner_machine_id(p_owner_id, p_device_no), '00000000-0000-0000-0000-000000000000'::uuid)
           end as machine_id
  ),
  rows as (
    select r.*, app.owner_order_bucket(r.status) as b
      from public.orders r, scope s
     where r.owner_id = p_owner_id
       and r.created_at >= p_from and r.created_at < p_to
       and r.status <> 'creating'
       and (s.machine_id is null or r.machine_id = s.machine_id)
  )
  select r.order_no, r.created_at,
         to_char(r.created_at at time zone p_tz, 'YYYY-MM-DD HH24:MI'),
         r.device_no, r.product_name, r.amount_mnt, r.status, r.b,
         r.product_done_ok, r.qpay_payment_id,
         case when r.status = 'paid' then r.notified_at end,
         count(*) over ()
    from rows r
   where p_bucket is null
      or r.b = p_bucket
      or (p_bucket = 'no_cup' and r.status = 'paid' and r.product_done_ok is distinct from true
          and r.notified_at < p_now - interval '5 minutes')
   order by r.created_at desc, r.id desc
   limit least(greatest(coalesce(p_limit, 50), 1), 500)
  offset greatest(coalesce(p_offset, 0), 0);
$$;

-- ---------------------------------------------------------------------
-- GRANTS — service role only, like everything in app.
-- ---------------------------------------------------------------------
revoke all on function app.phone_is_canonical(text) from public, anon, authenticated;
revoke all on function app.release_settle_undelivered(uuid, text) from public, anon, authenticated;
revoke all on function app.reserve_verify_attempt(uuid, uuid, uuid, text, inet, text, integer, integer, integer, integer, integer, integer) from public, anon, authenticated;
revoke all on function app.finish_verify_attempt(bigint, text) from public, anon, authenticated;
revoke all on function app.note_sale_auth_failure(uuid, text) from public, anon, authenticated;
revoke all on function app.note_sale_ok(uuid) from public, anon, authenticated;
revoke all on function app.operator_owner_members(uuid, uuid) from public, anon, authenticated;
revoke all on function app.operator_remove_member(uuid, uuid, uuid) from public, anon, authenticated;
revoke all on function app.operator_set_credential_active(uuid, uuid, boolean) from public, anon, authenticated;
revoke all on function app.session_alive(uuid) from public, anon, authenticated;
revoke all on function app.save_push_subscription(uuid, text, text, text, boolean, uuid) from public, anon, authenticated;
revoke all on function app.owner_problem_rows(uuid, timestamptz) from public, anon, authenticated;
revoke all on function app.owner_problem_summary(uuid, timestamptz) from public, anon, authenticated;
revoke all on function app.auth_attempt(text, inet, text) from public, anon, authenticated;
revoke all on function app.prune_auth_attempts() from public, anon, authenticated;
revoke all on function app.owner_orders(uuid, timestamptz, timestamptz, text, text, integer, integer, text, timestamptz) from public, anon, authenticated;

grant execute on function app.phone_is_canonical(text) to service_role;
grant execute on function app.release_settle_undelivered(uuid, text) to service_role;
grant execute on function app.reserve_verify_attempt(uuid, uuid, uuid, text, inet, text, integer, integer, integer, integer, integer, integer) to service_role;
grant execute on function app.finish_verify_attempt(bigint, text) to service_role;
grant execute on function app.note_sale_auth_failure(uuid, text) to service_role;
grant execute on function app.note_sale_ok(uuid) to service_role;
grant execute on function app.operator_owner_members(uuid, uuid) to service_role;
grant execute on function app.operator_remove_member(uuid, uuid, uuid) to service_role;
grant execute on function app.operator_set_credential_active(uuid, uuid, boolean) to service_role;
grant execute on function app.session_alive(uuid) to service_role;
grant execute on function app.save_push_subscription(uuid, text, text, text, boolean, uuid) to service_role;
grant execute on function app.owner_problem_rows(uuid, timestamptz) to service_role;
grant execute on function app.owner_problem_summary(uuid, timestamptz) to service_role;
grant execute on function app.auth_attempt(text, inet, text) to service_role;
grant execute on function app.prune_auth_attempts() to service_role;
grant execute on function app.owner_orders(uuid, timestamptz, timestamptz, text, text, integer, integer, text, timestamptz) to service_role;

commit;
