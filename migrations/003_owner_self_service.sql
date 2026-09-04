-- =====================================================================
-- jetinno-qpay-bridge — migration 003_owner_self_service.sql
--
-- SUPABASE ONLY (needs auth.users, anon, authenticated, service_role).
-- Apply AFTER 002_supabase_rls.sql, in the same sitting.
--
-- Additive. It creates new objects, adds nullable columns, relaxes three
-- NOT NULLs on qpay_credentials, and tightens grants that 001/002 left wider
-- than they intended. It drops nothing and changes no existing policy, so it
-- is inert until the owner UI exists.
--
-- WHY THIS EXISTS. Decision #33 of docs/multi-tenant-plan.md says "an offline
-- CLI only; no HTTP endpoint accepts a plaintext QPay password", with the
-- stated condition "until there is a real session system". Invite-gated
-- Supabase Auth against a CONFIRMED phone, a bridge that verifies the JWT
-- itself, admin-role membership checked in SQL, a Postgres-backed attempt
-- ledger, and a per-write audit row is that system. #33 is discharged, not
-- contradicted. Do not read this file as an unexplained reversal.
--
-- THE THREE INVARIANTS THIS FILE EXISTS TO PROTECT:
--
--  1. No role except the table owner has ANY privilege on
--     public.qpay_credentials. Owners read credential METADATA through
--     public.my_qpay_credentials, which does not contain the ciphertext.
--
--  2. `authenticated` can only SELECT. There is no owner-callable function
--     that writes anything. Every write — invite acceptance included — goes
--     through the bridge, which holds the service role and CRED_KEYS.
--     `anon` can call exactly one function, app.peek_invite(), which returns
--     a business name.
--
--  3. Authorisation for a credential write is enforced HERE, in SQL, not only
--     in the bridge. app.begin_credential_verification() and
--     app.confirm_credential_verification() both require p_actor_user_id to
--     hold an 'admin' membership on the credential's OWN owner_id. A bug in
--     the bridge cannot bypass it.
--
-- A NOTE ON THE TWO-PHASE WRITE. A credential is verified in two steps
-- (begin -> the owner reads a 4-digit nonce out of their own QPay portal ->
-- confirm). The candidate blob is staged in pending_* columns on the SAME
-- row, so a machine that is ALREADY earning keeps earning throughout. The
-- credential id never changes, so the AEAD AAD stays valid and no machine is
-- ever re-pointed.
-- =====================================================================

begin;


-- =====================================================================
-- 1. IDENTITY HELPERS
-- =====================================================================
create table public.operators (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  label      text not null,
  created_at timestamptz not null default now()
);
comment on table public.operators is
  'Humans who run the business. Written ONLY with the service role / SQL editor. '
  'A table and not a JWT claim on purpose: a custom claim needs an auth hook and '
  'does not take effect until the access token refreshes, so revoking operator '
  'access would lag by up to an hour. A DELETE here is effective on the next statement.';

alter table public.operators enable row level security;
revoke all on public.operators from anon, authenticated;

create or replace function app.is_operator() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.operators o where o.user_id = (select auth.uid()));
$$;

/*
 * Owner ids where a GIVEN user is an admin.
 *
 * Takes the user id as an argument rather than reading auth.uid(), because
 * every caller in this file is the bridge running as service_role on behalf
 * of a user whose JWT the bridge already verified against Supabase's JWKS.
 * There is no auth.uid() in that session.
 */
create or replace function app.admin_owner_ids_of(p_user_id uuid) returns uuid[]
language sql stable security definer set search_path = '' as $$
  select coalesce(array_agg(m.owner_id), '{}'::uuid[])
    from public.owner_members m
   where m.user_id = p_user_id
     and m.role = 'admin';
$$;

-- Mongolian mobile numbers are 8 digits; Supabase stores E.164 without '+'.
-- Normalise both sides so 9911-2233 / 99112233 / +976 9911 2233 compare equal.
create or replace function app.norm_phone(p text) returns text
language sql immutable as $$
  select case
    when p is null then null
    when regexp_replace(p, '[^0-9]', '', 'g') = '' then null
    when length(regexp_replace(p, '[^0-9]', '', 'g')) = 8
      then '976' || regexp_replace(p, '[^0-9]', '', 'g')
    else regexp_replace(p, '[^0-9]', '', 'g')
  end;
$$;


-- =====================================================================
-- 2. AUDIT — written by the same statement that writes the credential,
--    so it cannot be forgotten. Append-only. Operator-readable only.
-- =====================================================================
create table public.credential_audit (
  id            bigint generated always as identity primary key,
  at            timestamptz not null default now(),

  -- Deliberately NO foreign keys. An audit row must outlive the row it
  -- describes; an FK would either cascade the evidence away or block the
  -- delete it is meant to record. owner_id may therefore dangle. Do not
  -- "fix" this.
  owner_id      uuid,
  credential_id uuid,

  action        text not null check (action in (
                  'invite_created','invite_revoked','invite_mismatch','member_joined',
                  'verify_started','verify_confirmed','verify_aborted','verify_failed',
                  'rejected_duplicate','rejected_not_admin',
                  'deactivated','reactivated','label_changed','acceptance_confirmed')),

  actor_user_id uuid,                       -- auth.users.id; null for CLI actions
  actor_kind    text not null check (actor_kind in ('owner','operator','system')),

  -- source_ip is what the BRIDGE observed via Express (`app.set('trust proxy', 1)`),
  -- passed in as an argument by a service_role caller only. source_xff keeps
  -- the raw X-Forwarded-For header verbatim: a full header a human can read
  -- beats a wrong inet a query will trust. Never derived from a client
  -- argument on any path an owner can reach.
  source_ip     inet,
  source_xff    text,
  user_agent    text,

  key_id        text,
  detail        jsonb not null default '{}'::jsonb,

  -- Cheap structural guard against the one future mistake that would make
  -- this table worse than useless: a well-meaning "let's log what they
  -- submitted".
  constraint credential_audit_no_secrets check (
    not (detail ?| array['password','username','invoice_code','invoiceCode',
                         'sealed','token','plaintext','pending_sealed'])
  ),
  constraint credential_audit_ua_len  check (user_agent is null or length(user_agent) <= 300),
  constraint credential_audit_xff_len check (source_xff is null or length(source_xff) <= 300)
);
comment on table public.credential_audit is
  'Every credential verification, activation and membership grant, with actor, '
  'time and source IP. Append-only by trigger. Readable by operators through '
  'public.operator_credential_audit only. Honest limit: nothing in Postgres '
  'constrains the operator (plan section 8 item 3) — a superuser can disable '
  'the trigger. This detects mistakes and a compromised owner session, not a '
  'hostile operator. Do not describe it to owners as tamper-proof.';

create index credential_audit_at_idx     on public.credential_audit (at desc);
create index credential_audit_owner_idx  on public.credential_audit (owner_id, at desc);
create index credential_audit_cred_idx   on public.credential_audit (credential_id, at desc);
create index credential_audit_action_idx on public.credential_audit (action, at desc);

create or replace function app.deny_mutation() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  raise exception 'append-only object: % on %.% is not permitted',
    tg_op, tg_table_schema, tg_table_name using errcode = '0A000';
end $$;

create trigger credential_audit_append_only
  before update or delete or truncate on public.credential_audit
  for each statement execute function app.deny_mutation();

alter table public.credential_audit enable row level security;
-- Supabase's default privileges grant ALL on new public tables to the API
-- roles at CREATE time. Every new table in this file must revoke explicitly;
-- RLS alone would leave INSERT open to any policy added later by accident.
revoke all on public.credential_audit from anon, authenticated;
revoke update, delete, truncate on public.credential_audit from service_role;


-- =====================================================================
-- 3. INVITES — the only way a Supabase user becomes an owner member
-- =====================================================================
create table public.owner_invites (
  id             uuid primary key default gen_random_uuid(),
  owner_id       uuid not null references public.owners(id) on delete cascade,

  -- DEFAULT 'viewer', NOT 'admin'. Granting the power to redirect an owner's
  -- entire revenue stream must be a thing the operator explicitly types, not
  -- a thing he gets by leaving a flag off. One mistyped digit in the phone
  -- number plus an admin default is a stranger who can repoint the money and
  -- whose identity passes every other check in this file, because their
  -- identity genuinely IS the one the invite names.
  role           text not null default 'viewer' check (role in ('admin','viewer')),

  -- The RAW token exists only in the QR the operator hands over. It is
  -- generated in Node (32 random bytes, base64url) and never travels into
  -- Postgres on the create path — the CLI passes the digest.
  token_hash     bytea not null,
  -- A short non-secret handle so the operator can say "urilga OQ4K-7M2P" on
  -- the phone without ever reading the token back.
  reference      text not null,

  -- The invite names an identity. Holding the link is not enough: accepting
  -- also requires a CONFIRMED phone on auth.users that matches. And
  -- app.create_owner_invite() refuses a phone that does not already match
  -- owners.contact_phone, so the number has to be right in two places
  -- entered at two different times.
  invited_phone  text not null,

  created_by     uuid references auth.users(id) on delete set null,
  created_at     timestamptz not null default now(),
  expires_at     timestamptz not null default now() + interval '7 days',

  accepted_at    timestamptz,
  accepted_by    uuid references auth.users(id) on delete set null,
  accepted_ip    inet,

  revoked_at     timestamptz,
  revoked_reason text,

  attempt_count   integer not null default 0,
  last_attempt_at timestamptz,
  last_attempt_ip inet,

  constraint owner_invites_token_hash_key unique (token_hash),
  constraint owner_invites_reference_key  unique (reference),
  constraint owner_invites_hash_shape   check (octet_length(token_hash) = 32),
  constraint owner_invites_ref_shape    check (reference ~ '^[A-Z0-9]{4}-[A-Z0-9]{4}$'),
  constraint owner_invites_phone_shape  check (invited_phone ~ '^[0-9]{8,15}$'),
  constraint owner_invites_ttl_chk      check (expires_at > created_at and expires_at <= created_at + interval '30 days'),
  constraint owner_invites_accept_shape check ((accepted_at is null) = (accepted_by is null))
);
comment on column public.owner_invites.token_hash is
  'sha256 of the raw token. Built-in sha256(), not pgcrypto digest(): pgcrypto '
  'lands in schema `extensions` on Supabase and `public` on plain Postgres, so '
  'digest() under search_path='''' would resolve differently in the e2e than in '
  'production.';
comment on column public.owner_invites.attempt_count is
  'Incremented on every presentation of a VALID token, including a phone '
  'mismatch. attempt_count > 1 with no acceptance means someone holds the link '
  'but not the SIM — i.e. the message was intercepted or forwarded. Alert on it.';

create index owner_invites_owner_idx on public.owner_invites (owner_id, created_at desc);
create index owner_invites_open_idx  on public.owner_invites (expires_at)
  where accepted_at is null and revoked_at is null;

alter table public.owner_invites enable row level security;
revoke all on public.owner_invites from anon, authenticated;


-- =====================================================================
-- 4. qpay_credentials — the pending-row model
--
-- The operator creates the credential row EMPTY at install time and wires
-- machines.qpay_credential_id to it immediately. That is what makes the whole
-- flow possible: machines.qpay_credential_id is NOT NULL in 001 and stays
-- that way, so a machine could otherwise not be registered until after the
-- owner had finished the form — which would mean a second visit, or an
-- unregistered machine meeting a real customer.
--
-- Keeping machines untouched also keeps decision #12's property fully
-- enforced at all times: the composite FK machines_credential_owner_fk is
-- never relaxed, so a machine can only ever be wired to a credential
-- belonging to its own owner. Misrouted money stays unrepresentable.
-- =====================================================================
alter table public.qpay_credentials
  alter column sealed      drop not null,
  alter column key_id      drop not null,
  alter column fingerprint drop not null;

alter table public.qpay_credentials
  add column status text not null default 'active',

  -- The candidate credential, staged during verification. Ciphertext, sealed
  -- under the SAME AAD as `sealed` (credential id + owner id are unchanged),
  -- so staging it here is exactly as safe as the final state. Staged rather
  -- than written in place so that a machine which is already earning keeps
  -- earning while its owner rotates a password.
  add column pending_sealed            text,
  add column pending_key_id            text,
  add column pending_fingerprint       text,
  add column pending_username_hint     text,
  add column pending_invoice_code_hint text,

  -- The wrong-merchant-account detector. The bridge creates a 10₮ invoice on
  -- the candidate merchant with this 4-digit nonce in its description; the
  -- owner reads the nonce out of THEIR OWN QPay portal and types it back.
  -- Credentials that authenticate but belong to somebody else's merchant
  -- account fail here, in seconds, with the operator standing there — instead
  -- of at month end when the owner asks where their money went.
  add column verify_nonce      text,
  add column verify_invoice_id text,
  add column verify_started_at timestamptz,
  add column verify_expires_at timestamptz,
  add column verify_attempts   integer not null default 0,

  -- Set by the operator CLI at invite time, consumed and NULLed the moment
  -- the owner's credentials are sealed. Deviates from decision #15 ("invoice
  -- code inside the sealed blob") for a bounded window only, and buys the
  -- single largest reduction in form-abandonment available: the phone form
  -- drops from three fields to two, and the one field the owner cannot
  -- possibly recall from memory never appears on a phone at all.
  add column pending_invoice_code text,

  add column username_hint   text,   -- the MASKED display string, never the raw username
  add column configured_by   uuid,   -- auth.users id of the last successful writer
  add column configured_at   timestamptz,
  add column last_error_code text,
  add column source          text not null default 'cli',

  -- Stamped when a real 100₮ sale has been seen in the OWNER's own QPay
  -- portal. The acceptance test stops being a checklist item a rushed
  -- operator can skip and becomes a column that /health can count.
  add column acceptance_confirmed_at timestamptz,
  add column acceptance_order_id     uuid;

alter table public.qpay_credentials
  add constraint qpay_credentials_status_shape check (status in ('pending','active','disabled')),

  -- The state machine, in one place. 'pending' is an operator-created empty
  -- slot; anything else must carry a complete sealed blob.
  add constraint qpay_credentials_sealed_state_chk check (
    (status =  'pending' and sealed is null     and key_id is null     and fingerprint is null) or
    (status <> 'pending' and sealed is not null and key_id is not null and fingerprint is not null)),

  -- is_active is what src/owners.js reads and what the partial unique index
  -- keys on. Deriving it from status by CHECK rather than by convention means
  -- the two can never drift.
  add constraint qpay_credentials_active_status_chk check (is_active = (status = 'active')),

  -- A staged candidate is all-or-nothing.
  add constraint qpay_credentials_pending_shape check (
    (pending_sealed is null and pending_key_id is null and pending_fingerprint is null
     and verify_nonce is null and verify_expires_at is null) or
    (pending_sealed is not null and pending_key_id is not null and pending_fingerprint is not null
     and verify_nonce is not null and verify_expires_at is not null)),

  add constraint qpay_credentials_pending_sealed_shape check (pending_sealed is null or pending_sealed like 'v1.%'),
  add constraint qpay_credentials_pending_fp_shape     check (pending_fingerprint is null or pending_fingerprint ~ '^[0-9a-f]{64}$'),
  add constraint qpay_credentials_nonce_shape          check (verify_nonce is null or verify_nonce ~ '^[0-9]{4}$'),
  add constraint qpay_credentials_last_error_code_shape check (last_error_code is null or last_error_code ~ '^[A-Z_]{3,40}$'),
  add constraint qpay_credentials_source_shape         check (source in ('cli','self_service'));

comment on column public.qpay_credentials.status is
  'pending = operator created the slot and wired the machine, owner has not '
  'configured it yet; src/owners.js MUST treat it as unusable and return '
  'MERCHANT_NOT_READY — never DEVICE_NOT_REGISTERED, which means a seeding '
  'mistake and would hide the fact that a person wanted coffee and could not buy it.';
comment on column public.qpay_credentials.last_error_code is
  'A stable code the bridge sets (QPAY_AUTH_FAILED, QPAY_INVOICE_CODE_REJECTED, ...). '
  'The owner UI shows THIS; it must never show last_error, which carries the '
  'upstream body and echoes the merchant username (decision #28).';
comment on column public.qpay_credentials.pending_invoice_code is
  'Plaintext, deliberately, for the onboarding window only. Not a credential on '
  'its own: it cannot create an invoice without the username and password, and '
  'decision #14 made the fingerprint a KEYED HMAC precisely so publishing an '
  'invoice code costs nothing in brute-force resistance. NULLed at seal time.';

create index qpay_credentials_verify_idx on public.qpay_credentials (verify_expires_at)
  where verify_expires_at is not null;
create index qpay_credentials_pending_idx on public.qpay_credentials (status) where status = 'pending';


-- =====================================================================
-- 5. THE ATTEMPT LEDGER
--    In Postgres, not in process memory: Render restarts every instance on
--    deploy and runs two during one, so an in-memory limiter would reset the
--    attacker's counter on the operator's own schedule and be wrong across
--    instances in between.
-- =====================================================================
create table public.credential_verify_attempts (
  id            bigint generated always as identity primary key,
  at            timestamptz not null default now(),
  owner_id      uuid not null references public.owners(id) on delete cascade,
  credential_id uuid,
  actor_user_id uuid,

  -- Keyed HMAC of lower(trim(username)), namespaced. Counts DISTINCT
  -- usernames per owner per day — the control that actually targets credential
  -- stuffing, which needs breadth rather than depth — without ever storing a
  -- username.
  username_fp   text not null check (username_fp ~ '^[0-9a-f]{64}$'),

  outcome       text not null check (outcome in
    ('ok','auth_failed','invoice_code_failed','nonce_failed','rejected','locked','error','qpay_unreachable')),
  remote_ip     inet,
  user_agent    text
);
comment on table public.credential_verify_attempts is
  'Rate-limit ledger for POST /owner/v1/credentials/verify. Budgeted on '
  'owner_id, NEVER on IP: Mongolian mobile IPs are CGNAT-shared between honest '
  'owners and trivially rotated by an attacker, so an IP limiter punishes the '
  'wrong people and stops the wrong ones. outcome=''qpay_unreachable'' is '
  'recorded but never counted — a QPay outage must not lock out every honest '
  'owner simultaneously.';

create index cva_owner_at_idx on public.credential_verify_attempts (owner_id, at desc);
create index cva_at_idx       on public.credential_verify_attempts (at desc);

alter table public.credential_verify_attempts enable row level security;
revoke all on public.credential_verify_attempts from anon, authenticated;


-- =====================================================================
-- 6. WHAT THE OWNER MAY READ
--    qpay_credentials keeps ZERO privileges for anon/authenticated (002).
--    This view is the entire read surface and the ciphertext is not in it.
--    Columns are enumerated, never `select *`: a definer view over `*` starts
--    leaking on the next ALTER TABLE ... ADD COLUMN.
-- =====================================================================
create view public.my_qpay_credentials with (security_barrier = true) as
  select c.id,
         c.owner_id,
         c.label,
         c.status,
         c.is_active,
         c.username_hint,
         c.invoice_code_hint,
         c.source,
         c.last_verified_at,
         c.last_error_code,
         c.auth_fail_count,
         c.configured_at,
         c.acceptance_confirmed_at,
         (c.verify_expires_at is not null and c.verify_expires_at > now()) as verification_open,
         c.created_at,
         c.updated_at
    from public.qpay_credentials c
   where c.owner_id = any (app.my_owner_ids());
comment on view public.my_qpay_credentials is
  'Security-DEFINER by design (the caller has no privilege on the base table), '
  'so the owner filter in the WHERE clause IS the access check. security_barrier '
  'stops the planner pushing a user-supplied leaky function below that filter. '
  'sealed / key_id / fingerprint / pending_* / verify_nonce / pending_invoice_code '
  'are all absent, so no plan, no error message and no timing difference can '
  'surface them.';

create view public.operator_credential_audit with (security_barrier = true) as
  select a.id, a.at, a.owner_id, o.name as owner_name, a.credential_id,
         a.action, a.actor_user_id, a.actor_kind,
         a.source_ip, a.source_xff, a.user_agent, a.key_id, a.detail
    from public.credential_audit a
    left join public.owners o on o.id = a.owner_id
   where app.is_operator();
comment on view public.operator_credential_audit is
  'Lets the operator read the audit from a browser holding only the anon key '
  'plus their own JWT. The service-role key must never reach a browser.';

create view public.operator_owner_invites with (security_barrier = true) as
  select i.id, i.owner_id, o.name as owner_name, i.role, i.reference,
         i.invited_phone, i.created_at, i.expires_at,
         i.accepted_at, i.accepted_by, i.accepted_ip,
         i.revoked_at, i.revoked_reason,
         i.attempt_count, i.last_attempt_at, i.last_attempt_ip
    from public.owner_invites i
    join public.owners o on o.id = i.owner_id
   where app.is_operator();
comment on view public.operator_owner_invites is 'token_hash is deliberately absent.';

/*
 * VIEWS ARE TABLES AS FAR AS DEFAULT PRIVILEGES ARE CONCERNED.
 *
 * Supabase's `alter default privileges in schema public grant all on tables`
 * fires on CREATE VIEW too, so all three views above were just handed
 * INSERT/UPDATE/DELETE to anon AND authenticated. That is not cosmetic:
 * my_qpay_credentials is a single-table view, therefore AUTO-UPDATABLE, and a
 * view runs with its OWNER's privileges. Without the revoke below, any
 * authenticated user could
 *     update public.my_qpay_credentials set owner_id = '<someone else>'
 * and re-parent a credential row straight through the wall — the exact
 * "mapping tampering" of plan section 8 item 4, reachable with an anon key.
 *
 * Two independent fixes, because this one is too expensive to get wrong:
 *   1. revoke, then grant back only SELECT;
 *   2. an INSTEAD OF trigger, which ALSO removes auto-updatability entirely,
 *      so a future blanket `grant all on all tables in schema public` cannot
 *      reopen it.
 */
revoke all on public.my_qpay_credentials       from anon, authenticated;
revoke all on public.operator_credential_audit from anon, authenticated;
revoke all on public.operator_owner_invites    from anon, authenticated;
-- 002 created public.owner_orders and never revoked; same latent grant.
revoke all on public.owner_orders              from anon, authenticated;

grant select on public.my_qpay_credentials       to authenticated;
grant select on public.operator_credential_audit to authenticated;
grant select on public.operator_owner_invites    to authenticated;
grant select on public.owner_orders              to authenticated;

create trigger my_qpay_credentials_read_only
  instead of insert or update or delete on public.my_qpay_credentials
  for each row execute function app.deny_mutation();
create trigger operator_credential_audit_read_only
  instead of insert or update or delete on public.operator_credential_audit
  for each row execute function app.deny_mutation();
create trigger operator_owner_invites_read_only
  instead of insert or update or delete on public.operator_owner_invites
  for each row execute function app.deny_mutation();


-- =====================================================================
-- 7. INVITE FLOW
-- =====================================================================
/*
 * Pre-login peek — the ONLY function `anon` may call.
 *
 * The landing page shows "Та <Компани> дээр урилга авсан байна" before asking
 * anyone to sign in, so a tired shop manager can tell a real invite from a
 * phish without typing anything. Returns the business name and nothing else:
 * no ids, no contact, no role.
 */
create or replace function app.peek_invite(p_token text)
returns table (out_status text, out_owner_name text, out_expires_at timestamptz)
language plpgsql stable security definer set search_path = '' as $$
declare v record;
begin
  if p_token is null or length(p_token) < 20 then
    return query select 'invalid'::text, null::text, null::timestamptz;
    return;
  end if;

  select i.expires_at as exp, i.accepted_at as acc, i.revoked_at as rev, o.name as nm
    into v
    from public.owner_invites i
    join public.owners o on o.id = i.owner_id
   where i.token_hash = sha256(convert_to(p_token, 'utf8'));

  if not found then
    return query select 'invalid'::text, null::text, null::timestamptz;
  elsif v.rev is not null then
    return query select 'revoked'::text, v.nm, v.exp;
  elsif v.acc is not null then
    return query select 'used'::text, v.nm, v.exp;
  elsif v.exp <= now() then
    return query select 'expired'::text, v.nm, v.exp;
  else
    return query select 'valid'::text, v.nm, v.exp;
  end if;
end $$;

/*
 * Invite redemption. SERVICE ROLE ONLY — the bridge calls it after verifying
 * the user's Supabase access token against Supabase's JWKS itself.
 *
 * It is not granted to `authenticated` even though it could be, for two
 * reasons: the bridge must record the redemption in owner_step_up (that OTP
 * is what makes the credential screen openable without a second SMS), and
 * routing it through the bridge means the audit row carries an IP that Express
 * observed rather than one derived from a header inside Postgres.
 *
 * Forgery is closed by construction, not by a policy:
 *   - owner_id is READ OFF THE INVITE. It is not an argument, so there is no
 *     owner_id for a caller to substitute.
 *   - the invite is found by sha256(token); a stranger has no token.
 *   - and holding the token is still not enough: auth.users must show a
 *     CONFIRMED phone matching what the invite names. An intercepted or
 *     forwarded SMS therefore fails, and it fails LOUDLY — attempt_count is
 *     incremented and an 'invite_mismatch' audit row is written.
 *
 * Reads auth.users directly rather than any JWT claim: raw_user_meta_data is
 * writable by the user via supabase.auth.updateUser(), so anything shaped from
 * user_metadata is self-asserted and worthless as identity. This is the single
 * easiest way to build a Supabase auth check that looks right and is not.
 *
 * Returns a status instead of raising for every business outcome. Raising
 * would roll back the attempt_count increment that makes interception
 * visible — and a stable code maps to a Mongolian message far better than a
 * Postgres error ever will.
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

/*
 * Operator side. Takes the DIGEST, never the token: the raw token is generated
 * in the CLI and goes straight onto the screen the owner scans. Nothing that
 * touches Postgres can mint a working invite link from what Postgres stores.
 *
 * THE PHONE CROSS-CHECK IS THE POINT OF THIS FUNCTION. p_invited_phone must
 * already equal owners.contact_phone, which was entered during the sales
 * paperwork at a different time on a different screen. One mistyped digit at
 * the end of a tiring installation would otherwise put a live invite on a
 * stranger's phone, and — because their identity genuinely is the identity the
 * invite names — every other control in this file would wave them through.
 * Changing owners.contact_phone is a separate, deliberate operator action.
 */
create or replace function app.create_owner_invite(
  p_owner_id      uuid,
  p_token_hash    bytea,
  p_reference     text,
  p_invited_phone text,
  p_role          text default 'viewer',
  p_ttl_days      integer default 7,
  p_created_by    uuid default null
) returns table (out_invite_id uuid, out_reference text, out_expires_at timestamptz)
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_contact text;
  v_id      uuid;
  v_exp     timestamptz;
begin
  if p_ttl_days is null or p_ttl_days < 1 or p_ttl_days > 30 then
    raise exception 'BAD_TTL' using errcode = '22023';
  end if;
  if p_role not in ('admin','viewer') then
    raise exception 'BAD_ROLE' using errcode = '22023';
  end if;

  select o.contact_phone into v_contact from public.owners o where o.id = p_owner_id;
  if not found then
    raise exception 'OWNER_NOT_FOUND' using errcode = '22023';
  end if;
  if app.norm_phone(v_contact) is null then
    raise exception 'OWNER_HAS_NO_CONTACT_PHONE' using errcode = '22023';
  end if;
  if app.norm_phone(p_invited_phone) is distinct from app.norm_phone(v_contact) then
    raise exception 'PHONE_DOES_NOT_MATCH_OWNER_CONTACT' using errcode = '22023';
  end if;

  insert into public.owner_invites as i
    (owner_id, token_hash, reference, invited_phone, role, created_by, expires_at)
  values
    (p_owner_id, p_token_hash, upper(p_reference), app.norm_phone(p_invited_phone),
     p_role, p_created_by, now() + make_interval(days => p_ttl_days))
  returning i.id, i.expires_at into v_id, v_exp;

  insert into public.credential_audit (owner_id, action, actor_kind, actor_user_id, detail)
  values (p_owner_id, 'invite_created', 'operator', p_created_by,
          jsonb_build_object('reference', upper(p_reference), 'role', p_role,
                             'ttl_days', p_ttl_days));

  return query select v_id, upper(p_reference), v_exp;
end $$;

create or replace function app.revoke_owner_invite(p_invite_id uuid, p_reason text)
returns boolean
language plpgsql volatile security definer set search_path = '' as $$
declare v_owner uuid;
begin
  update public.owner_invites i
     set revoked_at = now(), revoked_reason = p_reason
   where i.id = p_invite_id and i.revoked_at is null and i.accepted_at is null
  returning i.owner_id into v_owner;
  if v_owner is null then return false; end if;

  insert into public.credential_audit (owner_id, action, actor_kind, detail)
  values (v_owner, 'invite_revoked', 'operator',
          jsonb_build_object('invite_id', p_invite_id, 'reason', p_reason));
  return true;
end $$;


-- =====================================================================
-- 8. THE CREDENTIAL WRITE PATH — service role only, two phases
-- =====================================================================
/*
 * The budget. One statement, evaluated in Postgres.
 *
 * Note what is NOT budgeted: opening the form. Only attempts that actually
 * reached QPay are counted, so an owner who opens the page five times while
 * hunting for their password is not locked out of connecting their own
 * payment account.
 */
create or replace function app.credential_verify_budget(
  p_owner_id    uuid,
  p_username_fp text,
  p_per_hour    integer default 5,
  p_per_day     integer default 20,
  p_distinct    integer default 2,
  p_lock_fails  integer default 5,
  p_lock_min    integer default 60
) returns table (out_allowed boolean, out_reason text, out_retry_minutes integer)
language plpgsql stable security definer set search_path = '' as $$
declare
  v_hour      integer;
  v_day       integer;
  v_distinct  integer;
  v_streak    integer;
  v_last_fail timestamptz;
begin
  select count(*) into v_hour from public.credential_verify_attempts a
   where a.owner_id = p_owner_id and a.at > now() - interval '1 hour'
     and a.outcome <> 'qpay_unreachable';
  select count(*) into v_day from public.credential_verify_attempts a
   where a.owner_id = p_owner_id and a.at > now() - interval '24 hours'
     and a.outcome <> 'qpay_unreachable';
  select count(distinct a.username_fp) into v_distinct
    from public.credential_verify_attempts a
   where a.owner_id = p_owner_id and a.at > now() - interval '24 hours'
     and a.outcome <> 'qpay_unreachable';

  -- Consecutive auth failures since the last non-auth-failure outcome.
  select count(*), max(a.at) into v_streak, v_last_fail
    from public.credential_verify_attempts a
   where a.owner_id = p_owner_id
     and a.outcome = 'auth_failed'
     and a.at > coalesce((select max(b.at) from public.credential_verify_attempts b
                           where b.owner_id = p_owner_id
                             and b.outcome not in ('auth_failed','qpay_unreachable')),
                         'epoch'::timestamptz);

  if v_streak >= p_lock_fails and v_last_fail > now() - make_interval(mins => p_lock_min) then
    -- Not permanent. A permanent lockout is itself a denial of service on an
    -- owner who fat-fingered, and its recovery path is a phone call to the
    -- operator — the model this whole feature exists to replace.
    return query select false, 'LOCKED'::text,
      ceil(extract(epoch from (v_last_fail + make_interval(mins => p_lock_min) - now())) / 60)::integer;
    return;
  end if;

  if v_hour >= p_per_hour then
    return query select false, 'RATE_LIMITED'::text, 60; return;
  end if;
  if v_day >= p_per_day then
    return query select false, 'RATE_LIMITED'::text, 240; return;
  end if;
  -- The anti-stuffing control. Stuffing needs breadth, not depth: an attacker
  -- with one owner session wants to test other people's usernames, not five
  -- more passwords for the one they already hold. An owner has one or two QPay
  -- merchants, ever.
  if v_distinct >= p_distinct
     and not exists (select 1 from public.credential_verify_attempts a
                      where a.owner_id = p_owner_id and a.at > now() - interval '24 hours'
                        and a.username_fp = p_username_fp) then
    return query select false, 'TOO_MANY_MERCHANTS'::text, 1440; return;
  end if;

  return query select true, null::text, null::integer;
end $$;

create or replace function app.record_verify_attempt(
  p_owner_id      uuid,
  p_credential_id uuid,
  p_actor_user_id uuid,
  p_username_fp   text,
  p_outcome       text,
  p_remote_ip     inet default null,
  p_user_agent    text default null
) returns void
language sql volatile security definer set search_path = '' as $$
  insert into public.credential_verify_attempts
    (owner_id, credential_id, actor_user_id, username_fp, outcome, remote_ip, user_agent)
  values (p_owner_id, p_credential_id, p_actor_user_id, p_username_fp, p_outcome,
          p_remote_ip, left(coalesce(p_user_agent, ''), 300));
$$;

/* Either a coordinated attack, or QPay changed its error semantics. Both want
 * a human before the next attempt. */
create or replace function app.global_auth_fails(p_minutes integer default 10)
returns integer
language sql stable security definer set search_path = '' as $$
  select count(*)::integer from public.credential_verify_attempts a
   where a.outcome = 'auth_failed' and a.at > now() - make_interval(mins => p_minutes);
$$;

/*
 * Who may write this credential, and what row is it?
 *
 * Resolves the credential FIRST, then checks that the actor holds an 'admin'
 * membership on THAT credential's owner. Never the other way round: a user can
 * be a member of several owners (one person, two businesses; a shop that
 * changed hands), so deriving "the" owner from the user and then looking up
 * the credential silently picks whichever membership sorted first and 404s
 * every credential belonging to the other business.
 */
create or replace function app.credential_slot(p_credential_id uuid, p_actor_user_id uuid)
returns table (out_credential_id uuid, out_owner_id uuid, out_label text, out_status text,
               out_pending_invoice_code text, out_is_admin boolean)
language sql stable security definer set search_path = '' as $$
  select c.id, c.owner_id, c.label, c.status, c.pending_invoice_code,
         c.owner_id = any (app.admin_owner_ids_of(p_actor_user_id))
    from public.qpay_credentials c
   where c.id = p_credential_id;
$$;

/*
 * PHASE 1 of the write. Called by the BRIDGE with the service role, after it
 * has: verified the caller's Supabase access token against Supabase's JWKS,
 * checked step-up freshness, read the budget, proved username+password against
 * QPay's token endpoint, created a 10₮ invoice carrying p_verify_nonce in its
 * description on the CANDIDATE merchant, and sealed the plaintext with
 * src/crypto.js.
 *
 * Everything it writes lands in pending_* on the EXISTING row. A live
 * credential keeps working: an owner rotating their QPay password does not
 * take their own machine down while they are halfway through the form.
 *
 * The admin check is HERE, in SQL, and not only in the bridge. The bridge
 * checks too, but a check that exists in exactly one place is a check that a
 * later refactor deletes.
 */
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

  -- Duplicate merchant, checked EARLY so the owner is never told "success"
  -- and then "duplicate". The partial unique index catches the race at
  -- confirm time; this catches the ordinary case with a message they can act
  -- on. Distinguishing same-owner from cross-owner matters: an owner who runs
  -- two shops off one QPay merchant account is a normal growth path, not a
  -- security event, and paging the operator for it trains him to ignore the
  -- alert that fires when someone enters credentials that are not theirs.
  select c.owner_id into v_clash
    from public.qpay_credentials c
   where c.fingerprint = p_fingerprint and c.is_active and c.id <> p_credential_id
   limit 1;
  if v_clash is not null then
    insert into public.credential_audit
      (owner_id, credential_id, action, actor_user_id, actor_kind, source_ip, source_xff, user_agent, detail)
    values (v_owner, p_credential_id, 'rejected_duplicate', p_actor_user_id, 'owner',
            p_source_ip, left(coalesce(p_source_xff,''),300), left(coalesce(p_user_agent,''),300),
            jsonb_build_object('same_owner', v_clash = v_owner));
    if v_clash = v_owner then
      return query select 'duplicate_same_owner'::text, v_owner;
    else
      return query select 'duplicate_other_owner'::text, v_owner;
    end if;
    return;
  end if;

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
     p_key_id, jsonb_build_object('invoice_code_hint', p_invoice_code_hint));

  return query select 'ok'::text, v_owner;
end $$;

/*
 * PHASE 2 — the wrong-merchant-account detector.
 *
 * The owner has opened their OWN QPay merchant portal and typed back the
 * 4-digit nonce they can see on the 10₮ invoice the bridge just created.
 * Credentials that authenticate perfectly but belong to somebody else's
 * merchant account — the owner's other business, a partner's account, an
 * account QPay issued to a different legal entity during the paperwork —
 * cannot pass this step, and they fail it visibly in seconds, with the
 * operator standing there.
 *
 * Everything before this proved "these credentials work". Only this proves
 * "these credentials are yours".
 */
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
    get stacked diagnostics v_conf = constraint_name;
    return query select case when v_conf = 'qpay_credentials_owner_label_key'
                             then 'duplicate_label' else 'duplicate_other_owner' end,
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

/* The owner said "I cannot see that invoice", the verification expired, or the
 * bridge's sweeper is cleaning up. Discards the candidate; the live credential
 * (if any) is untouched. Returns the invoice id so the caller can cancel it. */
create or replace function app.abort_credential_verification(
  p_credential_id uuid,
  p_actor_user_id uuid,
  p_reason        text
) returns table (out_status text, out_owner_id uuid, out_invoice_id text)
language plpgsql volatile security definer set search_path = '' as $$
declare v_owner uuid; v_inv text;
begin
  update public.qpay_credentials q
     set pending_sealed = null, pending_key_id = null, pending_fingerprint = null,
         pending_username_hint = null, pending_invoice_code_hint = null,
         verify_nonce = null, verify_expires_at = null, verify_attempts = 0,
         verify_invoice_id = null, updated_at = now()
   where q.id = p_credential_id and q.pending_sealed is not null
  returning q.owner_id, q.verify_invoice_id into v_owner, v_inv;

  if v_owner is null then
    return query select 'no_pending'::text, null::uuid, null::text; return;
  end if;

  insert into public.credential_audit
    (owner_id, credential_id, action, actor_user_id, actor_kind, detail)
  values (v_owner, p_credential_id, 'verify_aborted', p_actor_user_id,
          case when p_actor_user_id is null then 'system' else 'owner' end,
          jsonb_build_object('reason', p_reason));

  return query select 'ok'::text, v_owner, v_inv;
end $$;

/* Verification reached QPay and QPay said no. Recorded because repeated
 * failures on one owner's credential is what a stolen owner session looks
 * like. */
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
  update public.qpay_credentials q
     set last_error_code = p_failure_code,
         last_error_at   = now(),
         auth_fail_count = case when p_failure_code = 'QPAY_AUTH_FAILED'
                                then q.auth_fail_count + 1 else q.auth_fail_count end,
         updated_at = now()
   where q.id = p_credential_id
  returning q.owner_id into v_owner;
  if v_owner is null then return false; end if;

  insert into public.credential_audit
    (owner_id, credential_id, action, actor_user_id, actor_kind, source_ip, user_agent, detail)
  values (v_owner, p_credential_id, 'verify_failed', p_actor_user_id, 'owner',
          p_source_ip, left(coalesce(p_user_agent,''),300),
          jsonb_build_object('failure_code', p_failure_code));
  return true;
end $$;

/* The acceptance sale landed in the OWNER's own portal. Turns plan Phase 6
 * step 20 from a checklist item a rushed operator can skip into a column
 * /health can count. */
create or replace function app.confirm_acceptance_sale(
  p_credential_id uuid,
  p_order_id      uuid,
  p_actor_user_id uuid default null
) returns boolean
language plpgsql volatile security definer set search_path = '' as $$
declare v_owner uuid;
begin
  update public.qpay_credentials q
     set acceptance_confirmed_at = coalesce(q.acceptance_confirmed_at, now()),
         acceptance_order_id     = coalesce(q.acceptance_order_id, p_order_id),
         updated_at = now()
   where q.id = p_credential_id and q.status = 'active'
  returning q.owner_id into v_owner;
  if v_owner is null then return false; end if;

  insert into public.credential_audit (owner_id, credential_id, action, actor_user_id, actor_kind, detail)
  values (v_owner, p_credential_id, 'acceptance_confirmed', p_actor_user_id, 'operator',
          jsonb_build_object('order_id', p_order_id));
  return true;
end $$;

/* Metadata edits. Service role only, like everything else that writes: the
 * `authenticated` role holds no EXECUTE anywhere in `app` beyond what 002
 * granted for its own views. */
create or replace function app.set_credential_label(
  p_credential_id uuid, p_actor_user_id uuid, p_label text
) returns boolean
language plpgsql volatile security definer set search_path = '' as $$
declare v_owner uuid; v_conf text;
begin
  if p_label is null or btrim(p_label) = '' or length(btrim(p_label)) > 60 then
    raise exception 'BAD_LABEL' using errcode = '22023';
  end if;
  begin
    update public.qpay_credentials c
       set label = btrim(p_label), updated_at = now()
     where c.id = p_credential_id
       and c.owner_id = any (app.admin_owner_ids_of(p_actor_user_id))
    returning c.owner_id into v_owner;
  exception when unique_violation then
    -- Never let a raw unique_violation out of a definer function: PostgREST
    -- returns the DETAIL field, which reads "Key (fingerprint)=(<64 hex>)
    -- already exists" and hands an authenticated owner a value this file
    -- claims is unreachable. The catalogue-based regression gate in section 12
    -- structurally cannot see that channel; only wrapping every write can.
    get stacked diagnostics v_conf = constraint_name;
    raise exception 'DUPLICATE_LABEL' using errcode = '23505';
  end;
  if v_owner is null then return false; end if;

  insert into public.credential_audit (owner_id, credential_id, action, actor_user_id, actor_kind, detail)
  values (v_owner, p_credential_id, 'label_changed', p_actor_user_id, 'owner',
          jsonb_build_object('label', btrim(p_label)));
  return true;
end $$;

/*
 * The owner's emergency stop: "my QPay password leaked, stop using it."
 *
 * Returns the number of machines this will stop, so the UI can say
 * "Энэ үйлдэл 2 машины борлуулалтыг зогсооно" and make them confirm — an
 * unexplained silent outage is how self-service loses the operator's trust
 * and sends owners back to phoning him.
 */
create or replace function app.set_credential_active(
  p_credential_id uuid, p_actor_user_id uuid, p_active boolean
) returns table (out_ok boolean, out_affected_machines integer)
language plpgsql volatile security definer set search_path = '' as $$
declare v_owner uuid; v_n integer; v_conf text;
begin
  begin
    update public.qpay_credentials c
       set is_active = p_active,
           status    = case when p_active then 'active' else 'disabled' end,
           updated_at = now()
     where c.id = p_credential_id
       and c.status <> 'pending'          -- an empty slot cannot be activated
       and c.owner_id = any (app.admin_owner_ids_of(p_actor_user_id))
    returning c.owner_id into v_owner;
  exception when unique_violation then
    get stacked diagnostics v_conf = constraint_name;
    raise exception 'DUPLICATE_MERCHANT' using errcode = '23505';
  end;
  if v_owner is null then
    return query select false, 0; return;
  end if;

  select count(*)::integer into v_n from public.machines m
   where m.qpay_credential_id = p_credential_id and m.status = 'active';

  insert into public.credential_audit (owner_id, credential_id, action, actor_user_id, actor_kind, detail)
  values (v_owner, p_credential_id,
          case when p_active then 'reactivated' else 'deactivated' end,
          p_actor_user_id, 'owner', jsonb_build_object('affected_machines', v_n));

  return query select true, v_n;
end $$;


-- =====================================================================
-- 9. STEP-UP LEDGER
--    The bridge's own record of when a session last proved possession of the
--    SIM. Kept here rather than read out of a JWT claim because claim shapes
--    for authentication time vary by Supabase version, and a step-up check
--    that silently always passes is worse than no step-up at all.
-- =====================================================================
create table public.owner_step_up (
  user_id     uuid primary key references auth.users(id) on delete cascade,
  last_otp_at timestamptz not null,
  source      text not null check (source in ('invite_redeem','step_up')),
  updated_at  timestamptz not null default now()
);
comment on table public.owner_step_up is
  'Written by the bridge at invite redemption and at each explicit step-up. '
  'FIRST credential entry needs no second SMS: the redemption OTP is minutes '
  'old and the operator is standing there. Later credential CHANGES — which '
  'happen alone, months later, and are the stolen-session threat — require a '
  'fresh OTP within CRED_STEP_UP_SECONDS.';
alter table public.owner_step_up enable row level security;
revoke all on public.owner_step_up from anon, authenticated;

create or replace function app.touch_step_up(p_user_id uuid, p_source text)
returns void
language sql volatile security definer set search_path = '' as $$
  insert into public.owner_step_up (user_id, last_otp_at, source)
  values (p_user_id, now(), p_source)
  on conflict on constraint owner_step_up_pkey do update
    set last_otp_at = now(), source = excluded.source, updated_at = now();
$$;

create or replace function app.step_up_age_seconds(p_user_id uuid)
returns integer
language sql stable security definer set search_path = '' as $$
  select coalesce(
    (select extract(epoch from (now() - s.last_otp_at))::integer
       from public.owner_step_up s where s.user_id = p_user_id),
    2147483647);
$$;


-- =====================================================================
-- 10. OPERATOR DASHBOARD
-- =====================================================================
create view public.operator_onboarding_status with (security_barrier = true) as
  select m.id            as machine_id,
         m.device_no,
         m.label         as machine_label,
         m.location,
         o.id            as owner_id,
         o.name          as owner_name,
         o.contact_phone,
         c.id            as credential_id,
         c.status        as credential_status,
         c.source        as credential_source,
         c.last_verified_at,
         c.last_error_code,
         c.auth_fail_count,
         c.acceptance_confirmed_at,
         (select max(i.expires_at) from public.owner_invites i
           where i.owner_id = o.id and i.accepted_at is null and i.revoked_at is null)
                         as invite_expires_at,
         exists (select 1 from public.owner_members mm where mm.owner_id = o.id)
                         as has_member,
         (select count(*) from public.orders r
           where r.machine_id = m.id and r.status = 'paid')::integer as paid_orders,
         case
           when c.status = 'pending' and not exists
                (select 1 from public.owner_members mm where mm.owner_id = o.id) then 'invited'
           when c.status = 'pending' then 'account_created'
           when c.acceptance_confirmed_at is null then 'credentials_verified'
           else 'earning'
         end             as stage
    from public.machines m
    join public.owners o on o.id = m.owner_id
    join public.qpay_credentials c on c.id = m.qpay_credential_id
   where app.is_operator();
comment on view public.operator_onboarding_status is
  'Derived, never stored: a status column would drift. The operator''s one-screen '
  'answer to "which machines are not finished". Stages: invited -> account_created '
  '-> credentials_verified -> earning.';

revoke all  on public.operator_onboarding_status from anon, authenticated;
grant select on public.operator_onboarding_status to authenticated;
create trigger operator_onboarding_status_read_only
  instead of insert or update or delete on public.operator_onboarding_status
  for each row execute function app.deny_mutation();


-- =====================================================================
-- 11. PRIVILEGES
--     Functions default to EXECUTE for PUBLIC, so every REVOKE below is
--     load-bearing, not decorative. A new function added without one is
--     callable by anon the moment it exists.
-- =====================================================================
-- 001 created app.touch_updated_at() and never revoked it, so it is EXECUTE-able
-- by anon to this day. Harmless in itself (a trigger function called directly
-- raises), but it makes regression gate (d) below return a row forever, and a
-- gate nobody can read clean is a gate nobody runs. Found by running the gate,
-- not by reading the file.
revoke all on function app.touch_updated_at()                     from public;

revoke all on function app.is_operator()                          from public;
revoke all on function app.admin_owner_ids_of(uuid)               from public;
revoke all on function app.norm_phone(text)                       from public;
revoke all on function app.deny_mutation()                        from public;
revoke all on function app.peek_invite(text)                      from public;
revoke all on function app.accept_owner_invite(text,uuid,inet)    from public;
revoke all on function app.create_owner_invite(uuid,bytea,text,text,text,integer,uuid) from public;
revoke all on function app.revoke_owner_invite(uuid,text)         from public;
revoke all on function app.credential_verify_budget(uuid,text,integer,integer,integer,integer,integer) from public;
revoke all on function app.record_verify_attempt(uuid,uuid,uuid,text,text,inet,text) from public;
revoke all on function app.global_auth_fails(integer)             from public;
revoke all on function app.credential_slot(uuid,uuid)             from public;
revoke all on function app.begin_credential_verification(uuid,uuid,text,text,text,text,text,text,text,integer,inet,text,text) from public;
revoke all on function app.confirm_credential_verification(uuid,uuid,text,inet,text,text) from public;
revoke all on function app.abort_credential_verification(uuid,uuid,text) from public;
revoke all on function app.record_verify_failure(uuid,uuid,text,inet,text) from public;
revoke all on function app.confirm_acceptance_sale(uuid,uuid,uuid) from public;
revoke all on function app.set_credential_label(uuid,uuid,text)   from public;
revoke all on function app.set_credential_active(uuid,uuid,boolean) from public;
revoke all on function app.touch_step_up(uuid,text)               from public;
revoke all on function app.step_up_age_seconds(uuid)              from public;

-- 002 granted `usage on schema app` to authenticated only, so an anon caller
-- would hit "permission denied for schema app" before the function grant was
-- even consulted, and the pre-login invite page would silently not work. Both
-- the schema USAGE and the function EXECUTE are required.
grant usage on schema app to anon, service_role;

-- anon: exactly one function, and it returns a business name.
grant execute on function app.peek_invite(text) to anon, authenticated;

-- authenticated: is_operator() so the operator's own browser can gate its UI.
-- NOTHING ELSE. The authenticated role cannot write anything, anywhere.
grant execute on function app.is_operator() to authenticated;

-- service_role: the bridge and the operator CLI. Never in a browser.
grant execute on function app.accept_owner_invite(text,uuid,inet)                     to service_role;
grant execute on function app.create_owner_invite(uuid,bytea,text,text,text,integer,uuid) to service_role;
grant execute on function app.revoke_owner_invite(uuid,text)                          to service_role;
grant execute on function app.credential_verify_budget(uuid,text,integer,integer,integer,integer,integer) to service_role;
grant execute on function app.record_verify_attempt(uuid,uuid,uuid,text,text,inet,text) to service_role;
grant execute on function app.global_auth_fails(integer)                              to service_role;
grant execute on function app.credential_slot(uuid,uuid)                              to service_role;
grant execute on function app.begin_credential_verification(uuid,uuid,text,text,text,text,text,text,text,integer,inet,text,text) to service_role;
grant execute on function app.confirm_credential_verification(uuid,uuid,text,inet,text,text) to service_role;
grant execute on function app.abort_credential_verification(uuid,uuid,text)           to service_role;
grant execute on function app.record_verify_failure(uuid,uuid,text,inet,text)         to service_role;
grant execute on function app.confirm_acceptance_sale(uuid,uuid,uuid)                 to service_role;
grant execute on function app.set_credential_label(uuid,uuid,text)                    to service_role;
grant execute on function app.set_credential_active(uuid,uuid,boolean)                to service_role;
grant execute on function app.touch_step_up(uuid,text)                                to service_role;
grant execute on function app.step_up_age_seconds(uuid)                               to service_role;
grant execute on function app.admin_owner_ids_of(uuid)                                to service_role;
grant execute on function app.is_operator()                                           to service_role;

/*
 * Hardening 002 rather than changing it.
 *
 * 002 granted SELECT to authenticated on these tables, but it never revoked
 * what Supabase's default privileges had already granted at CREATE time in
 * 001 — which is ALL, to anon as well. RLS made that mostly harmless (an anon
 * caller matches no policy) but it left REFERENCES and TRIGGER standing, and
 * it left the regression gate below permanently noisy. A gate nobody can read
 * clean is a gate nobody runs.
 *
 * `revoke all`, then grant back exactly SELECT, to exactly authenticated.
 * anon ends with no table privilege anywhere in public: the only thing an
 * unauthenticated visitor may do is call app.peek_invite().
 */
revoke all on public.owners, public.owner_members, public.machines,
              public.machine_assignments, public.orders, public.order_events
  from anon, authenticated;

grant select on public.owners, public.owner_members, public.machines,
                public.machine_assignments, public.orders, public.order_events
  to authenticated;

-- Re-assert the invariant this file exists to protect, in case anything above
-- or in a future migration widened it.
revoke all on public.qpay_credentials from anon, authenticated;

commit;


-- =====================================================================
-- 12. REGRESSION GATE — run after EVERY future migration.
--     Each query must return zero rows.
-- =====================================================================
/*
-- (a) The ciphertext, the fingerprint, the staged candidate, the verification
--     nonce and the invite digest are unreachable.
select rcg.grantee, rcg.table_name, rcg.column_name
  from information_schema.role_column_grants rcg
 where rcg.grantee in ('anon','authenticated','PUBLIC')
   and rcg.column_name in ('sealed','fingerprint','token_hash','pending_sealed',
                           'pending_fingerprint','verify_nonce','pending_invoice_code');

-- (b) authenticated holds nothing but SELECT anywhere in public, and anon
--     holds nothing at all.
select grantee, table_name, privilege_type
  from information_schema.role_table_grants
 where table_schema = 'public'
   and (   (grantee = 'authenticated' and privilege_type <> 'SELECT')
        or  grantee in ('anon','PUBLIC'));

-- (c) Every SECURITY DEFINER function in app pins its search_path.
select p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'app' and p.prosecdef
   and not coalesce(array_to_string(p.proconfig, ',') like '%search_path=%', false);

-- (d) No function in app is executable by anon or authenticated except the
--     three that are meant to be.
select p.proname, r.rolname
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  cross join lateral (values ('anon'),('authenticated')) as r(rolname)
 where n.nspname = 'app'
   and has_function_privilege(r.rolname, p.oid, 'EXECUTE')
   and p.proname not in ('peek_invite','is_operator','my_owner_ids');

-- (e) Live proof, not just catalogue proof:
--     begin;
--       set local role authenticated;
--       set local request.jwt.claim.sub = '<a real owner user id>';
--       select sealed from public.qpay_credentials;                        -- must be 42501
--       select pending_sealed from public.my_qpay_credentials;             -- must be 42703
--       update public.my_qpay_credentials set owner_id = gen_random_uuid();-- must raise
--     rollback;
*/
