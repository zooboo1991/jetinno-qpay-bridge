-- =====================================================================
-- 009  Operators by phone — the bootstrap.
--
-- public.operators is keyed by auth.users.id, which does not exist until a
-- person has logged in once. And nobody could log in once: the Send SMS
-- hook only texts a code to a phone that is an owner member or holds an open
-- invite (005), and an operator is neither. So the first operator could
-- never receive a code, could never reach the console, and could therefore
-- never register the first owner. The whole system had no way in.
--
-- This lets the operator be named by PHONE, in SQL, before they have an
-- account:
--
--   insert into public.operator_phones (phone, label) values ('97699112233', 'Нэр');
--
-- The phone is proved the same way an owner's is: by the OTP Supabase
-- confirms. A number here with no confirmed login grants nothing.
-- public.operators stays, and either table makes an operator; revoking is a
-- DELETE from whichever one names them.
-- =====================================================================
begin;

create table if not exists public.operator_phones (
  phone      text primary key check (phone ~ '^976[0-9]{8}$'),
  label      text not null,
  created_at timestamptz not null default now()
);
comment on table public.operator_phones is
  'Operators named by phone before they have logged in. Written only from the '
  'SQL editor. The phone must be confirmed by a Supabase OTP before it counts.';

alter table public.operator_phones enable row level security;
revoke all on public.operator_phones from anon, authenticated;

/*
 * Replaces 007's body with the same signature, so every operator_* function
 * (007, 008) picks up phone-named operators without being touched.
 *
 * `phone_confirmed_at is not null` is the load-bearing condition: Supabase
 * creates the auth.users row when a code is REQUESTED, and a row that merely
 * asked for a code has proved nothing.
 */
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
      );
$$;

-- The RLS-side twin, kept in step so the two can never disagree.
create or replace function app.is_operator() returns boolean
language sql stable security definer set search_path = '' as $$
  select app.is_operator_user((select auth.uid()));
$$;

/*
 * 005's gate for the login SMS, widened by exactly one case: a phone named
 * as an operator. Without this the operator's first code is never sent.
 */
create or replace function app.phone_may_receive_otp(p_phone text)
returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1
      from public.owner_members m
      join auth.users u on u.id = m.user_id
     where app.norm_phone(u.phone) = app.norm_phone(p_phone)
  ) or exists (
    select 1
      from public.owner_invites i
     where app.norm_phone(i.invited_phone) = app.norm_phone(p_phone)
       and i.accepted_at is null
       and i.revoked_at is null
       and i.expires_at > now()
  ) or exists (
    select 1 from public.operator_phones op where op.phone = app.norm_phone(p_phone)
  );
$$;

commit;
