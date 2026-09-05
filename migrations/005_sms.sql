-- =====================================================================
-- 005  Outbound SMS: who may receive one, how many, and what happened
--
-- Every SMS costs real money and every SMS goes to a real person's phone.
-- Those two facts are the whole design here:
--
--   * The endpoint that sends them is reachable from the internet, so it
--     needs a gate that does not depend on the caller being honest.
--   * Anyone who knows an owner's phone number can ask Supabase for an OTP
--     as often as they like. Supabase has its own limits; they are generous
--     enough that a bored person with a loop is a phone bill and a very
--     annoyed customer.
-- =====================================================================

/*
 * A record of what was sent. NOT of what was said.
 *
 * The message body and the OTP itself are deliberately absent. A log that
 * carries live one-time codes is a log that grants account access to anyone
 * who can read it — including every future feature that dumps a table to a
 * support screen. The phone number is kept because delivery failures cannot
 * be chased without it, and because the bill is per-number.
 */
create table public.sms_sends (
  id             uuid primary key default gen_random_uuid(),
  phone          text not null,      -- normalised, digits only, no '+'
  purpose        text not null check (purpose in ('otp')),
  ok             boolean not null,
  gateway_status integer,
  error          text,
  at             timestamptz not null default now()
);
comment on table public.sms_sends is
  'One row per attempted send. Never stores the message body or the OTP: a '
  'log holding live one-time codes is a log that grants account access.';

create index sms_sends_phone_at_idx on public.sms_sends (phone, at desc);
create index sms_sends_at_idx       on public.sms_sends (at desc);

-- Supabase grants ALL on new public tables to the API roles at CREATE time.
revoke all on public.sms_sends from anon, authenticated;
revoke update, delete, truncate on public.sms_sends from service_role;

alter table public.sms_sends enable row level security;

/*
 * May this phone number be sent a login code at all?
 *
 * The portal is invite-only and has no signup route, so exactly two kinds of
 * number are legitimate: one that already belongs to a member of some owner,
 * and one named on an invite that is still open. Everything else is either a
 * typo or someone using our Supabase project as a free SMS cannon aimed at a
 * stranger's phone — the second of which is both a cost and a way to get a
 * sender ID blocked.
 *
 * This is enforced here rather than in the bridge's JavaScript because it is
 * the rule that decides whether money leaves the account, and the same rule
 * has to hold no matter which code path grows a second call site later.
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
  );
$$;

/*
 * How many codes has this number already been sent?
 *
 * Counts successes only. A gateway outage that fails ten sends must not lock
 * the owner out for an hour once it recovers — they never received anything,
 * so nothing was spent and nothing was delivered.
 *
 * The defaults are shaped around a real person mistyping a code: five in an
 * hour covers a bad signal and a retry or two, twenty in a day covers a
 * genuinely bad day, and neither is enough volume to be worth abusing.
 */
create or replace function app.sms_budget(
  p_phone    text,
  p_per_hour integer default 5,
  p_per_day  integer default 20
) returns table (out_allowed boolean, out_reason text, out_retry_minutes integer)
language plpgsql stable security definer set search_path = '' as $$
declare
  v_hour integer;
  v_day  integer;
  v_oldest_in_hour timestamptz;
begin
  select count(*), min(s.at) into v_hour, v_oldest_in_hour
    from public.sms_sends s
   where s.phone = app.norm_phone(p_phone)
     and s.ok
     and s.at > now() - interval '1 hour';

  select count(*) into v_day
    from public.sms_sends s
   where s.phone = app.norm_phone(p_phone)
     and s.ok
     and s.at > now() - interval '24 hours';

  if v_hour >= p_per_hour then
    return query select false, 'hourly_cap',
      greatest(1, ceil(extract(epoch from (v_oldest_in_hour + interval '1 hour' - now())) / 60)::integer);
    return;
  end if;

  if v_day >= p_per_day then
    return query select false, 'daily_cap', 60;
    return;
  end if;

  return query select true, null::text, 0;
end;
$$;

/* Written after the gateway answers, success or failure. */
create or replace function app.record_sms_send(
  p_phone          text,
  p_purpose        text,
  p_ok             boolean,
  p_gateway_status integer default null,
  p_error          text default null
) returns void
language sql volatile security definer set search_path = '' as $$
  insert into public.sms_sends (phone, purpose, ok, gateway_status, error)
  values (app.norm_phone(p_phone), p_purpose, p_ok, p_gateway_status,
          -- Gateway bodies can be long and can echo the request. Truncated,
          -- and never the message text.
          left(p_error, 200));
$$;

revoke all on function app.phone_may_receive_otp(text) from public, anon, authenticated;
revoke all on function app.sms_budget(text, integer, integer) from public, anon, authenticated;
revoke all on function app.record_sms_send(text, text, boolean, integer, text) from public, anon, authenticated;
grant execute on function app.phone_may_receive_otp(text) to service_role;
grant execute on function app.sms_budget(text, integer, integer) to service_role;
grant execute on function app.record_sms_send(text, text, boolean, integer, text) to service_role;
