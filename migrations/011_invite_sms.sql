-- =====================================================================
-- 011  The invite goes out by SMS.
--
-- The operator registers an owner and the bridge texts the invite link to
-- the number on the registration — no QR, and the token never passes
-- through the operator's screen. Two changes follow:
--
--   * sms_sends records those messages as purpose 'invite', so a failed
--     delivery can be chased the same way a failed login code can;
--   * the login-code budget counts login codes only. Without that, an
--     operator re-sending an invite would eat into the owner's own
--     five-codes-an-hour allowance and lock them out of logging in.
-- =====================================================================
begin;

alter table public.sms_sends drop constraint if exists sms_sends_purpose_check;
alter table public.sms_sends add constraint sms_sends_purpose_check check (purpose in ('otp', 'invite'));

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
     and s.purpose = 'otp'
     and s.at > now() - interval '1 hour';

  select count(*) into v_day
    from public.sms_sends s
   where s.phone = app.norm_phone(p_phone)
     and s.ok
     and s.purpose = 'otp'
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

commit;
