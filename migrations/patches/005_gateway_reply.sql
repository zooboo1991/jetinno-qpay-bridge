-- =====================================================================
-- 005-ын нэмэлт: sms_sends.gateway_reply + record_sms_send-ийн шинэ хэлбэр.
-- Зөвхөн 005-ыг 2026-09-05-ны өглөөнөөс ӨМНӨХ хувилбараар ажиллуулсан санд
-- хэрэгтэй. Шалгах query "005_sms нэмэлт (gateway_reply): ✗" гэвэл үүнийг
-- ажиллуул; ✓ гэвэл алгас.
-- =====================================================================
begin;

alter table public.sms_sends add column if not exists gateway_reply text;
comment on column public.sms_sends.gateway_reply is
  'What the gateway said back, with the OTP scrubbed out before it gets here. '
  'The gateway answers 200 with the outcome in the body, so without this a '
  'send that silently failed is indistinguishable from one that worked.';

-- Хуучин 5 аргументтай хувилбарыг устгана — үлдээвэл хоёр хэлбэр зэрэгцэн
-- оршиж, дараагийн хүн алийг нь жинхэнэ гэдгийг таахад хүрнэ.
drop function if exists app.record_sms_send(text, text, boolean, integer, text);

create or replace function app.record_sms_send(
  p_phone          text,
  p_purpose        text,
  p_ok             boolean,
  p_gateway_status integer default null,
  p_error          text default null,
  p_gateway_reply  text default null
) returns void
language sql volatile security definer set search_path = '' as $$
  insert into public.sms_sends (phone, purpose, ok, gateway_status, error, gateway_reply)
  values (app.norm_phone(p_phone), p_purpose, p_ok, p_gateway_status,
          left(p_error, 200), left(p_gateway_reply, 200));
$$;

revoke all on function app.record_sms_send(text, text, boolean, integer, text, text) from public, anon, authenticated;
grant execute on function app.record_sms_send(text, text, boolean, integer, text, text) to service_role;

commit;
