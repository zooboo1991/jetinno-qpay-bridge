-- =====================================================================
-- 013  The owner may type the invoice code.
--
-- QPay issues a merchant three things together — username, password and
-- invoice code — and gives them to the OWNER. Asking the operator for the
-- code at registration meant typing a placeholder when they did not have it
-- yet, and every owner then failed verification on a code they never saw.
--
-- The operator may still enter it; the owner's form now asks for it too,
-- and what the owner types wins. Registration therefore accepts no code.
-- The bridge carries the rest (src/credentials.js).
-- =====================================================================
begin;

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
  -- Optional now: QPay gives the code to the OWNER with their username and
  -- password, and the owner may type all three. Checked only when given.
  if v_code <> '' and v_code !~ '^[A-Za-z0-9_-]{3,64}$' then
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
    (p_credential_id, v_owner, 'Үндсэн данс', 'pending', false, 'cli',
     nullif(v_code, ''), nullif(right(v_code, 4), ''));

  -- notify_url stays NULL until the machine's first signed getQrCode pins it.
  insert into public.machines
    (id, owner_id, qpay_credential_id, device_no, label, location, notify_url, status, installed_at)
  values
    (v_machine, v_owner, p_credential_id, v_device, null, nullif(btrim(coalesce(p_location, '')), ''),
     null, 'active', now());

  insert into public.credential_audit (owner_id, credential_id, action, actor_kind, actor_user_id, detail)
  values (v_owner, p_credential_id, 'owner_provisioned', 'operator', p_actor_user_id,
          jsonb_build_object('device_no', v_device, 'invoice_code_hint', nullif(right(v_code, 4), '')));

  return query select 'ok'::text, v_owner, v_machine;
exception
  -- Two operators registering the same machine at once: the unique
  -- constraint decides, and the loser is told plainly.
  when unique_violation then
    return query select 'device_taken'::text, null::uuid, null::uuid;
end $$;

commit;
