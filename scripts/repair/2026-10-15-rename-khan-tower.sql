-- =====================================================================
-- 2026-10-15, at the operator's request: the business named «Хаан тауэр»
-- becomes «Coffeine», and its contact phone becomes 99147668.
--
-- - Exactly one business must match, otherwise nothing changes.
-- - Unaccepted invite links (sent to the old number) are revoked; issue a
--   new one to 99147668 from the operator page.
-- - People who already log in to this business keep their access.
-- - Machine labels and locations are not touched.
-- - The change is recorded in admin_audit by the owners trigger.
-- Copy this from chat or the file, not through pbcopy (Cyrillic).
-- =====================================================================
begin;

do $$
declare n int;
begin
  select count(*) into n from public.owners where name ~ '[Хх]аан\s*[Тт]ауэр';
  if n <> 1 then
    raise exception 'Хаан тауэр нэртэй бизнес % олдлоо, 1 байх ёстой. Юу ч өөрчлөгдсөнгүй.', n;
  end if;
end $$;

select app.revoke_owner_invite(i.id, 'contact_phone_changed')
  from public.owner_invites i
  join public.owners o on o.id = i.owner_id
 where o.name ~ '[Хх]аан\s*[Тт]ауэр'
   and i.accepted_at is null and i.revoked_at is null;

update public.owners
   set name = 'Coffeine',
       contact_phone = app.norm_phone('99147668')
 where name ~ '[Хх]аан\s*[Тт]ауэр'
returning id, name, contact_phone,
          (select count(*) from public.owner_members m where m.owner_id = owners.id) as members;

commit;
