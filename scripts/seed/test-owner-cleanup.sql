-- =====================================================================
-- Removes everything scripts/seed/test-owner.sql wrote, and nothing else:
-- every row is selected by the test owner's fixed id or a TEST- device.
-- =====================================================================
begin;

delete from public.machine_faults where device_no like 'TEST-%';
delete from public.orders where owner_id = '7e570000-0000-4000-8000-000000000001';
delete from public.machine_assignments where owner_id = '7e570000-0000-4000-8000-000000000001';
delete from public.machines where owner_id = '7e570000-0000-4000-8000-000000000001';
delete from public.owner_members where owner_id = '7e570000-0000-4000-8000-000000000001';
delete from public.qpay_credentials where owner_id = '7e570000-0000-4000-8000-000000000001';
-- Rows other tables keep about the owner (invites, audit, events) go with it
-- (on delete cascade / set null).
delete from public.owners where id = '7e570000-0000-4000-8000-000000000001';

select (select count(*) from public.owners where id = '7e570000-0000-4000-8000-000000000001') as owners_left,
       (select count(*) from public.orders where order_no like 'TST%') as orders_left,
       (select count(*) from public.machines where device_no like 'TEST-%') as machines_left,
       (select count(*) from public.machine_faults where device_no like 'TEST-%') as faults_left;

commit;
