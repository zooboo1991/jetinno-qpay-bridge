-- =====================================================================
-- 2026-10-16: the SaaS "Orders List" export was uploaded on the fault
-- import page. It has a device and a time column, so every order went in as
-- a fault with no code and no description ("todorkhoigui" on the owner's
-- Problems page). The portal now refuses that file.
--
-- Deletes:
--   - every fault row that came from an import of a file named "Orders List*"
--   - any imported fault row that names no fault at all (empty code AND no
--     description) - nothing an owner could act on
--   - the import-log rows of those "Orders List*" uploads
-- Real faults always carry a code, so they are not touched.
-- ASCII only, safe through pbcopy.
-- =====================================================================
begin;

with bad_imports as (
  select id from public.fault_imports where file_name ilike 'orders list%'
), gone as (
  delete from public.machine_faults f
   where f.import_id in (select id from bad_imports)
      or (f.code = '' and f.description is null)
  returning f.device_no
), gone_imports as (
  delete from public.fault_imports i
   where i.id in (select id from bad_imports)
  returning i.id
)
select (select count(*) from gone) as faults_deleted,
       (select string_agg(distinct device_no, ', ') from gone) as machines,
       (select count(*) from gone_imports) as imports_deleted,
       (select count(*) from public.machine_faults where device_no = '227983')
         - (select count(*) from gone where device_no = '227983') as real_faults_left_227983;

commit;
