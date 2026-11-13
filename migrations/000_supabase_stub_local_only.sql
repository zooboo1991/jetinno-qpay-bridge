-- Local-only stub reproducing the parts of a Supabase project that 002/003 need.
do $$ begin
  if not exists (select 1 from pg_roles where rolname='anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname='authenticated') then create role authenticated nologin; end if;
  if not exists (select 1 from pg_roles where rolname='service_role') then create role service_role nologin bypassrls; end if;
end $$;

create schema if not exists auth;
create table if not exists auth.users (
  id uuid primary key default gen_random_uuid(),
  email text,
  phone text,
  email_confirmed_at timestamptz,
  phone_confirmed_at timestamptz,
  raw_user_meta_data jsonb default '{}'::jsonb
);

alter table auth.users add column if not exists last_sign_in_at timestamptz;

-- GoTrue's session and refresh-token tables, the columns the bridge touches.
create table if not exists auth.sessions (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null,
  created_at timestamptz default now()
);
create table if not exists auth.refresh_tokens (
  id         bigint generated always as identity primary key,
  user_id    varchar(255),
  session_id uuid,
  token      varchar(255),
  revoked    boolean default false
);

create or replace function auth.uid() returns uuid
language sql stable as $$
  select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid
$$;

grant usage on schema auth to anon, authenticated, service_role;
-- Supabase's default privileges: new tables in public are granted to the API roles.
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
