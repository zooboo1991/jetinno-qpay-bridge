-- =====================================================================
-- 017  Phone notifications.
--
-- Two things reach an owner's phone, through the portal installed on its
-- home screen (Web Push):
--
--   * every sale, the moment its money is confirmed — opt-in per device;
--   * the operator's announcements to owners (the console's «Мэдэгдэл»),
--     which also stay readable in the portal and can go out by SMS.
--
-- A push subscription belongs to a person (auth.users), not to a business:
-- someone who runs two businesses hears about both. Which sales they hear
-- about is decided at send time from owner_members, so leaving a business
-- stops its pushes without touching this table.
--
-- orders.sale_push_at is the once-only marker: the settle path can run more
-- than once for one payment, and the row that sets it is the one that sends.
-- =====================================================================
begin;

create table if not exists public.push_subscriptions (
  id            bigint generated always as identity primary key,
  user_id       uuid not null references auth.users(id) on delete cascade,
  -- Issued by the browser's push service; only https endpoints are stored,
  -- and the bridge further allow-lists their hosts before ever posting.
  endpoint      text not null check (char_length(endpoint) between 12 and 1000 and endpoint like 'https://%'),
  p256dh        text not null check (char_length(p256dh) between 20 and 200),
  auth          text not null check (char_length(auth) between 8 and 100),
  notify_sales  boolean not null default true,
  created_at    timestamptz not null default now(),
  last_ok_at    timestamptz,
  constraint push_subscriptions_endpoint_key unique (endpoint)
);
create index if not exists push_subscriptions_user_idx on public.push_subscriptions (user_id);
alter table public.push_subscriptions enable row level security;
revoke all on public.push_subscriptions from anon, authenticated;

alter table public.orders add column if not exists sale_push_at timestamptz;

create table if not exists public.notifications (
  id               uuid primary key default gen_random_uuid(),
  title            text not null check (char_length(title) between 1 and 120),
  body             text not null check (char_length(body) between 1 and 1000),
  -- A page of the portal, never another site: a tapped notification is the
  -- most trusted link an owner will ever see.
  link             text check (link is null or (char_length(link) <= 300 and link ~ '^/[A-Za-z0-9]')),
  target           text not null check (target in ('all', 'owners')),
  channel          text not null check (channel in ('app', 'sms', 'both')),
  recipient_owners integer not null default 0,
  push_sent        integer not null default 0,
  push_failed      integer not null default 0,
  sms_sent         integer not null default 0,
  sms_failed       integer not null default 0,
  created_by       uuid,
  created_at       timestamptz not null default now()
);
create index if not exists notifications_created_idx on public.notifications (created_at desc);

create table if not exists public.notification_owners (
  notification_id uuid not null references public.notifications(id) on delete cascade,
  owner_id        uuid not null references public.owners(id) on delete cascade,
  primary key (notification_id, owner_id)
);
create index if not exists notification_owners_owner_idx on public.notification_owners (owner_id);

-- When a person last opened a business's notification list: what is newer
-- is the badge in the menu.
create table if not exists public.notification_seen (
  user_id  uuid not null references auth.users(id) on delete cascade,
  owner_id uuid not null references public.owners(id) on delete cascade,
  seen_at  timestamptz not null default now(),
  primary key (user_id, owner_id)
);

alter table public.notifications       enable row level security;
alter table public.notification_owners enable row level security;
alter table public.notification_seen   enable row level security;
revoke all on public.notifications, public.notification_owners, public.notification_seen
  from anon, authenticated;

-- Announcements sent by SMS are logged next to logins and invites.
alter table public.sms_sends drop constraint if exists sms_sends_purpose_check;
alter table public.sms_sends add constraint sms_sends_purpose_check
  check (purpose in ('otp', 'invite', 'announcement'));

/*
 * Records an announcement and the businesses it is addressed to. Delivery
 * (push, SMS) is the bridge's job afterwards; it writes the counts back.
 * 'all' means every active business at the moment of sending — one that
 * signs up next week does not inherit last week's news.
 */
create or replace function app.operator_create_notification(
  p_actor_user_id uuid,
  p_title         text,
  p_body          text,
  p_link          text,
  p_target        text,
  p_channel       text,
  p_owner_ids     uuid[]
) returns table (out_status text, out_id uuid, out_owner_ids uuid[])
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_id     uuid := gen_random_uuid();
  v_title  text := btrim(coalesce(p_title, ''));
  v_body   text := btrim(coalesce(p_body, ''));
  v_link   text := nullif(btrim(coalesce(p_link, '')), '');
  v_owners uuid[];
begin
  if not app.is_operator_user(p_actor_user_id) then
    return query select 'forbidden'::text, null::uuid, null::uuid[];
    return;
  end if;
  if length(v_title) < 1 or length(v_title) > 120 or length(v_body) < 1 or length(v_body) > 1000 then
    return query select 'invalid_text'::text, null::uuid, null::uuid[];
    return;
  end if;
  if v_link is not null and (length(v_link) > 300 or v_link !~ '^/[A-Za-z0-9]') then
    return query select 'invalid_link'::text, null::uuid, null::uuid[];
    return;
  end if;
  if p_target not in ('all', 'owners') or p_channel not in ('app', 'sms', 'both') then
    return query select 'invalid_target'::text, null::uuid, null::uuid[];
    return;
  end if;

  select coalesce(array_agg(o.id order by o.id), '{}') into v_owners
    from public.owners o
   where o.status = 'active'
     and (p_target = 'all' or o.id = any (coalesce(p_owner_ids, '{}')));
  if cardinality(v_owners) = 0 then
    return query select 'no_recipients'::text, null::uuid, null::uuid[];
    return;
  end if;

  insert into public.notifications (id, title, body, link, target, channel, recipient_owners, created_by)
  values (v_id, v_title, v_body, v_link, p_target, p_channel, cardinality(v_owners), p_actor_user_id);
  insert into public.notification_owners (notification_id, owner_id)
  select v_id, unnest(v_owners);

  return query select 'ok'::text, v_id, v_owners;
end $$;

/* The console's history: newest first, with the addressed businesses named. */
create or replace function app.operator_notifications(p_actor_user_id uuid, p_limit integer)
returns table (id uuid, title text, body text, link text, target text, channel text,
               recipient_owners integer, push_sent integer, push_failed integer,
               sms_sent integer, sms_failed integer, created_at timestamptz, owner_names text)
language plpgsql stable security definer set search_path = '' as $$
begin
  if not app.is_operator_user(p_actor_user_id) then return; end if;
  return query
  select n.id, n.title, n.body, n.link, n.target, n.channel, n.recipient_owners,
         n.push_sent, n.push_failed, n.sms_sent, n.sms_failed, n.created_at,
         case when n.target = 'owners' then
           (select string_agg(o.name, ', ' order by o.name)
              from public.notification_owners x join public.owners o on o.id = x.owner_id
             where x.notification_id = n.id)
         end
    from public.notifications n
   order by n.created_at desc
   limit least(greatest(coalesce(p_limit, 50), 1), 200);
end $$;

revoke all on function app.operator_create_notification(uuid, text, text, text, text, text, uuid[]) from public, anon, authenticated;
revoke all on function app.operator_notifications(uuid, integer) from public, anon, authenticated;
grant execute on function app.operator_create_notification(uuid, text, text, text, text, text, uuid[]) to service_role;
grant execute on function app.operator_notifications(uuid, integer) to service_role;

commit;
