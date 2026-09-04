Verified against real infrastructure: DDL applied to `postgres:16-alpine`, 30 crypto assertions, 5-way parallel settle claim, 2-way parallel sweep over 200 rows, RLS tested as the real `authenticated` role. Here is the plan.

---

# jetinno-qpay-bridge — multi-tenant implementation plan

Everything below was executed before being written down: `001_core.sql` and `002_supabase_rls.sql` applied cleanly to Postgres 16 in Docker; `src/crypto.js` passes 30 assertions on Node 26 (`open()` = 14.8 µs/op, sealed blob = 176 chars); the settle lease produced exactly one winner out of 5 simultaneous claims with `settle_attempts = 1`; two sweepers split 200 expired rows with zero overlap; RLS was exercised by actually `set role authenticated`.

---

## 1. Final decisions on every contested point

| # | Question | Decision | Why |
|---|---|---|---|
| 1 | Where `base_url` lives | **Global env var `QPAY_BASE_URL`, validated at boot against a hardcoded https-only allowlist. Never a DB column, never per-owner.** | A plaintext destination column beside the ciphertext turns one `UPDATE` into full credential exfiltration on the owner's next sale. No owner has a legitimate reason to choose their own QPay host. |
| 2 | Orders primary key | **uuid PK + `unique (machine_id, order_no)` + `unique (qpay_credential_id, qpay_sender_invoice_no)`.** | Jetinno's `orderNo` is unique per machine only. A global PK gives cross-tenant DoS (`ORDERNO_EXIST` on a collision) and ambiguous callbacks. Verified: same `orderNo` on two machines inserts fine; on one machine it is rejected. |
| 3 | `ON CONFLICT` form | **Untargeted `ON CONFLICT DO NOTHING`.** | Verified: targeted `ON CONFLICT (machine_id, order_no)` crashes with an unhandled duplicate-key error on `orders_sender_invoice_key`. Untargeted covers every unique index. |
| 4 | Token cache key | **`SHA-256(base_url \0 username \0 password)`, with an `ownerId` equality assertion on cache hit as a tripwire.** | Keying on `ownerId` means any `deviceNo → owner` resolution bug silently pays the wrong merchant. Keying on the credentials makes the worst case a clean auth error. Password rotation self-invalidates. Verified both. |
| 5 | Token single-flight | **Store an `inflight: true` flag on the entry and capture the entry in a local `const`.** | The refactor plan's placeholder (`now + 30_000`) is shorter than its own 60 s skew window, so coalescing never fired and `tokens.get(key).expiresAtMs = …` could throw `TypeError` inside the shared promise. Verified corrected: 10 concurrent calls → 1 auth call. |
| 6 | Token fetch deadline | **The token fetch owns an independent `AbortSignal.timeout(2500)`. The caller's request deadline is passed only to per-request calls.** | Otherwise request A hitting its 6.5 s deadline aborts the shared token fetch that request B is awaiting. |
| 7 | Unregistered `deviceNo` | **Fail closed: `DEVICE_NOT_REGISTERED` + an `ingest_errors` row. No default merchant, ever.** During Phase 3 only, a fallback scoped to one hardcoded literal device number. | An "any unregistered device" fallback does not degrade to today's behaviour — it routes another business's revenue into the operator's account, silently, and does not self-correct. |
| 8 | Credential resolution at settle | **Snapshot `owner_id` + `qpay_credential_id` onto the order row; settle builds its client from the snapshot, never re-resolves `deviceNo`.** | A resale or credential rotation mid-order otherwise checks payment against the wrong merchant, gets `paid:false`, and the paying customer gets nothing. |
| 9 | Settle claim predicate | **Schema design's, verbatim, `RETURNS SETOF`.** | The refactor plan's `status='awaiting_payment' AND (settling_at IS NULL OR …)` can never match a crashed `settling` row — permanently stranded. `RETURNS SETOF` because a composite return yields one all-NULL row on zero matches, which every driver reports as success. |
| 10 | Sweep mutual exclusion | **`FOR UPDATE SKIP LOCKED` + the same lease. Delete the advisory lock entirely.** | Session advisory locks are unsafe behind Supabase's transaction pooler — the unlock lands on a different backend, the lock leaks, and the sweep silently stops running forever. Verified SKIP LOCKED: 200 rows split across two sweepers, zero overlap. |
| 11 | Settle lease duration | **60 s** (`SETTLE_LEASE_SECONDS`), and only after the QPay fetch timeouts ship. | Worst case is QPay 5 s + notify 8 s ≈ 13 s. Too short brews twice; too long makes one customer wait. Every lease number is fiction until `src/qpay.js` has timeouts — today it has none and undici's default is 300 s. |
| 12 | Credential storage format | **One sealed blob `v1.<keyId>.<iv>.<tag>.<ct>` in a `text` column, in the schema design's multi-row table shape (PK = credential id).** | Crypto design's atomicity + one-IV reasoning is right; schema design's table shape is right because an owner may have two shops on two invoice codes. |
| 13 | AAD | **`v1\|qpay_credentials:<credential_id>\|owner:<owner_id>` — both ids bound.** | Credential id alone lets blobs swap between one owner's own rows; owner id alone breaks with multiple credentials. Both bound means a relocation *and* a re-parenting both fail authentication. Verified both. |
| 14 | Fingerprint | **Keyed `HMAC-SHA256` under a dedicated, never-rotated `CRED_FP_KEY`.** | A bare `sha256(username:invoice_code)` is brute-forceable — short structured usernames, and the design published `invoice_code` in plaintext. A separate key keeps fingerprints stable across master-key rotation, so the "two owners can't register the same merchant" index does not split into two namespaces mid-rotation. |
| 15 | `invoice_code` | **Inside the sealed blob.** A plaintext `invoice_code_hint` column keeps only the last 4 chars for support. | Removes the second brute-force input entirely and costs nothing — nothing queries it. |
| 16 | `QPAY_MOCK` | **Deleted. Replaced by `scripts/fake-qpay.js`, a real fake upstream.** | This is a security fix, not a test improvement: `QPAY_MOCK=1` makes `settle()` skip `checkPayment` entirely and registers an unauthenticated `/mock/pay/:orderNo` — one env var turns the live service into a free coffee dispenser. It also means the e2e never executes `src/qpay.js`, so it cannot see a token or an invoice_code. |
| 17 | Key storage location | **Secret file `/etc/secrets/cred_keys` preferred, `CRED_KEYS` env as fallback, but the source is chosen explicitly, logged at boot, and boot FAILS if both are present and disagree.** | The crypto design's `try { readFileSync } catch { env }` silently prefers the file, so an operator who rotates the file and forgets a stale env var encrypts under the wrong key with no signal. Verified: disagreement now refuses to start. |
| 18 | `JETINNO_APIKEY` fallback | **Deleted from both `src/server.js:8` and `src/simulate-machine.js:4`. Boot fails without the env var.** Stays global (Jetinno issues one key per portal account, not per machine). | A hardcoded key committed in git makes every machine endpoint forgeable if the var is ever unset during a service recreate. Cross-tenant forgery is closed differently — see items 19–21. |
| 19 | `notifyUrl` | **Trust-on-first-use: the first signed `getQrCode` pins `machines.notify_url`; every later request ignores the body value.** Plus a private/link-local address guard (`ALLOW_PRIVATE_NOTIFY_URL=1` for the e2e). | The request body value is an SSRF vector into Render's internal network and the metadata endpoint, with the response body landing in the `/recent` ring. |
| 20 | `productdone` | **`app.record_product_done` only accepts orders in `settling`/`payment_confirmed`/`paid`.** | Otherwise a forged `productdone` for a future `orderNo` permanently poisons `product_done_at` and stops that machine selling. Verified: 0 rows on an `awaiting_payment` order. |
| 21 | `getQrCode` replay guard | **Replay requires `device_no` AND `raw_order_amount` to match the stored order; otherwise `ORDERNO_EXIST`.** | Without the amount check, an attacker pre-creates the order at 1₮ and the machine replays that QR for a 5000₮ coffee. |
| 22 | Lost notify ACK | **`notify_sent_at` stamped BEFORE the fetch; no claim for `NOTIFY_GRACE_SECONDS` (120 s) afterwards.** | A brew takes 30–60 s, so `product_done_at` is not yet set when a lost ACK triggers a retry. The lease is irrelevant — this is the normal release path. Verified: re-claim inside the grace returns 0 rows, after the grace returns 1. |
| 23 | Draining `payment_confirmed` | **`app.claim_unnotified_orders` worker on a 30 s timer.** | The state was defined, indexed and alerted on but never drained, and the server answers every QPay callback `200 SUCCESS` so QPay never retries. One transient notify failure = permanent debt awaiting a human. |
| 24 | Sweeper finding `INVOICE_PAID` | **The sweeper calls `settleWithLease(order)` directly — never `settle()`.** | The sweeper already holds a fresh lease, so re-entering `claim_order_for_settle` returns 0 rows: the customer paid, nothing happens, and the order loops against QPay forever (which QPay treats as forbidden cron polling). |
| 25 | Give-up | **`settle_attempts >= 10` → terminal `needs_human`.** `release_settle(..., countAttempt=false)` for the benign "not paid yet" so an attacker cannot burn an order's attempts. | Nothing in any design capped retries. Verified: at the cap, both claim functions return 0 rows and `give_up` moves the row out. |
| 26 | Amount verification | **Sum the `PAID` rows; `< amount` → release as partial, `> amount` → `needs_human`, `=` → proceed. Enforced twice: in JS and by `orders_paid_amount_shape`.** | `checkPayment` already parses `payment_amount` and throws it away. With `AMOUNT_DIVISOR` still unconfirmed, a divisor mistake means a 10₮ payment dispenses a 1000₮ coffee. Verified: `mark_payment_confirmed` with a wrong amount returns 0 rows. |
| 27 | `GET /orders/:orderNo` | **Gated by `debugAllowed`, projection whitelisted.** `DEBUG_KEY` moves from `?key=` to an `X-Debug-Key` header. | The route is fully public today and all three designs planned to widen what it returns. Query strings land in Render's request logs and every proxy's access log. |
| 28 | Error bodies | **`fail()` returns `SYSTEM_ERROR: <incident-id>`; the detail is logged server-side only. `redact()` applied where `detail()` is constructed, not at call sites.** | QPay auth error bodies echo the merchant username, `pg` errors echo statement text, `CredentialCryptoError` names the active key id — and all of it currently goes into the HTTP response *and* the `/recent` ring. |
| 29 | Migration file split | **`001_core.sql` (portable) + `002_supabase_rls.sql` (`auth.users`, RLS, grants).** | A single file referencing `auth.users` and the `authenticated` role is unrunnable anywhere except Supabase, so it can never be tested before it hits production. |
| 30 | e2e database | **Real Postgres: Docker `postgres:16-alpine` auto-started, or `E2E_DATABASE_URL`. No PGlite.** | PGlite is single-process, which would make the five-parallel-callback assertion — the one test that protects the money — pass unconditionally. One driver, one dialect, a real race. |
| 31 | DB driver / region / plan | **`pg` (node-postgres) direct, via the Supabase transaction pooler `aws-0-ap-southeast-1.pooler.supabase.com:6543`. Supabase region `ap-southeast-1`. Paid plan, never free.** | Direct `db.<ref>.supabase.co:5432` is IPv6-only and Render's outbound is IPv4 — it looks like a DNS problem. Co-locate with Render Singapore, not with Mongolia; QPay's distance is fixed either way. Free Supabase projects pause, reproducing the exact cold-start failure the README rejected Render's free tier for. |
| 32 | `AMOUNT_DIVISOR`, `ABANDON_AFTER_MS` | **Per-machine columns; env values become defaults only for seeding.** | Properties of the firmware and the site, not of the server. |
| 33 | Admin credential-write path | **An offline CLI (`scripts/add-owner.js`) only. No HTTP endpoint accepts a plaintext QPay password.** | The only auth pattern in this codebase is a key in a query string. Do not build a network endpoint for the one input that is a plaintext merchant password until there is a real session system. |
| 34 | Detection | **Trigger-written append-only `admin_audit` on `owners`/`machines`/`qpay_credentials`, plus a weekly per-owner revenue reconciliation the owner checks against their own QPay portal.** | The AAD stops ciphertext relocation; it does **not** stop `update machines set owner_id=…`, which satisfies every FK and redirects 100 % of an owner's revenue. Both designs described that attacker as covered. Verified: the audit trigger fires and redacts the `sealed` blob while flagging that it changed. |

---

## 2. Postgres DDL

Two files. Apply `001_core.sql` first, everywhere. Apply `002_supabase_rls.sql` **only** on Supabase.

### `migrations/001_core.sql`

```sql
-- =====================================================================
-- jetinno-qpay-bridge — migration 001_core.sql
-- Portable Postgres 15+. NO Supabase-only objects: runs on plain postgres
-- (Docker) so the e2e can apply it. RLS/auth lives in 002.
-- Verified: applies clean in one transaction on postgres:16-alpine.
-- =====================================================================

begin;

create extension if not exists pgcrypto;

create schema if not exists app;
comment on schema app is 'Server-side helpers. Not exposed through PostgREST.';

create or replace function app.touch_updated_at() returns trigger
language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end $$;


-- =====================================================================
-- 1. TENANTS
-- =====================================================================
create table public.owners (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  contact_phone text,
  contact_email text,
  status        text not null default 'active' check (status in ('active','suspended')),
  notes         text,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
comment on table public.owners is 'A business that bought machines. Their machines'' money lands in their own QPay merchant account.';
create trigger owners_touch before update on public.owners
  for each row execute function app.touch_updated_at();


-- =====================================================================
-- 2. CREDENTIALS — ciphertext only; the key never enters Postgres
-- =====================================================================
create table public.qpay_credentials (
  id            uuid primary key,   -- app-generated: it is part of the AEAD AAD
  owner_id      uuid not null references public.owners(id) on delete restrict,
  label         text not null,

  sealed        text not null,      -- v1.<keyId>.<iv>.<tag>.<ct>, holds {username,password,invoiceCode}
  key_id        text not null,      -- denormalised copy of the id INSIDE `sealed`; rotation index only
  fingerprint   text not null,      -- keyed HMAC-SHA256 over lower(username)||':'||invoice_code
  invoice_code_hint text,           -- last 4 chars only, for support

  is_active     boolean not null default true,
  last_verified_at timestamptz,
  last_error    text,
  last_error_at timestamptz,
  auth_fail_count integer not null default 0,

  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),

  constraint qpay_credentials_owner_label_key unique (owner_id, label),
  constraint qpay_credentials_id_owner_key    unique (id, owner_id),
  constraint qpay_credentials_sealed_shape    check (sealed like 'v1.%'),
  constraint qpay_credentials_fp_shape        check (fingerprint ~ '^[0-9a-f]{64}$')
);
comment on column public.qpay_credentials.id is
  'Generated by the application BEFORE encrypting: the id is bound into the AEAD additional data together with owner_id. No DB default on purpose — a forgotten app-side id must fail loudly.';
comment on column public.qpay_credentials.sealed is
  'AES-256-GCM. AAD = ''v1|qpay_credentials:<id>|owner:<owner_id>''. Relocating this blob to another row, or re-parenting this row to another owner, fails authentication.';
comment on column public.qpay_credentials.fingerprint is
  'KEYED HMAC (CRED_FP_KEY), not a bare hash: a bare sha256 of a short structured username is brute-forceable from a dump.';

create unique index qpay_credentials_active_fingerprint_key
  on public.qpay_credentials (fingerprint) where is_active;
create index qpay_credentials_key_id_idx on public.qpay_credentials (key_id);
create trigger qpay_credentials_touch before update on public.qpay_credentials
  for each row execute function app.touch_updated_at();


-- =====================================================================
-- 3. MACHINES
-- =====================================================================
create table public.machines (
  id                 uuid primary key default gen_random_uuid(),
  owner_id           uuid not null,
  qpay_credential_id uuid not null,

  device_no          text not null,
  label              text,
  location           text,

  -- notifyUrl is NOT taken from the request body. Trust-on-first-use: the
  -- first signed getQrCode pins it here, every later request uses this value.
  notify_url         text,
  notify_url_pinned_at timestamptz,

  amount_divisor     integer not null default 100 check (amount_divisor in (1,100)),
  abandon_after_ms   integer not null default 600000 check (abandon_after_ms between 60000 and 3600000),

  status             text not null default 'active' check (status in ('active','disabled','retired')),
  installed_at       timestamptz,
  last_seen_at       timestamptz,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now(),

  constraint machines_device_no_key unique (device_no),
  constraint machines_id_owner_key  unique (id, owner_id),
  constraint machines_owner_fk foreign key (owner_id) references public.owners(id) on delete restrict,
  -- A machine can only be wired to a credential belonging to its OWN owner.
  -- Misrouted money becomes unrepresentable, not merely unlikely.
  constraint machines_credential_owner_fk
    foreign key (qpay_credential_id, owner_id)
    references public.qpay_credentials (id, owner_id) on delete restrict
);
comment on column public.machines.device_no is
  'Jetinno deviceNo. Globally unique: it is the only routing key the machine sends, so it must resolve to exactly one owner.';
comment on column public.machines.amount_divisor is
  '100 = machine sends cents (100000 -> 1000 MNT); 1 = machine sends tugrik. Confirm from the first live getQrCode log per model.';
create trigger machines_touch before update on public.machines
  for each row execute function app.touch_updated_at();


create table public.machine_assignments (
  id                 bigint generated always as identity primary key,
  machine_id         uuid not null references public.machines(id) on delete cascade,
  owner_id           uuid not null references public.owners(id) on delete restrict,
  qpay_credential_id uuid not null references public.qpay_credentials(id) on delete restrict,
  effective_from     timestamptz not null default now(),
  effective_to       timestamptz,
  reason             text,
  created_at         timestamptz not null default now(),
  constraint machine_assignments_range_chk check (effective_to is null or effective_to > effective_from)
);
create index machine_assignments_machine_idx on public.machine_assignments (machine_id, effective_from desc);
create unique index machine_assignments_one_open_key on public.machine_assignments (machine_id) where effective_to is null;


-- =====================================================================
-- 4. ORDERS — replaces the in-memory Map
-- =====================================================================
create table public.orders (
  id                     uuid primary key default gen_random_uuid(),

  machine_id             uuid not null,
  owner_id               uuid not null,   -- snapshot: immutable revenue attribution
  qpay_credential_id     uuid not null,   -- snapshot: settle must query the merchant that issued the invoice

  order_no               text not null,
  device_no              text not null,
  notify_url             text not null,   -- copied from machines, never from the request body
  product_id             text,
  product_name           text,
  raw_order_amount       text not null,   -- verbatim: it is a signed field
  amount_divisor         integer not null,
  amount_mnt             integer not null check (amount_mnt > 0),
  paid_amount_mnt        integer,

  qpay_sender_invoice_no text not null check (char_length(qpay_sender_invoice_no) between 1 and 45),
  invoice_attempt        integer not null default 1 check (invoice_attempt between 1 and 9),
  qpay_invoice_id        text,
  qpay_payment_id        text,
  callback_url           text not null,
  qr_code                text check (qr_code is null or char_length(qr_code) <= 128),
  qr_text_len            integer,

  status                 text not null default 'creating'
    check (status in ('creating','awaiting_payment','settling','payment_confirmed',
                      'paid','cancelled','failed','orphaned','needs_human')),
  settle_lease_until     timestamptz,
  settle_lease_owner     text,
  settle_attempts        integer not null default 0,
  notify_attempts        integer not null default 0,
  notify_sent_at         timestamptz,     -- set BEFORE the fetch: "assume delivered"
  last_error             text,
  last_error_at          timestamptz,

  payment_confirmed_at   timestamptz,
  notified_at            timestamptz,
  product_done_at        timestamptz,
  product_done_ok        boolean,
  cancelled_at           timestamptz,

  expires_at             timestamptz not null default now() + interval '10 minutes',
  created_at             timestamptz not null default now(),
  updated_at             timestamptz not null default now(),

  constraint orders_machine_owner_fk foreign key (machine_id, owner_id)
    references public.machines (id, owner_id) on delete restrict,
  constraint orders_credential_owner_fk foreign key (qpay_credential_id, owner_id)
    references public.qpay_credentials (id, owner_id) on delete restrict,

  constraint orders_machine_order_no_key unique (machine_id, order_no),
  constraint orders_sender_invoice_key unique (qpay_credential_id, qpay_sender_invoice_no),

  constraint orders_lease_shape check (status <> 'settling' or settle_lease_until is not null),
  constraint orders_confirmed_shape check (status not in ('payment_confirmed','paid') or payment_confirmed_at is not null),
  constraint orders_paid_shape check (status <> 'paid' or (payment_confirmed_at is not null and notified_at is not null)),
  constraint orders_paid_amount_shape check (status <> 'paid' or paid_amount_mnt = amount_mnt),
  constraint orders_live_needs_invoice
    check (status not in ('awaiting_payment','settling','payment_confirmed','paid') or qpay_invoice_id is not null)
);
comment on column public.orders.owner_id is
  'Denormalised from machines on purpose. Reselling a machine must not retroactively move last month''s revenue to the new owner. The composite FK stops it drifting at write time.';
comment on column public.orders.notify_sent_at is
  'Stamped immediately BEFORE the notify fetch, not after. A brew takes 30-60s, so a lost ACK must be treated as delivered until the grace window passes — otherwise the retry brews a second cup.';
comment on column public.orders.raw_order_amount is
  'Verbatim, because reproducing the Jetinno MD5 needs the exact string the machine sent, leading zeros included.';

create index orders_order_no_idx on public.orders (order_no);
create unique index orders_qpay_invoice_id_key on public.orders (qpay_invoice_id) where qpay_invoice_id is not null;
create unique index orders_qpay_payment_id_key on public.orders (qpay_payment_id) where qpay_payment_id is not null;
create index orders_sweep_idx on public.orders (expires_at)
  where status in ('creating','awaiting_payment','settling');
create index orders_owed_idx on public.orders (payment_confirmed_at)
  where status in ('payment_confirmed','settling');
create index orders_owner_created_idx on public.orders (owner_id, created_at desc);
create trigger orders_touch before update on public.orders
  for each row execute function app.touch_updated_at();


-- =====================================================================
-- 5. AUDIT / ERROR SURFACE
-- =====================================================================
create table public.order_events (
  id         bigint generated always as identity primary key,
  order_id   uuid references public.orders(id) on delete cascade,
  owner_id   uuid references public.owners(id) on delete cascade,
  machine_id uuid references public.machines(id) on delete set null,
  kind       text not null,
  detail     jsonb not null default '{}'::jsonb,
  at         timestamptz not null default now()
);
comment on table public.order_events is
  'Append-only. NEVER store the expected MD5 signature here — that hands out a forgeable value.';
create index order_events_order_idx on public.order_events (order_id, at desc);
create index order_events_owner_idx on public.order_events (owner_id, at desc);
create index order_events_kind_idx  on public.order_events (kind, at desc);

create table public.ingest_errors (
  id        bigint generated always as identity primary key,
  at        timestamptz not null default now(),
  path      text not null,
  device_no text,
  order_no  text,
  reason    text not null,
  payload   jsonb,
  remote_ip inet
);
create index ingest_errors_at_idx on public.ingest_errors (at desc);
create index ingest_errors_device_idx on public.ingest_errors (device_no, at desc);

-- The rows an attacker actually edits to redirect money. Trigger-written; the
-- application never writes this table directly.
create table public.admin_audit (
  id         bigint generated always as identity primary key,
  at         timestamptz not null default now(),
  table_name text not null,
  op         text not null,
  row_id     text,
  db_user    text not null default current_user,
  before     jsonb,
  after      jsonb,
  sealed_changed boolean not null default false
);
create index admin_audit_at_idx on public.admin_audit (at desc);
create index admin_audit_row_idx on public.admin_audit (table_name, row_id, at desc);

create or replace function app.audit_row() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
  b jsonb := case when tg_op = 'INSERT' then null else to_jsonb(old) end;
  a jsonb := case when tg_op = 'DELETE' then null else to_jsonb(new) end;
begin
  insert into public.admin_audit (table_name, op, row_id, before, after, sealed_changed)
  values (
    tg_table_name, tg_op,
    coalesce(a ->> 'id', b ->> 'id'),
    b - 'sealed', a - 'sealed',
    coalesce(b ->> 'sealed', '') is distinct from coalesce(a ->> 'sealed', '')
  );
  return null;
end $$;

create trigger machines_audit after insert or update or delete on public.machines
  for each row execute function app.audit_row();
create trigger qpay_credentials_audit after insert or update or delete on public.qpay_credentials
  for each row execute function app.audit_row();
create trigger owners_audit after insert or update or delete on public.owners
  for each row execute function app.audit_row();


-- =====================================================================
-- 6. CONCURRENCY — the lease that replaces the in-process `settling` flag
-- =====================================================================
/*
 * Atomic claim. Exactly one caller, across every instance, gets a row back.
 *
 * RETURNS SETOF, never a bare composite: a function returning a composite type
 * yields one all-NULL row when the UPDATE matches nothing, which every driver
 * reports as "1 row" — inverting the guard into a guaranteed double-dispense.
 *
 * Refusals, in order of importance:
 *   product_done_at set          -> the cup already came out; never again.
 *   notify_sent_at within grace  -> we told the machine and are still inside its
 *                                   brew time. A lost ACK must not brew twice.
 *   settle_attempts >= cap       -> stop hammering QPay; a human takes over.
 *   status settling + live lease -> another instance holds it.
 */
create or replace function app.claim_order_for_settle(
  p_order_id             uuid,
  p_lease_seconds        integer default 60,
  p_instance             text    default null,
  p_notify_grace_seconds integer default 120,
  p_max_attempts         integer default 10
) returns setof public.orders
language sql volatile as $$
  update public.orders o
     set status             = 'settling',
         settle_lease_until = now() + make_interval(secs => p_lease_seconds),
         settle_lease_owner = p_instance,
         settle_attempts    = o.settle_attempts + 1,
         updated_at         = now()
   where o.id = p_order_id
     and o.product_done_at is null
     and o.settle_attempts < p_max_attempts
     and (o.notify_sent_at is null
          or o.notify_sent_at < now() - make_interval(secs => p_notify_grace_seconds))
     and (o.status in ('awaiting_payment','payment_confirmed')
          or (o.status = 'settling' and o.settle_lease_until < now()))
  returning o.*;
$$;

/* Money confirmed, machine not told yet. Refuses to record a mismatched amount. */
create or replace function app.mark_payment_confirmed(
  p_order_id      uuid,
  p_payment_id    text,
  p_paid_amount   integer,
  p_lease_seconds integer default 60
) returns setof public.orders
language sql volatile as $$
  update public.orders o
     set qpay_payment_id      = coalesce(o.qpay_payment_id, p_payment_id),
         paid_amount_mnt      = p_paid_amount,
         payment_confirmed_at = coalesce(o.payment_confirmed_at, now()),
         settle_lease_until   = now() + make_interval(secs => p_lease_seconds),
         updated_at           = now()
   where o.id = p_order_id
     and o.status = 'settling'
     and p_paid_amount = o.amount_mnt
  returning o.*;
$$;

/* Stamped immediately BEFORE the notify fetch. */
create or replace function app.mark_notify_sent(p_order_id uuid)
returns setof public.orders
language sql volatile as $$
  update public.orders o
     set notify_sent_at  = now(),
         notify_attempts = o.notify_attempts + 1,
         updated_at      = now()
   where o.id = p_order_id and o.status = 'settling'
  returning o.*;
$$;

/* The machine ACKed. Terminal success. */
create or replace function app.finish_settle(p_order_id uuid)
returns setof public.orders
language sql volatile as $$
  update public.orders o
     set status             = 'paid',
         notified_at        = coalesce(o.notified_at, now()),
         settle_lease_until = null,
         settle_lease_owner = null,
         last_error         = null,
         updated_at         = now()
   where o.id = p_order_id and o.status = 'settling'
  returning o.*;
$$;

/*
 * Release without success: back to a retryable state the drain worker owns.
 * p_count_attempt=false undoes the claim's increment, for benign outcomes such
 * as "not paid yet". Without it, anyone hitting the public callback route
 * could burn a legitimate order's ten attempts and force it to needs_human.
 */
create or replace function app.release_settle(
  p_order_id uuid,
  p_error text default null,
  p_count_attempt boolean default true
) returns setof public.orders
language sql volatile as $$
  update public.orders o
     set status = case when o.payment_confirmed_at is not null
                       then 'payment_confirmed' else 'awaiting_payment' end,
         settle_attempts = case when p_count_attempt then o.settle_attempts
                                else greatest(o.settle_attempts - 1, 0) end,
         settle_lease_until = null,
         settle_lease_owner = null,
         last_error    = coalesce(p_error, o.last_error),
         last_error_at = case when p_error is null then o.last_error_at else now() end,
         updated_at    = now()
   where o.id = p_order_id and o.status = 'settling'
  returning o.*;
$$;

/* Terminal give-up. Nothing retries a needs_human row; a person does. */
create or replace function app.give_up(p_order_id uuid, p_error text)
returns setof public.orders
language sql volatile as $$
  update public.orders o
     set status = 'needs_human',
         settle_lease_until = null,
         settle_lease_owner = null,
         last_error = p_error,
         last_error_at = now(),
         updated_at = now()
   where o.id = p_order_id
     and o.status in ('creating','awaiting_payment','settling','payment_confirmed')
  returning o.*;
$$;

/* Sweeper claim: expired unpaid QRs. Never touches payment_confirmed. */
create or replace function app.claim_abandoned_orders(
  p_limit integer default 50,
  p_lease_seconds integer default 60,
  p_instance text default null,
  p_max_attempts integer default 10
) returns setof public.orders
language sql volatile as $$
  with candidate as (
    select o.id from public.orders o
     where o.expires_at < now()
       and o.status in ('creating','awaiting_payment','settling')
       and o.settle_attempts < p_max_attempts
       and (o.status <> 'settling' or o.settle_lease_until < now())
     order by o.expires_at
     limit p_limit
     for update skip locked
  )
  update public.orders o
     set status = 'settling',
         settle_lease_until = now() + make_interval(secs => p_lease_seconds),
         settle_lease_owner = p_instance,
         settle_attempts = o.settle_attempts + 1,
         updated_at = now()
    from candidate c
   where o.id = c.id
  returning o.*;
$$;

/* Drain worker: money in, machine not told (or told and never ACKed). */
create or replace function app.claim_unnotified_orders(
  p_limit integer default 20,
  p_lease_seconds integer default 60,
  p_instance text default null,
  p_notify_grace_seconds integer default 120,
  p_max_attempts integer default 10
) returns setof public.orders
language sql volatile as $$
  with candidate as (
    select o.id from public.orders o
     where o.status in ('payment_confirmed','settling')
       and o.product_done_at is null
       and o.settle_attempts < p_max_attempts
       and o.payment_confirmed_at < now() - interval '30 seconds'
       and (o.notify_sent_at is null
            or o.notify_sent_at < now() - make_interval(secs => p_notify_grace_seconds))
       and (o.status <> 'settling' or o.settle_lease_until < now())
     order by o.payment_confirmed_at
     limit p_limit
     for update skip locked
  )
  update public.orders o
     set status = 'settling',
         settle_lease_until = now() + make_interval(secs => p_lease_seconds),
         settle_lease_owner = p_instance,
         settle_attempts = o.settle_attempts + 1,
         updated_at = now()
    from candidate c
   where o.id = c.id
  returning o.*;
$$;

/*
 * The machine says the cup came out. Load-bearing, not bookkeeping: this
 * permanently blocks every future settle claim.
 *
 * Only accepted for an order we actually told to brew. A forged productdone
 * for an awaiting_payment order would otherwise poison it forever and stop
 * that machine selling.
 */
create or replace function app.record_product_done(p_order_id uuid, p_ok boolean)
returns setof public.orders
language sql volatile as $$
  update public.orders o
     set product_done_at = coalesce(o.product_done_at, now()),
         product_done_ok = coalesce(o.product_done_ok, p_ok),
         updated_at = now()
   where o.id = p_order_id
     and o.status in ('settling','payment_confirmed','paid')
  returning o.*;
$$;

create or replace function app.mark_cancelled(p_order_id uuid)
returns setof public.orders
language sql volatile as $$
  update public.orders o
     set status = 'cancelled', cancelled_at = now(),
         settle_lease_until = null, settle_lease_owner = null, updated_at = now()
   where o.id = p_order_id and o.status = 'settling' and o.payment_confirmed_at is null
  returning o.*;
$$;

commit;
```

### `migrations/002_supabase_rls.sql`

```sql
-- =====================================================================
-- jetinno-qpay-bridge — migration 002_supabase_rls.sql
-- SUPABASE ONLY (needs auth.users, anon, authenticated). Never run in the e2e.
-- The bridge connects as service_role and bypasses all of this; everything
-- here exists for the future owner dashboard and is READ-ONLY by design.
-- =====================================================================

begin;

create table public.owner_members (
  owner_id   uuid not null references public.owners(id) on delete cascade,
  user_id    uuid not null references auth.users(id) on delete cascade,
  role       text not null default 'viewer' check (role in ('admin','viewer')),
  created_at timestamptz not null default now(),
  primary key (owner_id, user_id)
);
create index owner_members_user_idx on public.owner_members (user_id);

-- STABLE so the planner calls it once per statement, not once per row.
-- SECURITY DEFINER so the policies below do not recurse into owner_members' RLS.
create or replace function app.my_owner_ids() returns uuid[]
language sql stable security definer set search_path = '' as $$
  select coalesce(array_agg(m.owner_id), '{}'::uuid[])
    from public.owner_members m
   where m.user_id = (select auth.uid());
$$;

alter table public.owners              enable row level security;
alter table public.owner_members       enable row level security;
alter table public.qpay_credentials    enable row level security;
alter table public.machines            enable row level security;
alter table public.machine_assignments enable row level security;
alter table public.orders              enable row level security;
alter table public.order_events        enable row level security;
alter table public.ingest_errors       enable row level security;
alter table public.admin_audit         enable row level security;

create policy owners_read_own on public.owners
  for select to authenticated using (id = any (app.my_owner_ids()));
create policy owner_members_read_own on public.owner_members
  for select to authenticated using (owner_id = any (app.my_owner_ids()));
create policy machines_read_own on public.machines
  for select to authenticated using (owner_id = any (app.my_owner_ids()));
create policy machine_assignments_read_own on public.machine_assignments
  for select to authenticated using (owner_id = any (app.my_owner_ids()));
create policy orders_read_own on public.orders
  for select to authenticated using (owner_id = any (app.my_owner_ids()));
create policy order_events_read_own on public.order_events
  for select to authenticated using (owner_id = any (app.my_owner_ids()));

-- qpay_credentials, ingest_errors and admin_audit get RLS with ZERO policies,
-- plus an explicit REVOKE. Two layers on purpose: RLS alone makes PostgREST
-- return a confusing empty array; the REVOKE returns a clear permission error.
revoke all on public.qpay_credentials from anon, authenticated;
revoke all on public.ingest_errors    from anon, authenticated;
revoke all on public.admin_audit      from anon, authenticated;

grant usage on schema public to anon, authenticated;
grant select on public.owners, public.owner_members, public.machines,
                public.machine_assignments, public.orders, public.order_events
  to authenticated;

grant usage on schema app to authenticated;
grant execute on function app.my_owner_ids() to authenticated;

-- The settle/claim helpers belong to the bridge alone.
revoke all on function app.claim_order_for_settle(uuid,integer,text,integer,integer) from public;
revoke all on function app.mark_payment_confirmed(uuid,text,integer,integer)          from public;
revoke all on function app.mark_notify_sent(uuid)                                     from public;
revoke all on function app.finish_settle(uuid)                                        from public;
revoke all on function app.release_settle(uuid,text,boolean)                          from public;
revoke all on function app.give_up(uuid,text)                                         from public;
revoke all on function app.claim_abandoned_orders(integer,integer,text,integer)        from public;
revoke all on function app.claim_unnotified_orders(integer,integer,text,integer,integer) from public;
revoke all on function app.record_product_done(uuid,boolean)                          from public;
revoke all on function app.mark_cancelled(uuid)                                       from public;
revoke all on function app.audit_row()                                                from public;

-- security_invoker so RLS evaluates as the caller. A view without it is the
-- classic Supabase RLS bypass.
create view public.owner_orders with (security_invoker = true) as
  select o.id, o.owner_id, o.machine_id, m.device_no, m.label as machine_label,
         o.order_no, o.product_name, o.amount_mnt, o.paid_amount_mnt, o.status,
         o.created_at, o.payment_confirmed_at, o.notified_at, o.product_done_at
    from public.orders o
    join public.machines m on m.id = o.machine_id;
grant select on public.owner_orders to authenticated;

commit;
```

Do **not** add `FORCE ROW LEVEL SECURITY` — it does not constrain `service_role` and only risks locking out admin tooling.

---

## 3. `src/crypto.js` — complete

Verified on Node 26: 30 assertions pass, `open()` = 14.8 µs/op over 20 000 iterations, sealed blob = 176 chars.

```js
/**
 * src/crypto.js — authenticated encryption for owner QPay credentials at rest.
 *
 * ONE sealed blob per credential row, AES-256-GCM, fresh random 96-bit IV per
 * write, full 128-bit tag, and the row identity (credential id + owner id)
 * bound in as AAD so a ciphertext can never be relocated to another row.
 *
 * Threat model: this protects against someone who obtains the DATABASE and
 * nothing else — a Supabase breach, a leaked read-only DB credential, a stolen
 * pg_dump, an RLS misconfiguration. It protects against nothing else. See
 * section 8 of the implementation plan.
 *
 * Decryption is ~15µs. It is free against Jetinno's 8-second budget; the
 * network hops around it are what need caching, not this.
 */
import { createCipheriv, createDecipheriv, randomBytes, hkdfSync, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';

const ALGO = 'aes-256-gcm';
const IV_BYTES = 12;  // 96 bits: the only IV length AES-GCM is properly specified for.
const TAG_BYTES = 16; // 128 bits. Never truncated.
const FORMAT = 'v1';
const INFO_ENC = 'jetinno-qpay-bridge/owner-credentials/v1';
const INFO_FP = 'jetinno-qpay-bridge/credential-fingerprint/v1';
const KEY_ID_RE = /^[a-z0-9][a-z0-9_-]{0,15}$/;

const b64u = (buf) => buf.toString('base64url');
const canonB64 = (s) => s.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');

export class CredentialCryptoError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'CredentialCryptoError';
    this.code = code; // NO_KEYRING | UNKNOWN_KEY | BAD_FORMAT | AUTH_FAILED | BAD_PAYLOAD
  }
}

const fail = (code, message) => {
  throw new CredentialCryptoError(code, message);
};

/**
 * Decode 32 bytes of base64 key material, refusing anything that does not
 * round-trip. Buffer.from(str,'base64') NEVER throws: it silently skips
 * characters it does not recognise and stops at the first padding run, so a
 * truncated paste becomes a short key and — the nastier case — a key with
 * trailing junk still decodes to exactly 32 bytes and sails past a length
 * check, quietly encrypting under a key nobody can reproduce tomorrow.
 */
function decodeKey(label, b64) {
  const raw = Buffer.from(b64, 'base64');
  if (raw.length !== 32) fail('NO_KEYRING', `${label} decoded to ${raw.length} bytes, need 32`);
  if (canonB64(raw.toString('base64')) !== canonB64(b64)) {
    fail('NO_KEYRING', `${label} is not clean base64 — check for a truncated or padded paste`);
  }
  return raw;
}

/** hkdfSync returns an ArrayBuffer in Node, not a Buffer. createCipheriv throws on it. */
const derive = (master, info) => Buffer.from(hkdfSync('sha256', master, Buffer.alloc(0), info, 32));

const SECRET_FILE = process.env.CRED_KEYS_FILE ?? '/etc/secrets/cred_keys';

/**
 * Two sources, and NEVER a silent preference between them. An operator who
 * rotates the secret file but leaves a stale env var behind would otherwise
 * start encrypting under the wrong key with no signal at all.
 */
function readSource(filePath, envName) {
  let fromFile = null;
  try {
    fromFile = readFileSync(filePath, 'utf8').trim();
  } catch {
    fromFile = null;
  }
  const fromEnv = (process.env[envName] ?? '').trim();

  if (fromFile && fromEnv && fromFile !== fromEnv) {
    fail('NO_KEYRING', `${envName} and ${filePath} are both set and disagree — remove one`);
  }
  const value = fromFile || fromEnv;
  if (!value) fail('NO_KEYRING', `${envName} is not set — refusing to start`);
  return { value, source: fromFile ? `file:${filePath}` : `env:${envName}` };
}

function buildKeyring() {
  const { value, source } = readSource(SECRET_FILE, 'CRED_KEYS');

  const keys = new Map();
  for (const entry of value.split(/[,\n]/)) {
    const line = entry.trim();
    if (!line || line.startsWith('#')) continue;

    const at = line.indexOf(':');
    if (at < 1) fail('NO_KEYRING', 'CRED_KEYS entry is not <keyId>:<base64>');
    const keyId = line.slice(0, at).trim();
    const b64 = line.slice(at + 1).trim();

    // The key id travels inside every ciphertext string, so keep it to a
    // charset that can never collide with the '.' separator.
    if (!KEY_ID_RE.test(keyId)) fail('NO_KEYRING', `bad key id: ${keyId}`);
    if (keys.has(keyId)) fail('NO_KEYRING', `duplicate key id: ${keyId}`);

    const master = decodeKey(`key ${keyId}`, b64);
    // HKDF so this master is only ever used for this one purpose. If the same
    // secret is later reused to sign webhooks or cookies, each purpose gets its
    // own subkey and no two share raw key bytes. Microseconds, once, at boot.
    const enc = derive(master, `${INFO_ENC}#${keyId}`);
    master.fill(0);
    keys.set(keyId, enc);
  }
  if (keys.size === 0) fail('NO_KEYRING', 'CRED_KEYS contained no usable entries');

  const activeId = (process.env.CRED_KEY_ACTIVE ?? '').trim() || [...keys.keys()][0];
  if (!keys.has(activeId)) fail('NO_KEYRING', `CRED_KEY_ACTIVE=${activeId} is not in CRED_KEYS`);

  // Fingerprints use their own key, deliberately OUTSIDE the rotating keyring:
  // a fingerprint must stay stable across a master-key rotation or the unique
  // index that stops two owners registering the same merchant silently splits
  // into two namespaces mid-rotation.
  const fpSource = readSource(process.env.CRED_FP_KEY_FILE ?? '/etc/secrets/cred_fp_key', 'CRED_FP_KEY');
  const fpMaster = decodeKey('CRED_FP_KEY', fpSource.value);
  const fpKey = derive(fpMaster, INFO_FP);
  fpMaster.fill(0);

  return { keys, activeId, fpKey, source, fpKeySource: fpSource.source };
}

let keyring = null;

/**
 * Parsed once at module load, never re-read. Rotating keys means a redeploy,
 * which is the correct blast radius: a live process must never switch keys
 * underneath an in-flight request.
 */
function ring() {
  if (!keyring) keyring = buildKeyring();
  return keyring;
}

/**
 * Call once at boot, before app.listen. A bad or missing key must fail the
 * deploy loudly, not the first customer of the morning.
 */
export function assertCryptoUsable() {
  const r = ring();
  const context = credentialAad({
    credentialId: '00000000-0000-4000-8000-000000000000',
    ownerId: '00000000-0000-4000-8000-000000000001',
  });
  const probe = seal({ probe: true }, { context });
  if (open(probe, { context }).probe !== true) fail('AUTH_FAILED', 'keyring self-test failed');
  if (fingerprint('selftest').length !== 64) fail('AUTH_FAILED', 'fingerprint self-test failed');
  return {
    activeKeyId: r.activeId,
    keyIds: [...r.keys.keys()],
    keyringSource: r.source,
    fpKeySource: r.fpKeySource,
  };
}

export const activeKeyId = () => ring().activeId;

/**
 * The additional authenticated data for a credential row.
 *
 * Binding BOTH ids matters. Without the credential id, blobs are swappable
 * between one owner's own rows; without the owner id, an attacker with UPDATE
 * re-parents a credential row to themselves. With both bound, either move
 * fails authentication instead of silently redirecting an owner's revenue.
 * Changing either id on a live row therefore requires a deliberate rewrap —
 * that is the intent, not an inconvenience.
 */
export function credentialAad({ credentialId, ownerId }) {
  if (!credentialId || !ownerId) fail('BAD_PAYLOAD', 'credentialAad needs credentialId and ownerId');
  return `qpay_credentials:${credentialId}|owner:${ownerId}`;
}

function aadFor(context) {
  if (typeof context !== 'string' || context.length === 0 || context.length > 200) {
    fail('BAD_PAYLOAD', 'context must be a short non-empty string');
  }
  return Buffer.from(`${FORMAT}|${context}`, 'utf8');
}

/**
 * Seals an object into `v1.<keyId>.<iv>.<tag>.<ciphertext>` (base64url parts).
 *
 * Self-describing on purpose: the key id travels with the ciphertext, so a row
 * can never disagree with a separate "which key" column. The key_id column in
 * Postgres is a denormalised copy for `WHERE key_id <> $active` during
 * rotation — this string is the authority.
 */
export function seal(value, { context }) {
  const { keys, activeId } = ring();
  const aad = aadFor(context);
  const plaintext = Buffer.from(JSON.stringify(value), 'utf8');

  // Fresh random IV on EVERY call, including a re-save of unchanged values.
  // Never derived from an id, never a counter, never an IV column reused on
  // update. A repeated (key, IV) pair under GCM leaks the XOR of both
  // plaintexts AND the GHASH subkey, which yields forged tags under that key
  // forever. 96 random bits is safe well past the seals this system will make.
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGO, keys.get(activeId), iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad, { plaintextLength: plaintext.length }); // must precede update()
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag(); // only valid after final()

  plaintext.fill(0);
  return [FORMAT, activeId, b64u(iv), b64u(tag), b64u(ct)].join('.');
}

/** Opens a sealed string. Throws on tampering, wrong context, or unknown key. */
export function open(sealed, { context }) {
  if (typeof sealed !== 'string') fail('BAD_FORMAT', 'sealed value is not a string');
  const parts = sealed.split('.');
  if (parts.length !== 5 || parts[0] !== FORMAT) fail('BAD_FORMAT', 'sealed value is not a v1 blob');

  const [, keyId, ivB64, tagB64, ctB64] = parts;
  const key = ring().keys.get(keyId);
  // A missing key is an operational error, not an attack: a key was retired
  // from CRED_KEYS before every row had been rewrapped. Say so plainly.
  if (!key) fail('UNKNOWN_KEY', `no key "${keyId}" in keyring — was it retired too early?`);

  const iv = Buffer.from(ivB64, 'base64url');
  const tag = Buffer.from(tagB64, 'base64url');
  const ct = Buffer.from(ctB64, 'base64url');
  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) fail('BAD_FORMAT', 'bad iv or tag length');

  const decipher = createDecipheriv(ALGO, key, iv, { authTagLength: TAG_BYTES });
  decipher.setAAD(aadFor(context));
  decipher.setAuthTag(tag); // must be set before final()

  let plaintext;
  try {
    // final() is what verifies the tag. Skipping it — or catching its throw and
    // using the update() output anyway — silently downgrades this to
    // unauthenticated CTR mode. No manual timingSafeEqual: OpenSSL's GCM tag
    // check is already constant-time, and a hand-rolled one is a bug waiting.
    plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    // Deliberately opaque: never echo iv/tag/ciphertext into logs or HTTP.
    fail('AUTH_FAILED', `ciphertext failed authentication (key ${keyId})`);
  }

  try {
    return JSON.parse(plaintext.toString('utf8'));
  } finally {
    // Narrows the window; does not close it. The JSON.stringify intermediate is
    // an immutable GC-managed string that cannot be wiped, and the decrypted
    // object lives in the credential cache by design. A heap dump of this
    // process contains plaintext credentials.
    plaintext.fill(0);
  }
}

export const sealedKeyId = (sealed) => (typeof sealed === 'string' ? sealed.split('.')[1] : null);
export const needsRewrap = (sealed) => sealedKeyId(sealed) !== ring().activeId;

/**
 * Rotation primitive: open with whatever key sealed it, re-seal under the
 * active key, and verify the new blob before the caller writes it back. The
 * verify is cheap and turns "rewrap silently corrupted 40 owners" into a
 * failed job.
 */
export function rewrap(sealed, { context }) {
  const value = open(sealed, { context });
  const resealed = seal(value, { context });
  if (JSON.stringify(open(resealed, { context })) !== JSON.stringify(value)) {
    fail('AUTH_FAILED', 'rewrap verification failed');
  }
  return resealed;
}

/**
 * Keyed fingerprint of a merchant identity. A plain SHA-256 would be
 * brute-forceable — QPay usernames are short and structured — which would hand
 * a database reader half the Basic auth pair from a dump with no key at all.
 */
export function fingerprint(text) {
  if (typeof text !== 'string' || !text) fail('BAD_PAYLOAD', 'fingerprint needs a non-empty string');
  return createHmac('sha256', ring().fpKey).update(text, 'utf8').digest('hex');
}

/** The canonical identity string a merchant fingerprint is taken over. */
export const merchantIdentity = ({ username, invoiceCode }) =>
  `${String(username).trim().toLowerCase()}:${String(invoiceCode).trim()}`;
```

---

## 4. Exactly what changes in `src/qpay.js` and `src/server.js`

### 4a. `src/qpay.js` — replaced in full

Every `process.env` read and the module-level `let tokenCache = null` are deleted. `qpayConfigured()` is deleted. The module-level `createInvoice` / `checkPayment` / `cancelInvoice` exports are deleted, so nothing can call QPay without naming an owner.

```js
/**
 * QPay v2 merchant API, per owner.
 *
 * Ported from the working gmath.mn integration. Three details cost real
 * incidents to get right — the token cache's expires_in handling, the PAID
 * status check, and cancelInvoice's treatment of INVOICE_PAID. Read the
 * comments before simplifying any of them.
 */
import crypto from 'node:crypto';
import { Agent, fetch as undiciFetch } from 'undici';

// A coffee machine sells a few times an hour. Node's global dispatcher drops
// idle sockets after 4s, so without a pinned agent EVERY sale pays a fresh
// TCP+TLS handshake to Ulaanbaatar — ~350ms of the 8s budget, every cup.
const agent = new Agent({ keepAliveTimeout: 600_000, keepAliveMaxTimeout: 900_000, connections: 8 });

// The ONLY hosts this bridge will ever send a merchant password to. base_url is
// deliberately global and never a database column: a plaintext destination
// column beside the ciphertext lets anyone with UPDATE on one text field
// exfiltrate every owner's plaintext credentials on their next sale.
const ALLOWED_BASE_URLS = new Set(['https://merchant.qpay.mn', 'https://merchant-sandbox.qpay.mn']);

export function resolveBaseUrl() {
  const raw = (process.env.QPAY_BASE_URL ?? 'https://merchant.qpay.mn').replace(/\/+$/, '');
  const allowExtra = (process.env.QPAY_BASE_URL_ALLOW_EXTRA ?? '').split(',').map((s) => s.trim().replace(/\/+$/, '')).filter(Boolean);
  const allowed = new Set([...ALLOWED_BASE_URLS, ...allowExtra]);
  if (!allowed.has(raw)) throw new Error(`QPAY_BASE_URL ${raw} is not in the allowlist`);
  // QPAY_BASE_URL_ALLOW_EXTRA exists ONLY so the e2e can point at
  // http://localhost:4310. It must never be set on the live service.
  if (!raw.startsWith('https://') && !allowExtra.includes(raw)) throw new Error('QPAY_BASE_URL must be https');
  return raw;
}

/**
 * Tokens are cached under a digest of the CREDENTIALS, never under an ownerId.
 *
 * This is the whole safety argument for multi-tenancy. Keyed by ownerId, any
 * bug in deviceNo->owner resolution would hand owner A's bearer token to a call
 * carrying owner B's invoice_code, and the money would land in the wrong
 * merchant account. Keyed by the credentials, a token can only be returned to a
 * caller that presented the exact username/password/base_url that minted it —
 * a resolution bug then produces a clean auth failure, never a silent misroute.
 *
 * base_url is inside the digest because sandbox and production share usernames.
 *
 * The value holds a PROMISE, not a token, so N concurrent requests for one
 * owner make ONE auth call (QPay forbids fetching a token per request).
 */
const tokens = new Map(); // credDigest -> { ownerId, inflight, expiresAtMs, tokenPromise }

const digest = ({ baseUrl, username, password }) =>
  crypto.createHash('sha256').update(`${baseUrl}\0${username}\0${password}`).digest('hex');

const redactWith = (creds) => (text) => {
  let s = String(text ?? '');
  if (creds.username) s = s.split(creds.username).join('<user>');
  if (creds.password) s = s.split(creds.password).join('<pass>');
  return s;
};

export function forOwner({ ownerId, credentialId, username, password, invoiceCode, baseUrl }) {
  if (!ownerId || !credentialId || !username || !password || !invoiceCode) {
    throw new Error('qpay.forOwner: incomplete credentials');
  }
  const base = baseUrl ?? resolveBaseUrl();
  const creds = { baseUrl: base, username, password };
  const key = digest(creds);
  const redact = redactWith(creds);

  // Redaction happens where the credentials are in scope, not at call sites.
  const detail = (res) => res.text().then((t) => redact(t).slice(0, 300)).catch(() => '');

  async function accessToken() {
    const now = Date.now();
    const hit = tokens.get(key);
    // `inflight` short-circuits the 60s skew window. Without it a placeholder
    // expiry shorter than the skew makes EVERY concurrent caller miss, so the
    // single-flight never fires — which is exactly the behaviour QPay forbids.
    if (hit && (hit.inflight || hit.expiresAtMs - 60_000 > now)) {
      // Belt to the digest's braces. If this fires, the Map was mutated or the
      // resolution layer is confused. Fail loudly rather than pay the wrong
      // merchant.
      if (hit.ownerId !== ownerId) {
        tokens.delete(key);
        throw new Error(`qpay token cache owner mismatch (${hit.ownerId} vs ${ownerId})`);
      }
      return hit.tokenPromise;
    }

    const basic = Buffer.from(`${username}:${password}`).toString('base64');
    // Captured in a LOCAL const: writing through tokens.get(key) races with the
    // .catch eviction below and throws TypeError inside the shared promise.
    const entry = { ownerId, inflight: true, expiresAtMs: 0, tokenPromise: null };
    entry.tokenPromise = (async () => {
      const res = await undiciFetch(`${base}/v2/auth/token`, {
        method: 'POST',
        headers: { Authorization: `Basic ${basic}` },
        dispatcher: agent,
        // INDEPENDENT signal, never the caller's request deadline: this promise
        // is shared, and one caller timing out must not abort another's token.
        signal: AbortSignal.timeout(Number(process.env.QPAY_TOKEN_TIMEOUT_MS ?? 2500)),
      });
      if (!res.ok) throw new Error(`qpay auth ${res.status}: ${await detail(res)}`);
      const json = await res.json();

      // UNCHANGED from the original — this cost a real incident. QPay's docs
      // call expires_in a duration in seconds, but real responses sometimes
      // carry an absolute unix timestamp. Anything past ~120 days is treated as
      // absolute rather than trusted as a duration.
      const asDurationMs = json.expires_in * 1000;
      entry.expiresAtMs =
        asDurationMs > 1000 * 60 * 60 * 24 * 120 ? asDurationMs : Date.now() + asDurationMs;
      entry.inflight = false;
      return json.access_token;
    })();

    tokens.set(key, entry);
    entry.tokenPromise.catch(() => {
      if (tokens.get(key) === entry) tokens.delete(key);
    });
    return entry.tokenPromise;
  }

  async function authed(path, init, signal) {
    const token = await accessToken();
    return undiciFetch(`${base}${path}`, {
      ...init,
      headers: { ...init.headers, Authorization: `Bearer ${token}` },
      dispatcher: agent,
      signal: signal ?? AbortSignal.timeout(Number(process.env.QPAY_CALL_TIMEOUT_MS ?? 5000)),
    });
  }

  return {
    ownerId,
    credentialId,

    /**
     * `senderInvoiceNo` must be unique for this merchant FOREVER — QPay rejects
     * a repeat permanently. It is passed in separately from orderNo so a
     * client-side timeout can retry under `${base}-2` instead of killing the
     * order.
     */
    async createInvoice({ senderInvoiceNo, amount, description, callbackUrl, signal }) {
      const res = await authed('/v2/invoice', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          invoice_code: invoiceCode,
          sender_invoice_no: senderInvoiceNo,
          invoice_receiver_code: 'terminal',
          invoice_description: description,
          amount,
          callback_url: callbackUrl,
        }),
      }, signal);
      if (!res.ok) throw new Error(`qpay invoice ${res.status}: ${await detail(res)}`);
      const json = await res.json();
      return {
        invoiceId: json.invoice_id,
        qrText: json.qr_text,
        qrImage: json.qr_image,
        shortUrl: json.qPay_shortUrl,
      };
    },

    /**
     * The authoritative answer to "was this paid?". Always call before telling
     * the machine to brew — the callback only says WHEN to look, it is never
     * itself proof. Do not put this on a timer; QPay forbids cron polling.
     */
    async checkPayment(invoiceId, signal) {
      const res = await authed('/v2/payment/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          object_type: 'INVOICE',
          object_id: invoiceId,
          offset: { page_number: 1, page_limit: 100 },
        }),
      }, signal);
      if (!res.ok) throw new Error(`qpay check ${res.status}: ${await detail(res)}`);
      const json = await res.json();
      const rows = (json.rows ?? []).map((r) => ({
        paymentId: String(r.payment_id),
        status: r.payment_status,
        amount: Number(r.payment_amount),
      }));
      const settledRows = rows.filter((r) => r.status === 'PAID');
      // Sum, not "find the first". A partial payment must not brew a full cup;
      // an overpayment must not be silently pocketed. server.js compares this
      // total to orders.amount_mnt before anything else happens.
      const paidTotal = settledRows.reduce((n, r) => n + r.amount, 0);
      return {
        paid: settledRows.length > 0,
        paidTotal,
        paymentId: settledRows[0]?.paymentId,
        rows,
      };
    },

    /**
     * Voids an invoice nobody paid, so its QR can never be paid later.
     *
     * A 404 and INVOICE_ALREADY_CANCELED both mean "already gone". INVOICE_PAID
     * is different and must never be swallowed: the customer did pay, and the
     * caller has to settle instead of voiding.
     */
    async cancelInvoice(invoiceId, signal) {
      const res = await authed(`/v2/invoice/${invoiceId}`, { method: 'DELETE' }, signal);
      if (res.ok || res.status === 404) return { cancelled: true };
      const text = await detail(res);
      if (text.includes('INVOICE_ALREADY_CANCELED')) return { cancelled: true };
      if (text.includes('INVOICE_PAID')) return { cancelled: false, paid: true };
      throw new Error(`qpay cancel ${res.status}: ${text}`);
    },
  };
}

/** For GET /health. Never exposes credentials or tokens. */
export const stats = () => ({ cachedTokens: tokens.size });
```

### 4b. New supporting modules

**`src/db.js`** — `pg` Pool against the Supabase transaction pooler.

```js
import pg from 'pg';
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  max: Number(process.env.PG_POOL_MAX ?? 5),
  connectionTimeoutMillis: 1500,   // fail fast: a hung DB must not eat the 8s budget
  idleTimeoutMillis: 30_000,
});
// A lock wait on the orders row would otherwise silently consume the Jetinno
// budget and look exactly like QPay being slow.
pool.on('connect', (c) => c.query(`set statement_timeout = ${Number(process.env.PG_STATEMENT_TIMEOUT_MS ?? 800)}`));
export const query = (text, params) => pool.query(text, params);
export const healthy = () => pool.query('select 1').then(() => true).catch(() => false);
export const close = () => pool.end();
```
Do **not** add named prepared statements or `PREPARE` — transaction-mode pgbouncer does not support them. Do **not** use `supabase-js`/PostgREST on the hot path.

**`src/store.js`** — one thin function per SQL statement in section 2 (`resolveMachine`, `pinNotifyUrl`, `findOrderByMachine`, `beginOrder`, `attachInvoice`, `bumpInvoiceAttempt`, `getOrderById`, `findOrdersByOrderNo`, `claimSettle`, `markPaymentConfirmed`, `markNotifySent`, `finishSettle`, `releaseSettle`, `giveUp`, `claimAbandoned`, `claimUnnotified`, `recordProductDone`, `markCancelled`, `logEvent`, `logIngestError`, `credentialHealth`). Every one is a single statement; never wrap `settle()` in a transaction — that would pin a pooled connection across two outbound HTTP calls.

**`src/owners.js`** — `deviceNo → { machine, owner, qpay client }`.
- In-process cache keyed by `deviceNo`, TTL 60 s, **stale-if-error capped at 15 minutes** (not 24 hours), and never stale for a machine whose last good lookup said `status <> 'active'`.
- The cache entry stores `machines.updated_at` and `qpay_credentials.updated_at`; a changed value on the next refresh is an immediate miss.
- `forgetDevice(deviceNo)` is exported, and **every** write path that touches `machines.owner_id`, `machines.qpay_credential_id`, `machines.status`, `owners.status` or a credential row must call it. Put the UPDATE and the invalidation in one function so it cannot be forgotten.
- `forOrder(order)` builds a client from `order.owner_id` + `order.qpay_credential_id` — this is the settle path and it never touches `deviceNo`.
- On a QPay auth failure, increment `qpay_credentials.auth_fail_count`; at 3 consecutive failures short-circuit that owner for 60 s. One owner's bad credentials must not burn the token timeout on every sale, and must never affect another owner.

**`scripts/add-owner.js`** — offline CLI. Prompts for username/password/invoice_code, generates the credential uuid, seals with `credentialAad`, computes the keyed fingerprint, INSERTs. The operator never pastes a plaintext QPay password into the Supabase SQL editor, where it persists in query history.

**`scripts/rewrap-credentials.js`** — `select id, owner_id, sealed from qpay_credentials where key_id <> $active`, then per row `rewrap()` and `update … where id = $1 and sealed = $2` (optimistic guard, so an owner who changed credentials mid-job is never reverted). Re-run until it reports 0.

**`scripts/fake-qpay.js`** — see section 7.

### 4c. `src/server.js` — change list

**Boot (top of file).**
```js
const required = (n) => { const v = process.env[n]; if (!v) { console.error(`${n} is not set — refusing to start`); process.exit(1); } return v; };
const APIKEY   = required('JETINNO_APIKEY');    // DELETE the ?? 'DBRW17YE7FHKR72T' fallback
const USERNAME = required('JETINNO_USERNAME');  // DELETE the ?? 'testname' fallback
const QPAY_BASE = qpay.resolveBaseUrl();        // throws on a non-allowlisted host
const cryptoHealth = assertCryptoUsable();      // fails the deploy, not the first customer
const INSTANCE = process.env.RENDER_INSTANCE_ID ?? `local-${process.pid}`;
```
Delete the same hardcoded fallbacks from `src/simulate-machine.js:4-5`. Rotate the Jetinno key with Jetinno if the repo has ever been shared. Then `await db.healthy()`, then `app.listen`, then fire-and-forget a token warm-up for each active owner (concurrency 3, errors logged not thrown) so the first customer after a deploy does not pay the ~820 ms cold-auth line.

**Delete entirely:** `const MOCK`, both `if (MOCK)` branches (lines 84-85 and 189), `app.all('/mock/pay/:orderNo', …)` (line 233), `const orders = new Map()` (line 28), and the `AMOUNT_DIVISOR` global (it becomes `machine.amount_divisor`).

**`fail()` stops echoing upstream text.**
```js
function fail(res, code, detail) {
  const incident = crypto.randomBytes(4).toString('hex');
  log('FAIL', code, incident, detail ?? '');   // full detail: server-side only
  res.json({ returnCode: 'FAIL', msg: detail ? `${code}: ${incident}` : code });
}
```
Jetinno only checks `returnCode`. The detailed string buys the caller nothing and costs you QPay usernames, `pg` statement text and internal key ids in an HTTP response and in the `/recent` ring.

**`POST /jetinno/getQrCode` — new order of operations.**
1. `log`, `verifySign` → `failSign` on failure. (Unchanged.)
2. `const machine = await owners.resolveDevice(deviceNo)`. Null → `store.logIngestError({path, deviceNo, orderNo, reason:'UNKNOWN_DEVICE'})` and `fail(res, 'DEVICE_NOT_REGISTERED')`, in under ~10 ms with zero QPay contact. **No default merchant, ever.**
3. `const amount = Math.round(Number(orderAmount) / machine.amount_divisor)`; non-finite or ≤ 0 → `fail(res, 'PARAM_ERROR')`.
4. Replay check: `const existing = await store.findOrderByMachine(machine.id, orderNo)`.
   - `existing && (existing.device_no !== deviceNo || existing.raw_order_amount !== String(orderAmount))` → `fail(res, 'ORDERNO_EXIST')`. **The amount comparison is new and load-bearing:** without it a pre-created 1₮ order gets replayed for a 5000₮ coffee.
   - `existing?.qr_code` → `log('getQrCode replay ->', …)` and respond with the stored QR. **Keep that exact log string** — `scripts/e2e.sh` greps for it.
   - `existing && existing.status === 'creating'` → poll `findOrderByMachine` every 250 ms for up to 5 s waiting for the concurrent winner's QR; then `fail(res, 'SYSTEM_ERROR', 'invoice still being created')`. Never create a second invoice.
5. `notify_url`: trust-on-first-use. If `machine.notify_url` is null, validate the body value (`http:`/`https:` only; reject private/loopback/link-local hosts unless `ALLOW_PRIVATE_NOTIFY_URL=1`) and `store.pinNotifyUrl(machine.id, url)`. If it is already pinned and the body differs, log `ingest_errors` reason `NOTIFY_URL_CHANGED` and **use the pinned one anyway**.
6. Build `senderInvoiceNo`: `${deviceNo}-${orderNo}` if ≤ 43 chars, else the order uuid hex; append `-${attempt}` for attempt ≥ 2.
7. **INSERT the order BEFORE calling QPay**, `on conflict do nothing returning id`. Zero rows means a concurrent retry won — go back to step 4. This closes a race that exists in the live code today: `orders.set()` at line 101 happens *after* `await qpay.createInvoice` at line 86, so two retries inside the same 8 s window both create invoices and the second permanently burns that `sender_invoice_no`.
8. `const deadline = AbortSignal.timeout(Number(process.env.REQUEST_DEADLINE_MS ?? 6500))` — one deadline for the whole request, not per-hop timeouts that sum past 8 s. `const invoice = await machine.qpay.createInvoice({ senderInvoiceNo, amount, description: `${deviceNo}/${orderNo} ${productName || productId}`, callbackUrl: `${PUBLIC_URL}/qpay/callback/${orderId}`, signal: deadline })`. The description carries the human-readable ids into the owner's QPay portal, since `sender_invoice_no` may be a uuid.
9. `qrCode = invoice.shortUrl ?? invoice.qrText`; the existing null and >128 checks stay.
10. `store.attachInvoice(...)`, retried 3× at 100 ms. If it still fails: best-effort `cancelInvoice`, mark the order `orphaned`, `fail(res, 'SYSTEM_ERROR')`. Leaving a payable QR we have no `invoice_id` for is the one outcome worse than not selling.
11. `respond(...)`, unchanged shape.
12. `catch`: mark the order `failed` and `bumpInvoiceAttempt` so the machine's retry starts a fresh attempt under `${base}-2`, then `fail(res, 'SYSTEM_ERROR', err.message)`.

**`POST /jetinno/productdone`.** Verify sign → resolve machine → `findOrderByMachine` → `store.recordProductDone(order.id, isFinish)`. Zero rows → `logIngestError(reason:'PRODUCTDONE_UNEXPECTED')`. Always answer `{returnCode:'SUCCESS'}` regardless — never tell a caller whether the order existed.

**`notifyMachine(order)`** takes the order row and uses `order.notify_url` (the pinned value). The 8 s `AbortSignal.timeout` stays.

**`settle()` splits in two.**
```js
async function claimAndSettle(orderId) {
  const [order] = await store.claimSettle(orderId, LEASE_S, INSTANCE, NOTIFY_GRACE_S);
  if (!order) return { ok: false, reason: 'not claimable' };   // exactly the old `if (order.settling) return`
  return settleWithLease(order);
}

/** Callers MUST already hold the lease. The sweeper and the drain worker call
 *  this directly — routing them through claimAndSettle would return 0 rows,
 *  because they are already holding the lease on their own order. */
async function settleWithLease(order) {
  const owner = await owners.forOrder(order);
  try {
    if (!order.payment_confirmed_at) {
      const { paid, paidTotal, paymentId } = await owner.qpay.checkPayment(order.qpay_invoice_id);
      if (!paid || paidTotal < order.amount_mnt) {
        // countAttempt=false: a benign "not paid yet" must not burn the cap.
        await store.releaseSettle(order.id, 'not paid yet', false);
        return { ok: false, reason: 'not paid yet' };
      }
      if (paidTotal !== order.amount_mnt) {
        await store.giveUp(order.id, `AMOUNT_MISMATCH paid=${paidTotal} expected=${order.amount_mnt}`);
        return { ok: false, reason: 'amount mismatch' };
      }
      const [confirmed] = await store.markPaymentConfirmed(order.id, paymentId, paidTotal, LEASE_S);
      if (!confirmed) { await store.releaseSettle(order.id, 'confirm rejected'); return { ok:false, reason:'confirm rejected' }; }
      order = confirmed;
    }
    // Stamped BEFORE the fetch. A brew takes 30-60s; a lost ACK must be treated
    // as delivered until NOTIFY_GRACE_S passes, or the retry brews a second cup.
    const [sent] = await store.markNotifySent(order.id);
    if (!sent) return { ok: false, reason: 'lost lease before notify' };
    const machineReply = await notifyMachine(order);
    const [paid] = await store.finishSettle(order.id);
    return { ok: true, machineReply, status: paid?.status };
  } catch (err) {
    await store.releaseSettle(order.id, err.message, true);
    throw err;
  }
}
```

**Sweeper.** Replaces the `for (const [orderNo, order] of orders)` loop. No advisory lock.
```js
async function sweepAbandoned() {
  const claimed = await store.claimAbandoned(50, LEASE_S, INSTANCE);
  for (const order of claimed) {
    try {
      const owner = await owners.forOrder(order);
      const result = await owner.qpay.cancelInvoice(order.qpay_invoice_id);
      if (result.paid) await settleWithLease(order);   // NOT settle() — we hold the lease
      else await store.markCancelled(order.id);
    } catch (err) { await store.releaseSettle(order.id, err.message, true); }
  }
}
```

**Drain worker (new), every 30 s.** Identical shape but `store.claimUnnotified(20, LEASE_S, INSTANCE, NOTIFY_GRACE_S)` → `settleWithLease(order)`. Plus, on each pass, `select id from orders where status in ('payment_confirmed','settling') and settle_attempts >= 10 and product_done_at is null` → `store.giveUp(id, 'attempt cap reached')`, so nothing loops against QPay forever.

**Routes.**
- `app.all('/qpay/callback/:ref')` — if `:ref` is a uuid, look up by id; otherwise by `order_no`, and **if that returns more than one row, log `ingest_errors` and settle nothing.** Keep this route forever: QPay holds the pre-cutover `orderNo` URLs and they cannot be rewritten. Still answers `200 SUCCESS` on every outcome. Add a per-IP rate limit (e.g. 60/min).
- `app.get('/check/:orderNo')` — now gated by `debugAllowed`; it is an operator tool.
- `debugAllowed(req)` reads `req.get('x-debug-key')`, not `req.query.key` — query strings land in Render's request log and every proxy's access log.
- `app.get('/orders/:ref')` — add `if (!debugAllowed(req)) return res.status(404).end()` and hardcode the projection to `{ id, orderNo, deviceNo, status, amountMnt, paidAmountMnt, qrTextLen, settleAttempts, notifyAttempts, createdAt, paymentConfirmedAt, notifiedAt, productDoneAt, lastError }`. Never spread the row — the credential blob is one join away.
- `/health` becomes `{ ok, publicUrl, qpayBaseUrl, dbHealthy, jetinnoApikeyConfigured, cryptoHealth: {activeKeyId, keyIds, keyringSource}, credentialsByKeyId, activeMachines, cachedTokens, ordersOwed }` where `ordersOwed` is the count in `payment_confirmed` older than 2 minutes. Those fields are what tell you at a glance that the service is in a safe configuration.

**`src/sign.js` — unchanged.**

**`package.json`** — add `pg` and `undici`. **`render.yaml`** — add `DATABASE_URL`, `CRED_KEYS`, `CRED_KEY_ACTIVE`, `CRED_FP_KEY`, `DEBUG_KEY`, all `sync: false`; the three `QPAY_*` credential vars stay until Phase 5.

---

## 5. New environment variables

Generate every key on the operator's own machine — never in a chat window, a CI log, or a shared terminal.

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

| Variable | Value | Notes |
|---|---|---|
| `DATABASE_URL` | Supabase → Settings → Database → **Connection pooling**, Transaction mode: `postgresql://postgres.<ref>:<pw>@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres` | Port **6543**, not 5432. The direct host is IPv6-only and Render's outbound is IPv4 — it fails looking like a DNS problem. |
| `CRED_KEYS` | `k1:<base64 32 bytes>` (later `k2:<…>,k1:<…>`) | Prefer a Render **Secret File** at `/etc/secrets/cred_keys` with the same content; the env var is the fallback. If both exist and differ, boot fails. |
| `CRED_KEY_ACTIVE` | `k1` | Names the key new writes seal under. |
| `CRED_FP_KEY` | one base64 32-byte value, **generated once and never rotated** | Or the secret file `/etc/secrets/cred_fp_key`. Rotating it means recomputing every fingerprint, which means decrypting every row. |
| `QPAY_BASE_URL` | `https://merchant.qpay.mn` | Validated against a hardcoded allowlist at boot. |
| `DEBUG_KEY` | `node -e "console.log(require('crypto').randomBytes(24).toString('base64url'))"` | Now sent as the `X-Debug-Key` header, never `?key=`. |
| `SETTLE_LEASE_SECONDS` | `60` | Must exceed worst-case settle (~13 s) with headroom. |
| `NOTIFY_GRACE_SECONDS` | `120` | Must exceed the machine's physical brew time (30–60 s). |
| `REQUEST_DEADLINE_MS` | `6500` | Leaves ~1.5 s of Jetinno's 8 s for network. |
| `QPAY_TOKEN_TIMEOUT_MS` / `QPAY_CALL_TIMEOUT_MS` | `2500` / `5000` | |
| `PG_STATEMENT_TIMEOUT_MS` / `PG_POOL_MAX` | `800` / `5` | |
| `ALLOW_PRIVATE_NOTIFY_URL` | unset in production, `1` in the e2e | The simulator's notifyUrl is on localhost. |
| `QPAY_BASE_URL_ALLOW_EXTRA` | unset in production, `http://localhost:4310` in the e2e | Never set on the live service. |
| removed in Phase 5 | `QPAY_USERNAME`, `QPAY_PASSWORD`, `QPAY_INVOICE_CODE`, `QPAY_MOCK`, `AMOUNT_DIVISOR` | |

**Key backup, the operationally dangerous part.** Keep an offline copy of every key in the operator's password manager, labelled with its key id and creation date, in a **separate entry** from `DATABASE_URL` and the Supabase service-role key. Then **prove the backup works**: restore it into a scratch process and open a real row before you trust it. Losing `CRED_KEYS` with no verified backup means every owner re-enters their QPay credentials by hand — a far likelier bad day than any cryptographic attack.

---

## 6. Rollout order

The live machine must keep selling throughout. Nothing structural ships in the same deploy as anything else; every phase is independently revertible by a Render rollback.

**Phase 0 — safety fixes, no multi-tenancy, no DB. Deploy today.**
1. Add the pinned undici `Agent` and `AbortSignal` timeouts to all four QPay fetches. Behaviour is unchanged except that a stalled QPay now fails cleanly instead of hanging to undici's 300 s default. This is the single highest-value change in the whole plan and every lease number is fiction until it lands.
2. Delete both hardcoded `JETINNO_APIKEY` / `JETINNO_USERNAME` fallbacks (`src/server.js:8-9`, `src/simulate-machine.js:4-5`); require them at boot. Set them in Render if not already set. Rotate with Jetinno if the repo has ever been public or shared.
3. Gate `GET /orders/:orderNo` behind `debugAllowed`; move `DEBUG_KEY` to the `X-Debug-Key` header. Stop echoing `err.message` from `fail()`.
4. Add `scripts/fake-qpay.js` and convert `scripts/e2e.sh` to use it, still with env credentials and the in-memory Map. **Get a green e2e against the real `qpay.js` before changing its shape.**
5. Deploy. Confirm with a real sale. Watch `/recent`.

**Phase 1 — `qpay.js` becomes per-owner, still one owner. Next day.**
6. Rewrite `src/qpay.js` to `forOwner()`. Delete the module-level exports and `qpayConfigured()`.
7. `src/server.js` builds exactly one client at boot from the existing env vars: `const legacyOwner = qpay.forOwner({ ownerId:'env', credentialId:'env', ...process.env })`. Every call site swaps.
8. Behaviour is byte-identical, no database involved, the diff is two files. Rollback is a `git revert`. Deploy, confirm a real sale.

**Phase 2 — the store lands but is not load-bearing.**
9. Apply `001_core.sql` in the Supabase SQL editor (keep the `.sql` in git — the operator's established pattern). Then `002_supabase_rls.sql`. **Migration first, always, before the code that reads it.**
10. Add `src/crypto.js`, `src/db.js`, `src/store.js`, `src/owners.js`. Set `DATABASE_URL`, `CRED_KEYS`, `CRED_KEY_ACTIVE`, `CRED_FP_KEY` in Render.
11. Deploy with `STORE=memory` but **dual-writing** to Postgres, every Postgres call wrapped in a try/catch that only logs. Reads still come from the Map, so a DB failure cannot cost a coffee. Run a full day and read the logged DB timings from real traffic — that number validates the latency budget, not my estimate.
12. Seed the live machine: `node scripts/add-owner.js` creates the owner + credential row holding the *current* env credentials encrypted, plus the `machines` row for the live `deviceNo`. Verify a row appears in `orders` for every real sale, that `owner_id` is set, and that dual-write logged **zero** errors — do not assume it, count it.

**Phase 3 — flip reads to Postgres. Evening, office machine idle.**
13. Wait **longer than `ABANDON_AFTER_MS` (10 min)** after Phase 2 is stable and confirm no `awaiting_payment` rows exist, so no payable order lives only in memory.
14. Set `STORE=pg`, redeploy. The legacy fallback is **scoped to one literal device number**: `if (deviceNo === LEGACY_DEVICE_NO) return legacyOwner;` — every other unregistered device gets `DEVICE_NOT_REGISTERED`. A seeding mistake on the legacy machine degrades to today's behaviour; a mistake on any *other* machine fails loudly instead of routing that business's revenue into the operator's account.
15. Delete the `Map` and the `settling` flag; route settle through `claimAndSettle`; start the drain worker; switch the sweeper to `claim_abandoned_orders`. The claim lease must be in place **now**, not deferred — Render's zero-downtime deploy runs old and new instances together for ~30 s, so multi-instance is not hypothetical at instance count 1.
16. Rollback is one env var back to `memory` plus a redeploy, about a minute. (Changing a Render env var triggers a redeploy on its own — that is why this is an evening job.)
17. Prove it: kill the service from the Render dashboard mid-order and confirm the order survives and settles. That is the capability being bought.

**Phase 4 — verify the legacy machine resolves from the DB.**
18. Add a startup assertion that `LEGACY_DEVICE_NO` resolves from `machines`. Once green for a full day, proceed.

**Phase 5 — the env fallback comes out.**
19. Delete the legacy branch and `LEGACY_DEVICE_NO`. Remove `QPAY_USERNAME` / `QPAY_PASSWORD` / `QPAY_INVOICE_CODE` from Render and `render.yaml`. From here the operator's own credentials are no more privileged than any owner's.

**Phase 6 — onboard the first real buyer.**
20. `scripts/add-owner.js`, register their `deviceNo`, then **one live 100₮ sale before handing the machine over**, and confirm in *their* QPay merchant portal that the money landed in *their* account. That is the only end-to-end proof that the per-owner token cache does what it claims.
21. Update the README: close the "Олон эзэмшигч" and "Санах ойн хадгалалт" open issues; document the onboarding CLI, the `CRED_KEYS` backup rule, and the incident runbook.

**Key rotation (later, and the same shape every time).** Phase A: add `k2`, set `CRED_KEY_ACTIVE=k2`, deploy — every existing `k1` row still opens because `k1` is still loaded, no request fails. Phase B: run `scripts/rewrap-credentials.js` as a one-off job until it reports 0 remaining; never lazy-rewrap on the `getQrCode` path. Phase C: `select key_id, count(*) from qpay_credentials group by key_id` must show only `k2`. Phase D: drop `k1` from `CRED_KEYS`, deploy. **Phase E, the step everyone forgets:** keep `k1` in the vault for at least 30 days — Supabase PITR and any pre-rotation dump contain `k1`-era ciphertext, and restoring one after `k1` is destroyed leaves permanently unreadable rows. Rotate annually, whenever anyone with Render access leaves, on any suspected leak, and after a lost laptop. **Rotating the master key does not invalidate credentials that already leaked in plaintext** — if you believe an owner's QPay password escaped, the owner must change it at merchant.qpay.mn and re-enter it.

---

## 7. How the e2e test changes

`npm run test:e2e` keeps its name and its three existing assertions verbatim. Two structural changes make it able to see what multi-tenancy can get wrong.

**Change 1 — `QPAY_MOCK` becomes a fake upstream.** `QPAY_MOCK=1` is a branch inside `server.js`, so the e2e never executes `src/qpay.js` at all — it cannot observe a token, a bearer header, or an `invoice_code`, which are precisely the things that misroute money. Add `scripts/fake-qpay.js` implementing `POST /v2/auth/token`, `POST /v2/invoice`, `POST /v2/payment/check`, `DELETE /v2/invoice/:id` and a `/slow` route that sleeps 10 s. It issues a **distinct token per Basic credential** and appends every request (path, Authorization header, `invoice_code`, `sender_invoice_no`) to a JSON log the assertions read. The e2e sets `QPAY_BASE_URL=http://localhost:4310` and `QPAY_BASE_URL_ALLOW_EXTRA=http://localhost:4310`.

**Change 2 — a real Postgres, no PGlite.** PGlite is single-process, which would make the five-parallel-callback assertion pass unconditionally — a silent pass is worse than no test. `scripts/e2e.sh` uses `E2E_DATABASE_URL` if set (a staging Supabase project), otherwise starts `docker run --rm -d postgres:16-alpine` and removes it in the existing `trap`. If neither is available it exits with a clear message. It applies **`001_core.sql` only** — `002_supabase_rls.sql` references `auth.users` and the `authenticated` role and is unrunnable on plain Postgres; validate it on a throwaway Supabase project instead.

**Change 3 — seeding.** Seed owner A (device `44401`, invoice code `INV_A`) and owner B (device `44402`, `INV_B`), credentials encrypted through `src/crypto.js` with a fixed test keyring, so encryption is exercised rather than bypassed. Set `ALLOW_PRIVATE_NOTIFY_URL=1` (the simulator is on localhost) and a fixed `DEBUG_KEY`; step 1's `curl "$B/orders/$ORDER"` gains `-H "X-Debug-Key: $DEBUG_KEY"`.

**Keep unchanged:** `Кофе яг 1 удаа гарлаа`, identical QR on replay, and the `getQrCode replay` grep. Keep emitting that exact log string.

**New assertions:**
1. **Two owners, two merchants** — the fake-qpay log shows two *different* bearer tokens; the `44401` invoice carried `INV_A` and `44402` carried `INV_B`; no request ever paired one owner's token with the other's invoice code. This is the test that would have caught a shared token cache.
2. **Token reuse within an owner** — three sequential `getQrCode` calls for `44401` produce exactly **one** `/v2/auth/token` request. Guards the single-flight fix.
3. **Unknown deviceNo** — device `99999` returns `{returnCode:'FAIL', msg:'DEVICE_NOT_REGISTERED'}` in under 500 ms (assert `curl -w %{time_total}` — "does not hang" is the actual requirement), with zero fake-qpay requests, and one `ingest_errors` row.
4. **Restart durability** — create an order, `kill -9` the server, restart it against the same DB, deliver the callback, assert coffee still comes out and the QR is unchanged. Impossible today; the whole justification for the migration.
5. **Exactly one settle across five parallel callbacks** — after the existing step 3, `select count(*) from orders where status='paid'` = 1 **and** `settle_attempts` = 1.
6. **Two processes, one database** — servers on 3100 and 3101 sharing the DB, five callbacks split across both, exactly one coffee. The only test that proves the lease works across connections.
7. **Lost ACK does not brew twice** — the fake machine brews but returns a 500 for the ACK; assert a second `notify` does not arrive within `NOTIFY_GRACE_SECONDS`, and that once `productdone` is delivered no further notify ever arrives.
8. **`payment_confirmed` drains** — after case 7, with the fake machine healthy again and `NOTIFY_GRACE_SECONDS=2`, the drain worker re-notifies and the order reaches `paid`.
9. **Sweep** — `ABANDON_AFTER_MS=1000`; assert fake-qpay logged a `DELETE /v2/invoice/:id` carrying **owner A's** bearer and the order is `cancelled`. Variant: fake-qpay answers `INVOICE_PAID` and the order settles instead — this is the path that silently did nothing under the old design.
10. **Timeout behaviour** — point fake-qpay at `/slow`; `getQrCode` returns FAIL within 7 s, the order row is `failed`, and the machine's retry with the same `orderNo` uses `sender_invoice_no` ending `-2`.
11. **Amount mismatch** — fake-qpay reports a payment of 1₮ on a 1000₮ order; assert no coffee, and the order lands in `needs_human`.
12. **No global QPay path** — `node -e 'import("./src/qpay.js").then(m => process.exit(m.createInvoice === undefined ? 0 : 1))'`. Fails the build if a module-level credential path is ever reintroduced.
13. **Two sweepers do not double-cancel** — two instances, 1 s sweep interval, one `DELETE` per invoice.

---

## 8. What this design still does NOT protect against

Say this plainly to owners in the contract rather than letting "encrypted at rest" imply a protection it does not provide.

1. **A Render dashboard compromise.** The master key, `CRED_FP_KEY`, `DATABASE_URL` and the Supabase service-role key all sit in the same Render service, plaintext in the dashboard. A phished password, a hijacked session, a team member you added and forgot, or Render staff gets both the key and the ciphertext — this encryption contributes exactly nothing. It is the most likely real-world breach for a project this size. **2FA on the Render account does more for you than any choice in this document.**
2. **Code execution in the running process.** RCE or a malicious npm dependency reads the keyring, reads decrypted credentials out of the cache, or simply calls QPay as any owner it likes. Encryption at rest protects data at rest; the process is not at rest. A heap dump contains plaintext credentials — `.fill(0)` narrows the window, it does not close it.
3. **The operator.** By design the operator can decrypt every owner's QPay username and password at will, and can create invoices on any owner's merchant for any amount. Nothing here constrains that. **Owners are trusting the operator personally, not the cryptography.**
4. **Mapping tampering, until you actually watch the audit table.** `update machines set owner_id=…, qpay_credential_id=…` satisfies every foreign key, breaks no AAD, decrypts nothing, and redirects 100 % of an owner's revenue. The AAD stops ciphertext *relocation*, not *mapping* changes. `admin_audit` records it and the weekly reconciliation catches it — but only if someone reads them. Nothing here is automatic.
5. **No decrypt audit trail.** With the key in Render, there is no record of who decrypted what and when. If credentials leak you will not be able to tell whether it happened through this system or the owner's own laptop. AWS/GCP KMS with envelope encryption is what buys that log — adopt it when you pass ~10 machines, when a second person gets Render access, or when a laptop holding the keys goes missing.
6. **A stolen laptop with a `.env` file.** Same key, same database URL, no benefit. Use a throwaway local keyring and a separate dev database; never the production key locally.
7. **Anything downstream of QPay.** If QPay is breached, or an owner's merchant login is phished, or they reuse that password elsewhere, none of this matters. Tell owners to use a QPay password they use nowhere else, since the operator now holds a copy.
8. **Credential deletion is not immediate.** Deleting a row does not remove it from Supabase PITR or from any backup taken before the deletion — and the rotation runbook requires keeping the old key through that retention window. Tell departing owners in writing that deletion takes effect within N days as backups roll off.
9. **Everything outside the sealed blob.** Owner names, `device_no → owner` mappings, order numbers, amounts, invoice ids, payment status and `key_id` are all plaintext. A DB reader learns exactly how much each machine earns and who owns it — just not how to take the money. Blob length also leaks roughly how long the credentials are; padding is not worth the complexity, but it is a leak.
10. **The Jetinno idempotency question is still open.** Whether a JL30 dedupes a repeated `paymentCallback` for the same `orderNo` decides how defensive the notify retry has to be. `notify_sent_at` + the 120 s grace + `product_done_at` is a belt-and-braces guess in the absence of an answer. **Send Jetinno one email and record the answer in the README** — it is the cheapest risk reduction left.
11. **Refunds are still manual.** `/jetinno/refund` returns `ERROR` unconditionally, so every `needs_human` order and every amount mismatch is a bank transfer the operator makes by hand. Write that runbook before you need it: how to find the order (`status='needs_human'` and the debt query), how to read `order_events` and `settle_lease_owner`, and who transfers the money.
12. **Alerts have nothing behind them.** Every "page the operator" in this plan is currently a query nobody runs. Wire `/health`'s `ordersOwed` and `needs_human` counts to something that actually reaches a phone — even a cron hitting the endpoint and a bookmark is more than nothing.
13. **Compliance.** This is not a PCI, ISO, or Mongolian personal-data-law posture. It is one competent control. What you can honestly tell an owner is: *a database breach alone does not expose their QPay account.* Nothing more.