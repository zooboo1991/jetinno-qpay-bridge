# Owner self-service credential entry — implementation plan

Layered on `docs/multi-tenant-plan.md`. Everything below was executed, not asserted: `000`+`001`+`002`+`003` apply clean in order to `postgres:16-alpine`; the RLS proof in §3 is real output; the log leak in §1 was reproduced on this repo.

**Artifacts written and validated:**
- `/Users/macbook/Downloads/jetinno-qpay-bridge/migrations/001_core.sql` — extracted from the plan markdown (it existed only as a fenced block; unrunnable and untestable as such)
- `/Users/macbook/Downloads/jetinno-qpay-bridge/migrations/002_supabase_rls.sql` — same
- `/Users/macbook/Downloads/jetinno-qpay-bridge/migrations/003_owner_self_service.sql` — **1505 lines, the file to paste. Applies clean; all four regression gates return zero rows.**
- `/Users/macbook/Downloads/jetinno-qpay-bridge/src/credentials.js` — the route, `node --check` clean, all reviewer greps zero

---

## 1. Final decisions

**Where the owner UI lives: a separate Next.js app on Vercel at `kofe.mn` (apex, operator-owned domain). The bridge gains one router, `/owner/v1/*`. The credential POST goes browser → bridge DIRECT, never through Vercel.** Next.js+Supabase is the operator's existing stack on gmath/rkh-club/kshop; a copy-heavy Mongolian UI reworded a dozen times in month one must not redeploy the process a coffee machine depends on. `CRED_KEYS` stays in exactly one dashboard — Render — because plan §8 item 1 names a dashboard compromise as the most likely real breach, so the bridge must be the sealer. The relay hop the credential-form design proposed is rejected: it buys nothing for key confinement (the key is on the bridge either way) and adds one more process holding a plaintext merchant password in memory, one more log surface. Direct + bearer also means no cookies on the bridge, therefore no CSRF surface, therefore none of that design's three-layer CSRF machinery.

**Auth: Supabase phone OTP, invite-only, no signup route.** The phone is the identity these owners actually have and already gave on the sales paperwork. Password auth is rejected outright — a second password field adjacent to the QPay password field is the single most dangerous UI mistake available, and its failure mode is a QPay merchant password typed into a login form. Email is rejected as primary and kept as an operator-attachable secondary identity.

| # | Contested point | Decision | Rationale |
|---|---|---|---|
| 1 | Machine before credential | **Pending credential row.** `qpay_credentials.sealed/key_id/fingerprint` become nullable + `status in ('pending','active','disabled')`. `machines` DDL is **untouched**. | Verified by insert: `machines.qpay_credential_id` is NOT NULL and 003-as-reviewed never altered it, so the operator could not register a device until after the owner finished the form. The pending row fixes that with zero change to `machines`, so `machines_credential_owner_fk` stays fully enforced and decision #12's "misrouted money is unrepresentable" survives intact — which the nullable-column alternative weakens (MATCH SIMPLE stops checking while NULL). |
| 2 | Credential change: INSERT or UPDATE | **UPDATE in place, id stable, staged in `pending_*` columns.** | The onboarding design's INSERT+deactivate re-points only `awaiting_credentials` machines, so a routine password rotation deactivates the credential a live machine still points at and kills it — the owner did exactly what they were told and the machine broke. Staging means the old blob keeps serving until the moment the new one is proven. |
| 3 | Do credentials belong to this owner? | **The 4-digit nonce.** The 10₮ probe invoice carries `Кофе машин холболт шалгах 4821`; the owner reads it out of *their own* QPay portal and types it back. Not cancelled until they answer. | Auth + invoice creation answer "do these work?", never "are they yours?". An owner with two businesses, or whose QPay account was opened under a partner's entity, passes both perfectly and sends every sale to a real wrong account, forever, undetected. This is the highest-consequence silent failure in the system and nothing else catches it. The reviewed design cancelled the invoice milliseconds before the only person who could validate it could look. A yes/no button gets tapped through; typing four digits is evidence. |
| 4 | Invoice code on the phone form | **Removed. The operator captures it at invite time into `pending_invoice_code`; consumed and NULLed at seal.** | It is the one field the owner cannot recall — they transcribe a long opaque string, Android autocapitalises it, and they leave the app to find it. Two fields they know by heart is the largest abandonment reduction available. Deviates from decision #15 for a bounded window only; decision #14 already made the fingerprint a *keyed* HMAC, so a plaintext invoice code adds no brute-force surface, and it cannot invoice without username+password. |
| 5 | `credential_submissions` reserve/complete | **Deleted.** | It caused four separate findings: form-opens burning the rate limit, a double-tap wedging on `credential_submissions_open_key`, a viewer reading the submission id, and a `complete_*` that authorised nobody. With a pending row the credential id already exists and the POST is synchronous — there is nothing to reserve. |
| 6 | Who checks admin? | **SQL, keyed on the credential's own owner.** `begin_/confirm_credential_verification` take `p_actor_user_id` and check `app.admin_owner_ids_of()`. | The reviewed function checked only `status='reserved'`, delegating authorisation to bridge JS the one concrete sketch never wrote. Resolving credential→owner (never user→owner) also fixes the multi-business user who could otherwise never configure their second company. |
| 7 | Invite phone | **`create_owner_invite` refuses a phone that does not already match `owners.contact_phone`; role defaults to `viewer`.** | One mistyped digit at the end of a tiring install put a live *admin* invite on a stranger's phone — and every other control waved them through, because their identity genuinely was the one the invite named. Two entries, two times, must agree. |
| 8 | Step-up OTP | **First entry: free (rides the redemption OTP, ≤60 min). Later changes: fresh OTP ≤10 min.** Deactivate is never gated. | A second international A2P SMS at the moment the operator is standing there is a coin flip on whether onboarding completes, defending against a stolen session that is not present at an installation. Bridge-owned `owner_step_up` table, not an `amr` claim — claim shapes vary and a step-up that silently always passes is worse than none. |
| 9 | Rate limit | **Postgres ledger, keyed on `owner_id`, counting QPay attempts only.** Transport failures never count. | Form-opens are free (the reviewed design locked an owner out for an hour after five *page loads*). IP keying punishes CGNAT'd Mongolian mobiles and stops nobody. |
| 10 | Who writes? | **`authenticated` can only SELECT. Every write is a bridge endpoint, invite redemption included.** | One sentence a regression gate can check. It also gives the bridge the reliable "this session just did an OTP" signal that makes #8 work, and puts an Express-observed IP in the audit instead of one guessed from a header inside Postgres. |
| 11 | Decision #33 | **Discharged in writing, in `003`'s header and in the plan — but only after Phase 0 lands.** | #33's condition was "until there is a real session system". The session system now exists, but the *ambient logging environment* #33 feared has not changed: global parser, unredacted `detail()`, query-string `DEBUG_KEY`, ungated `/orders`. Discharge it after those are fixed, not before. |

---

## 2. The migration

`/Users/macbook/Downloads/jetinno-qpay-bridge/migrations/003_owner_self_service.sql` — paste as-is. Applies in one transaction after `002`. The structural deltas, so a reviewer can check the file against intent:

```sql
-- The change that makes self-service possible at all:
alter table public.qpay_credentials
  alter column sealed drop not null, alter column key_id drop not null,
  alter column fingerprint drop not null;
alter table public.qpay_credentials
  add column status text not null default 'active',
  add column pending_sealed text, add column pending_key_id text,
  add column pending_fingerprint text, add column pending_username_hint text,
  add column pending_invoice_code_hint text,
  add column verify_nonce text, add column verify_invoice_id text,
  add column verify_started_at timestamptz, add column verify_expires_at timestamptz,
  add column verify_attempts integer not null default 0,
  add column pending_invoice_code text,
  add column username_hint text, add column configured_by uuid, add column configured_at timestamptz,
  add column last_error_code text, add column source text not null default 'cli',
  add column acceptance_confirmed_at timestamptz, add column acceptance_order_id uuid;

-- The state machine, in constraints rather than in convention:
add constraint qpay_credentials_sealed_state_chk check (
  (status =  'pending' and sealed is null     and key_id is null     and fingerprint is null) or
  (status <> 'pending' and sealed is not null and key_id is not null and fingerprint is not null));
add constraint qpay_credentials_active_status_chk check (is_active = (status = 'active'));
add constraint qpay_credentials_pending_shape check (   -- a staged candidate is all-or-nothing
  (pending_sealed is null and pending_key_id is null and pending_fingerprint is null
   and verify_nonce is null and verify_expires_at is null) or
  (pending_sealed is not null and pending_key_id is not null and pending_fingerprint is not null
   and verify_nonce is not null and verify_expires_at is not null));
```

New tables: `operators`, `credential_audit` (append-only, no FKs, `?|` no-secrets CHECK), `owner_invites` (role defaults `viewer`), `credential_verify_attempts`, `owner_step_up`.
New views: `my_qpay_credentials`, `operator_credential_audit`, `operator_owner_invites`, `operator_onboarding_status` — each revoked then granted SELECT, each with an `INSTEAD OF` trigger.
New functions (all `security definer`, `search_path=''`, all revoked from `public`): `is_operator`, `admin_owner_ids_of`, `norm_phone`, `deny_mutation`, `peek_invite`, `accept_owner_invite`, `create_owner_invite`, `revoke_owner_invite`, `credential_verify_budget`, `record_verify_attempt`, `global_auth_fails`, `credential_slot`, `begin_credential_verification`, `confirm_credential_verification`, `abort_credential_verification`, `record_verify_failure`, `confirm_acceptance_sale`, `set_credential_label`, `set_credential_active`, `touch_step_up`, `step_up_age_seconds`.

**Found by running the file, not by reading it:** gate (d) returned `app.touch_updated_at | anon` — a trigger function 001 created and never revoked, EXECUTE-able by anon to this day. Harmless in itself, but a gate that always shows noise is a gate nobody runs. `003` now revokes it, and all four gates read clean.

Every write function wraps `unique_violation` and re-raises a fixed code. This closes the channel the security reviewer found: PostgREST returns Postgres' DETAIL field, which reads `Key (fingerprint)=(<64 hex>) already exists` — a value the design claims is unreachable, surfaced through a channel the catalogue-based gate structurally cannot see.

---

## 3. RLS, and the proof

There is exactly **one** RLS policy in the whole delta, and it is on nothing sensitive — 002's existing read policies are unchanged. `qpay_credentials` gets no policy at all, because a policy implies a privilege and there is none to qualify:

```sql
revoke all on public.qpay_credentials from anon, authenticated;   -- re-asserted at the end of 003
```

The entire owner read surface is a definer view with enumerated columns (never `select *` — that starts leaking on the next `ADD COLUMN`) plus `security_barrier` (stops the planner pushing a leaky function below the owner filter) plus an `INSTEAD OF` trigger (removes auto-updatability, so a future blanket grant cannot reopen it):

```sql
create view public.my_qpay_credentials with (security_barrier = true) as
  select c.id, c.owner_id, c.label, c.status, c.is_active, c.username_hint,
         c.invoice_code_hint, c.source, c.last_verified_at, c.last_error_code,
         c.auth_fail_count, c.configured_at, c.acceptance_confirmed_at,
         (c.verify_expires_at is not null and c.verify_expires_at > now()) as verification_open,
         c.created_at, c.updated_at
    from public.qpay_credentials c
   where c.owner_id = any (app.my_owner_ids());
revoke all  on public.my_qpay_credentials from anon, authenticated;
grant select on public.my_qpay_credentials to authenticated;
create trigger my_qpay_credentials_read_only instead of insert or update or delete
  on public.my_qpay_credentials for each row execute function app.deny_mutation();
```

**Proof-by-walkthrough.** Run as the real `authenticated` role with a real owner's `sub`, one statement per transaction. Actual output:

```
1  read blob:          ERROR:  permission denied for table qpay_credentials
2  count rows:         ERROR:  permission denied for table qpay_credentials
3  blind search:       ERROR:  permission denied for table qpay_credentials
4  RETURNING:          ERROR:  permission denied for table qpay_credentials
5  staged via view:    ERROR:  column "pending_sealed" does not exist
6  re-parent via view: ERROR:  permission denied for view my_qpay_credentials
7  self-grant admin:   ERROR:  permission denied for table owner_members
8  invite digest:      ERROR:  permission denied for table owner_invites
9  audit as owner:     owner sees 0 audit rows
10 verify ledger:      ERROR:  permission denied for table credential_verify_attempts
11 call the writer:    ERROR:  permission denied for function begin_credential_verification
12 delete an audit:    ERROR:  permission denied for table credential_audit
13 self-redeem invite: ERROR:  permission denied for function accept_owner_invite

--- what the owner CAN see ---
 label                | status | username_hint | invoice_code_hint | source       | verification_open
 Хүнс маркет — үндсэн | active | ne••••••99    | ••••7777          | self_service | f
```

Line 1 is the whole argument. The four escape routes an attacker actually tries — read it, count it, binary-search it one character at a time through a `WHERE`, or exfiltrate it through `RETURNING` — all hit the same table-level denial, because Postgres enforces column SELECT privilege in `WHERE` and `RETURNING` alike and there is no privilege to qualify. Line 5 is stronger than a denial: the column does not exist in the view's output type, so no plan, no error message and no timing difference can reference it. Line 6 is the hole the schema reviewer found by *executing* the migration — `my_qpay_credentials` is single-table and therefore auto-updatable, and Supabase's default privileges fire on `CREATE VIEW`, so without the revoke `update public.my_qpay_credentials set owner_id = '<someone else>'` was a working cross-owner re-parenting primitive reachable with an anon key. Closed twice.

**Functional walkthrough, also real output:**

```
T1  machine registered against a PENDING credential                    -> PASS
T2a invite with a mistyped phone      -> PHONE_DOES_NOT_MATCH_OWNER_CONTACT
T2b invite with the paperwork phone   -> accepted, ref OQ4K-7M2P
T3  owner_invites.role default        -> 'viewer'::text
T4a thief holds the link, not the SIM -> phone_mismatch (+ invite_mismatch audit row, IP recorded)
T4b real owner                        -> accepted
T4c thief retries                     -> used
T4d owner re-clicks their own link    -> already_accepted (not an error)
T5a a shop VIEWER writes the payout   -> not_admin
T5b the admin owner                   -> ok
T5c during verification               -> status=pending is_active=f sealed=null staged=t
T5d wrong nonce                       -> nonce_wrong, 4 attempts left
T5e right nonce                       -> ok
T5f after confirm  -> status=active source=self_service pending_invoice_code=(null) nonce=(null)
T6a mid-rotation on a LIVE credential -> status=active, OLD sealed blob still serving
T6b after rotation                    -> new blob live, machine never stopped
T7  machine still wired to the SAME credential id                      -> true
T8a same owner, same merchant         -> duplicate_same_owner  (normal growth, no page)
T8b other owner, same merchant        -> duplicate_other_owner (page the operator)
T9b 5 QPay OUTAGES                    -> still allowed (an outage must not lock out everyone)
T9c 5 real AUTH failures              -> LOCKED, retry in 60 min
T9e 3rd distinct username in 24h      -> TOO_MANY_MERCHANTS
T10a update credential_audit          -> append-only object: UPDATE ... is not permitted
T10b detail = {"password":"hunter2"}  -> rejected by credential_audit_no_secrets
```

---

## 4. The route

`/Users/macbook/Downloads/jetinno-qpay-bridge/src/credentials.js`. Mounted `app.use('/owner/v1', credentials)`. Endpoints: `POST /invites/redeem`, `POST /credentials/verify`, `POST /credentials/confirm`, `POST /credentials/abort`, `POST /credentials/:id/active`, `GET /credentials/:id`, plus `mountVerifyCallback(app)` and `sweepAbandonedVerifications()`.

**The log-safety argument, verified rather than assumed.** I reproduced the leak on this repo:

```
RING CONTAINS PASSWORD: true
RING LINE: unhandled {"expose":true,"statusCode":400,"status":400,
           "body":"{\"username\":\"shopA\",\"password\":\"CANARY-PW-123\",",
           "type":"entity.parse.failed"}
2kb CAP ENFORCED: false  (sent 50040 bytes -> HTTP 200)
```

Two facts follow. First, the global `express.json()` at `server.js:6` throws on malformed JSON and body-parser attaches the raw request text as `err.body` (`lib/read.js:131`) — so one house-style line, `app.use((err,req,res,next) => log('unhandled', err))`, puts a live merchant password into the ring that `GET /recent` serves, on a request that never reached the credential route. **One correction to the security review: `err.message` does *not* quote the body on Node 22 or 26** — I checked — so `delete err.body` is the load-bearing control, not defence in depth. Second, body-parser sets `req._body` before parsing (`read.js:46`) and returns early when it is set (`json.js:106`), so the router's 2kb cap is dead code behind a global parser: a 50,040-byte body reached the handler with HTTP 200. Both are fixed by deleting the global parser in Phase 0; the module's own controls (no `log()` import, a `safeLog` with no rest parameter and no object spread, `req.body = undefined` as the first statement) cannot defend a request that never arrives.

**Verification, in three proofs.** `warmToken` proves username+password. `createInvoice` proves the invoice code — and because the *operator* now supplies that value, a failure here means the operator typed it wrong, so the message says so, gives his number, and pages him rather than blaming the owner. The nonce proves the account is the owner's. `sender_invoice_no` is `verify-<12 hex>-<epoch>`, deliberately a different shape from a sale's `${deviceNo}-${orderNo}`; `callback_url` is `/qpay/verify-callback`, a route that answers `200 SUCCESS` and settles nothing, never `/qpay/callback/:ref` — settle's ref-is-not-a-uuid branch falls back to lookup by `order_no`, a namespace a verify invoice must never enter. 10₮ not 1₮: a merchant-level minimum would fail a *correct* credential and produce a confident wrong answer.

**The nonce is never returned in the response.** If it were, the page could show the owner a number to type back and the step would prove nothing.

Reviewer greps against the file, all zero: logs a request body; logs an error, message or stack; imports `server.js`; sets `Access-Control-Allow-Credentials`; returns `sealed`/`fingerprint` in any response.

**Supporting modules to add** (`src/store.js` gains one thin function per SQL statement): `acceptOwnerInvite`, `touchStepUp`, `stepUpAgeSeconds`, `credentialSlot`, `credentialForOwner`, `credentialVerifyBudget`, `recordVerifyAttempt`, `recordVerifyFailure`, `globalAuthFails`, `usernameFpEverConfigured`, `beginCredentialVerification`, `confirmCredentialVerification`, `abortCredentialVerification`, `expiredVerifications`, `setCredentialActive`, `logCredentialEvent`, `revokeOtherSessions`. `src/qpay.js` gains `warmToken(signal)`, `evictOwner(ownerId)`, and typed `QPayHttpError` with `.status`/`.stage` so `classify()` need not regex a message. `src/owners.js` must treat `status <> 'active'` as unusable and return **`MERCHANT_NOT_READY`, never `DEVICE_NOT_REGISTERED`** — one means a seeding mistake, the other means a person is standing in front of a machine wanting coffee, and merging them loses the only signal that says so. New `src/alerts.js`: `pageOperator()` and `notifyOwnerCredentialChanged()`, the latter sending to `owners.contact_phone` from the paperwork, **not** the session's phone, so a hijacked identity cannot silence its own alert. Latin script, no links, ever.

New deps: `jose`. New env: `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `PORTAL_ORIGIN`, `CRED_VERIFY_TTL_MINUTES=20`, `CRED_STEP_UP_FIRST_SECONDS=3600`, `CRED_STEP_UP_CHANGE_SECONDS=600`.

---

## 5. The owner-facing screens

`{ОПЕРАТОР}`, `{УТАС}`, `kofe.mn` are placeholders. Every page server-rendered so it shows the business name, machine number and operator's phone before any JavaScript runs, with a `<noscript>` carrying the phone number — supabase-js needs `fetch` and fails on old Android WebViews as a **blank white page**, which on a payment-credential page reads as "this is fake".

**`/invite/[token]` — before login.** Server-rendered from `app.peek_invite()`, which is the only thing `anon` may call.
> **Сайн байна уу.**
> **{БИЗНЕСИЙН НЭР}** дээр урилга ирсэн байна.
> Үргэлжлүүлэхийн тулд **{МАСКЛАСАН ДУГААР}** дугаарт очих 6 оронтой кодыг оруулна уу.
> [ Код авах ]
> Асуух зүйл байвал {ОПЕРАТОР} — {УТАС}

Expired / revoked / used gets its own screen, never a 404 — a 404 reads as "the site is broken" and ends in a phone call:
> Энэ урилгын хугацаа дууссан байна. {УТАС} руу залгавал шинэ холбоос өгнө. **[ Оператор руу залгах ]**

**`/` — credential missing.** One red banner, one button, nothing competing.
> **QPay данс холбоогүй байна — машин мөнгө авч чадахгүй.**
> Машин **44403** · {МАШИНЫ БАЙРШИЛ}
> [ QPay холбох ]

**`/qpay` — the form. Two fields.**
> **Гарчиг:** QPay мерчант мэдээллээ холбох
> **Дэд гарчиг:** Ингэснээр борлуулалт шууд таны данс руу орно.
>
> Машин дээр гарах QR кодыг таны QPay мерчант дансаар үүсгэдэг. Тиймээс үйлчлүүлэгчийн төлсөн мөнгө хэн нэгний данс дундуур явахгүй, шууд танд ирнэ.
>
> `QPay нэвтрэх нэр` — merchant.qpay.mn дээр нэвтэрдэг нэр.
> `QPay нууц үг` — merchant.qpay.mn-д нэвтэрдэг нууц үг. **Банкны аппын ПИН биш.**
>
> *(Нэхэмжлэхийн кодыг {ОПЕРАТОР} аль хэдийн оруулсан. Та бичих шаардлагагүй.)*

Fields: `autocapitalize="none" autocorrect="off" spellcheck="false" autocomplete="off"`, press-and-hold to reveal (client-side only — typing a merchant password blind on a phone is the #1 typo source). Whitespace detected client-side with a one-tap "Арилгах"; the password is never trimmed server-side.

> **Блок 1 — "Эргэлзэж байвал зөв бодож байна":**
> Төлбөрийн нууц үгээ вэб хуудсанд бичихээс эргэлзэж байгаа бол та зөв бодож байна. Бөглөхийн өмнө 3 зүйлийг шалгаарай:
> 1. Хаягийн мөрөнд **kofe.mn** гэж байна уу? Өөр хаяг байвал бүү бөглө.
> 2. Энэ хуудас таны машины дугаар **44403**-ыг харуулж байна уу? Харуулахгүй бол **ЗОГС**, юу ч бүү бич.
> 3. Энэ холбоосыг машин суурилуулах үед бид танд биечлэн өгсөн. Мессеж, Facebook, имэйлээр ирсэн ижил төстэй холбоос **манайх биш**.
>
> **Блок 2 — "Энэ мэдээлэл хаана хадгалагдах вэ" (нуухгүйгээр):**
> - Нууц үгийг шифрлэж хадгална. Өгөгдлийн сан задарсан ч тэндээс нууц үг унших боломжгүй.
> - Гэхдээ шулуухан хэлье: манай сервер энэ мэдээллийг ашиглан таны QPay данс дээр нэхэмжлэх үүсгэнэ. Өөрөөр хэлбэл системд ашиглах эрх нь байгаа. Та {ОПЕРАТОР}-д итгэж байгаа хэрэг — код руу биш, хүн рүү нь.
> - Тиймээс QPay-дээ өөр хаана ч давхардуулж хэрэглээгүй, **тусдаа нууц үг** тавиарай.
> - Бид утсаар ярьж байгаад QPay нууц үг **хэзээ ч** асуухгүй. Хэн нэгэн асуувал таслаад {УТАС} руу залгаарай.
>
> **[ Шалгаад хадгалах ]**  *(not "Хадгалах" — it promises the verification about to happen)*
> **Ачаалж байх үед:** QPay-тэй холбогдож байна… 10 секунд хүлээнэ үү.

Block 2's second bullet is the one to protect from a future edit. "We store it encrypted" alone implies a protection it does not provide (§8 item 3); an owner who later works out that the operator's server can invoice on their merchant, having been told only "encrypted", has been misled.

**`/qpay/check` — the nonce screen. This is the screen that catches the wrong account.**
> **Одоо нэг зүйл шалгая.**
> Бид таны QPay данс дээр **10₮**-ийн туршилтын нэхэмжлэх үүсгэлээ.
>
> **merchant.qpay.mn** рүү өөрийн утаснаасаа орж, "Нэхэмжлэх" хэсгээс дараах мөрийг олоорой:
> > `Кофе машин холболт шалгах ####`
>
> Тэнд байгаа **4 оронтой тоог** доор бичнэ үү.
> `[ _ _ _ _ ]`  ← `inputmode="numeric"`
>
> **[ Баталгаажуулах ]**
> Яагаад? Ингэснээр бид таны оруулсан мэдээлэл **яг таны** данс мөн эсэхийг батална. Өөр хүний данс байвал мөнгө тань руу орохгүй.
>
> [ Ийм нэхэмжлэх харагдахгүй байна ]

That last link is a hard stop, with no third option — a third option is the one everybody picks:
> **Зогсоё.** Энэ мэдээлэл таны данс биш байх магадлалтай. Хадгалаагүй. {ОПЕРАТОР} рүү залгая: **{УТАС}**

**Errors** — each maps to one action:
- **AUTH_FAILED:** QPay нэвтрэх нэр эсвэл нууц үг таарсангүй. merchant.qpay.mn дээр нэвтэрч чадаж байгаа эсэхээ шалгаад дахин оролдоно уу.
- **INVOICE_CODE_FAILED:** Таны нэр, нууц үг **зөв байна**. Гэхдээ {ОПЕРАТОР}-ын оруулсан нэхэмжлэхийн код буруу байна. Энэ таны буруу биш — {УТАС} руу залгаарай, бид засна.
- **QPAY_UNREACHABLE:** QPay яг одоо хариу өгөхгүй байна. **Таны буруу биш.** Таны оруулсныг хадгалаагүй. 2-3 минутын дараа дахин оролдоно уу. [ Дахин оролдох ]
- **NONCE_WRONG:** Тоо таарсангүй. Дахин **{N}** удаа оролдож болно. Портал дээрх хамгийн сүүлийн 10₮-ийн нэхэмжлэхийг хараарай.
- **RATE_LIMITED / LOCKED:** Хэт олон удаа оролдлоо. **{N}** минутын дараа дахин оролдоно уу, эсвэл {УТАС} руу залгаарай.
- **DUPLICATE_SAME_OWNER:** Энэ QPay данс таны өөр машинд аль хэдийн холбогдсон байна. [ Тэр дансыг энэ машинд ч ашиглах ]
- **DUPLICATE_OTHER_OWNER:** Энэ QPay данс өөр бүртгэлд холбогдсон байна. {УТАС} руу залгана уу. *(never says which owner)*
- **REAUTH_REQUIRED** is presented as a confirmation step, not an error: "Аюулгүй байдлын үүднээс дугаараа дахин баталгаажуулна уу." **The form fields are never cleared** — they hold a password typed blind on a phone keyboard.
- **SERVER_ERROR:** Систем дээр алдаа гарлаа. Дугаар: `a3f19c2b` — энэ дугаарыг {УТАС} руу илгээнэ үү.

**`/qpay/ok`:**
> **Холбогдлоо.** Таны машин 1 минутын дотор мөнгө хүлээж авч эхэлнэ.
> Одоо {ОПЕРАТОР}-ын хүнтэй хамт **100₮-ийн туршилтын худалдаа** хийж, мөнгө өөрийнхөө QPay данс руу орсныг нүдээрээ хараарай.

**`/qpay` configured state** — a card, no form. No eye icon, no "Show", no copy button, no pre-filled values (pre-filling is read-back by another name). `[ Солих ]` opens an empty form.

**`/help`:** operator's phone, machine serial, and the reminder list.

**SMS (Latin only — Cyrillic is mangled on some Mongolian A2P routes; the operator already hit this on uvsnuur):**
`{OPERATOR} kofe mashin: batalgaajuulah kod {CODE}. Hen negentei helj bolohgui.`
Credential-change alert: `Tany QPay holbolt solygdloo. Ta bish bol yaaraltai zalgana uu: {UTAS}` — no link, ever.

---

## 6. Where this slots into the 6-phase rollout

No phase moves. Phases 0–5 are the plan's, extended.

**Phase 0** (already the plan's step 3, now with three additions — all prerequisites for discharging #33):
- 3a. **Delete `app.use(express.json())` from `server.js:6`**; give every route its own scoped parser with its own limit. A `getQrCode` body is a few hundred bytes and has no reason to accept 100 kb either.
- 3b. Add a bridge-wide error handler whose **first statement is `delete err.body`**, logging `err.name` + an incident id only — never `err.message`, never `err.stack` into the ring.
- 3c. `DEBUG_KEY` moves from `?key=` to `X-Debug-Key` (already decision #27, simply not done in code); gate `GET /orders/:orderNo` behind `debugAllowed` with a whitelisted projection; apply `redact()` inside `qpay.js`'s `detail()` so an unredacted upstream message cannot be constructed anywhere; stop `settleRoute` returning `err.message`. **These are live in production today** and `/check/:orderNo` currently echoes QPay's 401 body, which contains the merchant username.
- 3d. Add the e2e canary, **including the malformed-body case** — that is the one a hand-written test always forgets and the only control here that survives six months.

**Phase 2, step 9:** apply `001` → `002` → `003` in the same sitting. `001` and `002` now exist as files (`migrations/001_core.sql`, `migrations/002_supabase_rls.sql`) — they existed only as fenced blocks in a 1473-line markdown, and hand-selecting a line range to paste into a live SQL editor is not a migration procedure. Wire `scripts/e2e.sh` to apply `000`+`001`+`002`+`003` and assert the four gates.

**Phase 2, step 12:** `scripts/add-owner.js` gains `--pending` (owner + empty credential row, no QPay prompt) and writes a `credential_audit` row with `actor_kind='operator'` on every seed, so Phase 6's first owner-written row lands in a table with a real baseline rather than an empty one.

**Phases 3, 4, 5 — untouched.** Build the Next.js app during this window; it shares nothing with the hot path.

**Do not enable self-service before Phase 5 is done.** This is the one real ordering constraint and it follows from the plan rather than changing it: until step 19 removes `QPAY_USERNAME`/`PASSWORD`/`INVOICE_CODE`, a second source of truth is still live, and a self-service write could appear to succeed while changing nothing the running process reads.

**Phase 6, step 20** — the only step that changes, and it grows rather than moving:
- 20a. `add-owner.js --pending`, `register-machine.js` (works now, because the credential row exists), `invite-owner.js --admin`.
- 20b. Owner scans the QR, sees their company name via `peek_invite`, OTPs in, enters two fields.
- 20c. **The nonce check** — new. Owner reads the 10₮ invoice in their own portal.
- 20d. The unchanged 100₮ acceptance sale, now recorded: `node scripts/confirm-acceptance.js --credential <id> --order <id>` stamps `acceptance_confirmed_at`, and `/health` counts credentials that reached `active` without one.
- 20e. Check `operator_credential_audit` shows one `verify_confirmed` with that owner's `actor_user_id` and a plausible IP.

**Keep the CLI.** `source='cli'` vs `'self_service'` records which path was used, and is the honest measure of whether self-service works or has quietly reverted to the model the operator just rejected.

**`/health` gains:**
```json
"onboarding": { "machinesAwaitingCredentials": 1, "invitesPending": 1, "invitesExpiringIn72h": 1,
  "credentialsFailingAuth": 0, "merchantNotReadyLast24h": 4, "verifiedButNoAcceptanceSale": 1,
  "abandonedVerifications": 0 }
```
`scripts/onboarding-report.js` on a 09:00 Ulaanbaatar cron SMSes the operator if anything is non-terminal. §8 item 12 says every "page the operator" in this plan is a query nobody runs; this is the one that must not be.

---

## 7. Operator runbook — onboarding one buyer

**At the desk, before driving out**

1. `node scripts/add-owner.js --pending --name "Хүнс маркет ХХК" --phone 99112233 --label "Хүнс маркет — үндсэн"` → prints `ownerId`, `credentialId`. **The phone you type here is the one everything else is checked against. Read it off the signed contract, not from memory.**
2. `node scripts/set-invoice-code.js --credential <credentialId> --code <QPay invoice code>` — read it off their QPay contract. If you cannot find it, stop: the owner will not find it on a phone either.
3. `node scripts/register-machine.js --owner <ownerId> --credential <credentialId> --device-no 44403 --label "Хүнс маркет" --location "3-р хороо"`.
4. `node scripts/invite-owner.js --owner <ownerId> --phone 99112233 --admin` — the CLI prints the number back spaced (`99 11 22 33`) and makes you retype the last four. **Do not skip this.** A transposed digit here puts admin control of this owner's money on a stranger's phone, and every other check in the system will let them through. It prints the URL, the reference (`OQ4K-7M2P`), the expiry, and a terminal QR.

**On site, after the machine is installed**

5. Turn the laptop around. **The owner scans the QR with their own phone camera.** Nothing is sent by SMS. This is the strongest anti-phishing control in the whole system and it costs nothing.
6. Say it out loud, and it is printed on a card in the box: *"Энэ холбоосыг би танд өөрөө өглөө. Ийм холбоос мессежээр, Facebook-ээр ирвэл манайх биш."*
7. Add the page to their home screen (`Кофе машин – QPay`). Their default path afterwards is an icon, not a link.
8. Owner taps **[ Код авах ]**, gets the OTP, enters it. **If the SMS has not arrived in 60 seconds, stop and call — do not wait it out.** That is a carrier-route problem and you want to find it now, not at 2am in three months.
9. Owner enters **two fields** on `/qpay`: QPay нэвтрэх нэр, QPay нууц үг. You do not read them, you do not type them, and **you never take a QPay password over the phone.** Sitting beside them while *they* type is allowed. Reading a password down a voice call is not — the moment it crosses that call you personally hold it with no audit row, and the promise printed on their screen becomes a lie you told first.
10. Screen shows the 10₮ nonce step. **Owner opens merchant.qpay.mn on their own phone** and finds `Кофе машин холболт шалгах ####`. They type the four digits.
11. **If they cannot see that invoice: STOP.** The credentials are for an account they do not control. Nothing has been saved. Work out which QPay account is actually theirs before going any further. This is the failure you are here to catch.
12. Screen shows **"Холбогдлоо."** Wait 60 seconds.
13. **One real 100₮ sale on the machine.** Owner opens their own QPay portal and sees 100₮ arrive **in their own account**. Nothing before this counts as done.
14. `node scripts/confirm-acceptance.js --credential <credentialId> --order <orderId>`. This is what stops the daily report chasing you about this machine.
15. Point at `/help`, read the phone number out loud, and say the sentence one more time: *"Бид утсаар QPay нууц үг хэзээ ч асуухгүй."*
16. **Now** you leave.

**If the owner will not finish on site:** do not leave on a promise. Write an agreed date. The machine will meet a real customer within hours and return `MERCHANT_NOT_READY`; put the printed card in it ("Тун удахгүй ажиллана"). T+24h the daily report fires and you send **one** SMS with no link ("Аппаа нээж QPay-ээ холбоно уу"). T+72h you call. T+14d the invite expires: reissue or collect the machine.

---

## 8. What remains risky

**Fixed:** every critical and high finding. Machine-before-credential (pending row, verified by insert); wrong-merchant-account (the nonce); rotation bricking a live machine (staged `pending_*`, verified in T6); raw Postgres errors on the phone (submissions deleted, status codes not `raise`); `complete_*` authorising nobody (admin check in SQL, T5a); mistyped invite phone (cross-check + viewer default, T2a/T3); silent death after a password rotation (alert on the *first* auth failure, to owner **and** operator); the `err.body` leak and the dead 2kb cap (Phase 0); multi-business users; same-owner fingerprint collisions; the `unique_violation` DETAIL channel.

**Accepted, not fixed — and why:**

1. **The credential-testing oracle.** `AUTH_FAILED` vs `INVOICE_CODE_FAILED` is one clean bit confirming that a `(username, password)` pair is a valid QPay merchant login, hosted where QPay cannot rate-limit or see it. Bulk stuffing is genuinely closed (20/day against at most 2 usernames), but verifying one already-leaked pair costs one request. I keep the distinct messages: merging them into "мэдээлэл буруу байна" sends owners to the phone, which is the outcome this feature exists to prevent. Mitigation that costs nothing: an operator alert when an owner produces `AUTH_FAILED` on a username fingerprint they have never successfully configured — a confused shop manager retries their own username. **Record in §8 as accepted risk.**

2. **`pending_invoice_code` is plaintext during onboarding.** A deliberate deviation from decision #15. It cannot invoice without the username and password, and decision #14's keyed HMAC means publishing it costs nothing in brute-force resistance. It is NULLed at seal. The trade buys the largest single reduction in form abandonment available. **Record in §8's "what this does not protect against".**

3. **`username_hint` leaks four characters of the username** in plaintext. Without a recognisable hint an owner with two shops cannot tell which merchant is configured, and resolving that confusion is a phone call.

4. **`app.request_ip()` is not used for credential writes**, so the XFF-index bug is moot on that path — the bridge passes what Express observed with `trust proxy = 1`, and the raw header is stored verbatim in `source_xff` rather than guessing an index. `accept_owner_invite` is likewise bridge-called. Nothing owner-reachable derives an IP inside Postgres any more.

5. **A stolen owner session can still redirect that owner's future revenue.** Bounded by detection, not prevented: fresh OTP within 10 minutes for a *change*, an SMS to the paperwork number (not the session's), an audit row, a global sign-out, and the weekly reconciliation. **Say this in the contract as detection, not prevention.**

6. **The operator can decrypt every owner's credentials at will** (§8 item 3). Self-service changes who *types* the password, not who can *read* it. Do not let "we never see your password" become the sales line; it is not true.

**Unverified prerequisites — confirm before the first install, not on a customer:**
- **Does the QPay merchant portal display `invoice_description` in its invoice list?** The entire nonce check depends on it. Test on the operator's own merchant account first. If it does not, the fallback is the 100₮ acceptance sale as sole detector, and step 20d becomes mandatory rather than a backstop.
- **QPay's minimum invoice amount.** 10₮ is a judgement, not a verified fact.
- **Supabase's Send SMS auth hook on the operator's plan**, needed for a Mongolian aggregator; the built-ins are Twilio/MessageBird/Vonage/Textlocal over international A2P. Send a test OTP to a Mobicom, a Unitel and a Skytel number.
- **The blank-page risk on old Android.** SSR + `<noscript>` covers it, but test on a real cheap handset, not a desktop emulator.

**The failure this design cannot prevent, only shape:** the owner gives up and says *"чи өөрөө оруулаад өгөөч"*. The permitted concession is the operator beside them (or on video) while the **owner** types. The forbidden one is a QPay password over a voice call. Put that line in the installer's checklist, not only in a design document — and watch the `source` column to find out how often it actually happens.