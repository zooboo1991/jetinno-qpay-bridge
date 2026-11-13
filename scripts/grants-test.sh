#!/usr/bin/env bash
# 003's regression gate, actually run. Applies every migration to a throwaway
# Postgres and asserts what the API roles (anon, authenticated) can reach:
# nothing secret, nothing writable, no app function except the three meant
# for them. A migration that forgets its `revoke` fails here, not in
# production through PostgREST. Never touches Supabase.
set -uo pipefail
cd ~/Downloads/jetinno-qpay-bridge

PORT=55482
NAME=jetinno-grants-test

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1; return 0; }
trap cleanup EXIT
cleanup

docker run -d --rm --name "$NAME" -e POSTGRES_PASSWORD=test -e POSTGRES_DB=bridge \
  -p "$PORT:5432" postgres:16-alpine >/dev/null

ready=0
for _ in $(seq 1 60); do
  if docker exec "$NAME" psql -U postgres -d bridge -Atc 'select 1' >/dev/null 2>&1; then
    ready=1; break
  fi
  node -e "setTimeout(()=>{},1000)"
done
if [ "$ready" != "1" ]; then echo "  ✗ Postgres 60 секундэд бэлэн болсонгүй"; exit 1; fi

for f in migrations/0*.sql; do
  if ! docker exec -i "$NAME" psql -U postgres -d bridge -v ON_ERROR_STOP=1 -q < "$f" >/dev/null 2>&1; then
    echo "  ✗ migration failed: $f"
    exit 1
  fi
done

q() { docker exec "$NAME" psql -U postgres -d bridge -Atc "$1" 2>&1; }
PASS=0; TOTAL=0
gate() {
  TOTAL=$((TOTAL + 1))
  local out
  out=$(q "$2")
  if [ -z "$out" ]; then echo "  ✓ $1"; PASS=$((PASS + 1)); else echo "  ✗ $1"; echo "$out" | sed 's/^/      /'; fi
}

gate '(a) шифрлэгдсэн blob, fingerprint, урилгын digest anon/authenticated-д харагдахгүй' \
  "select rcg.grantee||' '||rcg.table_name||'.'||rcg.column_name
     from information_schema.role_column_grants rcg
    where rcg.grantee in ('anon','authenticated','PUBLIC')
      and rcg.column_name in ('sealed','fingerprint','token_hash','pending_sealed',
                              'pending_fingerprint','verify_nonce','pending_invoice_code')"

gate '(b) authenticated-д public дотор SELECT-ээс өөр эрх алга, anon-д огт алга' \
  "select grantee||' '||table_name||' '||privilege_type
     from information_schema.role_table_grants
    where table_schema = 'public'
      and ((grantee = 'authenticated' and privilege_type <> 'SELECT') or grantee in ('anon','PUBLIC'))"

gate '(c) app дахь SECURITY DEFINER функц бүр search_path-аа тогтоосон' \
  "select p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'app' and p.prosecdef
      and not coalesce(array_to_string(p.proconfig, ',') like '%search_path=%', false)"

gate '(d) app-ын функцийг anon/authenticated дуудаж чадахгүй (зөвхөн peek_invite, is_operator, my_owner_ids)' \
  "select p.proname||' '||r.rolname
     from pg_proc p
     join pg_namespace n on n.oid = p.pronamespace
     cross join lateral (values ('anon'),('authenticated')) as r(rolname)
    where n.nspname = 'app'
      and has_function_privilege(r.rolname, p.oid, 'EXECUTE')
      and p.proname not in ('peek_invite','is_operator','my_owner_ids')"

gate '(e) public дахь хүснэгт бүр RLS-тэй' \
  "select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind = 'r' and not c.relrowsecurity"

# (f) Live proof: as the authenticated role, the secret column and the new
# 018 functions are refused.
TOTAL=$((TOTAL + 1))
live=$(docker exec -i "$NAME" psql -U postgres -d bridge -At -v ON_ERROR_STOP=0 2>&1 <<'SQL'
begin;
set local role authenticated;
select sealed from public.qpay_credentials limit 1;
rollback;
begin;
set local role authenticated;
select * from app.auth_attempt('otp_request', '1.2.3.4', '99110000');
rollback;
begin;
set local role anon;
select app.operator_remove_member(gen_random_uuid(), gen_random_uuid(), gen_random_uuid());
rollback;
SQL
)
if [ "$(echo "$live" | grep -c 'permission denied')" = "3" ]; then
  echo "  ✓ (f) authenticated/anon шууд дуудахад permission denied (3/3)"; PASS=$((PASS + 1))
else
  echo "  ✗ (f) шууд дуудалт хаагдаагүй"; echo "$live" | sed 's/^/      /'
fi

echo
echo "  $PASS/$TOTAL давлаа"
[ "$PASS" = "$TOTAL" ]
