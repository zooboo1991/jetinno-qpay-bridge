#!/usr/bin/env bash
# Runs scripts/tenant-test.mjs against a throwaway Postgres carrying the real
# migrations. Never touches Supabase; needs no production credential.
set -uo pipefail
cd ~/Downloads/jetinno-qpay-bridge

PORT=55444
NAME=jetinno-tenant-test

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1; return 0; }
trap cleanup EXIT
cleanup

docker run -d --rm --name "$NAME" -e POSTGRES_PASSWORD=test -e POSTGRES_DB=bridge \
  -p "$PORT:5432" postgres:16-alpine >/dev/null

# pg_isready answers OK during the image's own initdb phase, on a temporary
# server that is then shut down and restarted — so it is not a readiness
# signal. Waiting on a real query is.
ready=0
for _ in $(seq 1 60); do
  if docker exec "$NAME" psql -U postgres -d bridge -Atc 'select 1' >/dev/null 2>&1; then
    ready=1; break
  fi
  node -e "setTimeout(()=>{},1000)"
done
if [ "$ready" != "1" ]; then echo "  ✗ Postgres 60 секундэд бэлэн болсонгүй"; exit 1; fi

# 000 is the local stub for what a real Supabase project already provides.
for f in migrations/000_*.sql migrations/001_*.sql migrations/002_*.sql migrations/003_*.sql migrations/006_*.sql; do
  if ! docker exec -i "$NAME" psql -U postgres -d bridge -v ON_ERROR_STOP=1 -q < "$f" >/dev/null 2>&1; then
    echo "  ✗ migration failed: $f"
    exit 1
  fi
done

DATABASE_URL="postgresql://postgres:test@localhost:$PORT/bridge" node scripts/tenant-test.mjs
