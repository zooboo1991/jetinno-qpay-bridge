#!/usr/bin/env bash
# Runs scripts/stats-test.mjs against a throwaway Postgres carrying the real
# migrations. Never touches Supabase; needs no production credential.
set -uo pipefail
cd ~/Downloads/jetinno-qpay-bridge

PORT=55433
NAME=jetinno-stats-test

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1; return 0; }
trap cleanup EXIT
cleanup

docker run -d --rm --name "$NAME" -e POSTGRES_PASSWORD=test -e POSTGRES_DB=bridge \
  -p "$PORT:5432" postgres:16-alpine >/dev/null

for _ in $(seq 1 40); do
  docker exec "$NAME" pg_isready -U postgres -d bridge >/dev/null 2>&1 && break
  node -e "setTimeout(()=>{},1000)"
done

# 000 is the local stub for what a real Supabase project already provides.
for f in migrations/000_*.sql migrations/001_*.sql migrations/002_*.sql migrations/003_*.sql migrations/004_*.sql; do
  if ! docker exec -i "$NAME" psql -U postgres -d bridge -v ON_ERROR_STOP=1 -q < "$f" >/dev/null 2>&1; then
    echo "  ✗ migration failed: $f"
    exit 1
  fi
done

DATABASE_URL="postgresql://postgres:test@localhost:$PORT/bridge" node scripts/stats-test.mjs
