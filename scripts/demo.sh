#!/usr/bin/env bash
#
# The whole system on one laptop, one command, no real money.
#
#   npm run demo
#
# Starts the bridge in mock mode and a simulated coffee machine, walks a sale
# from "someone pressed a button" to "the cup came out", and leaves both
# running so the dashboards can be poked at. Ctrl-C stops everything.
#
# Nothing here touches QPay, Supabase, Render or a real machine: the QR is a
# local URL and "paying" is a curl.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PORT=${PORT:-3100}
MACHINE_PORT=${MACHINE_PORT:-4000}
KEY=${DEBUG_KEY:-demo}
ORDER="DEMO$(date +%H%M%S)"

freeport() {
  local pids
  pids=$(lsof -nP -iTCP:"$1" -sTCP:LISTEN -t 2>/dev/null)
  [ -n "$pids" ] && kill -9 $pids 2>/dev/null
  return 0
}
cleanup() {
  echo ""
  echo "  Зогсоож байна…"
  freeport "$PORT"; freeport "$MACHINE_PORT"
  return 0
}
trap cleanup EXIT INT TERM
freeport "$PORT"; freeport "$MACHINE_PORT"

say() { printf '\n\033[1m%s\033[0m\n' "$1"; }
ok()  { printf '  \033[32m✓\033[0m %s\n' "$1"; }

say "1. Гүүрийг асааж байна (mock горим — QPay-д холбогдохгүй)"
PORT=$PORT QPAY_MOCK=1 \
  JETINNO_USERNAME=testname JETINNO_APIKEY=DBRW17YE7FHKR72T \
  DEBUG_KEY=$KEY PUBLIC_URL=http://localhost:$PORT \
  node src/server.js > /tmp/demo-bridge.log 2>&1 &
for _ in $(seq 1 40); do
  curl -s -o /dev/null "http://localhost:$PORT/health" && break
  sleep 0.5
done
ok "http://localhost:$PORT"

say "2. Дуураймал кофе машин асааж, кофе сонгов"
BRIDGE_URL=http://localhost:$PORT TEST_ORDER_NO=$ORDER MACHINE_PORT=$MACHINE_PORT \
  node src/simulate-machine.js > /tmp/demo-machine.log 2>&1 &
for _ in $(seq 1 40); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' -H "X-Debug-Key: $KEY" "http://localhost:$PORT/orders/$ORDER")" = "200" ] && break
  sleep 0.5
done
QR=$(curl -s -H "X-Debug-Key: $KEY" "http://localhost:$PORT/orders/$ORDER" | node -pe "JSON.parse(require('fs').readFileSync(0,'utf8')).qrCode")
AMT=$(curl -s -H "X-Debug-Key: $KEY" "http://localhost:$PORT/orders/$ORDER" | node -pe "JSON.parse(require('fs').readFileSync(0,'utf8')).amountMnt")
ok "Машины дэлгэцэнд QR гарлаа: $QR"
ok "Үнэ: ${AMT}₮  ·  захиалга: $ORDER"

say "3. Хэрэглэгч QR-ыг уншуулж төллөө"
curl -s "http://localhost:$PORT/mock/pay/$ORDER" > /dev/null
sleep 1.5
if grep -q "Кофе гаргаж" /tmp/demo-machine.log; then
  ok "МАШИН КОФЕ ГАРГАЛАА — бүтэн гинж ажиллалаа"
else
  echo "  ✗ Кофе гараагүй. Лог: /tmp/demo-machine.log"
fi

say "4. Хоёр дахь удаа төлбөрийн мэдэгдэл ирвэл (QPay давтдаг)"
AGAIN=$(curl -s "http://localhost:$PORT/mock/pay/$ORDER")
CUPS=$(grep -c "Кофе гаргаж" /tmp/demo-machine.log)
if [ "$CUPS" = "1" ]; then
  ok "Хоёр дахь кофе ГАРААГҮЙ — нэг төлбөр = нэг аяга ($AGAIN)"
else
  echo "  ✗ $CUPS аяга гарсан байна — энэ бол алдаа"
fi

say "Одоо өөрөө үзэж болно (Ctrl-C-ээр зогсооно)"
cat <<TXT
  Серверийн лог утаснаас     http://localhost:$PORT/recent?key=$KEY
  Идэвхтэй захиалгууд        http://localhost:$PORT/orders?key=$KEY
  Алдаанууд                  http://localhost:$PORT/errors?key=$KEY
  Эрүүл мэнд                 http://localhost:$PORT/health

  Шинэ кофе зарах (өөр дугаараар):
    BRIDGE_URL=http://localhost:$PORT TEST_ORDER_NO=CUP2 MACHINE_PORT=4001 \\
      JETINNO_USERNAME=testname JETINNO_APIKEY=DBRW17YE7FHKR72T \\
      node src/simulate-machine.js
    curl http://localhost:$PORT/mock/pay/CUP2

  Эзэмшигчийн самбар (өөр терминал дээр):
    cd ~/Downloads/coffeine-owner && npm run dev
    → http://localhost:3300/dev/preview?state=active

TXT
wait
