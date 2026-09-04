#!/usr/bin/env bash
set -uo pipefail
cd ~/Downloads/jetinno-qpay-bridge

PORT=3100
B=http://localhost:$PORT
LOG=$(mktemp -d)
ORDER=TESTRUN$RANDOM

cleanup() {
  pkill -f "node src/server.js" 2>/dev/null
  pkill -f "node src/simulate-machine.js" 2>/dev/null
  return 0
}
trap cleanup EXIT
cleanup

# The server no longer falls back to the documentation's sample key, so the
# test supplies it explicitly. These are the public spec's example values —
# a test identity, never a real deployment's.
export JETINNO_USERNAME=testname
export JETINNO_APIKEY=DBRW17YE7FHKR72T
# The order-inspection endpoints are key-gated now, so the test authenticates
# like an operator would.
export DEBUG_KEY=e2e-debug-key
DBG=(-H "X-Debug-Key: e2e-debug-key")

PORT=$PORT QPAY_MOCK=1 PUBLIC_URL=$B node src/server.js > "$LOG/server.log" 2>&1 &
curl -sf --retry-connrefused --retry 20 --retry-delay 1 "$B/health" > /dev/null

echo "### 1. Машин кофе сонголоо (getQrCode)"
BRIDGE_URL=$B TEST_ORDER_NO=$ORDER MACHINE_PORT=4000 node src/simulate-machine.js > "$LOG/machine.log" 2>&1 &
curl -sf -o /dev/null "${DBG[@]}" --retry-all-errors --retry 30 --retry-delay 1 "$B/orders/$ORDER"
QR1=$(curl -s "${DBG[@]}" "$B/orders/$ORDER" | sed 's/.*"qrCode":"\([^"]*\)".*/\1/')
echo "    QR: $QR1"

echo
echo "### 2. Ижил orderNo-гоор дахин getQrCode (машины 8 сек timeout-ийн давталт)"
QR2=$(O=$ORDER B=$B node -e '
import("./src/sign.js").then(async ({ SIGNABLE, buildSign, flatten, timestamp }) => {
  const data = { deviceNo: "44401", productId: "1", productName: "拿铁", orderNo: process.env.O, orderAmount: "100000", notifyUrl: "http://localhost:4000/notify" };
  const body = { username: "testname", time: timestamp(), data };
  body.sign = buildSign(flatten(body), SIGNABLE.getQrCodeRequest, "DBRW17YE7FHKR72T");
  const r = await fetch(process.env.B + "/jetinno/getQrCode", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json();
  console.log(j.data?.qrCode ?? "FAIL:" + j.msg);
});')
echo "    QR: $QR2"

echo
echo "### 3. Таван зэрэгцээ төлбөрийн мэдэгдэл"
PIDS=()
for i in 1 2 3 4 5; do
  curl -s -o /dev/null -w "    callback$i -> HTTP %{http_code}\n" \
    --retry-all-errors --retry 20 --retry-delay 1 "$B/mock/pay/$ORDER" &
  PIDS+=($!)
done
for p in "${PIDS[@]}"; do wait "$p"; done

echo
echo "### 4. QPay webhook-ийн хариу формат"
printf "    "
curl -s -w " <- HTTP %{http_code}\n" "$B/qpay/callback/$ORDER"

echo
echo "###############################################"
PASS=1

COFFEES=$(grep -c 'Кофе гаргаж' "$LOG/machine.log")
if [ "$COFFEES" = "1" ]; then echo "  ✓ Кофе яг 1 удаа гарлаа"; else echo "  ✗ Кофе $COFFEES удаа гарлаа (1 байх ёстой)"; PASS=0; fi

if [ -n "$QR2" ] && [ "$QR1" = "$QR2" ]; then echo "  ✓ Давталтад ижил QR буцлаа — шинэ invoice үүсээгүй"; else echo "  ✗ Давталтад өөр QR: '$QR2'"; PASS=0; fi

if grep -q 'getQrCode replay' "$LOG/server.log"; then echo "  ✓ Сервер давталтыг таньсан"; else echo "  ✗ Сервер давталтыг танихгүй"; PASS=0; fi

[ "$PASS" = "1" ] && echo "  БҮХ ШАЛГУУР ДАВЛАА" || echo "  АЛДАА ИЛЭРЛЭЭ"
echo "###############################################"
echo
echo "--- машины лог ---"; cat "$LOG/machine.log"
echo "--- серверийн лог ---"; cat "$LOG/server.log"
