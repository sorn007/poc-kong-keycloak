#!/usr/bin/env bash
# Phase 0 (CIBA pilot) — ทดสอบ Headless Authentication แบบ E2E
# จำลองแบบ production: อุปกรณ์ ID **ล็อกอินค้างไว้ก่อนเริ่ม** (เหมือนแอป ID บนมือถือที่ล็อกอินอยู่)
# ลำดับ: AD login -> คำขอ #1 (buyer-user) -> approve -> token -> Buyer 200
#      -> คำขอ #2 -> deny -> access_denied -> auth_req_id ปลอม -> invalid_grant
# ตรวจ security: /pending เห็นเฉพาะคำขอของตัวเอง (login_hint ตรง username)
source "$(dirname "$0")/_lib.sh"
require_jq

wait_for "Keycloak discovery" "$ISSUER/.well-known/openid-configuration" 180 || exit 1
echo

HEADLESS="http://localhost:3030"
IDDEV="http://localhost:3040"
CIBA_AUTH="$ISSUER/protocol/openid-connect/ext/ciba/auth"
GRANT="urn:openid:params:grant-type:ciba"

# helper: CIBA request (confidential client headless-app)
ciba_request() { # $1=login_hint $2=binding_message -> JSON
  curl -s -X POST "$CIBA_AUTH" \
    -d client_id=headless-app -d client_secret="$CIBA_CLIENT_SECRET" \
    -d scope="openid orders.read" -d login_hint="$1" -d binding_message="$2"
}
ciba_poll() { # $1=auth_req_id -> JSON
  curl -s "$ISSUER/protocol/openid-connect/token" \
    -d grant_type="$GRANT" -d auth_req_id="$1" \
    -d client_id=headless-app -d client_secret="$CIBA_CLIENT_SECRET"
}
# helper: AD login ผ่าน upstream realm (PKCE browser flow) — ต้องทำ 1 ครั้งต่อ user
ad_login() { # $1=username $2=cookie jar -> ตั้ง device_session ใน jar
  local LJAR="$1" USER="$2"
  local PAGE ACT DATA=() N V
  PAGE=$(curl -s -L -c "$LJAR" -b "$LJAR" -w "\nFINAL:%{url_effective}" "$IDDEV/auth/login")
  ACT=$(grep -o 'action="[^"]*"' <<<"$PAGE" | head -1 | sed 's/^action="//;s/"$//;s/&amp;/\&/g')
  [ -z "$ACT" ] && return 1
  DATA=(-d "username=$USER" -d "password=$TEST_USER_PASSWORD" -d "credentialId=")
  while IFS= read -r tag; do
    N="$(sed -n 's/.*[ ]name="\([^"]*\)".*/\1/p' <<<"$tag")"; V="$(sed -n 's/.*value="\([^"]*\)".*/\1/p' <<<"$tag")"
    [ -n "$N" ] && [ -n "$V" ] && DATA+=(-d "$N=$V")
  done < <(grep -o '<input[^>]*type="hidden"[^>]*>' <<<"$PAGE")
  curl -s -c "$LJAR" -b "$LJAR" -L -o /dev/null "${DATA[@]}" "$ACT"
}

JAR="$(mktemp)"

echo "--- 0) ผู้อนุมัติล็อกอินค้างไว้บนอุปกรณ์ (เหมือนแอป ID ที่เปิดอยู่) ---"
ad_login "$JAR" "buyer-user"
PEND0=$(curl -s -b "$JAR" "$IDDEV/pending" | jq 'length')
if [ -n "$PEND0" ] && [ "$PEND0" -ge 0 ] 2>/dev/null; then
  check "อุปกรณ์ ID ล็อกอินแล้ว (session พร้อม)" "yes" "yes"
else
  check "AD login ล้มเหลว" "yes" "no"; exit 1
fi

echo "--- 1) คำขอ #1: CIBA request (login_hint=buyer-user) ---"
BM="E2E-approve-$(date +%s)"
RESP=$(ciba_request buyer-user "$BM")
AUTH_REQ_ID=$(echo "$RESP" | jq -r '.auth_req_id // empty')
INTERVAL=$(echo "$RESP" | jq -r '.interval // 5')
[ -n "$AUTH_REQ_ID" ] && check "CIBA request -> ได้ auth_req_id" "yes" "yes" || { check "CIBA request -> ได้ auth_req_id" "yes" "no ($RESP)"; exit 1; }
check "response มี interval (poll guidance)" "true" "$(echo "$RESP" | jq 'has("interval")')"

echo "--- 2) poll ก่อนอนุมัติ -> authorization_pending ---"
sleep 1
PENDING=$(ciba_poll "$AUTH_REQ_ID")
ERR=$(echo "$PENDING" | jq -r '.error // empty')
check "poll ก่อนอนุมัติ -> authorization_pending" "authorization_pending" "$ERR"

echo "--- 2b) อุปกรณ์ ID เห็นเฉพาะคำขอของตัวเอง (login_hint=buyer-user) ---"
PEND_LIST=$(curl -s -b "$JAR" "$IDDEV/pending")
PID=$(echo "$PEND_LIST" | jq -r '.[] | select(.binding_message=="'"$BM"'") | .id' | head -1)
[ -n "$PID" ] && check "อุปกรณ์ ID เห็นคำขอของตัวเอง (ผูก login_hint=username)" "yes" "yes" || { check "อุปกรณ์ ID เห็นคำขอของตัวเอง" "yes" "no"; exit 1; }
OTHER=$(echo "$PEND_LIST" | jq '[.[] | select(.login_hint!="buyer-user")] | length')
check "ไม่เห็นคำขอของ user อื่น" "0" "$OTHER"

echo "--- 3) อนุมัติผ่านอุปกรณ์ ID -> callback 200 ---"
APPROVE=$(curl -s -b "$JAR" -X POST "$IDDEV/ciba/approve?id=$PID")
CB_STATUS=$(echo "$APPROVE" | jq -r '.callback_status // empty')
check "id-device ยืนยัน (KC callback 200)" "200" "$CB_STATUS"

echo "--- 4) poll หลังอนุมัติ -> ได้ token ---"
TOKEN_JSON=""
for i in 1 2 3 4 5; do
  sleep "$INTERVAL"
  TOKEN_JSON=$(ciba_poll "$AUTH_REQ_ID")
  ERR=$(echo "$TOKEN_JSON" | jq -r '.error // empty')
  [ -z "$ERR" ] && break
  echo "  poll#$i -> $ERR (รอ $INTERVAL วินาที)"
done
AT=$(echo "$TOKEN_JSON" | jq -r '.access_token // empty')
[ -n "$AT" ] && check "poll -> ได้ access_token" "yes" "yes" || { check "poll -> ได้ access_token" "yes" "no ($TOKEN_JSON)"; exit 1; }

PAY=$(jwt_payload "$AT")
check "token aud มี buyer-api" "yes" "$(echo "$PAY" | jq -r 'if (.aud|type)=="array" then (.aud|index("buyer-api")|if . then "yes" else "no" end) else (if .aud=="buyer-api" then "yes" else "no" end) end')"
check "token principal_type = user" "user" "$(echo "$PAY" | jq -r '.principal_type // empty')"
check "token scope มี orders.read" "yes" "$(echo "$PAY" | jq -r '.scope' | grep -qw orders.read && echo yes || echo no)"
check "token iss = realm central" "$ISSUER" "$(echo "$PAY" | jq -r '.iss')"

echo "--- 5) เรียก Buyer API เดิมด้วย CIBA token (จุดพิสูจน์หลัก) ---"
CODE=$(curl -s -o /tmp/ciba-orders.json -w "%{http_code}" "$BUYER/orders" -H "Authorization: Bearer $AT")
check "GET buyer /orders -> 200 (Guard เดิมยอมรับ CIBA token)" "200" "$CODE"

echo "--- 6) คำขอ #2: deny path ---"
BM2="E2E-deny-$(date +%s)"
RESP2=$(ciba_request buyer-user "$BM2")
ARID2=$(echo "$RESP2" | jq -r '.auth_req_id // empty')
[ -z "$ARID2" ] && { check "ขอคำขอที่สอง (เพื่อ deny)" "yes" "no ($RESP2)"; exit 1; }
sleep 1
PID2=$(curl -s -b "$JAR" "$IDDEV/pending" | jq -r '.[] | select(.binding_message=="'"$BM2"'") | .id' | head -1)
[ -z "$PID2" ] && { check "พบคำขอที่สองบนอุปกรณ์" "yes" "no"; exit 1; }
DENY_RES=$(curl -s -b "$JAR" -X POST "$IDDEV/ciba/deny?id=$PID2")
check "ผู้ใช้ปฏิเสธบนอุปกรณ์ ID (callback 200)" "200" "$(echo "$DENY_RES" | jq -r '.callback_status // empty')"
sleep "$INTERVAL"
DENY=$(ciba_poll "$ARID2")
check "ผู้ใช้ปฏิเสธ -> poll ได้ access_denied" "access_denied" "$(echo "$DENY" | jq -r '.error // empty')"

echo "--- 7) auth_req_id ปลอม -> invalid_grant ---"
BOGUS=$(ciba_poll "bogus-auth-req-id-000")
check "auth_req_id ปลอม -> invalid_grant" "invalid_grant" "$(echo "$BOGUS" | jq -r '.error // empty')"

rm -f /tmp/ciba-orders.json
summary
