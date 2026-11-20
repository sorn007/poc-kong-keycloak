#!/usr/bin/env bash
# STT v2 — Session Transfer ข้ามแอป (cross-app) — ตั้งค่า Keycloak 3 ชิ้น:
# 1) สร้าง client scope `stt-bridge` (audience mapper -> cis-web) — เงื่อนไขของ KC Token Exchange
#    Standard V2: client ที่ยื่นขอ exchange (requester) ต้องอยู่ใน aud ของ subject token
#    (scope นี้เติมแค่ aud ไม่เพิ่มสิทธิ์เรียก API ของ CIS เลย — Guard ยังตรวจ aud=cis-api เสมอ)
# 2) ผูก stt-bridge เป็น **optional** scope ของ buyer-web / fintech-web / mobile-app (ต้นทางที่โอนได้)
# 3) เลื่อน cis-web เป็น confidential client (client-secret) — KC V2 อนุญาตเฉพาะ confidential
#    requester + ต้อง authenticate ที่ token endpoint (ตรงตามมาตรฐาน server-side web app)
# รันซ้ำได้ (idempotent — recreate scope + append optional scopes + PUT client)
source "$(dirname "$0")/_lib.sh"
require_jq

wait_for "Keycloak discovery" "$ISSUER/.well-known/openid-configuration" 180 || exit 1

ADM=$(curl -s "$KC/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli \
  -d username="$KC_BOOTSTRAP_ADMIN_USERNAME" -d password="$KC_BOOTSTRAP_ADMIN_PASSWORD" |
  jq -r '.access_token // empty')
[ -n "$ADM" ] || { check "admin token (master)" "yes" "no"; exit 1; }
AUTH="Authorization: Bearer $ADM"
BASE="$KC/admin/realms/$REALM"

echo "--- 1) Upsert client scope stt-bridge (audience mapper -> cis-web) ---"
SID=$(curl -s "$BASE/client-scopes" -H "$AUTH" | jq -r '.[] | select(.name=="stt-bridge") | .id' | head -1)
if [ -n "$SID" ]; then
  curl -s -o /dev/null -X DELETE "$BASE/client-scopes/$SID" -H "$AUTH"
  for i in $(seq 1 20); do
    STILL=$(curl -s "$BASE/client-scopes" -H "$AUTH" | jq '[.[] | select(.name=="stt-bridge")] | length')
    [ "$STILL" = "0" ] && break
    sleep 0.5
  done
  echo "  ลบ scope เดิมแล้ว (สร้างใหม่เพื่อ idempotent)"
fi
CODE=$(curl -s -o /tmp/stt-scope.txt -w "%{http_code}" -X POST "$BASE/client-scopes" -H "$AUTH" -H "Content-Type: application/json" -d '{
  "name": "stt-bridge",
  "protocol": "openid-connect",
  "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "false"},
  "protocolMappers": [{
    "name": "aud-cis-web-for-exchange",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-audience-mapper",
    "consentRequired": false,
    "config": {
      "included.client.audience": "cis-web",
      "access.token.claim": "true",
      "id.token.claim": "false"
    }
  }, {
    "name": "aud-central-id-portal-for-exchange",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-audience-mapper",
    "consentRequired": false,
    "config": {
      "included.client.audience": "central-id-portal",
      "access.token.claim": "true",
      "id.token.claim": "false"
    }
  }]
}')
check "สร้าง client scope stt-bridge" "201" "$CODE"
SID=$(curl -s "$BASE/client-scopes" -H "$AUTH" | jq -r '.[] | select(.name=="stt-bridge") | .id' | head -1)
[ -n "$SID" ] || { check "ได้ id ของ stt-bridge" "yes" "no"; exit 1; }
MAPPER=$(curl -s "$BASE/client-scopes/$SID" -H "$AUTH" | jq -r '.protocolMappers[0].config["included.client.audience"] // empty')
check "mapper เติม aud=cis-web" "cis-web" "$MAPPER"

echo "--- 2) ผูก stt-bridge เป็น optional scope ของต้นทาง (buyer-web/fintech-web/mobile-app) ---"
# หมายเหตุ: Admin API ของ KC 26 ใช้ **PUT บน item path** (/clients/{id}/optional-client-scopes/{scopeId})
# — PUT บน collection ไม่มีในระบบ (404) และไม่ต้องส่ง body
for CL in buyer-web fintech-web mobile-app; do
  CID=$(curl -s "$BASE/clients?clientId=$CL" -H "$AUTH" | jq -r '.[0].id // empty')
  [ -n "$CID" ] || { check "เจอ client $CL" "yes" "no"; continue; }
  HAS=$(curl -s "$BASE/clients/$CID/optional-client-scopes" -H "$AUTH" | jq -r --arg s "$SID" '[.[].id] | index($s) != null')
  if [ "$HAS" = "true" ]; then
    check "$CL มี optional scope stt-bridge แล้ว" "yes" "yes"
  else
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$BASE/clients/$CID/optional-client-scopes/$SID" -H "$AUTH")
    check "ผูก optional scope stt-bridge ให้ $CL (PUT item 204)" "204" "$CODE"
  fi
done

echo "--- 3) เลื่อน cis-web เป็น confidential client (client-secret) ---"
CID=$(curl -s "$BASE/clients?clientId=cis-web" -H "$AUTH" | jq -r '.[0].id // empty')
[ -n "$CID" ] || { check "เจอ client cis-web" "yes" "no"; exit 1; }
# GET เต็ม -> แก้ field -> PUT (สำรอง: minimal PUT ถ้า full-rep PUT ไม่ผ่าน)
# พร้อมเปิด Standard Token Exchange V2 เฉพาะ client นี้ (attribute ของ KC 26.2+ — server feature
# เปิด default แล้ว แต่ยังต้องเปิด switch ราย client: "Standard token exchange is not enabled
# for the requested client" ถ้าลืม)
REPRESENTATION=$(curl -s "$BASE/clients/$CID" -H "$AUTH" | jq --arg sec "$CIS_CLIENT_SECRET" '.publicClient = false | .clientAuthenticatorType = "client-secret" | .secret = $sec | .attributes = ((.attributes // {}) + {"standard.token.exchange.enabled": "true"})')
CODE=$(curl -s -o /tmp/stt-cis-put.txt -w "%{http_code}" -X PUT "$BASE/clients/$CID" -H "$AUTH" -H "Content-Type: application/json" -d "$REPRESENTATION")
if [ "$CODE" != "204" ]; then
  echo "  full-representation PUT ได้ $CODE — ลอง minimal PUT"
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$BASE/clients/$CID" -H "$AUTH" -H "Content-Type: application/json" -d "{\"publicClient\": false, \"clientAuthenticatorType\": \"client-secret\", \"secret\": \"$CIS_CLIENT_SECRET\", \"attributes\": {\"standard.token.exchange.enabled\": \"true\"}}")
fi
check "cis-web -> confidential + เปิด Standard Token Exchange (PUT 204)" "204" "$CODE"
PUB=$(curl -s "$BASE/clients/$CID" -H "$AUTH" | jq -r '.publicClient')
check "ยืนยัน cis-web publicClient=false" "false" "$PUB"
STE=$(curl -s "$BASE/clients/$CID" -H "$AUTH" | jq -r '.attributes["standard.token.exchange.enabled"]')
check "ยืนยัน standard.token.exchange.enabled=true" "true" "$STE"

echo "--- 4) เลื่อน central-id-portal เป็น confidential + เปิด Token Exchange (portal รับตั๋วด้วย) ---"
PID=$(curl -s "$BASE/clients?clientId=central-id-portal" -H "$AUTH" | jq -r '.[0].id // empty')
[ -n "$PID" ] || { check "เจอ client central-id-portal" "yes" "no"; exit 1; }
REPRESENTATION=$(curl -s "$BASE/clients/$PID" -H "$AUTH" | jq --arg sec "$IDPORTAL_CLIENT_SECRET" '.publicClient = false | .clientAuthenticatorType = "client-secret" | .secret = $sec | .attributes = ((.attributes // {}) + {"standard.token.exchange.enabled": "true"})')
CODE=$(curl -s -o /tmp/stt-portal-put.txt -w "%{http_code}" -X PUT "$BASE/clients/$PID" -H "$AUTH" -H "Content-Type: application/json" -d "$REPRESENTATION")
if [ "$CODE" != "204" ]; then
  echo "  full-representation PUT ได้ $CODE — ลอง minimal PUT"
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$BASE/clients/$PID" -H "$AUTH" -H "Content-Type: application/json" -d "{\"publicClient\": false, \"clientAuthenticatorType\": \"client-secret\", \"secret\": \"$IDPORTAL_CLIENT_SECRET\", \"attributes\": {\"standard.token.exchange.enabled\": \"true\"}}")
fi
check "central-id-portal -> confidential + เปิด Token Exchange (PUT 204)" "204" "$CODE"
PPUB=$(curl -s "$BASE/clients/$PID" -H "$AUTH" | jq -r '.publicClient')
check "ยืนยัน central-id-portal publicClient=false" "false" "$PPUB"
PMAPPER=$(curl -s "$BASE/client-scopes/$SID" -H "$AUTH" | jq -r '[.protocolMappers[].config["included.client.audience"]] | index("central-id-portal") != null')
check "stt-bridge มี aud ของ portal แล้ว (แท็ก 2 mappers)" "true" "$PMAPPER"

rm -f /tmp/stt-scope.txt /tmp/stt-cis-put.txt
summary
