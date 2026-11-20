#!/usr/bin/env bash
# Fintech App (Embedded Login exception demo) — ตั้งค่า Keycloak:
# 1) Upsert confidential client fintech-web (Direct Access Grants เปิด — exception pattern)
# 2) เปิด Brute Force Protection ระดับ realm (**top-level fields** ของ RealmRepresentation
#    — ไม่ใช่ attributes map: bruteForceProtected/failureCount/waitIncrementSeconds
#      เป็น field หลักของ realm, KC จะดึงออกจาก attributes ตอน PUT)
#    5 ความล้มเหลว -> ล็อกชั่วคราว 30 วินาที (ครอบคลุมทุก client/flow — ล็อกที่ ID กลาง = ล็อกทุกแอป)
# รันซ้ำได้ (idempotent — 409/async-delete กันด้วยการรอ+retry)
source "$(dirname "$0")/_lib.sh"
require_jq

wait_for "Keycloak discovery" "$ISSUER/.well-known/openid-configuration" 180 || exit 1

ADM=$(curl -s "$KC/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli \
  -d username="$KC_BOOTSTRAP_ADMIN_USERNAME" -d password="$KC_BOOTSTRAP_ADMIN_PASSWORD" |
  jq -r '.access_token // empty')
[ -n "$ADM" ] || { check "admin token (master)" "yes" "no"; exit 1; }
AUTH="Authorization: Bearer $ADM"

FT="fintech-web"

echo "--- 1) Upsert confidential client $FT (Direct Grant — exception pattern) ---"
CID=$(curl -s "$KC/admin/realms/central/clients?clientId=$FT" -H "$AUTH" | jq -r '.[0].id // empty')
if [ -n "$CID" ]; then
  curl -s -o /dev/null -X DELETE "$KC/admin/realms/central/clients/$CID" -H "$AUTH"
  for i in $(seq 1 40); do
    STILL=$(curl -s "$KC/admin/realms/central/clients?clientId=$FT" -H "$AUTH" | jq 'length')
    [ "$STILL" = "0" ] && break
    sleep 0.5
  done
  echo "  ลบ client เดิมแล้ว (สร้างใหม่เพื่อ idempotent)"
fi
CODE=""
for attempt in 1 2 3; do
  CODE=$(curl -s -o /tmp/ft-create.txt -w "%{http_code}" -X POST "$KC/admin/realms/central/clients" -H "$AUTH" -H "Content-Type: application/json" -d "{
    \"clientId\": \"$FT\",
    \"name\": \"Fintech App (Embedded Login POC)\",
    \"enabled\": true,
    \"protocol\": \"openid-connect\",
    \"publicClient\": false,
    \"clientAuthenticatorType\": \"client-secret\",
    \"secret\": \"$FINTECH_CLIENT_SECRET\",
    \"standardFlowEnabled\": false,
    \"directAccessGrantsEnabled\": true,
    \"attributes\": {\"oidc.ciba.grant.enabled\": \"false\"},
    \"defaultClientScopes\": [\"orders.read\", \"identity-buyer-web\", \"basic\", \"role_list\", \"profile\", \"email\", \"roles\", \"web-origins\", \"acr\"],
    \"optionalClientScopes\": [\"stt-bridge\"]
  }")
  [ "$CODE" = "201" ] && break
  echo "  attempt#$1 -> $CODE: $(cat /tmp/ft-create.txt | head -c 120) (รอ 2 วินาทีแล้วลองใหม่)"
  sleep 2
done
check "สร้าง client $FT (confidential + Direct Grant)" "201" "$CODE"

echo "--- 2) เปิด Brute Force Protection ระดับ realm ---"
# bruteForceProtected/waitIncrementSeconds/permanentLockout = top-level fields
# ส่วน failureCount = realm attribute (string) — Keycloak อ่านจาก attributes
curl -s -o /dev/null -w "%{http_code}" -X PUT "$KC/admin/realms/central" -H "$AUTH" -H "Content-Type: application/json" -d '{
  "bruteForceProtected": true,
  "permanentLockout": false,
  "waitIncrementSeconds": 30,
  "maxFailureWaitSeconds": 900,
  "minimumQuickLoginWaitSeconds": 60,
  "quickLoginCheckMilliSeconds": 1000,
  "attributes": { "failureCount": "5" }
}' > /tmp/ft-put.txt
PUT_CODE=$(cat /tmp/ft-put.txt)
check "ตั้ง Brute Force Protection (PUT realm)" "204" "$PUT_CODE"

GOT=$(curl -s "$KC/admin/realms/central" -H "$AUTH" | jq -c '{bruteForceProtected, waitIncrementSeconds, permanentLockout, attrFC: .attributes.failureCount}')
check "Brute Force Policy ติดตั้งครบ" \
  '{"bruteForceProtected":true,"waitIncrementSeconds":30,"permanentLockout":false,"attrFC":"5"}' \
  "$GOT"

rm -f /tmp/ft-put.txt /tmp/ft-create.txt
summary
