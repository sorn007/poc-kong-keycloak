#!/usr/bin/env bash
# Phase 0 (CIBA pilot) — ตั้งค่า Keycloak สำหรับ Headless Authentication:
# 1) CIBA Policy ระดับ realm central (poll / expires / interval / login_hint)
# 2) Upsert confidential client headless-app (เปิด CIBA Grant + scope identity-buyer-web)
# รันซ้ำได้ (idempotent)
source "$(dirname "$0")/_lib.sh"
require_jq

wait_for "Keycloak discovery" "$ISSUER/.well-known/openid-configuration" 180 || exit 1

ADM=$(curl -s "$KC/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli \
  -d username="$KC_BOOTSTRAP_ADMIN_USERNAME" -d password="$KC_BOOTSTRAP_ADMIN_PASSWORD" |
  jq -r '.access_token // empty')
[ -n "$ADM" ] || { check "admin token (master)" "yes" "no"; exit 1; }
AUTH="Authorization: Bearer $ADM"

CIBA_CLIENT_ID="headless-app"

echo "--- 1) CIBA Policy ระดับ realm central ---"
# GET realm -> merge attributes -> PUT ครบทั้ง representation (กัน attributes เดิมหาย)
curl -s "$KC/admin/realms/central" -H "$AUTH" |
  jq '.attributes = ((.attributes // {}) + {
        cibaBackchannelTokenDeliveryMode: "poll",
        cibaExpiresIn: "120",
        cibaInterval: "5",
        cibaAuthRequestedUserHint: "login_hint"
      })' |
  curl -s -o /dev/null -w "%{http_code}" -X PUT "$KC/admin/realms/central" -H "$AUTH" -H "Content-Type: application/json" -d @- > /tmp/ciba-put.txt
PUT_CODE=$(cat /tmp/ciba-put.txt)
check "ตั้ง CIBA Policy (PUT realm)" "204" "$PUT_CODE"

GOT=$(curl -s "$KC/admin/realms/central" -H "$AUTH" | jq -c '.attributes | {cibaBackchannelTokenDeliveryMode, cibaExpiresIn, cibaInterval, cibaAuthRequestedUserHint}')
check "CIBA Policy ติดตั้งครบ 4 ค่า" \
  '{"cibaBackchannelTokenDeliveryMode":"poll","cibaExpiresIn":"120","cibaInterval":"5","cibaAuthRequestedUserHint":"login_hint"}' \
  "$GOT"

echo "--- 2) Upsert confidential client $CIBA_CLIENT_ID (CIBA Grant) ---"
CID=$(curl -s "$KC/admin/realms/central/clients?clientId=$CIBA_CLIENT_ID" -H "$AUTH" | jq -r '.[0].id // empty')
if [ -n "$CID" ]; then
  curl -s -o /dev/null -X DELETE "$KC/admin/realms/central/clients/$CID" -H "$AUTH"
  for i in $(seq 1 20); do
    GONE=$(curl -s "$KC/admin/realms/central/clients?clientId=$CIBA_CLIENT_ID" -H "$AUTH" | jq 'length')
    [ "$GONE" = "0" ] && break
    sleep 0.25
  done
  echo "  ลบ client เดิมแล้ว (สร้างใหม่เพื่อ idempotent)"
fi
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$KC/admin/realms/central/clients" -H "$AUTH" -H "Content-Type: application/json" -d "{
  \"clientId\": \"$CIBA_CLIENT_ID\",
  \"name\": \"Headless App (CIBA POC)\",
  \"enabled\": true,
  \"protocol\": \"openid-connect\",
  \"publicClient\": false,
  \"clientAuthenticatorType\": \"client-secret\",
  \"secret\": \"$CIBA_CLIENT_SECRET\",
  \"standardFlowEnabled\": false,
  \"directAccessGrantsEnabled\": false,
  \"attributes\": {\"oidc.ciba.grant.enabled\": \"true\"},
  \"defaultClientScopes\": [\"orders.read\", \"identity-buyer-web\", \"basic\", \"role_list\", \"profile\", \"email\", \"roles\", \"web-origins\", \"acr\"]
}")
check "สร้าง client $CIBA_CLIENT_ID (confidential + CIBA grant)" "201" "$CODE"

echo "--- 3) Verify client representation ---"
REP=$(curl -s "$KC/admin/realms/central/clients?clientId=$CIBA_CLIENT_ID" -H "$AUTH")
check "client เป็น confidential (publicClient=false)" "false" "$(echo "$REP" | jq -r '.[0].publicClient')"
check "CIBA Grant enabled (oidc.ciba.grant.enabled)" "true" "$(echo "$REP" | jq -r '.[0].attributes["oidc.ciba.grant.enabled"]')"
check "scope identity-buyer-web ถูก assign (aud=buyer-api)" "yes" \
  "$(echo "$REP" | jq -r '.[0].defaultClientScopes | index("identity-buyer-web") | if . then "yes" else "no" end')"
check "scope orders.read ถูก assign" "yes" \
  "$(echo "$REP" | jq -r '.[0].defaultClientScopes | index("orders.read") | if . then "yes" else "no" end')"

echo "--- 4) approver client บน upstream realm (ให้ :3040 ต้อง login ก่อนอนุมัติ) ---"
# id-device ต้องรู้จักผู้ใช้ก่อนอนุมัติ — client นี้ใช้ OIDC PKCE login ผ่าน realm
# central-id-upstream ("Central ID จริง") แล้ว id-device ตรวจว่า user ตรง login_hint
UP="central-id-upstream"
APPROVER_ID="id-device-approver"
AID=$(curl -s "$KC/admin/realms/$UP/clients?clientId=$APPROVER_ID" -H "$AUTH" | jq -r '.[0].id // empty')
if [ -n "$AID" ]; then
  curl -s -o /dev/null -X DELETE "$KC/admin/realms/$UP/clients/$AID" -H "$AUTH"
  for i in $(seq 1 20); do
    GONE=$(curl -s "$KC/admin/realms/$UP/clients?clientId=$APPROVER_ID" -H "$AUTH" | jq 'length')
    [ "$GONE" = "0" ] && break
    sleep 0.25
  done
  echo "  ลบ approver client เดิมแล้ว"
fi
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$KC/admin/realms/$UP/clients" -H "$AUTH" -H "Content-Type: application/json" -d "{
  \"clientId\": \"$APPROVER_ID\",
  \"name\": \"ID Device Approver (POC)\",
  \"enabled\": true,
  \"protocol\": \"openid-connect\",
  \"publicClient\": true,
  \"standardFlowEnabled\": true,
  \"directAccessGrantsEnabled\": false,
  \"attributes\": {\"pkce.code.challenge.method\": \"S256\"},
  \"redirectUris\": [\"http://localhost:3040/auth/callback\"],
  \"webOrigins\": [\"http://localhost:3040\"],
  \"defaultClientScopes\": [\"basic\", \"profile\", \"email\", \"roles\", \"web-origins\", \"acr\"]
}")
check "สร้าง client $APPROVER_ID บน upstream realm (PKCE S256)" "201" "$CODE"

rm -f /tmp/ciba-put.txt
summary
