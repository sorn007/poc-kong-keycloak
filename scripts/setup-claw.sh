#!/usr/bin/env bash
# Claw Web (SPA) — ตั้งค่า Keycloak ให้แอปในเบราว์เซอร์ที่ login ผ่าน @central/login-js (ADR-009):
# upsert public client `claw-web`
#   • Authorization Code + PKCE S256 "บังคับ" · ปิด implicit flow และ Direct Grant
#   • webOrigins = origin ของแอป (Keycloak ใส่ CORS header ที่ token endpoint เฉพาะ origin ที่ลงทะเบียน)
#   • post-logout redirect URI ลงทะเบียนไว้ (logout จึงกลับมาที่แอปได้โดยไม่มีหน้า confirm)
#   • scope identity-buyer-web + orders.* → token มี aud=buyer-api ใช้กับ Buyer API ผ่าน Kong ได้
# รันซ้ำได้ (idempotent) · เครื่องที่ import realm ใหม่มี client นี้อยู่แล้วจาก template
# (script นี้มีไว้สำหรับเครื่องที่ import realm ไปก่อนหน้า / ต้องการ reset ค่า)
source "$(dirname "$0")/_lib.sh"
require_jq

wait_for "Keycloak discovery" "$ISSUER/.well-known/openid-configuration" 180 || exit 1

ADM=$(curl -s "$KC/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli \
  -d username="$KC_BOOTSTRAP_ADMIN_USERNAME" -d password="$KC_BOOTSTRAP_ADMIN_PASSWORD" |
  jq -r '.access_token // empty')
[ -n "$ADM" ] || { check "admin token (master)" "yes" "no"; exit 1; }
AUTH="Authorization: Bearer $ADM"

CLIENT_ID="claw-web"
REDIRECT="http://localhost:3060/auth/callback"
echo "--- 1) Upsert public client $CLIENT_ID (PKCE S256 enforced) ---"
CID=$(curl -s "$KC/admin/realms/central/clients?clientId=$CLIENT_ID" -H "$AUTH" | jq -r '.[0].id // empty')
if [ -n "$CID" ]; then
  curl -s -o /dev/null -X DELETE "$KC/admin/realms/central/clients/$CID" -H "$AUTH"
  for i in $(seq 1 20); do
    GONE=$(curl -s "$KC/admin/realms/central/clients?clientId=$CLIENT_ID" -H "$AUTH" | jq 'length')
    [ "$GONE" = "0" ] && break
    sleep 0.25
  done
  echo "  ลบ client เดิมแล้ว (สร้างใหม่เพื่อ idempotent)"
fi
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$KC/admin/realms/central/clients" -H "$AUTH" -H "Content-Type: application/json" -d "{
  \"clientId\": \"$CLIENT_ID\",
  \"name\": \"Claw Web (SPA + @central/login-js)\",
  \"enabled\": true,
  \"protocol\": \"openid-connect\",
  \"publicClient\": true,
  \"standardFlowEnabled\": true,
  \"implicitFlowEnabled\": false,
  \"directAccessGrantsEnabled\": false,
  \"rootUrl\": \"http://localhost:3060\",
  \"redirectUris\": [\"$REDIRECT\"],
  \"webOrigins\": [\"http://localhost:3060\"],
  \"attributes\": {\"pkce.code.challenge.method\": \"S256\", \"post.logout.redirect.uris\": \"http://localhost:3060\"},
  \"defaultClientScopes\": [\"orders.read\", \"orders.write\", \"identity-buyer-web\", \"basic\", \"role_list\", \"profile\", \"email\", \"roles\", \"web-origins\", \"acr\"]
}")
check "สร้าง client $CLIENT_ID (public + PKCE S256)" "201" "$CODE"

echo "--- 2) Verify client representation ---"
REP=$(curl -s "$KC/admin/realms/central/clients?clientId=$CLIENT_ID" -H "$AUTH")
check "client เป็น public (publicClient=true)" "true" "$(echo "$REP" | jq -r '.[0].publicClient')"
check "Standard flow เปิด (Authorization Code)" "true" "$(echo "$REP" | jq -r '.[0].standardFlowEnabled')"
check "Implicit flow ปิด" "false" "$(echo "$REP" | jq -r '.[0].implicitFlowEnabled')"
check "Direct Grant ปิด (SPA ไม่ใช้ password grant)" "false" "$(echo "$REP" | jq -r '.[0].directAccessGrantsEnabled')"
check "PKCE บังคับแบบ S256" "S256" "$(echo "$REP" | jq -r '.[0].attributes["pkce.code.challenge.method"]')"
check "redirect URI ตรงกับที่ SDK ใช้" '["http://localhost:3060/auth/callback"]' "$(echo "$REP" | jq -c '.[0].redirectUris')"
check "webOrigins = origin ของแอป (CORS ที่ token endpoint)" '["http://localhost:3060"]' "$(echo "$REP" | jq -c '.[0].webOrigins')"
check "post-logout redirect URI ลงทะเบียน" "http://localhost:3060" "$(echo "$REP" | jq -r '.[0].attributes["post.logout.redirect.uris"]')"
check "scope identity-buyer-web ถูก assign (aud=buyer-api)" "yes" \
  "$(echo "$REP" | jq -r '.[0].defaultClientScopes | index("identity-buyer-web") | if . then "yes" else "no" end')"
check "scope orders.read + orders.write ถูก assign" "yes" \
  "$(echo "$REP" | jq -r '.[0].defaultClientScopes | if (index("orders.read") and index("orders.write")) then "yes" else "no" end')"

echo "--- 3) PKCE บังคับจริงที่ authorize endpoint (ไม่ตาม redirect) ---"
# Keycloak ปฏิเสธทันทีด้วย redirect กลับมาพร้อม error=invalid_request — ไม่มี code ถูกออกและไม่เข้าหน้า login
LOC=$(curl -s -o /dev/null -D - "$ISSUER/protocol/openid-connect/auth?client_id=$CLIENT_ID&response_type=code&scope=openid&redirect_uri=http%3A%2F%2Flocalhost%3A3060%2Fauth%2Fcallback&state=s1" |
  grep -i '^location:' | tr -d '\r')
case "$LOC" in
  *error=invalid_request*code_challenge_method*) check "authorize ไม่ส่ง code_challenge → ปฏิเสธ (invalid_request)" "yes" "yes" ;;
  *) check "authorize ไม่ส่ง code_challenge → ปฏิเสธ (invalid_request)" "yes" "no (${LOC:0:80})" ;;
esac
LOC=$(curl -s -o /dev/null -D - "$ISSUER/protocol/openid-connect/auth?client_id=$CLIENT_ID&response_type=code&scope=openid&redirect_uri=http%3A%2F%2Flocalhost%3A3060%2Fauth%2Fcallback&state=s1&code_challenge=plainverifier123456789012345678901234567890123&code_challenge_method=plain" |
  grep -i '^location:' | tr -d '\r')
case "$LOC" in
  *error=invalid_request*) check "PKCE แบบ plain → ปฏิเสธ (รับ S256 เท่านั้น)" "yes" "yes" ;;
  *) check "PKCE แบบ plain → ปฏิเสธ (รับ S256 เท่านั้น)" "yes" "no (${LOC:0:80})" ;;
esac
summary
