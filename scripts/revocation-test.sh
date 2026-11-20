#!/usr/bin/env bash
# Phase 8 — Revocation & Session Lifecycle
# introspect · revoke access/refresh · disable user · ข้อจำกัดของ JWT ที่ออกไปแล้ว
source "$(dirname "$0")/_lib.sh"
require_jq

wait_for "Keycloak" "$ISSUER/.well-known/openid-configuration" 180
wait_for "Buyer API" "$BUYER/" 60
echo

# ---------- Introspect + Revoke access token ----------
RESP="$(curl -s "$ISSUER/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=buyer-web -d username=buyer-user \
  -d password="$TEST_USER_PASSWORD" -d scope='openid orders.read')"
AT="$(jq -r '.access_token // empty' <<<"$RESP")"
RT="$(jq -r '.refresh_token // empty' <<<"$RESP")"

ACTIVE1="$(curl -s -d client_id=partner-001 -d client_secret="$PARTNER_001_CLIENT_SECRET" \
  -d token="$AT" "$ISSUER/protocol/openid-connect/token/introspect" | jq -r .active)"
check "introspect ก่อน revoke → active=true" "true" "$ACTIVE1"
check "Buyer รับ token ก่อน revoke → 200" "200" "$(code -H "Authorization: Bearer $AT" "$BUYER/orders")"

curl -s -o /dev/null -d client_id=buyer-web -d token="$AT" \
  "$ISSUER/protocol/openid-connect/revoke"

ACTIVE2="$(curl -s -d client_id=partner-001 -d client_secret="$PARTNER_001_CLIENT_SECRET" \
  -d token="$AT" "$ISSUER/protocol/openid-connect/token/introspect" | jq -r .active)"
check "introspect หลัง revoke → active=false" "false" "$ACTIVE2"
# ข้อจำกัด JWT (พิสูจน์ตามดีไซน์): Guard ตรวจ JWKS ล้วน (กฎ CLAUDE.md #8 — ไม่ introspect ทุก request)
# → token ที่ revoke ยังผ่าน signature จน exp; กลไกเดียวที่รู้ revocation คือ introspection
# (production: token สั้น + introspection เฉพาะ operation เสียงสูง ดู rootcase §6)
check "(ข้อจำกัด JWT) Buyer ยังรับ token หลัง revoke จน exp (introspection คือทางเดียวที่รู้)" "200" "$(code -H "Authorization: Bearer $AT" "$BUYER/orders")"

# ---------- Refresh token: rotation และ revoke ----------
NEW_AT="$(curl -s "$ISSUER/protocol/openid-connect/token" \
  -d grant_type=refresh_token -d client_id=buyer-web -d refresh_token="$RT" |
  jq -r '.access_token // empty')"
[ -n "$NEW_AT" ] && check "refresh_token grant ใช้ได้ (rotation)" "yes" "yes" || check "refresh_token grant ใช้ได้ (rotation)" "yes" "no"

RT_REUSE="$(curl -s -o /dev/null -w '%{http_code}' "$ISSUER/protocol/openid-connect/token" \
  -d grant_type=refresh_token -d client_id=buyer-web -d refresh_token="$RT")"
check "refresh token เดิมใช้ซ้ำไม่ได้ (rotation, HTTP $RT_REUSE)" "400" "$RT_REUSE"

curl -s -o /dev/null -d client_id=buyer-web -d token="$NEW_AT" \
  "$ISSUER/protocol/openid-connect/revoke"
ACTIVE3="$(curl -s -d client_id=partner-001 -d client_secret="$PARTNER_001_CLIENT_SECRET" \
  -d token="$NEW_AT" "$ISSUER/protocol/openid-connect/token/introspect" | jq -r .active)"
check "token ที่ refresh มาแล้ว revoke ได้ → active=false" "false" "$ACTIVE3"

# ---------- Disable user ----------
read -r ADMIN_TOK UID_BUYER <<<"$(admin_token_and_uid buyer-user)"

# ข้อจำกัดของ JWT: token ที่ออกไปก่อน disable ยังผ่าน JWKS validation จนหมดอายุ
# จึงต้อง mint token ก่อนปิด user
T_BEFORE="$(pwd_token buyer-web buyer-user 'openid orders.read')"

curl -s -o /dev/null -X PUT "$KC/admin/realms/$REALM/users/$UID_BUYER" \
  -H "Authorization: Bearer $ADMIN_TOK" -H "Content-Type: application/json" \
  -d '{"enabled": false}'

DIS_CODE="$(curl -s -o /dev/null -w '%{http_code}' "$ISSUER/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=buyer-web -d username=buyer-user -d password="$TEST_USER_PASSWORD")"
[ "$DIS_CODE" != "200" ] && check "user ถูก disable → password grant ล้มเหลว (HTTP $DIS_CODE)" "yes" "yes" ||
  check "user ถูก disable → password grant ต้องล้มเหลว" "yes" "no"

curl -s -o /dev/null -X PUT "$KC/admin/realms/$REALM/users/$UID_BUYER" \
  -H "Authorization: Bearer $ADMIN_TOK" -H "Content-Type: application/json" \
  -d '{"enabled": true}'
check "(ข้อจำกัด JWT) token ที่ออกก่อนหน้ายังผ่าน JWKS จน exp → 200" "200" "$(code -H "Authorization: Bearer $T_BEFORE" "$BUYER/orders")"

T_AFTER="$(pwd_token buyer-web buyer-user 'openid orders.read')"
[ -n "$T_AFTER" ] && check "เปิด user กลับมา → login ได้อีก" "yes" "yes" || check "เปิด user กลับมา → login ได้อีก" "yes" "no"

echo
echo "หมายเหตุ: JWT validation ล้วนไม่รู้ revocation เรียลไทม์ — production ต้องใช้"
echo "short-lived token + revocation event/introspection ตาม Security SLA (ดู rootcase §6)"

summary
