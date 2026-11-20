#!/usr/bin/env bash
# Phase 6-7 — Open API ผ่าน Kong Gateway (:8000)
# jwt plugin (signature+iss ที่ gateway) · key-auth · rate-limiting
# aud/scope ยังถูกตรวจซ้ำที่ Guard ของ service เสมอ (defense in depth)
source "$(dirname "$0")/_lib.sh"
require_jq

wait_for "Kong admin" "http://localhost:8001/" 60
wait_for "Keycloak" "$ISSUER/.well-known/openid-configuration" 180
wait_for "Buyer API" "$BUYER/" 60
echo

T_PARTNER="$(cc_token)"
T_CIS="$(pwd_token cis-web cis-user 'openid projects.read' "$CIS_CLIENT_SECRET")"
T_BUYER="$(pwd_token buyer-web buyer-user 'openid orders.read')"

# --- Route หลัก /openapi/buyer (jwt plugin) ---
check "ไม่มี Authorization → Kong jwt ปฏิเสธ 401" "401" "$(code "$KONG/openapi/buyer/orders")"
check "partner token ผ่าน Kong → Buyer /orders 200" "200" "$(code -H "Authorization: Bearer $T_PARTNER" "$KONG/openapi/buyer/orders")"
check "cis token (aud=cis-api) ผ่าน Kong แต่ Buyer Guard ปฏิเสธ 401" "401" "$(code -H "Authorization: Bearer $T_CIS" "$KONG/openapi/buyer/orders")"

# --- Route key-auth /openapi/keyauth ---
check "keyauth: ไม่มี apikey → Kong ปฏิเสธ 401" "401" "$(code "$KONG/openapi/keyauth/orders" -H "Authorization: Bearer $T_BUYER")"
check "keyauth: apikey ถูกต้อง + bearer token → 200" "200" "$(code "$KONG/openapi/keyauth/orders" -H "apikey: partner-001-demo-key" -H "Authorization: Bearer $T_BUYER")"
check "keyauth: apikey ผิด → 401" "401" "$(code "$KONG/openapi/keyauth/orders" -H "apikey: wrong-key" -H "Authorization: Bearer $T_BUYER")"

# --- Route rate-limit /openapi/ratelimit (3 ครั้ง/นาที) ---
R1=$(code -H "Authorization: Bearer $T_BUYER" "$KONG/openapi/ratelimit/orders")
R2=$(code -H "Authorization: Bearer $T_BUYER" "$KONG/openapi/ratelimit/orders")
R3=$(code -H "Authorization: Bearer $T_BUYER" "$KONG/openapi/ratelimit/orders")
R4=$(code -H "Authorization: Bearer $T_BUYER" "$KONG/openapi/ratelimit/orders")
if [ "$R4" = "429" ] || [ "$R3" = "429" ]; then
  check "rate limit ทำงาน (ยิง 4 ครั้งติด → เจอ 429; ได้ $R1,$R2,$R3,$R4)" "yes" "yes"
else
  check "rate limit ทำงาน (ยิง 4 ครั้งติด → เจอ 429)" "yes" "no"
fi

# --- Route custom plugin oidc-central /openapi/oidc ---
# plugin เขียนเอง (kong/custom/kong/plugins/oidc-central): JWKS fetch+cache + ตรวจ
# signature/iss/exp + **บังคับ aud และ scope ที่ gateway** — สิ่งที่ jwt plugin OSS ข้ามไป
OIDC="$KONG/openapi/oidc/orders"
check "oidc-central: ไม่มี token → 401" "401" "$(code "$OIDC")"
check "oidc-central: token ถูกต้อง (aud+scope ครบ) → ผ่านไป service 200" "200" "$(code -H "Authorization: Bearer $T_PARTNER" "$OIDC")"
check "oidc-central: cis token (aud=cis-api) → 403 audience mismatch ที่ gateway" "403" "$(code -H "Authorization: Bearer $T_CIS" "$OIDC")"
check "oidc-central: signature ถูกแก้ → 401" "401" "$(code -H "Authorization: Bearer ${T_PARTNER}x" "$OIDC")"
MSG=$(curl -s -H "Authorization: Bearer $T_CIS" "$OIDC" --max-time 15)
check "oidc-central: ข้อความระบุ audience mismatch ชัดเจน" "yes" "$(echo "$MSG" | grep -q 'audience mismatch' && echo yes || echo no)"

# --- Route custom plugin oidc-introspect /openapi/introspect (revoke-aware gateway) ---
# ตรวจผ่าน Keycloak introspection (RFC 7662) — revoke/disable ที่ Keycloak → gateway ปฏิเสธทันที
OIDC_INT="$KONG/openapi/introspect/orders"
check "introspect: ไม่มี token → 401" "401" "$(code "$OIDC_INT")"
check "introspect: token active → ผ่าน 200" "200" "$(code -H "Authorization: Bearer $T_PARTNER" "$OIDC_INT")"

# --- Portal ผ่าน Kong (single entry point demo) ---
check "portal-id ผ่าน Kong (:8000/portal/id) → 200" "200" "$(code "$KONG/portal/id")"
check "portal-buyer ผ่าน Kong (:8000/portal/buyer) → 200" "200" "$(code "$KONG/portal/buyer")"
check "portal-cis ผ่าน Kong (:8000/portal/cis) → 200" "200" "$(code "$KONG/portal/cis")"

# --- Request size limiting (1MB) ---
BIG="$(mktemp)"
head -c 2097152 /dev/zero | tr '\0' 'a' > "$BIG"
check "request-size: payload 2MB → Kong ปฏิเสธ 413" "413" "$(code -X POST -H "Authorization: Bearer $T_BUYER" --data-binary @"$BIG" -H "Content-Type: text/plain" "$KONG/openapi/buyer/orders")"
rm -f "$BIG"

# --- CORS preflight ---
CORS_HEADERS="$(curl -s -i -X OPTIONS -H "Origin: https://partner.example" -H "Access-Control-Request-Method: POST" "$KONG/openapi/buyer/orders" --max-time 15)"
check "cors: preflight OPTIONS → มี Access-Control-Allow-Origin" "yes" "$(echo "$CORS_HEADERS" | grep -qi 'access-control-allow-origin' && echo yes || echo no)"

# --- Prometheus metrics (status listener :8100) ---
PROM="$(curl -s "http://localhost:8100/metrics" --max-time 15)"
check "prometheus: kong_http_requests_total ตรวจสอบได้ (per service/route/status)" "yes" "$(echo "$PROM" | grep -q 'kong_http_requests_total' && echo yes || echo no)"

# --- Introspect revoke path (ท้ายสุด — revoke ทำให้ T_PARTNER ตาย) ---
REV="$(curl -s -o /dev/null -w "%{http_code}" -X POST "$ISSUER/protocol/openid-connect/revoke" -d client_id=partner-001 -d client_secret="$PARTNER_001_CLIENT_SECRET" -d "token=$T_PARTNER" --max-time 15)"
check "introspect: revoke token ที่ Keycloak สำเร็จ" "200" "$REV"
sleep 12
check "introspect: token หลัง revoke → 401 inactive (gateway รู้ทัน)" "401" "$(code -H "Authorization: Bearer $T_PARTNER" "$OIDC_INT")"

# --- Central API Keys (ออกจาก ID Portal ผูก scope) — ใช้กับ Open API / MCP ---
# flow: Bearer ของ buyer-user → POST /apikeys/create (scopes) → key → ยิง /openapi/apikey
# (plugin central-apikey ตรวจ key กับ ID Portal /apikeys/validate แล้วบังคับ scope ตาม method)
UT_USER="$(pwd_token buyer-web buyer-user 'openid')"
AK_CREATE="$(curl -s -X POST "http://localhost:3000/apikeys/create" -H "Authorization: Bearer $UT_USER" -d "name=oitest-reader" -d "scopes=orders.read")"
AK_A="$(echo "$AK_CREATE" | jq -r '.key // empty')"
AK_B="$(curl -s -X POST "http://localhost:3000/apikeys/create" -H "Authorization: Bearer $UT_USER" -d "name=oitest-writer" -d "scopes=orders.read,orders.write" | jq -r '.key // empty')"
check "apikey: สร้างผ่าน ID Portal ได้ 2 ใบ (reader/writer)" "yes" "$([ -n "$AK_A" ] && [ -n "$AK_B" ] && echo yes || echo no)"
check "apikey: key ขึ้นต้น central_ (รูปแบบระบบ)" "yes" "$(echo "$AK_A" | grep -q '^central_' && echo yes || echo no)"
check "apikey (orders.read): GET → 200" "200" "$(code -H "apikey: $AK_A" "$KONG/openapi/apikey/orders")"
check "apikey (orders.read): POST → 403 (ขาด orders.write)" "403" "$(code -X POST -H "apikey: $AK_A" "$KONG/openapi/apikey/orders")"
check "apikey (read+write): POST → 201 ผ่าน scope guard ชั้น service" "201" "$(code -X POST -H "apikey: $AK_B" "$KONG/openapi/apikey/orders")"
check "apikey: ไม่มี key → 401" "401" "$(code "$KONG/openapi/apikey/orders")"
VAL="$(curl -s -X POST "http://localhost:3000/apikeys/validate" -d "key=$AK_A")"
check "apikey: validate endpoint (MCP contract) → active + scopes" "yes" "$(echo "$VAL" | jq -r '.active == true and (.scopes | index("orders.read") != null)' | grep -q true && echo yes || echo no)"
AK_ID="$(echo "$AK_CREATE" | jq -r '.key_id // empty')"
REV_A="$(curl -s -X POST "http://localhost:3000/apikeys/revoke" -H "Authorization: Bearer $UT_USER" -d "id=$AK_ID")"
sleep 17
check "apikey: revoke แล้ว (cache หมด) → 401 ที่ gateway" "401" "$(code -H "apikey: $AK_A" "$KONG/openapi/apikey/orders")"
check "apikey: revoke ตอบสถานะถูกต้อง" "yes" "$(echo "$REV_A" | grep -q '"revoked":true' && echo yes || echo no)"

summary
