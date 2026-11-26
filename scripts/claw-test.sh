#!/usr/bin/env bash
# ทดสอบ claw-web + @central/login-js (ADR-009) — curl เล่นบทเป็น "เบราว์เซอร์ + SDK":
#   1) แอป static + security headers (CSP, ไม่ log callback)
#   2) PKCE บังคับกับ client claw-web ที่ authorize endpoint
#   3) login ผ่าน Central ID (Identity Brokering) → แลก code แบบไม่มี client secret → claims ของ token
#   4) refresh token rotation + reuse detection
#   5) ใช้ token เรียก Buyer API ผ่าน Kong (GET/POST, ไม่มี token, cross-audience)
#   6) CORS ของ Keycloak (เบราว์เซอร์เรียก token/JWKS endpoint ได้เฉพาะ origin ที่ลงทะเบียน)
#   7) negative: verifier ผิด + ใช้ code ซ้ำ (ทำท้ายของ session แรก — Keycloak เพิกถอน token ของ session หลังจากนี้)
#   8) logout แบบเบราว์เซอร์จริง (ตาม redirect จนจบ) → session จบ (ใช้ session ใหม่)
# ทุก check ดู "response แรก" หรือ status ตรง ๆ — ไม่ใช้ curl -L แล้ว grep ว่า "ไม่พบข้อความ"
# ต้องรัน: bash scripts/setup-claw.sh และ docker compose up -d claw-web ก่อน
# (การทำงานของ "SDK ในเบราว์เซอร์จริง" ตรวจแยกด้วย tools/screenshots/claw.mjs)
source "$(dirname "$0")/_lib.sh"
require_jq

wait_for "Keycloak discovery" "$ISSUER/.well-known/openid-configuration" 180 || exit 1
wait_for "claw-web :3060" "http://localhost:3060/" 60 || exit 1

CLAW="http://localhost:3060"
CLIENT_ID="claw-web"
REDIRECT="http://localhost:3060/auth/callback"
TOKEN_EP="$ISSUER/protocol/openid-connect/token"
AUTHZ="$ISSUER/protocol/openid-connect/auth?client_id=$CLIENT_ID&response_type=code&scope=openid%20profile&redirect_uri=http%3A%2F%2Flocalhost%3A3060%2Fauth%2Fcallback"
FIXED_CHALLENGE="$(printf abc | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=\n')"
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

b64url() { tr '+/' '-_' | tr -d '=\n'; }
pkce_pair() {
  VERIFIER="$(head -c 32 /dev/urandom | base64 | b64url)"
  CHALLENGE="$(printf %s "$VERIFIER" | openssl dgst -sha256 -binary | base64 | b64url)"
}
code_of() { sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<<"$1"; }
jwt_header() { cut -d. -f1 <<<"$1" | tr '_-' '/+' | awk '{l=length($0)%4; printf "%s", $0; if(l==2)print "=="; if(l==3)print "="}' | base64 -d 2>/dev/null; }
# first_header <name> <curl args…> — ค่า header ของ "response แรก" (ไม่ตาม redirect) · ไม่มี header = string ว่าง
first_header() { local name="$1"; shift; curl -s -o /dev/null -D - "$@" | tr -d '\r' | grep -i "^$name:" | head -1 | sed 's/^[^:]*: //'; true; }
first_status() { curl -s -o /dev/null -D - "$@" | tr -d '\r' | head -1 | awk '{print $2}'; }
# login_form <jar> — เริ่ม flow ใน jar นี้แล้วกรอกหน้า login ของ Central ID
# ตั้งตัวแปรให้ผู้เรียก: CALLBACK_URL (URL ของ callback), VERIFIER (PKCE ของ flow นี้),
#   LOGIN_STATE / LOGIN_NONCE (ค่าที่ส่งไปในคำขอ authorize), LOGIN_ACTION
# ⚠️ ต้องเรียกตรง ๆ ห้ามใส่ใน $(...) — subshell ทำให้ตัวแปรเหล่านี้หาย
login_form() {
  local jar="$1" page tag name value
  pkce_pair
  LOGIN_STATE="c$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  LOGIN_NONCE="n$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  page="$(curl -s -L -c "$jar" -b "$jar" "$AUTHZ&state=$LOGIN_STATE&nonce=$LOGIN_NONCE&code_challenge=$CHALLENGE&code_challenge_method=S256")"
  LOGIN_ACTION="$(grep -o 'action="[^"]*"' <<<"$page" | head -1 | sed 's/^action="//;s/"$//;s/&amp;/\&/g')"
  local data=(-d "username=buyer-user" -d "password=$TEST_USER_PASSWORD" -d "credentialId=")
  while IFS= read -r tag; do
    name="$(sed -n 's/.*[ ]name="\([^"]*\)".*/\1/p' <<<"$tag")"
    value="$(sed -n 's/.*value="\([^"]*\)".*/\1/p' <<<"$tag")"
    [ -n "$name" ] && [ -n "$value" ] && data+=(-d "$name=$value")
  done < <(grep -o '<input[^>]*type="hidden"[^>]*>' <<<"$page")
  CALLBACK_URL="$(curl -s -c "$jar" -b "$jar" -L -o /dev/null -w "%{url_effective}" "${data[@]}" "$LOGIN_ACTION")"
}
# silent_result — authorize แบบ prompt=none ใน $1: คืน "code" ถ้ายังมี session, "error=<code>" ถ้าไม่มี
silent_result() {
  local loc
  loc="$(curl -s -o /dev/null -D - -b "$1" "$AUTHZ&state=s$RANDOM&code_challenge=$FIXED_CHALLENGE&code_challenge_method=S256&prompt=none" | tr -d '\r' | grep -i '^location:')"
  if grep -q '[?&]code=' <<<"$loc"; then echo "code"; else grep -oE 'error=[a-z_]+' <<<"$loc" | head -1; fi
}

echo "--- 1) แอป static + security headers ---"
INDEX_HEADERS="$(curl -s -o /dev/null -D - "$CLAW/" | tr -d '\r')"
check "GET / ตอบ 200" "200" "$(awk 'NR==1{print $2}' <<<"$INDEX_HEADERS")"
check "CSP: script/style เฉพาะ 'self' (ไม่มี inline script และไม่มี unsafe-inline/eval)" "yes" \
  "$(grep -qi "^content-security-policy:.*script-src 'self'; style-src 'self';" <<<"$INDEX_HEADERS" && ! grep -qi "unsafe-inline\|unsafe-eval" <<<"$INDEX_HEADERS" && echo yes || echo no)"
check "CSP: connect-src จำกัดเฉพาะ Keycloak + Kong" "yes" \
  "$(grep -qi "^content-security-policy:.*connect-src 'self' http://localhost:8080 http://localhost:8000;" <<<"$INDEX_HEADERS" && echo yes || echo no)"
check "security headers: nosniff + frame DENY + no-referrer" "yes" \
  "$(grep -qi '^x-content-type-options: nosniff' <<<"$INDEX_HEADERS" && grep -qi '^x-frame-options: DENY' <<<"$INDEX_HEADERS" && grep -qi '^referrer-policy: no-referrer' <<<"$INDEX_HEADERS" && echo yes || echo no)"
check "SPA fallback: /auth/callback ตอบ 200 text/html" "200 text/html" \
  "$(first_status "$CLAW/auth/callback?code=probe-not-a-real-code&state=s") $(first_header content-type "$CLAW/auth/callback?code=probe-not-a-real-code&state=s" | sed 's/;.*//')"
check "หน้า callback ไม่ให้ browser cache (no-store)" "no-store" "$(first_header cache-control "$CLAW/auth/callback?code=x&state=s")"
check "SDK ถูก serve เป็น JavaScript" "200 application/javascript" "$(curl -s -o /dev/null -w '%{http_code} %{content_type}' "$CLAW/vendor/login-js/index.js")"
expect_contains "config.js ถูกสร้างจาก env (issuer + clientId)" "$(curl -s "$CLAW/js/config.js")" "clientId: 'claw-web'"
check "nginx ไม่ log /auth/callback (URL มี authorization code)" "0" "$(docker logs poc-claw-web 2>&1 | grep -c 'auth/callback')"

echo "--- 2) PKCE บังคับกับ client $CLIENT_ID (ดู response แรก ไม่ตาม redirect) ---"
LOC="$(first_header location "$AUTHZ&state=s1")"
case "$LOC" in
  "$REDIRECT"*"error=invalid_request"*"code_challenge_method"*) check "authorize ไม่ส่ง code_challenge → ปฏิเสธทันที (ไม่ออก code ไม่เข้าหน้า login)" "yes" "yes" ;;
  *) check "authorize ไม่ส่ง code_challenge → ปฏิเสธทันที (ไม่ออก code ไม่เข้าหน้า login)" "yes" "no (${LOC:0:100})" ;;
esac
LOC="$(first_header location "$AUTHZ&state=s1&code_challenge=plainverifier123456789012345678901234567890123&code_challenge_method=plain")"
case "$LOC" in
  "$REDIRECT"*"error=invalid_request"*) check "PKCE แบบ plain → ปฏิเสธ (รับ S256 เท่านั้น)" "yes" "yes" ;;
  *) check "PKCE แบบ plain → ปฏิเสธ (รับ S256 เท่านั้น)" "yes" "no (${LOC:0:100})" ;;
esac
pkce_pair
LOC="$(first_header location "$AUTHZ&state=s2&nonce=n2&code_challenge=$CHALLENGE&code_challenge_method=S256")"
check "S256 ถูกต้อง → พาไป Central ID ผ่าน Identity Brokering" "yes" \
  "$([[ "$LOC" == http://localhost:8080/realms/central/broker/central-id/login* ]] && echo yes || echo no)"

echo "--- 3) Login ผ่าน Central ID + แลก code แบบไม่มี client secret (ทำแบบ SDK) ---"
JAR="$(mktemp -p "$TMPD")"
login_form "$JAR"
FINAL="$CALLBACK_URL"
check "ได้หน้า login ของ Central ID (upstream realm)" "yes" "$([[ "$LOGIN_ACTION" == *central-id-upstream* ]] && echo yes || echo no)"
cb_param() { tr '?' '\n' <<<"$FINAL" | tail -1 | tr '&' '\n' | sed -n "s/^$1=\(.*\)$/\1/p"; }
check "callback มี code + state + iss" "yes" "$([ -n "$(cb_param code)" ] && [ -n "$(cb_param state)" ] && [ -n "$(cb_param iss)" ] && echo yes || echo no)"
check "callback: state ที่ได้ตรงกับที่ส่งไป" "$LOGIN_STATE" "$(cb_param state)"
check "callback: iss ตรงกับ issuer (RFC 9207 กัน mix-up attack)" "yes" \
  "$([ "$(cb_param iss | sed 's/%3A/:/g; s/%2F/\//g')" = "$ISSUER" ] && echo yes || echo no)"
TOK="$(curl -s "$TOKEN_EP" -d grant_type=authorization_code -d client_id=$CLIENT_ID -d code="$(cb_param code)" \
  -d redirect_uri="$REDIRECT" -d code_verifier="$VERIFIER")"
check "แลก code ด้วย verifier → ได้ access/refresh/id token (ไม่ใช้ client_secret)" "yes" \
  "$(jq -e '.access_token and .refresh_token and .id_token' <<<"$TOK" >/dev/null 2>&1 && echo yes || echo no)"
AT="$(jq -r '.access_token // empty' <<<"$TOK")"
RT="$(jq -r '.refresh_token // empty' <<<"$TOK")"
IDT="$(jq -r '.id_token // empty' <<<"$TOK")"
check "id_token เซ็นด้วย RS256" "RS256" "$(jwt_header "$IDT" | jq -r '.alg // "not-a-jwt"')"
check "id_token: aud = claw-web และ nonce ตรงกับที่ส่งไป (ผูก response กับคำขอ กัน code injection)" "yes" \
  "$(jwt_payload "$IDT" | jq -e --arg c "$CLIENT_ID" --arg n "$LOGIN_NONCE" '((.aud == $c) or (.aud | type == "array" and index($c))) and .nonce == $n' >/dev/null && echo yes || echo no)"
check "access token: aud = buyer-api · scope orders.read + orders.write · principal_type = user" "yes" \
  "$(jwt_payload "$AT" | jq -e '((.aud == "buyer-api") or (.aud | type == "array" and index("buyer-api")))
       and ((.scope | split(" ")) | (index("orders.read") and index("orders.write"))) and .principal_type == "user"' >/dev/null && echo yes || echo no)"
check "expires_in = 300 (อายุ token สั้นตาม realm)" "300" "$(jq -r '.expires_in' <<<"$TOK")"

echo "--- 4) Refresh token rotation ---"
RT1="$(curl -s "$TOKEN_EP" -d grant_type=refresh_token -d client_id=$CLIENT_ID -d refresh_token="$RT")"
check "refresh ด้วย refresh token ปัจจุบัน → ได้ token ชุดใหม่" "yes" \
  "$(jq -e '.access_token and .refresh_token and .id_token' <<<"$RT1" >/dev/null 2>&1 && echo yes || echo no)"
check "refresh token ถูก rotate (ใบใหม่ไม่ซ้ำใบเก่า)" "yes" \
  "$([ -n "$(jq -r '.refresh_token // empty' <<<"$RT1")" ] && [ "$(jq -r '.refresh_token' <<<"$RT1")" != "$RT" ] && echo yes || echo no)"
check "id_token ที่ได้จาก refresh ยังเป็น RS256 + aud = claw-web" "yes" \
  "$(jwt_payload "$(jq -r '.id_token // empty' <<<"$RT1")" | jq -e --arg c "$CLIENT_ID" '((.aud == $c) or (.aud | type == "array" and index($c)))' >/dev/null \
     && [ "$(jwt_header "$(jq -r '.id_token // empty' <<<"$RT1")" | jq -r '.alg')" = "RS256" ] && echo yes || echo no)"
REPLAY="$(curl -s "$TOKEN_EP" -d grant_type=refresh_token -d client_id=$CLIENT_ID -d refresh_token="$RT")"
check "ใช้ refresh token ใบเก่าซ้ำ → ปฏิเสธ (reuse detection)" "yes" \
  "$(jq -e '.error == "invalid_grant"' <<<"$REPLAY" >/dev/null && echo yes || echo no)"

echo "--- 5) ใช้ token เรียก Buyer API ผ่าน Kong ---"
SUB="$(jwt_payload "$IDT" | jq -r '.sub')"
ORDERS="$(curl -s "$KONG/openapi/oidc/orders" -H "Authorization: Bearer $AT")"
check "GET /openapi/oidc/orders → 200 และ API เห็น user เดียวกับ id_token" "yes" \
  "$(jq -e --arg sub "$SUB" '.ok == true and .auth.subject == $sub and .auth.principalType == "user"' <<<"$ORDERS" >/dev/null && echo yes || echo no)"
check "POST /openapi/oidc/orders (ต้องมี orders.write) → 201" "201" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$KONG/openapi/oidc/orders" -H "Authorization: Bearer $AT")"
check "ไม่มี token → 401" "401" "$(first_status -H "Origin: http://localhost:3060" "$KONG/openapi/oidc/orders")"
check "Kong ใส่ CORS header แม้ตอบ 401 (เบราว์เซอร์อ่าน error ได้)" "*" \
  "$(first_header access-control-allow-origin -H "Origin: http://localhost:3060" "$KONG/openapi/oidc/orders")"
PREFLIGHT="$(curl -s -o /dev/null -D - -X OPTIONS "$KONG/openapi/oidc/orders" -H "Origin: http://localhost:3060" \
  -H "Access-Control-Request-Method: GET" -H "Access-Control-Request-Headers: authorization" | tr -d '\r')"
check "preflight ขอ Bearer header → 200 และ Allow-Headers มี authorization" "yes" \
  "$([[ "$(awk 'NR==1{print $2}' <<<"$PREFLIGHT")" == "200" ]] && grep -qi '^access-control-allow-headers:.*authorization' <<<"$PREFLIGHT" && echo yes || echo no)"
CIS_AT="$(pwd_token cis-web buyer-user "openid projects.read" "$CIS_CLIENT_SECRET")"
check "token ของ cis-web (aud=cis-api) ใช้กับ Buyer API ไม่ได้ (cross-audience)" "403" \
  "$(curl -s -o /dev/null -w '%{http_code}' "$KONG/openapi/oidc/orders" -H "Authorization: Bearer $CIS_AT")"

echo "--- 6) CORS ของ Keycloak: เฉพาะ origin ของแอปเรียก token/JWKS endpoint ได้ ---"
check "token endpoint ส่ง Access-Control-Allow-Origin = http://localhost:3060" "http://localhost:3060" \
  "$(first_header access-control-allow-origin -H "Origin: http://localhost:3060" "$TOKEN_EP" -d grant_type=refresh_token -d client_id=$CLIENT_ID -d refresh_token=bogus)"
FOREIGN_ACAO="$(first_header access-control-allow-origin -H "Origin: http://localhost:3061" "$TOKEN_EP" -d grant_type=refresh_token -d client_id=$CLIENT_ID -d refresh_token=bogus)"
check "origin อื่น (http://localhost:3061) ไม่ได้ CORS header → เบราว์เซอร์ block" "absent" \
  "$([ -z "$FOREIGN_ACAO" ] && echo absent || echo "present: $FOREIGN_ACAO")"
check "JWKS endpoint อนุญาต origin ของแอป (SDK ดึง key มาตรวจลายเซ็น id_token ได้)" "http://localhost:3060" \
  "$(first_header access-control-allow-origin -H "Origin: http://localhost:3060" "$ISSUER/protocol/openid-connect/certs")"

echo "--- 7) Negative: verifier ผิด + ใช้ code ซ้ำ (ทำท้าย — Keycloak เพิกถอน token ของ session นี้หลังจากนี้) ---"
pkce_pair
FINAL2="$(curl -s -c "$JAR" -b "$JAR" -L -o /dev/null -w "%{url_effective}" "$AUTHZ&state=s3&nonce=n3&code_challenge=$CHALLENGE&code_challenge_method=S256")"
CODE2="$(code_of "$FINAL2")"
check "session เดิมยังได้ code ใบใหม่ (SSO ยังอยู่แม้ refresh token เคยถูก replay)" "yes" "$([ -n "$CODE2" ] && echo yes || echo no)"
WRONG="$(curl -s "$TOKEN_EP" -d grant_type=authorization_code -d client_id=$CLIENT_ID -d code="$CODE2" \
  -d redirect_uri="$REDIRECT" -d code_verifier="wrong-verifier-wrong-verifier-wrong-verifier-wrong-ver")"
check "verifier ไม่ตรง → ปฏิเสธ (400 invalid_grant และระบุ PKCE)" "yes" \
  "$(jq -e '.error == "invalid_grant" and (.error_description | test("PKCE"))' <<<"$WRONG" >/dev/null && echo yes || echo no)"
REUSE="$(curl -s "$TOKEN_EP" -d grant_type=authorization_code -d client_id=$CLIENT_ID -d code="$CODE2" \
  -d redirect_uri="$REDIRECT" -d code_verifier="$VERIFIER")"
check "code ที่ถูกใช้ไปแล้ว (แม้แลกด้วย verifier ผิด) ใช้ซ้ำไม่ได้" "yes" \
  "$(jq -e '.error == "invalid_grant"' <<<"$REUSE" >/dev/null && echo yes || echo no)"

echo "--- 8) Logout แบบเบราว์เซอร์จริง (RP-initiated + ตาม redirect จนจบ) — ใช้ session ใหม่ ---"
JAR2="$(mktemp -p "$TMPD")"
login_form "$JAR2"
FINAL3="$CALLBACK_URL"
check "session ใหม่: ได้หน้า login ของ Central ID (jar ใหม่ไม่มี session ค้าง)" "yes" "$([[ "$LOGIN_ACTION" == *central-id-upstream* ]] && echo yes || echo no)"
IDT2="$(curl -s "$TOKEN_EP" -d grant_type=authorization_code -d client_id=$CLIENT_ID -d code="$(code_of "$FINAL3")" \
  -d redirect_uri="$REDIRECT" -d code_verifier="$VERIFIER" | jq -r '.id_token // empty')"
check "session ใหม่: แลก code ได้ id_token" "yes" "$([ -n "$IDT2" ] && echo yes || echo no)"
check "ก่อน logout: prompt=none ยังได้ code (SSO session ยังอยู่)" "code" "$(silent_result "$JAR2")"
OUT="$(curl -s -o /dev/null --max-redirs 10 -L -c "$JAR2" -b "$JAR2" -w "%{http_code} %{url_effective} %{num_redirects}" \
  "$ISSUER/protocol/openid-connect/logout?id_token_hint=$IDT2&client_id=$CLIENT_ID&post_logout_redirect_uri=http://localhost:3060&state=%2F")"
FINAL_URL="$(awk '{print $2}' <<<"$OUT")"
echo "  logout: $(awk '{print $3}' <<<"$OUT") redirects → $FINAL_URL"
case "$FINAL_URL" in
  http://localhost:3060/*) BACK=yes ;;
  *) BACK="no ($OUT)" ;;
esac
check "logout แล้วกลับมาที่แอปทันที (ไม่ติดหน้า confirm)" "yes" "$BACK"
check "หลัง logout: prompt=none → error=login_required (session จบแล้ว)" "error=login_required" "$(silent_result "$JAR2")"
curl -s -L -c "$JAR2" -b "$JAR2" -o "$TMPD/reopen.html" "$AUTHZ&state=re&code_challenge=$FIXED_CHALLENGE&code_challenge_method=S256"
check "เปิด claw-web ใหม่หลัง logout → ต้องกรอกรหัสอีกครั้ง (Central ID ถูก logout ด้วย)" "yes" \
  "$(grep -q 'name="username"' "$TMPD/reopen.html" && echo yes || echo no)"

summary
