#!/usr/bin/env bash
# Phase 5 — ทดสอบ SSO จริง: login ผ่าน Keycloak ครั้งเดียว (cookie jar เดียว)
# แล้วเริ่ม flow ของ CIS → ต้องได้ code ทันทีโดยไม่เจอหน้า login
# และ logout กลาง → session ต้องถูกยุติทุกระบบ
# ทำงานโดยเล่นบทบาท "แอป frontend" เอง (สร้าง PKCE และแลก code เอง)
source "$(dirname "$0")/_lib.sh"
require_jq

wait_for "Keycloak discovery" "$ISSUER/.well-known/openid-configuration" 180 || exit 1
echo

b64url_std() { tr '+/' '-_' | tr -d '=\n'; }

JAR="$(mktemp)"
HDRS="$(mktemp)"
trap 'rm -f "$JAR" "$HDRS"' EXIT

pkce_pair() {
  VERIFIER="$(head -c 32 /dev/urandom | base64 | b64url_std)"
  CHALLENGE="$(printf %s "$VERIFIER" | openssl dgst -sha256 -binary | base64 | b64url_std)"
}

# ---------- ขั้น 1: Login ที่ BUYER (buyer-web) ----------
pkce_pair
STATE_B="s$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"

AUTH_BUYER="$ISSUER/protocol/openid-connect/auth?client_id=buyer-web&response_type=code&scope=openid%20orders.read%20orders.write&redirect_uri=http%3A%2F%2Flocalhost%3A3010%2Fauth%2Fcallback&state=$STATE_B&code_challenge=$CHALLENGE&code_challenge_method=S256&nonce=n$(date +%s)"

# ตาม redirect ไปหน้า login ของ Keycloak
PAGE="$(curl -s -L -c "$JAR" -b "$JAR" "$AUTH_BUYER")"
ACTION="$(grep -o 'action="[^"]*"' <<<"$PAGE" | head -1 | sed 's/^action="//;s/"$//;s/&amp;/\&/g')"
[ -z "$ACTION" ] && { echo "FAIL  ไม่พบ login form ของ Keycloak (ธีมเปลี่ยน?)"; exit 1; }

# รวบรวม hidden inputs (execution, client_id ฯลฯ) เพื่อ POST กลับพร้อม credential
DATA=(-d "username=buyer-user" -d "password=$TEST_USER_PASSWORD" -d "credentialId=")
while IFS= read -r tag; do
  N="$(sed -n 's/.*[ ]name="\([^"]*\)".*/\1/p' <<<"$tag")"
  V="$(sed -n 's/.*value="\([^"]*\)".*/\1/p' <<<"$tag")"
  [ -n "$N" ] && [ -n "$V" ] && DATA+=(-d "$N=$V")
done < <(grep -o '<input[^>]*type="hidden"[^>]*>' <<<"$PAGE")

# POST credential — ตาม redirect จนครบ (Identity Brokering: login ที่ upstream realm แล้ว
# วิ่งกลับผ่าน broker endpoint ของ realm central ก่อนถึง callback ของแอป)
FINAL_B="$(curl -s -c "$JAR" -b "$JAR" -L -o /dev/null -w "%{url_effective}" "${DATA[@]}" "$ACTION")"
expect_contains "login buyer-web สำเร็จ (ผ่าน Central ID brokering) → callback มี code=" "$FINAL_B" "code="

CODE_B="$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<<"$FINAL_B")"
TOK_BUYER="$(curl -s "$ISSUER/protocol/openid-connect/token" \
  -d grant_type=authorization_code -d client_id=buyer-web \
  -d code="$CODE_B" \
  -d redirect_uri="http://localhost:3010/auth/callback" \
  -d code_verifier="$VERIFIER")"
AT_BUYER="$(jq -r '.access_token // empty' <<<"$TOK_BUYER")"
ID_BUYER="$(jq -r '.id_token // empty' <<<"$TOK_BUYER")"
[ -n "$AT_BUYER" ] && check "แลก code ของ buyer-web ได้ access_token (PKCE ผ่าน)" "yes" "yes" || check "แลก code ของ buyer-web ได้ access_token" "yes" "no"
expect_contains "buyer token aud มี buyer-api" "$(jwt_payload "$AT_BUYER")" '"aud"'

# ---------- ขั้น 2: เริ่ม flow ของ CIS ด้วย cookie เดิม — ต้อง SSO ----------
pkce_pair
STATE_C="s$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"

AUTH_CIS="$ISSUER/protocol/openid-connect/auth?client_id=cis-web&response_type=code&scope=openid%20projects.read%20projects.write&redirect_uri=http%3A%2F%2Flocalhost%3A3020%2Fauth%2Fcallback&state=$STATE_C&code_challenge=$CHALLENGE&code_challenge_method=S256&nonce=n$(date +%s)"

# ตาม redirect ทั้ง chain (SSO ที่ upstream realm ให้ code ทันที ไม่เจอหน้า login)
FINAL_C="$(curl -s -b "$JAR" -c "$JAR" -L -o /dev/null -w "%{url_effective}" "$AUTH_CIS")"
expect_contains "SSO! cis-web ได้ callback ทันที ไม่เจอหน้า login" "$FINAL_C" "/auth/callback"
expect_contains "SSO callback มี code=" "$FINAL_C" "code="

CODE_C="$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<<"$FINAL_C")"
# cis-web เป็น confidential client (ตั้งโดย setup-stt.sh) — token endpoint บังคับ client_secret
# ตามมาตรฐาน server-side web app (แอปจริงที่ services/cis-api ก็ส่ง secret เช่นกัน)
TOK_CIS="$(curl -s "$ISSUER/protocol/openid-connect/token" \
  -d grant_type=authorization_code -d client_id=cis-web \
  -d client_secret="$CIS_CLIENT_SECRET" \
  -d code="$CODE_C" \
  -d redirect_uri="http://localhost:3020/auth/callback" \
  -d code_verifier="$VERIFIER")"
AT_CIS="$(jq -r '.access_token // empty' <<<"$TOK_CIS")"
[ -n "$AT_CIS" ] && check "แลก code ของ cis-web ได้ access_token" "yes" "yes" || check "แลก code ของ cis-web ได้ access_token" "yes" "no"
expect_contains "cis token aud มี cis-api" "$(jwt_payload "$AT_CIS")" '"aud"'

# ---------- ขั้น 3: Logout จากแอป (downstream realm) ----------
# สถาปัตยกรรม brokering: SSO session จริงอยู่ที่ Central ID (upstream) —
# logout ที่แอปยุติ session ฝั่ง Keycloak เท่านั้น ไม่กระทบ Central ID (เหมือน logout Google จากแอป)
curl -s -b "$JAR" -c "$JAR" -o /dev/null \
  "$ISSUER/protocol/openid-connect/logout?id_token_hint=$ID_BUYER"

pkce_pair
AUTH_CIS2="$ISSUER/protocol/openid-connect/auth?client_id=cis-web&response_type=code&scope=openid%20projects.read&redirect_uri=http%3A%2F%2Flocalhost%3A3020%2Fauth%2Fcallback&state=x&code_challenge=$CHALLENGE&code_challenge_method=S256"
FINAL_C2="$(curl -s -b "$JAR" -c "$JAR" -L -o /dev/null -w "%{url_effective}" "$AUTH_CIS2")"
if grep -q "code=" <<<"$FINAL_C2"; then
  check "logout จากแอป → SSO ของ Central ID ยังอยู่ (login ใหม่ได้ code อัตโนมัติ)" "yes" "yes"
else
  check "logout จากแอป → SSO ของ Central ID ยังอยู่" "yes" "no ($FINAL_C2)"
fi

# ---------- ขั้น 4: Logout กลางที่ Central ID จริง (upstream) ----------
# KC แสดงหน้า confirm เมื่อ logout ด้วย session cookie เพียงอย่างเดียว — POST confirmLogout
UP_LOGOUT="$KC/realms/central-id-upstream/protocol/openid-connect/logout"
CONFIRM_PAGE="$(curl -s -b "$JAR" -c "$JAR" "$UP_LOGOUT")"
ACTION_UP="$(grep -o 'action="[^"]*"' <<<"$CONFIRM_PAGE" | head -1 | sed 's/^action="//;s/"$//;s/&amp;/\&/g')"
if [ -n "$ACTION_UP" ]; then
  DATA_UP=(-d "confirmLogout=true")
  while IFS= read -r tag; do
    N="$(sed -n 's/.*[ ]name="\([^"]*\)".*/\1/p' <<<"$tag")"; V="$(sed -n 's/.*value="\([^"]*\)".*/\1/p' <<<"$tag")"
    [ -n "$N" ] && [ -n "$V" ] && [ "$N" != "confirmLogout" ] && DATA_UP+=(-d "$N=$V")
  done < <(grep -o '<input[^>]*type="hidden"[^>]*>' <<<"$CONFIRM_PAGE")
  curl -s -b "$JAR" -c "$JAR" -L -o /dev/null "${DATA_UP[@]}" "$ACTION_UP"
  check "logout กลางที่ Central ID (confirm page)" "yes" "yes"
else
  check "logout กลางที่ Central ID (confirm page)" "yes" "ไม่พบ form confirm"
fi

# ---------- ขั้น 5: flow ใหม่จาก "อุปกรณ์ใหม่" (cookie jar ใหม่) หลัง logout กลาง ----------
# ต้องเจอหน้า login ของ Central ID จริงอีกครั้ง (SSO session ของ Central ID ถูกยุติจริง)
# หมายเหตุ: session ของ Keycloak ที่ล็อกอินค้างในเครื่องเดิมยัง valid จน exp (ข้อจำกัดเดียวกับ JWT —
# production ควรตั้ง backchannel logout จาก Central ID -> Keycloak เพื่อยุติทันที)
pkce_pair
AUTH_CIS3="$ISSUER/protocol/openid-connect/auth?client_id=cis-web&response_type=code&scope=openid%20projects.read&redirect_uri=http%3A%2F%2Flocalhost%3A3020%2Fauth%2Fcallback&state=y&code_challenge=$CHALLENGE&code_challenge_method=S256"
JAR2="$(mktemp)"
FINAL_C3="$(curl -s -b "$JAR2" -c "$JAR2" -L -o /dev/null -w "%{url_effective}" "$AUTH_CIS3")"
rm -f "$JAR2"
if grep -q "code=" <<<"$FINAL_C3"; then
  check "หลัง logout กลาง → อุปกรณ์ใหม่ต้องไม่มี SSO (ต้อง login ที่ Central ID)" "no-code" "ยังได้ code"
elif grep -q "central-id-upstream" <<<"$FINAL_C3"; then
  check "หลัง logout กลาง → อุปกรณ์ใหม่ถูกพาไปหน้า login ของ Central ID จริง" "yes" "yes"
else
  check "หลัง logout กลาง → อุปกรณ์ใหม่ถูกพาไปหน้า login ของ Central ID จริง" "central-id-upstream" "$FINAL_C3"
fi

summary
