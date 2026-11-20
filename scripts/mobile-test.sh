#!/usr/bin/env bash
# Phase demo — Mobile App (public client + PKCE enforced) ตาม RFC 8252
# จำลอง flow จริงของแอป mobile: system browser login (ผ่าน Identity Brokering -> Central ID จริง)
# -> แลก code ด้วย PKCE -> refresh token rotation -> จำลอง "token ถูกขโมยไปใช้ซ้ำ"
# ตรวจว่า: (a) PKCE ถูกบังคับที่ server (b) rotation ทำงาน (c) replay refresh token เก่า
#          ทำให้ทั้งตระกูล token ถูกยกเลิก (กันขโมยแม้เจ้าของจริงโดนกระทบชั่วคราว)
source "$(dirname "$0")/_lib.sh"
require_jq

wait_for "Keycloak discovery" "$ISSUER/.well-known/openid-configuration" 180 || exit 1
echo

b64url_std() { tr '+/' '-_' | tr -d '=\n'; }
JAR="$(mktemp)"
REDIRECT="http://127.0.0.1:14785/mobile/callback"

pkce_pair() {
  VERIFIER="$(head -c 32 /dev/urandom | base64 | b64url_std)"
  CHALLENGE="$(printf %s "$VERIFIER" | openssl dgst -sha256 -binary | base64 | b64url_std)"
}
CODE_OF() { sed -n 's/.*[?&]code=\([^&]*\).*/\1/p'; }

# ---------- Test B: flow เต็มผ่าน system browser จำลอง (login ที่ Central ID จริง) ----------
pkce_pair
AUTH_URL="$ISSUER/protocol/openid-connect/auth?client_id=mobile-app&response_type=code&scope=openid%20orders.read&redirect_uri=http%3A%2F%2F127.0.0.1%3A14785%2Fmobile%2Fcallback&state=m1&code_challenge=$CHALLENGE&code_challenge_method=S256&nonce=n$(date +%s)"

PAGE="$(curl -s -L -c "$JAR" -b "$JAR" -w "\nFINAL:%{url_effective}" "$AUTH_URL")"
ACTION="$(grep -o 'action="[^"]*"' <<<"$PAGE" | head -1 | sed 's/^action="//;s/"$//;s/&amp;/\&/g')"
[ -z "$ACTION" ] && { check "ได้หน้า login ของ Central ID จริง" "yes" "no"; exit 1; }
check "ได้หน้า login ของ Central ID จริง (upstream realm)" "yes" "yes"

DATA=(-d "username=buyer-user" -d "password=$TEST_USER_PASSWORD" -d "credentialId=")
while IFS= read -r tag; do
  N="$(sed -n 's/.*[ ]name="\([^"]*\)".*/\1/p' <<<"$tag")"; V="$(sed -n 's/.*value="\([^"]*\)".*/\1/p' <<<"$tag")"
  [ -n "$N" ] && [ -n "$V" ] && DATA+=(-d "$N=$V")
done < <(grep -o '<input[^>]*type="hidden"[^>]*>' <<<"$PAGE")

FINAL_B="$(curl -s -c "$JAR" -b "$JAR" -L -o /dev/null -w "%{url_effective}" "${DATA[@]}" "$ACTION")"
if grep -q "127.0.0.1:14785/mobile/callback" <<<"$FINAL_B" && grep -q "code=" <<<"$FINAL_B"; then
  check "callback กลับแอป (loopback redirect ตาม RFC 8252) พร้อม code" "yes" "yes"
else
  check "callback กลับแอป (loopback redirect ตาม RFC 8252) พร้อม code" "yes" "no ($FINAL_B)"
fi
CODE_B="$(CODE_OF <<<"$FINAL_B")"

# แลก code ด้วย PKCE (public client — ไม่มี client secret)
TOK="$(curl -s "$ISSUER/protocol/openid-connect/token" \
  -d grant_type=authorization_code -d client_id=mobile-app \
  -d code="$CODE_B" -d redirect_uri="$REDIRECT" -d code_verifier="$VERIFIER")"
AT="$(jq -r '.access_token // empty' <<<"$TOK")"
R0="$(jq -r '.refresh_token // empty' <<<"$TOK")"
[ -n "$AT" ] && check "แลก code -> token (public client ไม่มี secret, PKCE ผ่าน)" "yes" "yes" || check "แลก code -> token" "yes" "no"
[ -n "$R0" ] && check "ได้ refresh token (สำหรับ mobile offline)" "yes" "yes" || check "ได้ refresh token" "yes" "no"

# ความเสี่ยงกรณี PKCE ไม่ได้บังคับ — ทดสอบท้าย script (Test G) ด้วย code ชุดใหม่
# (ห้ามใช้ code เดิมซ้ำ: code reuse จะทำให้ KC revoke session ทั้งก้อน กระทบการทดสอบ rotation)

# ---------- Test C: token ครบตาม Token Contract ----------
PAY="$(jwt_payload "$AT")"
check "mobile token aud มี buyer-api" "yes" "$(echo "$PAY" | jq -r 'if (.aud|type)=="array" then (.aud|index("buyer-api")|if . then "yes" else "no" end) else (if .aud=="buyer-api" then "yes" else "no" end) end' 2>/dev/null)"
check "mobile token principal_type = user" "user" "$(echo "$PAY" | jq -r '.principal_type // empty')"
check "mobile token scope มี orders.read" "yes" "$(echo "$PAY" | jq -r '.scope' | grep -qw orders.read && echo yes || echo no)"

# ---------- Test D: refresh token rotation ----------
RTOK1="$(curl -s "$ISSUER/protocol/openid-connect/token" \
  -d grant_type=refresh_token -d client_id=mobile-app -d refresh_token="$R0")"
AT1="$(jq -r '.access_token // empty' <<<"$RTOK1")"
R1="$(jq -r '.refresh_token // empty' <<<"$RTOK1")"
[ -n "$R1" ] && check "refresh ครั้งแรก -> ได้ refresh token ใหม่ (rotation)" "yes" "yes" || check "refresh ครั้งแรก -> ได้ refresh token ใหม่" "yes" "no"
[ -n "$R1" ] && [ "$R1" != "$R0" ] && check "refresh token ใหม่ไม่ซ้ำเดิม (rotation จริง)" "yes" "yes" || check "refresh token ใหม่ไม่ซ้ำเดิม" "yes" "no"

# ---------- Test E: จำลอง "token ถูกขโมย" — เอา r0 (ตัวเก่าที่ถูกใช้แล้ว) มาใช้ซ้ำ ----------
CODE_E=$(curl -s -o /tmp/mt-e.json -w "%{http_code}" "$ISSUER/protocol/openid-connect/token" \
  -d grant_type=refresh_token -d client_id=mobile-app -d refresh_token="$R0")
[ "$CODE_E" = "400" ] && check "ขโมยใช้ refresh token เก่าซ้ำ -> ปฏิเสธ 400" "400" "400" || check "ขโมยใช้ refresh token เก่าซ้ำ -> ปฏิเสธ" "400" "$CODE_E"
rm -f /tmp/mt-e.json

# ---------- Test F: ตระกูล token ถูกยกเลิกทั้งหมด (เจ้าของจริงก็ต้อง login ใหม่) ----------
CODE_F=$(curl -s -o /dev/null -w "%{http_code}" "$ISSUER/protocol/openid-connect/token" \
  -d grant_type=refresh_token -d client_id=mobile-app -d refresh_token="$R1")
if [ "$CODE_F" = "400" ]; then
  check "ตระกูล token ถูกยกเลิกทั้งหมด (RT ใหม่สุดก็ใช้ไม่ได้ -> ขโมยไม่ได้อะไรเลย)" "400" "400"
else
  check "ตระกูล token ถูกยกเลิกทั้งหมด (RT ใหม่สุดก็ใช้ไม่ได้)" "400" "$CODE_F"
fi

# ---------- Test G: PKCE enforced — flow แบบไม่ส่ง code_challenge เลย ต้องแลกไม่ได้ ----------
# (authorize ไม่มี challenge ยังได้ code — แต่ code นี้แลก token ไม่ได้เพราะไม่มี verifier)
pkce_pair
AUTH_NOCH="$ISSUER/protocol/openid-connect/auth?client_id=mobile-app&response_type=code&scope=openid%20orders.read&redirect_uri=http%3A%2F%2F127.0.0.1%3A14785%2Fmobile%2Fcallback&state=g1"
PAGE_G="$(curl -s -L -c "$JAR" -b "$JAR" -w "\nFINAL:%{url_effective}" "$AUTH_NOCH")"
ACTION_G="$(grep -o 'action="[^"]*"' <<<"$PAGE_G" | head -1 | sed 's/^action="//;s/"$//;s/&amp;/\&/g')"
DATA_G=(-d "username=buyer-user" -d "password=$TEST_USER_PASSWORD" -d "credentialId=")
while IFS= read -r tag; do
  N="$(sed -n 's/.*[ ]name="\([^"]*\)".*/\1/p' <<<"$tag")"; V="$(sed -n 's/.*value="\([^"]*\)".*/\1/p' <<<"$tag")"
  [ -n "$N" ] && [ -n "$V" ] && DATA_G+=(-d "$N=$V")
done < <(grep -o '<input[^>]*type="hidden"[^>]*>' <<<"$PAGE_G")
FINAL_G="$(curl -s -c "$JAR" -b "$JAR" -L -o /dev/null -w "%{url_effective}" "${DATA_G[@]}" "$ACTION_G")"
CODE_G="$(CODE_OF <<<"$FINAL_G")"
TOK_G="$(curl -s "$ISSUER/protocol/openid-connect/token" \
  -d grant_type=authorization_code -d client_id=mobile-app \
  -d code="$CODE_G" -d redirect_uri="$REDIRECT")"
if jq -e '.error' <<<"$TOK_G" > /dev/null 2>&1; then
  check "flow ไม่ส่ง code_challenge -> แลก code ไม่ได้ (PKCE บังคับจริง)" "yes" "yes"
else
  check "flow ไม่ส่ง code_challenge -> แลก code ไม่ได้ (PKCE บังคับจริง)" "yes" "no (แลกได้!)"
fi

rm -f "$JAR"
summary
