#!/usr/bin/env bash
# Session Transfer Token (STT) v2 — ข้ามแอปได้ทุกคู่ (จำลอง Native-to-Web SSO แบบ Auth0)
# ต้นทางมี native session -> สร้าง one-time code ที่ ID Portal (ผูก dest = client ปลายทาง, TTL 60s)
# -> เปิดเว็บปลายทางด้วย code -> ปลายทาง redeem + ตรวจ aud ของตัวเอง -> ได้ session ไม่กรอกรหัสผ่าน
#
# จุดพิสูจน์เพิ่มจาก v1:
# - dest binding: code ของปลายทางหนึ่ง redeem ด้วยอีกปลายทาง -> destination_mismatch
# - aud ตรวจทุกปลายทาง: cis-aud token ไป Buyer -> audience_mismatch (ตาม Security Rule 1)
# - CIS ต่าง aud -> ใช้ Token Exchange (KC Standard V2): subject token ต้องมี cis-web ใน aud
#   (scope stt-bridge) แล้วแลกเป็น token aud=cis-api — พิสูจน์ด้วยการเรียก /projects ให้ 200
#
# ต้องรันก่อน: bash scripts/setup-stt.sh (stt-bridge + cis-web confidential)
source "$(dirname "$0")/_lib.sh"
require_jq

wait_for "Keycloak discovery" "$ISSUER/.well-known/openid-configuration" 180 || exit 1
wait_for "ID Portal (STT broker)" "http://localhost:3000/" 120 || exit 1
wait_for "Buyer Portal" "http://localhost:3010/" 60 || exit 1
wait_for "CIS Portal" "http://localhost:3020/" 60 || exit 1
wait_for "Fintech App" "http://localhost:3050/" 60 || exit 1
echo

IDPORTAL="http://localhost:3000"
BUYER="http://localhost:3010"
CIS="http://localhost:3020"
FT="http://localhost:3050"
STT_CREATE="$IDPORTAL/stt/create"
STT_REDEEM="$IDPORTAL/stt/redeem"

# token ต้นทางแบบต่าง ๆ (จำลอง native session ของแอปมือถือ/เว็บที่ login แล้ว)
MOBILE_AT=$(pwd_token buyer-web buyer-user "openid orders.read")                                  # aud=[buyer-api]
BRIDGE_AT=$(pwd_token buyer-web buyer-user "openid orders.read stt-bridge")                       # aud=[buyer-api cis-web]
CIS_AT=$(curl -s "$ISSUER/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=cis-web -d client_secret="$CIS_CLIENT_SECRET" \
  -d username=buyer-user -d password="$TEST_USER_PASSWORD" \
  -d scope="openid projects.read" | jq -r '.access_token // empty')                               # aud=[cis-api] (cis-web เป็น confidential แล้ว)

create_code() { # create_code <token> <dest> -> code
  curl -s -X POST "$STT_CREATE" -H "Authorization: Bearer $1" -d "dest=$2" | jq -r '.code // empty'
}

echo "--- 0) เตรียม token ต้นทาง ---"
[ -n "$MOBILE_AT" ] && check "token ต้นทาง aud=buyer-api (mobile จำลอง)" "yes" "yes" || { check "token buyer-aud" "yes" "no"; exit 1; }
[ -n "$BRIDGE_AT" ] && check "token ต้นทาง +stt-bridge (aud รวม cis-web)" "yes" "yes" || { check "token bridge" "yes" "no"; exit 1; }
AUD_BRIDGE=$(jwt_payload "$BRIDGE_AT" | jq -r '[.aud[]] | join(",")')
check "bridge token มี cis-web ใน aud" "yes" "$(echo "$AUD_BRIDGE" | grep -q cis-web && echo yes || echo no)"
[ -n "$CIS_AT" ] && check "token ต้นทาง aud=cis-api (cis-web confidential + Direct Grant)" "yes" "yes" || { check "token cis-aud" "yes" "no"; exit 1; }

echo "--- 1) redeem ถูกต้อง (dest ตรง) + one-time + dest binding ---"
CODE1=$(create_code "$MOBILE_AT" "fintech-web")
[ -n "$CODE1" ] && check "create (dest=fintech-web) -> code" "yes" "yes" || { check "create code" "yes" "no"; exit 1; }
R1=$(curl -s -X POST "$STT_REDEEM" -d "code=$CODE1" -d "dest=fintech-web")
[ "$(echo "$R1" | jq -r '.username // empty')" = "buyer-user" ] && check "redeem (dest ตรง) -> username ถูก" "yes" "yes" || check "redeem username" "buyer-user" "$(echo "$R1" | jq -r '.username')"
HAS1=$(echo "$R1" | jq -r 'if (has("access_token") and has("aud")) then "yes" else "no" end')
check "redeem ได้ access_token + aud จาก broker" "yes" "$HAS1"
REUSE=$(curl -s -X POST "$STT_REDEEM" -d "code=$CODE1" -d "dest=fintech-web")
check "redeem ซ้ำ -> ปฏิเสธ (one-time)" "invalid_or_used_or_expired_code" "$(echo "$REUSE" | jq -r '.error // empty')"
CODE1B=$(create_code "$MOBILE_AT" "fintech-web")
MIS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$STT_REDEEM" -d "code=$CODE1B" -d "dest=cis-web")
check "redeem ปลายทางอื่น -> 403 destination_mismatch" "403" "$MIS"
AFTER=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$STT_REDEEM" -d "code=$CODE1B" -d "dest=fintech-web")
check "code ยังใช้กับปลายทางจริงได้หลังโดนยิงผิด dest (ไม่นับใช้)" "200" "$AFTER"

echo "--- 2) ปลายทาง Buyer (:3010) — aud ตรง ผ่านทันที ---"
JAR=$(mktemp)
CODE2=$(create_code "$MOBILE_AT" "buyer-web")
curl -s -c "$JAR" -b "$JAR" -L -o /tmp/stt-buyer.html -w "%{http_code}" "$BUYER/auth/stt?code=$CODE2" > /tmp/stt-buyer.code
grep -q "ล็อกอินผ่าน ID อยู่" /tmp/stt-buyer.html && check "Buyer เปิดด้วย STT -> session โดยไม่กรอกรหัสผ่าน" "yes" "yes" || check "Buyer STT session" "yes" "no"
check "หน้า Buyer แสดง buyer-user" "yes" "$(grep -q 'buyer-user' /tmp/stt-buyer.html && echo yes || echo no)"

echo "--- 3) ปลายทาง Buyer — cis-aud token -> ปฏิเสธ (aud) ---"
CODE3=$(create_code "$CIS_AT" "buyer-web")
curl -s -L -o /tmp/stt-buyer-bad.html -w "%{http_code}" "$BUYER/auth/stt?code=$CODE3" > /tmp/stt-buyer-bad.code
check "Buyer ปฏิเสธ cis-aud token -> 403 audience_mismatch" "403" "$(cat /tmp/stt-buyer-bad.code)"
check "หน้า error ระบุสาเหตุ aud" "yes" "$(grep -q 'audience_mismatch' /tmp/stt-buyer-bad.html && echo yes || echo no)"

echo "--- 4) ปลายทาง CIS (:3020) — ต่าง aud -> Token Exchange เป็น token aud=cis-api ---"
JARC=$(mktemp)
CODE4=$(create_code "$BRIDGE_AT" "cis-web")
curl -s -c "$JARC" -b "$JARC" -L -o /tmp/stt-cis.html -w "%{http_code}" "$CIS/auth/stt?code=$CODE4" > /tmp/stt-cis.code
grep -q "โอน session สำเร็จ" /tmp/stt-cis.html && check "CIS เปิดด้วย STT -> exchange + session (ไม่กรอกรหัสผ่าน)" "yes" "yes" || { check "CIS STT" "yes" "no ($(head -c 120 /tmp/stt-cis.html | tr -d '\n'))"; }
curl -s -b "$JARC" -c "$JARC" -o /tmp/stt-cis-home.html "$CIS/"
grep -q "ล็อกอินผ่าน ID อยู่" /tmp/stt-cis-home.html && check "session ที่ได้ใช้ได้จริง (CIS home ยืนยัน)" "yes" "yes" || check "CIS home" "yes" "no"

# หลักฐาน sub-preservation: sub ของ token หลัง Exchange == sub ของ subject_token (user เดิม)
SUB_SRC="$(echo "$BRIDGE_AT" | cut -d. -f2 | tr '_-' '/+' | awk '{l=length($0)%4; printf "%s", $0; if(l==2)print "=="; if(l==3)print "="}' | base64 -d 2>/dev/null | jq -r '.sub')"
CIS_TOK="$(grep cis_session "$JARC" | awk '{print $NF}')"
SUB_DST="$(echo "$CIS_TOK" | cut -d. -f2 | tr '_-' '/+' | awk '{l=length($0)%4; printf "%s", $0; if(l==2)print "=="; if(l==3)print "="}' | base64 -d 2>/dev/null | jq -r '.sub')"
check "sub คงเดิมหลัง Token Exchange (source == dest)" "yes" "$([ -n "$SUB_SRC" ] && [ "$SUB_SRC" = "$SUB_DST" ] && echo yes || echo no)"
PROJ=$(curl -s -b "$JARC" -o /tmp/stt-cis-proj.json -w "%{http_code}" "$CIS/projects")
check "พิสูจน์ token ใหม่ aud=cis-api: GET /projects -> 200 (CIS Guard ผ่าน)" "200" "$PROJ"

echo "--- 5) ปลายทาง CIS — token ไม่มี stt-bridge -> ปฏิเสธ (เงื่อนไข exchange V2) ---"
CODE5=$(create_code "$MOBILE_AT" "cis-web")  # aud=[buyer-api] เท่านั้น — ไม่มี cis-web
curl -s -L -o /tmp/stt-cis-bad.html -w "%{http_code}" "$CIS/auth/stt?code=$CODE5" > /tmp/stt-cis-bad.code
check "CIS ปฏิเสธ token ไม่มี cis-web ใน aud" "403" "$(cat /tmp/stt-cis-bad.code)"
check "หน้า error แนะนำทางแก้ (scope stt-bridge)" "yes" "$(grep -q 'stt-bridge\|audience_mismatch' /tmp/stt-cis-bad.html && echo yes || echo no)"

echo "--- 6) ปลายทาง Fintech (:3050) — เดิมยังใช้ได้ + code ปลอม ---"
JARF=$(mktemp)
CODE6=$(create_code "$MOBILE_AT" "fintech-web")
curl -s -c "$JARF" -b "$JARF" -L -o /tmp/stt-ft.html -w "%{http_code}" "$FT/auth/stt?code=$CODE6" > /tmp/stt-ft.code
grep -q 'class="proof ok"' /tmp/stt-ft.html && check "Fintech เปิดด้วย STT -> session + Buyer proof" "yes" "yes" || check "Fintech STT" "yes" "no"
curl -s -L -o /tmp/stt-ft-bad.html "$FT/auth/stt?code=fake-code-000"
check "code ปลอม -> กลับฟอร์ม login พร้อมข้อความ" "yes" "$(grep -q 'ไม่ถูกต้อง\|หมดอายุ' /tmp/stt-ft-bad.html && echo yes || echo no)"

echo "--- 7) SSO Ticket ของ ID กลาง — เปิดแท็บใหม่ตรง ๆ (CIS/Buyer) ไม่ต้อง login ---"
# fintech login สำเร็จ → ออกตั๋ว central_sso (cookie ของ host localhost — browser ส่งให้ทุก port)
# ปลายทางเจอไม่มี session → redeem ตั๋วแทนการ login (renew อัตโนมัติถ้า token ใกล้หมดอายุ)
JARF2=$(mktemp)
curl -s -c "$JARF2" -b "$JARF2" -L -o /dev/null --data-urlencode "username=buyer-user" --data-urlencode "password=$TEST_USER_PASSWORD" "$FT/login"
TICKET=$(awk '/central_sso/{print $7}' "$JARF2")
[ -n "$TICKET" ] && check "fintech login -> ได้ตั๋ว central_sso" "yes" "yes" || { check "ตั๋ว SSO" "yes" "no"; exit 1; }
# จำลอง "แท็บใหม่" — jar มีเฉพาะตั๋ว (ไม่มี session ของแอปปลายทางเลย)
mk_ticket_jar() { printf '.localhost\tFALSE\t/\tFALSE\t0\tcentral_sso\t%s\n' "$TICKET" > "$1"; }
JART=$(mktemp); mk_ticket_jar "$JART"
curl -s -c "$JART" -b "$JART" -L -o /tmp/sso-cis.html "http://localhost:3020/"
check "เปิด CIS (:3020) ตรง ๆ ด้วยตั๋ว -> SSO เข้าเลย" "yes" "$(grep -q 'ล็อกอินผ่าน ID อยู่' /tmp/sso-cis.html && echo yes || echo no)"
check "ตั๋วใช้ซ้ำได้ -> เปิด Buyer (:3010) ตรง ๆ ก็ SSO" "yes" "$(JART2=$(mktemp); mk_ticket_jar "$JART2"; curl -s -c "$JART2" -b "$JART2" -L -o /tmp/sso-buyer.html "http://localhost:3010/"; grep -q 'ล็อกอินผ่าน ID อยู่' /tmp/sso-buyer.html && echo yes || echo no)"
# ต่อเนื่องภายใน 30 วิ: เปิด CIS (set marker ของ cis) แล้วเปิด Buyer ทันที —
# marker กันวน loop ต้องแยกต่อแอป (sso_try_cis / sso_try_buyer) ไม่งั้นแอปถัดไปโดนบังไม่ redeem
curl -s -c "$JART" -b "$JART" -L -o /dev/null "http://localhost:3020/"
grep -q sso_try_cis "$JART" && check "CIS set marker แยกของตัวเอง (sso_try_cis)" "yes" "yes" || check "CIS marker" "yes" "no"
curl -s -c "$JART" -b "$JART" -L -o /tmp/sso-buyer2.html "http://localhost:3010/"
check "เปิด Buyer ทันทีหลัง CIS (marker ไม่บังแอปอื่น) -> SSO เข้าเลย" "yes" "$(grep -q 'ล็อกอินผ่าน ID อยู่' /tmp/sso-buyer2.html && echo yes || echo no)"
# ID Portal (:3000) — เปิดตรง ๆ ก็ SSO (portal เป็นทั้ง broker และปลายทาง — Token Exchange เป็น aud=central-id)
curl -s -c "$JART" -b "$JART" -L -o /tmp/sso-id.html "http://localhost:3000/"
check "เปิด ID Portal (:3000) ตรง ๆ ด้วยตั๋ว -> SSO เข้าเลย (Token Exchange)" "yes" "$(grep -q 'ล็อกอินผ่าน ID อยู่' /tmp/sso-id.html && echo yes || echo no)"
rm -f /tmp/sso-id.html
# logout ที่ fintech -> revoke ตั๋ว -> "แท็บใหม่" (ตั๋วอย่างเดียว ไม่มี session เดิม) ต้องไม่ SSO อีก
# (session ที่ได้ไปแล้วยังอยู่จน exp — ตามข้อจำกัด JWT)
curl -s -c "$JARF2" -b "$JARF2" -L -o /dev/null "$FT/logout"
JART3=$(mktemp); mk_ticket_jar "$JART3"
curl -s -c "$JART3" -b "$JART3" -L -o /tmp/sso-after.html "http://localhost:3020/"
check "logout ที่ fintech -> revoke ตั๋ว -> แท็บใหม่ไม่ SSO (เจอหน้า login ของ ID)" "yes" "$(grep -q 'ล็อกอิน ID' /tmp/sso-after.html && ! grep -q 'ล็อกอินผ่าน ID อยู่' /tmp/sso-after.html && echo yes || echo no)"

echo "--- 8) Logout กลาง propagate — logout ที่แอปหนึ่ง -> session แอปอื่นตายตามทันที ---"
# fintech login → CIS รับ session ผ่านตั๋ว (sso_bound) → logout ที่ fintech (revoke + logout-all)
# → CIS ที่ยังถือ session เดิมจะโดนเคลียร์ตั้งแต่ request หน้าถัดไป (ตรวจตั๋วกับ ID กลาง)
JARF3=$(mktemp); JARC3=$(mktemp)
curl -s -c "$JARF3" -b "$JARF3" -L -o /dev/null --data-urlencode "username=buyer-user" --data-urlencode "password=$TEST_USER_PASSWORD" "$FT/login"
TICKET3=$(awk '/central_sso/{print $7}' "$JARF3")
printf '.localhost\tFALSE\t/\tFALSE\t0\tcentral_sso\t%s\n' "$TICKET3" > "$JARC3"
curl -s -c "$JARC3" -b "$JARC3" -L -o /dev/null "http://localhost:3020/"
grep -q cis_session "$JARC3" && check "CIS ได้ session จากตั๋ว (ผูก sso_bound)" "yes" "yes" || check "CIS session จากตั๋ว" "yes" "no"
curl -s -c "$JARF3" -b "$JARF3" -L -o /dev/null "$FT/logout"
curl -s -c "$JARC3" -b "$JARC3" -L -o /tmp/lo-cis.html "http://localhost:3020/"
check "logout ที่ fintech -> CIS session เดิมตายตาม (propagate)" "yes" "$(grep -q 'ล็อกอินผ่าน ID อยู่' /tmp/lo-cis.html && echo no || echo yes)"
# ทิศกลับ: login fintech ใหม่ → CIS SSO ใหม่ (มี session) → logout ที่ CIS (global) → fintech ตายตาม
curl -s -c "$JARF3" -b "$JARF3" -L -o /dev/null --data-urlencode "username=buyer-user" --data-urlencode "password=$TEST_USER_PASSWORD" "$FT/login"
TICKET4=$(awk '/central_sso/{print $7}' "$JARF3")
printf '.localhost\tFALSE\t/\tFALSE\t0\tcentral_sso\t%s\n' "$TICKET4" > "$JARC3"
curl -s -c "$JARC3" -b "$JARC3" -L -o /dev/null "http://localhost:3020/"
curl -s -c "$JARC3" -b "$JARC3" -L -o /dev/null "http://localhost:3020/auth/logout"
curl -s -c "$JARF3" -b "$JARF3" -L -o /tmp/lo-ft.html "http://localhost:3050/home"
check "logout ที่ CIS (global) -> fintech session เดิมตายตาม (expired)" "yes" "$(grep -q 'เข้าสู่ระบบสำเร็จ' /tmp/lo-ft.html && echo no || echo yes)"
# เคสปุ่มโอน session (browser = jar เดียว): fintech login -> กดปุ่มไป Buyer (STT)
# -> Buyer session ต้องผูกตั๋วด้วย (sso_bound) -> logout กลางที่ fintech -> Buyer ตายตาม
JARF4=$(mktemp)
curl -s -c "$JARF4" -b "$JARF4" -L -o /dev/null --data-urlencode "username=buyer-user" --data-urlencode "password=$TEST_USER_PASSWORD" "$FT/login"
LOCB=$(curl -s -c "$JARF4" -b "$JARF4" -o /dev/null -w "%{redirect_url}" "$FT/stt/transfer?to=buyer")
CODEB=$(echo "$LOCB" | sed -n 's/.*code=\([^&]*\).*/\1/p')
curl -s -c "$JARF4" -b "$JARF4" -L -o /dev/null "http://localhost:3010/auth/stt?code=$CODEB"
check "กดปุ่มไป Buyer (STT) -> session ผูกตั๋ว (sso_bound)" "yes" "$(grep -q sso_bound "$JARF4" && echo yes || echo no)"
curl -s -c "$JARF4" -b "$JARF4" -L -o /dev/null "$FT/logout"
curl -s -c "$JARF4" -b "$JARF4" -L -o /tmp/lo-buyer.html "http://localhost:3010/"
check "logout กลางที่ fintech -> Buyer (จากปุ่ม STT) ตายตามด้วย" "yes" "$(grep -q 'ล็อกอินผ่าน ID อยู่' /tmp/lo-buyer.html && echo no || echo yes)"
rm -f "$JARF4" /tmp/lo-buyer.html
rm -f "$JARF3" "$JARC3" /tmp/lo-cis.html /tmp/lo-ft.html
rm -f "$JARF2" "$JART" "$JART3" /tmp/sso-cis.html /tmp/sso-buyer.html /tmp/sso-after.html

rm -f /tmp/stt-*.html /tmp/stt-*.json /tmp/stt-*.code "$JAR" "$JARC" "$JARF"
summary
