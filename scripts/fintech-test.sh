#!/usr/bin/env bash
# Fintech App (Embedded Login exception demo) — ทดสอบ E2E:
# 1) ฟอร์ม login ของตัวเอง (username/password)
# 2) login ถูกต้อง -> token ฝั่ง server + เรียก Buyer API 200
# 3) ยิงรหัสผ่านผิด 5 ครั้ง -> แอปล็อกชั่วคราว (และ KC ล็อก user ระดับ realm)
# 4) รหัสถูกต้องระหว่างถูกล็อก -> ต้องยังไม่ผ่าน (พิสูจน์ว่ามีการกันยิงจริง)
# 5) รอพ้นรอบล็อก -> login ใหม่ผ่านอีกครั้ง
# เงื่อนไข KC 26.3: brute force ระดับ realm (failureCount=5, wait 30s) + แอปล็อกเอง 35s
source "$(dirname "$0")/_lib.sh"
require_jq

wait_for "Keycloak discovery" "$ISSUER/.well-known/openid-configuration" 180 || exit 1
wait_for "Fintech App" "http://localhost:3050/" 120 || exit 1
echo

FT="http://localhost:3050"
JAR="$(mktemp)"

# title_of <file> — ดึง <title> เพื่อระบุหน้าปัจจุบัน (แต่ละหน้ามี title ต่างกันชัดเจน)
title_of() { grep -oE '<title>[^<]*</title>' "$1" 2>/dev/null | head -1; }

echo "--- 1) หน้า login ของ Fintech App (ฟอร์ม user/pass ของตัวเอง) ---"
CODE=$(curl -s -c "$JAR" -b "$JAR" -o /tmp/ft-login.html -w "%{http_code}" "$FT/")
HAS_FORM=$(grep -q 'name="username"' /tmp/ft-login.html && grep -q 'name="password"' /tmp/ft-login.html && echo yes || echo no)
check "หน้า login: HTTP $CODE + ฟอร์ม username/password" "yes" "$HAS_FORM"

echo "--- 2) login ถูกต้อง (buyer-user) -> home + Buyer API 200 ---"
CODE=$(curl -s -c "$JAR" -b "$JAR" -L -o /tmp/ft-home.html -w "%{http_code}" \
  --data-urlencode "username=buyer-user" --data-urlencode "password=$TEST_USER_PASSWORD" "$FT/login")
HOME_OK="no"
grep -q "เข้าสู่ระบบสำเร็จ" /tmp/ft-home.html && HOME_OK="yes"
BUY_OK="no"; grep -q 'class="proof ok"' /tmp/ft-home.html && BUY_OK="yes"
check "login ถูกต้อง -> หน้า home (server-side session)" "yes" "$HOME_OK"
check "home: พิสูจน์ Buyer API (การ์ดผลลัพธ์)" "yes" "$BUY_OK"

echo "--- 3) Brute force: ยิงรหัสผ่านผิด 5 ครั้ง -> แอปล็อก 35s ---"
for i in 1 2 3 4 5; do
  C=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w "%{http_code}" \
    --data-urlencode "username=buyer-user" --data-urlencode "password=wrong-$i" "$FT/login")
  echo "  wrong#$i -> HTTP $C"
done
# คำขอถัดไป (รหัสถูกต้อง) ต้องเจอการล็อก — จากแอป (35s) และ/หรือ KC (30s)
C=$(curl -s -c "$JAR" -b "$JAR" -L -o /tmp/ft-lock.html -w "%{http_code}" \
  --data-urlencode "username=buyer-user" --data-urlencode "password=$TEST_USER_PASSWORD" "$FT/login")
LOCK_OK="no"
grep -qE "ล็อก|locked|พยายาม|Invalid user credentials|รอสักครู่" /tmp/ft-lock.html && LOCK_OK="yes"
check "รหัสถูกต้องระหว่างล็อก -> ถูกปฏิเสธ (แอปและ/หรือ KC lock)" "yes" "$LOCK_OK"

echo "--- 4) รอพ้นรอบล็อก (app 35s + KC quick-login 60s) แล้ว login ใหม่ -> ต้องกลับมาผ่าน ---"
sleep 70
CODE=$(curl -s -c "$JAR" -b "$JAR" -L -o /tmp/ft-final.html -w "%{http_code}" \
  --data-urlencode "username=buyer-user" --data-urlencode "password=$TEST_USER_PASSWORD" "$FT/login")
FINAL_OK="no"
grep -q "เข้าสู่ระบบสำเร็จ" /tmp/ft-final.html && FINAL_OK="yes"
check "หลังพ้นรอบล็อก -> login ได้อีกครั้ง" "yes" "$FINAL_OK"

rm -f /tmp/ft-login.html /tmp/ft-home.html /tmp/ft-lock.html /tmp/ft-final.html
summary
