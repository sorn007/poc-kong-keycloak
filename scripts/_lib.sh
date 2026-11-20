#!/usr/bin/env bash
# Shared helpers สำหรับ test scripts ทั้งหมด — source จากตัว script เท่านั้น
# usage ใน script: source "$(dirname "$0")/_lib.sh"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[1]}")/.." && pwd)"
cd "$ROOT_DIR"

# โหลด secret/config จาก .env
set -a
[ -f .env ] && source .env
set +a

KC="http://localhost:8080"
KONG="http://localhost:8000"
BUYER="http://localhost:3010"
CIS="http://localhost:3020"
REALM="central"
ISSUER="$KC/realms/$REALM"
PASS=0
FAIL=0

check() {
  # check "ชื่อเคส" expected actual
  local name="$1" expect="$2" actual="$3"
  if [ "$expect" = "$actual" ]; then
    PASS=$((PASS + 1))
    echo "PASS  $name (got $actual)"
  else
    FAIL=$((FAIL + 1))
    echo "FAIL  $name (expect $expect, got $actual)"
  fi
}

expect_contains() {
  # expect_contains "ชื่อเคส" haystack needle
  local name="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    PASS=$((PASS + 1))
    echo "PASS  $name"
  else
    FAIL=$((FAIL + 1))
    echo "FAIL  $name (ไม่พบ '$needle')"
  fi
}

summary() {
  echo
  echo "======================================================"
  echo "  สรุป: PASS=$PASS FAIL=$FAIL"
  echo "======================================================"
  [ "$FAIL" -eq 0 ]
}

require_jq() {
  # ถ้าไม่มี jq ในเครื่อง ใช้ jq ผ่าน docker image ทางการแทน (ต้องมี docker)
  # MSYS_NO_PATHCONV — กัน git-bash แปลง /w เป็น W:/ (Linux ไม่สนใจ env นี้)
  if ! command -v jq >/dev/null 2>&1; then
    jq() { MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm -i -v "$PWD:/w" -w /w ghcr.io/jqlang/jq "$@"; }
    docker image inspect ghcr.io/jqlang/jq >/dev/null 2>&1 ||
      docker pull ghcr.io/jqlang/jq >/dev/null || {
      echo "ไม่มีทั้ง jq ในเครื่องและ docker — ติดตั้ง jq จาก https://jqlang.org"
      exit 1
    }
  fi
}

code() {
  # code curl-args... → เอาเฉพาะ HTTP status
  curl -s -o /dev/null -w '%{http_code}' "$@"
}

wait_for() {
  # wait_for "ชื่อ" url timeout-seconds → รอจน HTTP 200
  local name="$1" url="$2" timeout="${3:-120}" i=0
  echo "รอ $name ที่ $url ..."
  until [ "$(curl -s -o /dev/null -w '%{http_code}' "$url")" = "200" ]; do
    sleep 2
    i=$((i + 2))
    if [ "$i" -ge "$timeout" ]; then
      echo "TIMEOUT รอ $name — ลอง docker compose ps และดู log ของ container"
      return 1
    fi
  done
  echo "✓ $name พร้อมใช้งาน"
}

# ถอด payload จาก JWT (base64url) → JSON string
jwt_payload() {
  local p="${1#*.}"
  p="${p%%.*}"
  p="$(printf %s "$p" | tr '_-' '/+')"
  case $((${#p} % 4)) in
    2) p="${p}==" ;;
    3) p="${p}=" ;;
  esac
  printf %s "$p" | base64 -d 2>/dev/null
}

# Password grant — echo access_token (ค่าว่างถ้าล้มเหลว)
pwd_token() {
  # pwd_token <client_id> <username> [scope] [client_secret]
  # client_secret จำเป็นสำหรับ confidential client (เช่น cis-web ตั้งแต่ setup-stt.sh)
  curl -s "$ISSUER/protocol/openid-connect/token" \
    -d grant_type=password \
    -d client_id="$1" \
    ${4:+-d client_secret="$4"} \
    -d username="$2" \
    -d password="$TEST_USER_PASSWORD" \
    -d scope="${3:-openid}" |
    jq -r '.access_token // empty'
}

# Client credentials grant ของ partner-001 — echo access_token
cc_token() {
  curl -s "$ISSUER/protocol/openid-connect/token" \
    -d grant_type=client_credentials \
    -d client_id=partner-001 \
    -d client_secret="$PARTNER_001_CLIENT_SECRET" |
    jq -r '.access_token // empty'
}

# Admin token (realm master) — echo "admin_token user_id"
admin_token_and_uid() {
  local admin_tok uid
  admin_tok="$(curl -s "$KC/realms/master/protocol/openid-connect/token" \
    -d grant_type=password \
    -d client_id=admin-cli \
    -d username="$KC_BOOTSTRAP_ADMIN_USERNAME" \
    -d password="$KC_BOOTSTRAP_ADMIN_PASSWORD" |
    jq -r '.access_token // empty')"
  uid="$(curl -s "$KC/admin/realms/$REALM/users?username=$1&exact=true" \
    -H "Authorization: Bearer $admin_tok" |
    jq -r '.[0].id // empty')"
  printf '%s %s\n' "$admin_tok" "$uid"
}
