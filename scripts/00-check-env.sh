#!/usr/bin/env bash
# ตรวจเครื่องพร้อมรัน POC หรือยัง
set -u
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"
FAIL=0

ok()   { echo "OK    $1"; }
miss() { echo "MISS $1 → $2"; FAIL=$((FAIL + 1)); }

command -v docker >/dev/null 2>&1 && ok "docker ($(docker --version 2>/dev/null | sed 's/Docker version //;s/,.*//'))" ||
  miss "docker" "ติดตั้ง Docker Desktop"
command -v jq >/dev/null 2>&1 && ok "jq ($(jq --version))" ||
  { command -v docker >/dev/null 2>&1 && ok "jq (ผ่าน docker fallback ghcr.io/jqlang/jq)"; } ||
  miss "jq" "ติดตั้ง jq (https://jqlang.org/download/)"
command -v curl >/dev/null 2>&1 && ok "curl" ||
  miss "curl" "ใช้ curl ที่มากับ git-bash/OS"
command -v openssl >/dev/null 2>&1 && ok "openssl" ||
  miss "openssl" "ใช้ openssl ที่มากับ git-bash (หรือรัน setup-keys.sh ผ่าน docker fallback)"
[ -f .env ] && ok ".env" || miss ".env" "cp .env.example .env แล้วแก้รหัสผ่าน"
[ -f keycloak/central-realm.json ] && ok "keycloak/central-realm.json (generated)" ||
  miss "keycloak/central-realm.json" "รัน bash scripts/setup.sh ก่อน"
[ -f kong/kong.yml ] && ok "kong/kong.yml (generated)" ||
  miss "kong/kong.yml" "รัน bash scripts/setup.sh ก่อน (ต้องมี Keycloak รันอยู่เพื่อดึง public key)"

echo
if [ "$FAIL" -eq 0 ]; then
  echo "✓ พร้อมรัน: bash scripts/setup.sh หรือ docker compose up -d --build"
else
  echo "✗ ขาด $FAIL รายการ — แก้ตามข้างบนก่อน"
  exit 1
fi
