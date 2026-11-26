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

# Docker Compose v2 + BuildKit — service ทุกตัว build ร่วมกับ SDK กลาง (packages/) ผ่าน
# build.additional_contexts (ADR-008): ใช้ docker-compose v1 ไม่ได้ และต้องมี BuildKit
# ตรวจ "ความสามารถจริง" โดยให้ compose อ่านไฟล์ที่มี additional_contexts (แทนการเทียบเลขเวอร์ชัน)
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  PROBE_DIR="$(mktemp -d)"
  printf 'services:\n  probe:\n    build:\n      context: .\n      additional_contexts:\n        sdk: .\n' > "$PROBE_DIR/compose.yaml"
  if docker compose -f "$PROBE_DIR/compose.yaml" config -q >/dev/null 2>&1; then
    ok "docker compose v2 ($(docker compose version --short 2>/dev/null)) — รองรับ build.additional_contexts"
  else
    miss "docker compose (build.additional_contexts)" "อัปเกรด Docker Compose v2 เป็นรุ่นล่าสุด (มาพร้อม Docker Desktop รุ่นใหม่) — docker-compose v1 ใช้กับ repo นี้ไม่ได้"
  fi
  rm -rf "$PROBE_DIR"
else
  miss "docker compose v2" "ติดตั้ง Docker Compose v2 (plugin ของ Docker — ไม่ใช่ docker-compose ตัวเก่า)"
fi
if docker buildx version >/dev/null 2>&1 && [ "${DOCKER_BUILDKIT:-1}" != "0" ]; then
  ok "buildkit ($(docker buildx version 2>/dev/null | awk '{print $2}'))"
else
  miss "buildkit" "การ build ต้องใช้ BuildKit (ติดตั้ง buildx plugin และอย่าตั้ง DOCKER_BUILDKIT=0)"
fi
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
