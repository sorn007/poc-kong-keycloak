#!/usr/bin/env bash
# Phase 9 — Dual Validation: รับทั้ง central token และ legacy token (token เดิมของระบบ)
# เลือก validator จาก iss บน "allowlist คงที่" เท่านั้น — ห้าม fallback อิสระ
source "$(dirname "$0")/_lib.sh"
require_jq

wait_for "Buyer API" "$BUYER/" 60
wait_for "CIS API" "$CIS/" 60
echo

T_BUYER="$(pwd_token buyer-web buyer-user 'openid orders.read')"
T_CIS="$(pwd_token cis-web cis-user 'openid projects.read' "$CIS_CLIENT_SECRET")"

# 1) Central token → ผ่าน
check "central token → /orders/dual 200" "200" "$(code -H "Authorization: Bearer $T_BUYER" "$BUYER/orders/dual")"

# 2) Legacy token ของ Buyer (mint จาก /dev) → ผ่าน
LEGACY_BUYER="$(curl -s -X POST "$BUYER/dev/mint-legacy-token" \
  -H 'Content-Type: application/json' -d '{"sub":"legacy-buyer-user"}' |
  jq -r '.token // empty')"
check "mint legacy buyer token → /orders/dual 200" "200" "$(code -H "Authorization: Bearer $LEGACY_BUYER" "$BUYER/orders/dual")"

# 3) Legacy token ของ CIS (iss ไม่อยู่ใน allowlist ของ Buyer) → 401 ทันที
LEGACY_CIS="$(curl -s -X POST "$CIS/dev/mint-legacy-token" \
  -H 'Content-Type: application/json' -d '{"sub":"legacy-cis-user"}' |
  jq -r '.token // empty')"
check "legacy token iss=legacy-cis (นอก allowlist) → 401" "401" "$(code -H "Authorization: Bearer $LEGACY_CIS" "$BUYER/orders/dual")"

# 4) Central token ของ CIS (iss อยู่ใน allowlist → เลือก central validator → aud ผิด) → 401
check "cis central token (iss ok, aud=cis-api) → 401" "401" "$(code -H "Authorization: Bearer $T_CIS" "$BUYER/orders/dual")"

# 5) Legacy token ที่แก้ signature → 401
TAMPERED="${LEGACY_BUYER:0:-2}xx"
check "legacy token ที่แก้ signature → 401" "401" "$(code -H "Authorization: Bearer $TAMPERED" "$BUYER/orders/dual")"

# 6) ขยะที่ไม่ใช่ JWT → 401
check "token ไม่ถอดรูปได้ → 401" "401" "$(code -H "Authorization: Bearer not-a-jwt" "$BUYER/orders/dual")"

summary
