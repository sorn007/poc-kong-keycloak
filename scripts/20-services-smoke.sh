#!/usr/bin/env bash
# Phase 3-4 — ตรวจ Buyer (NestJS) และ CIS (Go Fiber) ตรวจ central token เอง
# เรียกตรงถึง service (ไม่ผ่าน Kong) — เคส 401/403 พื้นฐาน
source "$(dirname "$0")/_lib.sh"
require_jq

wait_for "Buyer API" "$BUYER/" 60
wait_for "CIS API" "$CIS/" 60
echo

T_BUYER="$(pwd_token buyer-web buyer-user 'openid orders.read orders.write')"
T_CIS="$(pwd_token cis-web cis-user 'openid projects.read projects.write' "$CIS_CLIENT_SECRET")"
T_PARTNER="$(cc_token)"

# --- Buyer ---
check "GET /orders ไม่มี header → 401" "401" "$(code "$BUYER/orders")"
check "GET /orders ด้วย buyer token → 200" "200" "$(code -H "Authorization: Bearer $T_BUYER" "$BUYER/orders")"
check "GET /orders ด้วย partner token (aud buyer-api + orders.read) → 200" "200" "$(code -H "Authorization: Bearer $T_PARTNER" "$BUYER/orders")"
check "POST /orders ด้วย partner token (ไม่มี orders.write) → 403" "403" "$(code -X POST -H "Authorization: Bearer $T_PARTNER" "$BUYER/orders")"
# POST สร้างสำเร็จคืน 201 Created (REST semantics)
check "POST /orders ด้วย buyer token (มี orders.write) → 201" "201" "$(code -X POST -H "Authorization: Bearer $T_BUYER" "$BUYER/orders")"
check "GET /orders ด้วย cis token (aud=cis-api ผิดฝั่ง) → 401" "401" "$(code -H "Authorization: Bearer $T_CIS" "$BUYER/orders")"
check "GET /orders ด้วย token ปลอม → 401" "401" "$(code -H "Authorization: Bearer fake.token.value" "$BUYER/orders")"

# --- CIS ---
check "GET /open-api/projects ไม่มี header → 401" "401" "$(code "$CIS/open-api/projects")"
check "GET /open-api/projects ด้วย cis token → 200" "200" "$(code -H "Authorization: Bearer $T_CIS" "$CIS/open-api/projects")"
check "GET /open-api/projects ด้วย buyer token (aud=buyer-api ผิดฝั่ง) → 401" "401" "$(code -H "Authorization: Bearer $T_BUYER" "$CIS/open-api/projects")"
check "GET /open-api/projects ด้วย partner token (aud=buyer-api ไม่ตรง cis-api) → 401" "401" "$(code -H "Authorization: Bearer $T_PARTNER" "$CIS/open-api/projects")"

# --- Open API ฝั่ง Buyer: partner ผูก tenant company_001 ---
TENANT_OK="$(curl -s -H "Authorization: Bearer $T_PARTNER" "$BUYER/open-api/orders")"
check "GET /open-api/orders partner (principal_type=service, tenant company_001) → 200" "200" "$(code -H "Authorization: Bearer $T_PARTNER" "$BUYER/open-api/orders")"

summary
