#!/usr/bin/env bash
# Phase 1 — ตรวจ Keycloak ออก token ได้ถูกต้องตาม Token Contract
# (discovery, password grant, client credentials, ตรวจ claims iss/aud/scope/principal_type)
source "$(dirname "$0")/_lib.sh"
require_jq

wait_for "Keycloak discovery" "$ISSUER/.well-known/openid-configuration" 180 || exit 1
echo

# 1. Discovery endpoint
DISC_ISSUER="$(curl -s "$ISSUER/.well-known/openid-configuration" | jq -r '.issuer // empty')"
check "discovery .issuer = $ISSUER" "$ISSUER" "$DISC_ISSUER"

# kid สร้างโดย Keycloak เอง (auto) — ตรวจว่า JWKS มี RSA key อย่างน้อย 1 ตัว
JWKS_KID="$(curl -s "$ISSUER/protocol/openid-connect/certs" |
  jq -r '[.keys[] | select(.kty == "RSA")][0].kid // empty')"
[ -n "$JWKS_KID" ] && check "JWKS มี RSA signing key (kid=$JWKS_KID)" "yes" "yes" ||
  check "JWKS มี RSA signing key" "yes" "no"

# helper: aud อาจเป็น string หรือ array — คืนเป็นคั่นด้วยช่องว่าง
aud_of() { jwt_payload "$1" | jq -r 'if (.aud | type) == "array" then (.aud | join(" ")) else (.aud // "") end'; }

# 2. Password grant (buyer-web)
T_BUYER="$(pwd_token buyer-web buyer-user 'openid orders.read orders.write')"
[ -n "$T_BUYER" ] && check "password grant buyer-web ได้ access_token" "yes" "yes" || check "password grant buyer-web ได้ access_token" "yes" "no"

P_BUYER="$(jwt_payload "$T_BUYER")"
check "buyer token iss = realm central" "$ISSUER" "$(echo "$P_BUYER" | jq -r .iss)"
check "buyer token aud มี buyer-api" "yes" "$(aud_of "$T_BUYER" | grep -qw buyer-api && echo yes)"
check "buyer token principal_type = user" "user" "$(echo "$P_BUYER" | jq -r '.principal_type // empty')"
check "buyer token scope มี orders.read" "yes" "$(echo "$P_BUYER" | jq -r '.scope // empty' | grep -qw orders.read && echo yes || echo no)"

# 3. Client credentials (partner-001)
T_PARTNER="$(cc_token)"
[ -n "$T_PARTNER" ] && check "client_credentials partner-001 ได้ access_token" "yes" "yes" || check "client_credentials partner-001 ได้ access_token" "yes" "no"

P_PARTNER="$(jwt_payload "$T_PARTNER")"
check "partner token principal_type = service" "service" "$(echo "$P_PARTNER" | jq -r '.principal_type // empty')"
check "partner token scope มี orders.read" "yes" "$(echo "$P_PARTNER" | jq -r '.scope // empty' | grep -qw orders.read && echo yes || echo no)"
check "partner token scope ไม่มี projects.read (จะได้ 403 ตอนยิง CIS)" "no" "$(echo "$P_PARTNER" | jq -r '.scope // empty' | grep -qw projects.read && echo yes || echo no)"

# 4. Password grant (cis-web)
T_CIS="$(pwd_token cis-web cis-user 'openid projects.read projects.write' "$CIS_CLIENT_SECRET")"
P_CIS="$(jwt_payload "$T_CIS")"
check "cis token aud มี cis-api" "yes" "$(aud_of "$T_CIS" | grep -qw cis-api && echo yes)"
check "cis token scope มี projects.read" "yes" "$(echo "$P_CIS" | jq -r '.scope // empty' | grep -qw projects.read && echo yes || echo no)"

# 5. disabled-user ต้อง login ไม่ได้
CODE_DISABLED="$(curl -s -o /dev/null -w '%{http_code}' "$ISSUER/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=buyer-web -d username=disabled-user -d password="$TEST_USER_PASSWORD")"
[ "$CODE_DISABLED" != "200" ] && check "disabled-user login ไม่ได้ (HTTP $CODE_DISABLED)" "yes" "yes" ||
  check "disabled-user login ไม่ได้" "yes" "no"

summary
