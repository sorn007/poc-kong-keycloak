#!/usr/bin/env bash
# Identity Brokering (ทางเลือก B): จำลอง ID จริงเป็น realm upstream
# ผู้ใช้ login ที่ upstream realm -> realm central (Keycloak ซ่อนเบื้องหลัง) ออก token ให้แอป
# 1) realm central-id-upstream + client central-broker + users
# 2) realm central: IdP central-id + first-broker-login flow (auto-link) + browser flow redirect
# รันซ้ำได้ (ลบของเดิมแล้วสร้างใหม่เสมอ)
source "$(dirname "$0")/_lib.sh"
require_jq

wait_for "Keycloak discovery" "$ISSUER/.well-known/openid-configuration" 180 || exit 1

ADM=$(curl -s "$KC/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli \
  -d username="$KC_BOOTSTRAP_ADMIN_USERNAME" -d password="$KC_BOOTSTRAP_ADMIN_PASSWORD" |
  jq -r '.access_token // empty')
[ -n "$ADM" ] || { check "admin token (master)" "yes" "no"; exit 1; }
AUTH="Authorization: Bearer $ADM"

UP="central-id-upstream"
BROKER_ALIAS="central-id"
FLOW_FL="central-id-first-login"
FLOW_BROWSER="browser-central-id"
REDIRECT_URI="$ISSUER/broker/$BROKER_ALIAS/endpoint"

enc() { printf %s "$1" | sed 's/ /%20/g'; }

# ตั้ง requirement ของ execution: PUT /flows/{alias}/executions ด้วย object เต็มที่ GET มาแล้วแก้ requirement
# หมายเหตุ: auth-cookie ต้องเป็น ALTERNATIVE (ไม่ใช่ REQUIRED) — cookie ไม่มี = attempted และ flow พังทันที
set_req() { # $1=flowAlias $2=providerId $3=requirement
  curl -s "$KC/admin/realms/central/authentication/flows/$(enc "$1")/executions" -H "$AUTH" \
    | jq '.[] | select(.providerId=="'"$2"'") | .requirement="'"$3"'"' \
    | curl -s -o /dev/null -X PUT "$KC/admin/realms/central/authentication/flows/$(enc "$1")/executions" -H "$AUTH" -H "Content-Type: application/json" -d @-
}

# ลบ flow แล้วรอจน alias หายจริง (KC อาจใช้เวลา async สั้น ๆ — สร้างทันทีจะชน alias 400)
delete_flow() {
  local ALIAS="$1" ID
  ID=$(curl -s "$KC/admin/realms/central/authentication/flows" -H "$AUTH" | jq -r '.[] | select(.alias=="'"$ALIAS"'") | .id' | head -1)
  [ -n "$ID" ] && curl -s -o /dev/null -X DELETE "$KC/admin/realms/central/authentication/flows/$ID" -H "$AUTH"
  for i in $(seq 1 20); do
    FOUND=$(curl -s "$KC/admin/realms/central/authentication/flows" -H "$AUTH" | jq '[.[] | select(.alias=="'"$ALIAS"'")] | length')
    [ "$FOUND" = "0" ] && return 0
    sleep 0.25
  done
  return 1
}

echo "--- 1) upstream realm: $UP (จำลอง ID จริง - theme เขียว) ---"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$KC/admin/realms/$UP" -H "$AUTH")
echo "  ลบ realm เดิม: HTTP $CODE (404 = ยังไม่มี)"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$KC/admin/realms" -H "$AUTH" -H "Content-Type: application/json" -d "{
  \"realm\": \"$UP\", \"enabled\": true, \"displayName\": \"ID\",
  \"loginTheme\": \"central-upstream\",
  \"ssoSessionIdleTimeout\": 1800, \"ssoSessionMaxLifespan\": 36000,
  \"accessTokenLifespan\": 300, \"sslRequired\": \"external\",
  \"registrationAllowed\": false, \"rememberMe\": false
}")
check "สร้าง upstream realm $UP" "201" "$CODE"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$KC/admin/realms/$UP/clients" -H "$AUTH" -H "Content-Type: application/json" -d "{
  \"clientId\": \"central-broker\", \"enabled\": true, \"protocol\": \"openid-connect\",
  \"publicClient\": false, \"clientAuthenticatorType\": \"client-secret\",
  \"secret\": \"$CENTRAL_BROKER_CLIENT_SECRET\",
  \"standardFlowEnabled\": true, \"directAccessGrantsEnabled\": false,
  \"redirectUris\": [\"$REDIRECT_URI\"],
  \"attributes\": {\"post.logout.redirect.uris\": \"$REDIRECT_URI/logout_response\"}
}")
check "สร้าง client central-broker (รวม logout_response redirect สำหรับ Single Logout)" "201" "$CODE"

for U in "buyer-user:buyer@central.local:Buyer:Demo" "cis-user:cis@central.local:CIS:Demo"; do
  UN="${U%%:*}"; REST="${U#*:}"; EM="${REST%%:*}"; REST="${REST#*:}"; FN="${REST%%:*}"; LN="${REST##*:}"
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$KC/admin/realms/$UP/users" -H "$AUTH" -H "Content-Type: application/json" -d "{
    \"username\": \"$UN\", \"enabled\": true, \"email\": \"$EM\", \"emailVerified\": true,
    \"firstName\": \"$FN\", \"lastName\": \"$LN\",
    \"credentials\": [{\"type\": \"password\", \"value\": \"$TEST_USER_PASSWORD\", \"temporary\": false}]
  }")
  check "สร้าง user $UN (ใน ID จริง)" "201" "$CODE"
done

echo "--- 2) first-broker-login flow (auto-link ไม่ถามผู้ใช้) ---"
# upsert: ถ้า flow ถูกอ้างอิงโดย IdP อยู่ จะลบไม่ได้ — ใช้ที่มีอยู่ต่อ สร้างเฉพาะ execution ที่ยังไม่มี
EXISTS=$(curl -s "$KC/admin/realms/central/authentication/flows" -H "$AUTH" | jq '[.[] | select(.alias=="'"$FLOW_FL"'")] | length')
if [ "$EXISTS" = "0" ]; then
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$KC/admin/realms/central/authentication/flows" -H "$AUTH" -H "Content-Type: application/json" -d "{
    \"alias\": \"$FLOW_FL\", \"description\": \"Auto-link from ID without prompts\",
    \"providerId\": \"basic-flow\", \"topLevel\": true, \"builtIn\": false
  }")
  check "สร้าง flow $FLOW_FL" "201" "$CODE"
  for PAIR in "idp-detect-existing-broker-user:10" "idp-auto-link:20"; do
    PROV="${PAIR%%:*}"; PRIO="${PAIR##*:}"
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$KC/admin/realms/central/authentication/flows/$(enc "$FLOW_FL")/executions/execution" -H "$AUTH" -H "Content-Type: application/json" -d "{\"provider\": \"$PROV\", \"priority\": $PRIO}")
    check "  execution $PROV" "201" "$CODE"
  done
else
  echo "  flow มีอยู่แล้ว — ใช้เดิม (upsert)"
fi
set_req "$FLOW_FL" "idp-detect-existing-broker-user" "REQUIRED"
set_req "$FLOW_FL" "idp-auto-link" "REQUIRED"
NREQ=$(curl -s "$KC/admin/realms/central/authentication/flows/$(enc "$FLOW_FL")/executions" -H "$AUTH" | jq '[.[] | select(.requirement=="REQUIRED")] | length')
check "  executions REQUIRED ครบ 2" "2" "$NREQ"

echo "--- 3) IdP instance $BROKER_ALIAS (keycloak-oidc -> upstream) ---"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$KC/admin/realms/central/identity-provider/instances/$BROKER_ALIAS" -H "$AUTH")
for i in $(seq 1 20); do
  EX=$(curl -s "$KC/admin/realms/central/identity-provider/instances" -H "$AUTH" | jq '[.[] | select(.alias=="'"$BROKER_ALIAS"'")] | length')
  [ "$EX" = "0" ] && break
  sleep 0.25
done
echo "  ลบ IdP เดิม: HTTP $CODE (404 = ยังไม่มี)"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$KC/admin/realms/central/identity-provider/instances" -H "$AUTH" -H "Content-Type: application/json" -d "{
  \"alias\": \"$BROKER_ALIAS\", \"providerId\": \"keycloak-oidc\", \"enabled\": true,
  \"displayName\": \"ID\", \"firstBrokerLoginFlowAlias\": \"$FLOW_FL\",
  \"config\": {
    \"issuer\": \"$KC/realms/$UP\",
    \"authorizationUrl\": \"$KC/realms/$UP/protocol/openid-connect/auth\",
    \"tokenUrl\": \"$KC/realms/$UP/protocol/openid-connect/token\",
    \"logoutUrl\": \"$KC/realms/$UP/protocol/openid-connect/logout\",
    \"userInfoUrl\": \"$KC/realms/$UP/protocol/openid-connect/userinfo\",
    \"jwksUrl\": \"$KC/realms/$UP/protocol/openid-connect/certs\",
    \"useJwksUrl\": \"true\", \"validateSignature\": \"true\",
    \"clientId\": \"central-broker\", \"clientSecret\": \"$CENTRAL_BROKER_CLIENT_SECRET\",
    \"clientAuthMethod\": \"client_secret_post\",
    \"defaultScope\": \"openid profile email\",
    \"syncMode\": \"FORCE\", \"trustEmail\": \"true\", \"storeTokens\": \"false\",
    \"hideOnLoginPage\": \"true\"
  }
}")
check "สร้าง IdP $BROKER_ALIAS (FORCE + auto-link)" "201" "$CODE"

echo "--- 4) browser flow ใหม่ (redirect ไป ID อัตโนมัติ) ---"
EXISTS=$(curl -s "$KC/admin/realms/central/authentication/flows" -H "$AUTH" | jq '[.[] | select(.alias=="'"$FLOW_BROWSER"'")] | length')
if [ "$EXISTS" = "0" ]; then
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$KC/admin/realms/central/authentication/flows" -H "$AUTH" -H "Content-Type: application/json" -d "{
    \"alias\": \"$FLOW_BROWSER\", \"description\": \"SSO cookie first, then redirect to ID\",
    \"providerId\": \"basic-flow\", \"topLevel\": true, \"builtIn\": false
  }")
  check "สร้าง flow $FLOW_BROWSER" "201" "$CODE"
  for PAIR in "auth-cookie:10" "identity-provider-redirector:20"; do
    PROV="${PAIR%%:*}"; PRIO="${PAIR##*:}"
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$KC/admin/realms/central/authentication/flows/$(enc "$FLOW_BROWSER")/executions/execution" -H "$AUTH" -H "Content-Type: application/json" -d "{\"provider\": \"$PROV\", \"priority\": $PRIO}")
    check "  execution $PROV" "201" "$CODE"
  done
else
  echo "  flow มีอยู่แล้ว — ใช้เดิม (upsert)"
fi
set_req "$FLOW_BROWSER" "auth-cookie" "ALTERNATIVE"
set_req "$FLOW_BROWSER" "identity-provider-redirector" "ALTERNATIVE"
RID=$(curl -s "$KC/admin/realms/central/authentication/flows/$(enc "$FLOW_BROWSER")/executions" -H "$AUTH" | jq -r '.[] | select(.providerId=="identity-provider-redirector") | .id')
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$KC/admin/realms/central/authentication/executions/$RID/config" -H "$AUTH" -H "Content-Type: application/json" -d "{
  \"alias\": \"central-id-default\", \"config\": {\"defaultProvider\": \"$BROKER_ALIAS\"}
}")
check "  redirector defaultProvider=central-id" "201" "$CODE"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$KC/admin/realms/central" -H "$AUTH" -H "Content-Type: application/json" -d "{\"browserFlow\": \"$FLOW_BROWSER\"}")
check "ตั้ง browserFlow ของ realm central" "204" "$CODE"

echo "--- 5) ทดสอบ redirect chain ---"
JAR="$(mktemp)"
V="testverifier_0123456789012345678901234567890"
CH=$(printf %s "$V" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
AUTH_URL="$ISSUER/protocol/openid-connect/auth?client_id=buyer-web&response_type=code&scope=openid&redirect_uri=http%3A%2F%2Flocalhost%3A3010%2Fauth%2Fcallback&state=t&code_challenge=$CH&code_challenge_method=S256"
FINAL_URL=$(curl -s -L -c "$JAR" -b "$JAR" -o /dev/null -w "%{url_effective}" "$AUTH_URL")
rm -f "$JAR"
case "$FINAL_URL" in
  *"$UP"*) check "authorize พาไปหน้า login ของ ID จริง" "yes" "yes" ;;
  *) check "authorize พาไปหน้า login ของ ID จริง" "yes" "no ($FINAL_URL)" ;;
esac

summary
