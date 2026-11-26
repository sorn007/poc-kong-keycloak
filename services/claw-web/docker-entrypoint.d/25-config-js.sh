#!/bin/sh
# สร้าง js/config.js ของ claw-web จาก env (รันโดย docker-entrypoint ของ image nginx ก่อนเริ่ม nginx)
# ค่าจาก env ทั้งหมด — ไม่มีค่าตายตัวของ environment อยู่ใน image · เปลี่ยน env แล้ว recreate container ได้ไม่ต้อง build ใหม่
set -e

: "${KEYCLOAK_ISSUER:?KEYCLOAK_ISSUER is required}"
: "${KONG_PROXY_URL:?KONG_PROXY_URL is required}"
: "${APP_BASE_URL:?APP_BASE_URL is required}"
: "${CLAW_CLIENT_ID:?CLAW_CLIENT_ID is required}"

envsubst '$KEYCLOAK_ISSUER $KONG_PROXY_URL $APP_BASE_URL $CLAW_CLIENT_ID' \
  < /usr/share/nginx/html/js/config.js.template \
  > /usr/share/nginx/html/js/config.js

echo "$0: wrote js/config.js (issuer=$KEYCLOAK_ISSUER client=$CLAW_CLIENT_ID kong=$KONG_PROXY_URL)"
