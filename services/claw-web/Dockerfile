# Claw Web — แอปในเบราว์เซอร์ (SPA) ที่ login ด้วย @central/login-js (ADR-009)
# ไม่มี backend: nginx เสิร์ฟไฟล์ static และสร้าง config.js จาก env ตอน container เริ่ม
# Login SDK (packages/login-js) มาผ่าน build context เพิ่ม (compose: additional_contexts.login-js)

# ── stage 1: build @central/login-js ──
FROM node:22-alpine AS sdk
COPY --from=login-js . /sdk/
WORKDIR /sdk
RUN npm ci && npm run build

# ── stage 2: nginx แบบ non-root (listen 8080 ภายใน container) ──
FROM nginxinc/nginx-unprivileged:alpine
COPY nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
# template ถูก envsubst ตอน container เริ่ม — ใส่ origin ของ Keycloak/Kong ลงใน CSP
COPY nginx/default.conf.template /etc/nginx/templates/default.conf.template
# สร้าง js/config.js จาก env (25-config-js.sh รันหลัง 20-envsubst-on-templates.sh)
COPY --chmod=755 docker-entrypoint.d/25-config-js.sh /docker-entrypoint.d/25-config-js.sh
# เป็นเจ้าของโดย user nginx (uid 101) เพื่อให้ entrypoint เขียน config.js ได้
COPY --chown=101:101 html/ /usr/share/nginx/html/
COPY --from=sdk --chown=101:101 /sdk/dist/ /usr/share/nginx/html/vendor/login-js/
EXPOSE 8080
