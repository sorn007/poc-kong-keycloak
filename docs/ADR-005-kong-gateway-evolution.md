# ADR-005: วิวัฒนาการของ Kong Gateway ใน POC (Introspection / Portal Routing / Plugins ที่ทำและไม่ทำ)

วันที่: 2026-11-20 · สถานะ: ยอมรับ (implement แล้ว — `openapi-test.sh` 22/22)

## บริบท

ADR-003 กำหนดบทบาท Kong = API Gateway (routing/rate-limit/key-auth) ไม่ใช่ตัว SSO ภายหลัง POC เพิ่มความสามารถแบบ custom plugin (ADR-004 ส่วนท้าย: oidc-central) คำถามต่อมาคือ "flow Kong/Keycloak ยังขาดอะไร" — ได้ระบุช่องว่าง 3 หลัก + ย่อยอีกหลายข้อ (ดู finding 53) และตัดสินใจแก้/ยอมรับดังนี้

## การตัดสินใจ

### 1. Introspection ผ่าน Kong (custom plugin `oidc-introspect`) — ทำ
ปิดจุดอ่อนใหญ่สุดของ JWKS-only gateway: **token ที่ถูก revoke / user ถูก disable ยัง valid ถึง exp** โดยตรวจผ่าน Keycloak introspection endpoint (RFC 7662) ด้วย client credential ของ partner-001 + cache ผล 10 วินาที (Security Rule 8: ไม่ยิง Keycloak ทุก request) — ทดสอบแล้ว: revoke → request ถัดไป (หลัง cache หมด) ได้ 401 ทันที ข้อแลก: SLA การรู้ทัน = cache TTL (POC 10s; production ปรับตามนโยบาย + fail-closed ได้)

### 2. Portal ผ่าน Kong (single entry point demo) — ทำแบบจำกัด
เพิ่ม routes `/portal/id|buyer|cis` → ทุก portal เปิดผ่าน Kong :8000 ได้ ข้อจำกัดที่ยอมรับ: ลิงก์ภายใน/redirect_uri ของแอปยัง hardcode เป็น localhost:3010 ฯลฯ → การ login flow จะหลุดออกจาก Kong หลัง redirect ครั้งแรก (production ต้อง front ด้วย hostname เดียว + ลงทะเบียน redirect_uri ตรงกัน)

### 3. Hardening plugins สำเร็จรูป — ทำ
`request-size-limiting` (1MB) + `cors` (preflight รองรับ partner ฝั่ง browser) บนทุกเส้น Open API + `prometheus` (global) เปิด status listener `:8100/metrics` — ได้ `kong_http_requests_total` แยกตาม service/route/status code

### 4. OIDC login/session ที่ gateway — ไม่ทำ (บันทึกไว้ชัด)
การเขียน session/OIDC-flow plugin เอง = สร้าง Enterprise openid-connect ของคนอื่นซ้ำ และซ้ำกับที่แอป + SSO Ticket ทำอยู่ ทางเลือกสู่ production: (ก) Kong Enterprise openid-connect plugin, (ข) BFF/session gateway แยก, (ค) คง pattern ปัจจุบัน (แอปทำ AC flow เอง + central SSO ticket สำหรับข้ามแอป)

### 5. JWT route rotation sensitivity — ยอมรับ + guidance
route `/openapi/buyer` (jwt plugin) ฝัง key ตอน `setup.sh` — realm rotate key แล้วต้องรัน setup.sh ใหม่ (หรือใช้ route `/openapi/oidc` ซึ่งดึง JWKS สด) — production: ทำ gitops pipeline regenerate kong.yml ตาม rotation

## ผลทดสอบ

`openapi-test.sh` 22/22: jwt/key-auth/rate-limit เดิม + introspect (active 200, revoke→401, signature 401) + portal 3 routes + request-size 413 + cors preflight + prometheus metrics

## ช่องว่างที่เหลือสู่ production (สรุป)

- backchannel logout จาก Keycloak ไปยัง apps (แทน per-request /sso/check ของ portal — ดู ADR-004)
- Kong HA (multi-node), WAF, mTLS upstream
- per-consumer quota/APM ระดับ production

## ส่วนขยาย: Central API Keys — ออก key ผูก scope จาก ID Portal ใช้กับ Open API / MCP (2026-11-20)

ID Portal เพิ่มหน้า `/apikeys`: ผู้ใช้สร้าง API key (format `central_<random>` — แสดงเต็มครั้งเดียว) พร้อมเลือก scope จากชุดที่ระบบกำหนด (orders.*, projects.*) — key ผูก owner + scopes และ revoke ได้ทันที

การใช้งาน (สองทาง — contract เดียวกัน):
1. **Open API ผ่าน Kong**: route `/openapi/apikey/*` ใช้ custom plugin `central-apikey` — อ่าน header `apikey` → ถาม `POST /apikeys/validate` (cache 15s) → บังคับ scope ตาม method (GET→read_scope / POST→write_scope) → ส่งต่อด้วย gateway-trust header (X-Gateway-Auth shared secret + X-Central-Scopes/Owner)
2. **MCP server**: ตรวจ key ด้วย `POST /apikeys/validate` → {active, owner, scopes} — บังคับ scope ต่อ tool ด้วยข้อมูลเดียวกัน — contract เดียวกับ Kong plugin

ข้อดีเชิง operation: เพิ่ม/ยกเลิก key ที่ ID Portal **ทันทีโดยไม่แตะ Kong config** (ต่างจาก key-auth ที่ต้อง regen kong.yml) · production: เก็บ hash + DB, quota per key, audit log

## ผลกระทบ