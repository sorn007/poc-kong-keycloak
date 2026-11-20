# แผน Migration จาก POC สู่ Production

เอกสารนี้สรุปทางเลือกการเชื่อม Central ID (ระบบเดิม) กับ Keycloak และลำดับงาน migration ของ Buyer (NestJS) / CIS (Go Fiber) — อ้างอิง rootcase.md และผล POC

## 1. ทางเลือกเชื่อม Central ID กับ Keycloak

### Option A — Keycloak เป็น Identity Provider หลัก

- ย้ายการ Authentication ไปที่ Keycloak ทั้งหมด; Central ID เหลือหน้าที่ User Profile / Business Identity
- User migration: import user เข้า Keycloak หรือใช้ User Federation (LDAP/DB ของ Central)
- **ดี**: สถาปัตยกรรมสะอาดที่สุด, ได้ feature ของ Keycloak ครบ (session, policy, required actions)
- **เสีย**: Migration impact สูงสุด — ย้าย credential/password, reset session ทุกระบบ, แก้ UX login เดิม

### Option B — Keycloak เป็น Identity Broker

- Keycloak เชื่อม Central ID ผ่าน OIDC (หรือ SAML) — ผู้ใช้ยัง login ที่ Central ID เดิม
- Keycloak แลก token กับ Central ID แล้วออก token มาตรฐานให้ Buyer/CIS/Open API
- **ดี**: รักษา login experience เดิม, เปิดตัวได้เร็ว, ค่อยย้าย user ทีหลัง
- **เสีย**: Central ID ต้องรองรับ OIDC มาตรฐาน (authorization endpoint, token endpoint, JWKS), ต้องออกแบบ sync logout/disable ระหว่างสองระบบ (back-channel), มี 2 hop ตอน login

### ข้อเสนอ

เริ่มประเมิน **Option B ก่อน** หาก Central ID รองรับ OIDC มาตรฐาน — เงื่อนไขตรวจสอบ:
1. Central ID มี `/authorize` + `/token` + JWKS ที่ใช้งานได้
2. รองรับ `response_type=code` + PKCE
3. มีวิธีรับทราบ logout/disable จาก Central ID (event หรือ polling) เพื่อส่งต่อให้ Keycloak ยุติ session

ถ้าข้อใดข้อหาไม่ได้ → โอนไป Option A พร้อมแผน user migration แบบ gradual (lazy import ตอน user login ครั้งแรก)

## 2. ลำดับ Migration Middleware (Dual Validation → ปิด Legacy)

| Phase | งาน | ระบบ | เกณฑ์ผ่าน |
| ----- | --- | ---- | --------- |
| 1 | Deploy Central Validator แต่ยังไม่เปิดใช้ (shadow) | Buyer/CIS | log เทียบผลตรวจสอง validator ไม่ error production |
| 2 | เปิด Dual Validation (central + legacy) | Buyer/CIS | `dual-validation-test.sh` ผ่านทั้งสองระบบ |
| 3 | Buyer Login เริ่มใช้ Central Token (OIDC + PKCE) | Buyer | login ผ่าน Keycloak, legacy token เดิมยังใช้ได้ |
| 4 | CIS Login เริ่มใช้ Central Token | CIS | เหมือนข้อ 3 |
| 5 | Open API รับเฉพาะ Central Token (Kong + Guard) | Kong/Buyer/CIS | partner flows ผ่านครบ |
| 6 | ปิด Legacy Token Validator | Buyer/CIS | metrics แสดงไม่มี consumer ใช้ legacy token แล้ว |

> เก็บ metric แยกตาม iss/client_id/endpoint ตลอด Phase 2-5 เพื่อหา consumer ที่ยังใช้ legacy token ก่อนปิด (Phase 6)

## 3. สิ่งที่ต้องทำเพิ่มก่อนขึ้น Production (จาก POC)

| หัวข้อ | ใน POC | ต้องทำใน Production |
| ------ | ------ | -------------------- |
| Signing key | static key สร้างครั้งเดียว (setup-keys.sh) | key rotation runbook + kid ต่อ environment |
| Direct Access Grants (password grant) | เปิดเพื่อ automation | **ปิด** — ใช้ Authorization Code + PKCE เท่านั้น |
| Token ใน cookie demo | cookie HttpOnly ฝั่ง app | ใช้ BFF pattern หรือ backend session พร้อม CSRF protection |
| State/PKCE store | in-memory map | session store แบบ durable (Redis/DB) |
| DEV endpoints (/dev/mint-legacy-token) | เปิด | ไม่ deploy / ลบทิ้งก่อน release |
| HTTPS | http บน localhost (sslRequired=external) | sslRequired=all + TLS ทุก endpoint |
| Revocation | short-lived JWT 5 นาที + introspect/revoke | + revocation event (logout/disable) กระจายถึงทุกระบบตาม Security SLA |
| Kong | DB-less 1 instance | HA, admin API ล็อก network, log/monitoring |
| Monitoring | log พื้นฐาน | metrics: token validation failures แยก iss/aud, revocation delay, JWKS refresh errors |
| Tenant binding | hardcoded company_001 | ตารางสิทธิ์ Partner→Tenant ที่ตรวจจากข้อมูลจริง |

## 4. Backlog หลัง POC (เรียงตามลำดับแนะนำ)

1. ตัดสินใจ Option A/B จากผลตรวจ Central ID §1
2. สร้าง realm แยก environment (dev/uat/prod) + key rotation
3. นำ CentralAuthGuard / auth middleware ไปแพ็กเป็น shared library (`@central/auth-middleware` ฝั่ง NestJS + go module ฝั่ง CIS) ตามที่ rootcase แนะนำ — คง business authorization ไว้ที่แต่ละระบบ
4. Wire revocation event: logout/disable จาก Keycloak → queue/webhook → Buyer/CIS ยุติ session ตาม SLA
5. ออกแบบ Partner Portal: generate/rotate/revoke client credentials + ผูก scope/tenant
6. ประเมิน Kong Enterprise OIDC plugin หากต้องการ enforcement ระดับ gateway ที่ครบ OIDC (aud/scope/introspection)
