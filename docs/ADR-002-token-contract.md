# ADR-002: Token Contract กลางของทุกระบบ

## บริบท

แต่ละระบบเดิมออก token รูปแบบใครรูปแบบมัน (local JWT + shared secret) ทำให้ตรวจ token ข้ามระบบไม่ได้ และ middleware ต้องรู้ secret ของทุกระบบ ต้องกำหนด contract กลางก่อนเขียน Guard/Middleware ของ Buyer/CIS

## การตัดสินใจ

Access token เป็น JWT แบบ **RS256** ออกโดย Keycloak realm `central` โดยมี claim หลัก:

| Claim | ค่า | เหตุผล |
| ----- | --- | ------ |
| `iss` | `http://localhost:8080/realms/central` (POC) | คงที่ทุก client — ใช้เป็น allowlist ตอนเลือก validator |
| `aud` | `buyer-api` / `cis-api` / `central-id` (portal) | กัน cross-audience token confusion — ตรวจที่ Guard เสมอ |
| `sub` | Central User ID / client id | principal ของ token |
| `scope` | space-separated เช่น `orders.read` | API authorization |
| `client_id` | buyer-web / cis-web / partner-001 / central-id-portal | ระบุ client ต้นทาง |
| `principal_type` | `user` / `service` | ห้ามใช้การมี/ไม่มี `sub` ตัดสิน — ต้องมี claim ชัดเจน |
| `tenant_id` | `company_001` (POC hardcoded) | tenant binding — production มาจากข้อมูลจริง |
| `jti` | token id | audit / revocation tracking |

Key การ implement สำคัญ (ที่มาของ gotcha — พิสูจน์แล้วบน KC 26.3 วันที่ 2026-11-13 ดู docs/test-results.md §4):
- **Keycloak ไม่ใส่ `aud` อัตโนมัติตาม client** — ต้องสร้าง Audience Mapper (oidc-audience-mapper) ผ่าน realm config
- **Mapper config key ต้องเป็นเอกพจน์บน KC 26.x: `access.token.claim` / `id.token.claim`** — รูปแบบพหูพจน์ (`access.token.claims`) ที่พบในเอกสาร/ตัวอย่างเก่าถูกข้าม**เงียบ ๆ** (`OIDCAttributeMapperHelper.includeInAccessToken()` อ่านเฉพาะ key เอกพจน์ ไม่มี legacy fallback)
- **Realm ที่ import ด้วย `clientScopes` ชัดเจน ต้องใส่ stock scopes (`basic` ฯลฯ) เอง** — บน KC 26 `sub` ของ access token มาจาก sub mapper ใน scope `basic` (ไม่ใช่จาก initToken ยกเว้น TRANSIENT session เช่น client_credentials) — ถ้าไม่มี basic scope token จะไม่มี `sub` ทั้ง realm — template ของ POC ผสมนิยาม stock scopes จริงไว้แล้ว
- Mappers ของ POC อยู่ใน **identity scope ต่อ client หนึ่งอัน** (`identity-buyer-web`, `identity-cis-web`, `identity-partner-001`) เพราะ `principal_type` ต่างกันต่อ client จึงแชร์ scope กันไม่ได้
- `principal_type` / `tenant_id` ใช้ Hardcoded Claim Mapper (POC) — production ควรมาจากข้อมูล user/client จริง
- เวลา token: access 5 นาที, SSO session idle 30 นาที, refresh rotation (`revokeRefreshToken=true`, `refreshTokenMaxReuse=0`)
- ตรวจทุกครั้ง: signature (JWKS, RS256 เท่านั้น), iss, aud, exp (+ leeway 5s)

## ข้อยกเว้นของ POC

- `directAccessGrantsEnabled` (password grant) เปิดที่ buyer-web/cis-web **เพื่อ automation script เท่านั้น** — production ปิด
- token ฝั่ง browser demo เก็บใน cookie HttpOnly — production ควรใช้ BFF/session จริง

## ผลกระทบ

- ทุกระบบเขียน validator แยกตามภาษา แต่ semantics เดียวกัน (`verifyCentralToken` / `auth.VerifyCentral`)
- ห้ามเพิ่ม claim ที่ตรวจแล้วเชื่อเด็ดขาดโดยไม่แก่ ADR นี้ก่อน
