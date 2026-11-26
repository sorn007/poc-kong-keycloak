# Security Audit — ตรวจ Source Code ตามคำถามของ Reviewer (4 จุด)

> ตอบคำถามจาก code review: "Design Intent เข้าใจชัดแล้ว — Implementation ทำได้ตรงตาม Design หรือไม่"
> วิธีตอบ: **อ่านจากโค้ดจริง + พิสูจน์ด้วย test ที่รันได้** (ทุกข้ออ้างอิง file:line) — audit เมื่อ 2026-11-23 · **อัปเดต 2026-11-25: gap Q1 (restart = kick ทุกคน) ปิดแล้วด้วย store backend Redis — พิสูจน์ restart จริงด้านล่าง**
> ผลรวม: **ทุกคำถามมี implementation จริง** · พบช่องโหว่/ช่องว่าง 3 จุด → แก้ใน audit นี้ 2 จุด + บันทึกยอมรับ 1 จุด (ยอมรับนั้นปิดเพิ่มใน 2026-11-25)

---

## Q1 — Ticket Broker: Ticket เก็บที่ไหน · Atomic Revocation · Restart แล้วเป็นอย่างไร

**ไฟล์:** `services/central-id/internal/sso/sso.go` (memory) · `internal/sso/redis.go` (Redis)

| คำถาม | คำตอบจากโค้ด | หลักฐาน |
| ------ | ------------- | ------- |
| เก็บที่ไหน | **2 backends เลือกด้วย env `STORE_BACKEND`**: memory = in-process map (`Store.byID/byKey/byUser` + `sync.Mutex`, default ของ POC) · redis = `RedisTicketStore` (SETEX 30 นาที + AOF, compose service `redis:7-alpine`) — เลือกผ่าน factory `NewTicketStoreFor` | sso.go:31-36 · store.go:8-15 · factory.go · redis.go:43-58 |
| Atomic Revocation | ✅ memory: **atomic ภายใน single process** (mutex เดียวกับ read) · redis: SET/DEL เป็น atomic per-key — ตั๋วเดียว: `Revoke` (ตั้ง flag + KeepTTL) · global: `RevokeAll()` (logout กลาง) | sso.go:113-131 · redis.go:95-124 |
| Validate consume ไหม | **ไม่ consume** (reusable ตลอด TTL 30 นาที) — `Get`/`Check` อ่านอย่างเดียว | sso.go:135-148 |
| Restart ID Portal | **ขึ้นกับ backend**: memory = ตั๋วหายหมด → `/sso/check` `alive:false` → ทุก session fail-closed (kick ผู้ใช้) · **redis = ตั๋วรอด** — พิสูจน์จริง 2026-11-25: ออกตั๋ว → `docker compose restart central-id` → alive:true · restart Redis เอง (AOF) → alive:true | ทดสอบ E2E ใน audit นี้; keys `central:sso:ticket:*` ใน redis-cli |
| Refresh token ในตั๋ว | เก็บ plaintext (memory และ redis entry JSON) เพื่อ renew — **production ต้องเก็บ hash** | ดูช่องว่างด้านล่าง |

**ช่องว่างที่แก้แล้ว (2026-11-25):** restart = kick ทุกคน → **ปิดด้วย `STORE_BACKEND=redis`** (ทน restart + หลาย replica ใช้ state ร่วมกัน) — sweep 162/162 checks ผ่านบน Redis · **คงเหลือ production gaps:** Redis ตัวเดี่ยวยังเป็น SPoF (production: Sentinel/Cluster + TLS + ACL) · refresh token plaintext → เก็บ hash + TTL ตาม ADR-005

---

## Q2 — Application Session Guard: ตรวจตั๋วทุก request จริงไหม · Broker timeout ทำอย่างไร

**ผล audit (ครอบคลุมจริง แต่ไม่ 100% ทุก route):**

| แอป | ตรวจที่ไหน | ไม่ครอบ | fail ถ้า broker ล่ม |
| --- | ---------- | ------- | ------------------ |
| Buyer :3010 | `home.controller.ts` (หน้า `/`) + `/auth/login` redeem path | `/orders`, `/orders/page` — ตรวจ **JWT exp อย่างเดียว** | **fail-open** (`catch → return true` — home.controller.ts:20-24) |
| CIS :3020 | `handlers.go` Home (`/`) | `ProjectsPage` — **ไม่มี check** (แก้แล้วใน audit นี้) | fail-open |
| Fintech :3050 | `handlers.go` Home (`/home`) ✅ | `/orders`(n/a) | fail-open |
| MCP :3010/mcp | **ทุก request** (validate ก่อน dispatch) | — | 401 ทันที (fail-closed) |
| Kong central-apikey route | ทุก request ผ่าน cache 15s | — | 403/401 (แยก error) |

**สรุปตรงไปตรงมา:** ticket liveness ถูกตรวจ **เฉพาะหน้า page-render** ไม่ใช่ทุก API request — API routes พึ่ง JWT `exp` (ข้อจำกัด JWT ตาม rootcase §6: revoke แล้ว token เดิม valid ถึง exp ≤ 5 นาที) — ผล audit: **ยอมรับโดยตั้งใจ** และบันทึก guidance: production ต้องใช้ **OIDC Back-Channel Logout** (KC `backchannel.logout.url` ต่อ client) เพื่อเร่ง revocation โดยไม่เพิ่ม per-request call

**Broker timeout:** ทั้งสามแอป **fail-open** (ตรวจไม่ได้ → ปล่อยผ่าน, JWT exp ยังกำกับ) — ตัดสินใจเพื่อ availability; ทางเลือก fail-closed มี trade-off UX และต้องยอมรับ downtime ของ ID Portal กระทบทุกแอป

---

## Q3 — STT Redeem: Atomic Consume · Destination Binding · Replay Protection

**ไฟล์:** `services/central-id/internal/stt/stt.go` (+ unit test `stt_test.go`)

| คำถาม | คำตอบจากโค้ด | หลักฐาน |
| ------ | ------------- | ------- |
| Atomic Consume | ✅ `Redeem` ครอง `sync.Mutex` ตลอด: ค้น → ตรวจ TTL/dest → **delete ก่อนคืนค่า** — concurrent redeem ซ้อนเข้ามาได้ key เดียว | stt.go:74-86 (`defer s.mu.Unlock`) |
| Destination Binding | ✅ `Create(..., dest)` ผูก code กับ `dest` ตอนออก · `Redeem(code, dest)` ตรวจ `e.dest != dest → ErrDestMismatch` — **ไม่ลบทิ้งเมื่อ dest ผิด** (code ยังใช้กับปลายทางจริงได้) | stt.go:88-93 |
| Replay Protection | ✅ redeem สำเร็จ = **ลบทันที** → ใช้ซ้ำได้ `ErrNotFound`; unit test ครอบ: `stt_test.go` — TestCreateRedeemDestBinding + TestDestMismatchKeepsEntry (go test ผ่าน) | stt_test.go |
| TTL | 60 วินาที — หมดอายุ → `ErrExpired` (ไม่ leak ว่าเคยมีจริง) | stt.go:23, 76-80 |

> เดิม error ตอน dest mismatch ตอบเป็น wrapped error (`%w (entry.dest=… redeem.dest=…)`) — **เปลี่ยนแล้ว**: ปัจจุบันตอบ `invalid_or_used_or_expired_code` ข้อความเดียวทุกกรณี (404/403) เพื่อไม่ leak สถานะ — ดู finding เดิมและ openapi/stt tests

---

## Q4 — Token Exchange: ตรวจ aud / scope / azp / sub / Client Permission อย่างไร

| ขั้น | ใครตรวจ | กลไก | หลักฐาน |
| ---- | ------- | ----- | ------- |
| ก่อน Exchange — requester สิทธิ์พอ | **Keycloak Standard Token Exchange V2** | requester ต้องเป็น **confidential client** (`cis-web`/`central-id-portal` ถูกเลื่อนเป็น confidential โดย `setup-stt.sh`) + เปิด `standard.token.exchange.enabled` + requester ต้องอยู่ใน **aud ของ subject token** (scope `stt-bridge` เติม `cis-web`/`central-id-portal` ลง aud) | Context7 Keycloak docs + ทดสอบ: subject token ไร้ cis-web ใน aud → KC ปฏิเสธ |
| ก่อน Exchange — ฝั่งเรา (defense in depth) | CIS `/auth/stt` ตรวจ **ก่อนยิง exchange**: dest binding (จาก redeem) + aud ปลายทางจาก validate | CIS `oidc.go` — redeemSTT + ตรวจ `contains(aud, cfg.ClientID) || issuedFor == cfg.ClientID` | มี early-check ให้ error อ่านง่าย ก่อนเสีย round trip |
| ตอน Exchange — sub/azp/scope | **Keycloak เป็นผู้ออก**: token ใหม่ = subject เดิม (sub คงเดิม), aud/scope/claims จาก **scopes+mappers ของ requester** (cis-web → `aud=cis-api`, principal_type, tenant) — **escalate เกินไม่ได้** เพราะ KC ออกตาม client config ของ requester เท่านั้น | ทดสอบ: `stt-test.sh` — sub คงเดิมยืนยันด้วย check "sub คงเดิมหลัง Token Exchange" | ✅ |
| หลัง Exchange — ปลายทางเชื่อไหม | CIS ตรวจ token ที่ได้ **เต็มรูปแบบด้วย JWKS** (signature/iss/aud=cis-api/exp) เหมือน token ปกติ — ไม่ต้องเชื่อว่า "มาจาก exchange" | `auth.VerifyCentral` ใน CIS middleware | ✅ |

**ข้อจำกัดที่ยอมรับ:** (1) ไม่มีการตรวจ `azp` แยกต่างหากหลัง exchange — KC เป็นผู้กำหนด azp ของ token ใหม่ = requester (cis-web) ตาม spec (2) ไม่มี consent/delegation approval flow ระหว่าง user — POC ยอมรับ, production อาจต้องมี (3) `requested_subject` (impersonation) ถูกปิดโดย KC Standard V2 ✅ (ตรวจจากซอร์ส `StandardTokenExchangeProvider.supports()`)

---

## สรุปสิ่งที่แก้/เพิ่มจาก audit นี้

| # | สิ่งที่แก้ | ไฟล์ |
| - | --------- | ---- |
| 1 | CIS `ProjectsPage` — เพิ่ม ticket liveness check (ตั๋วตาย → เคลียร์ session + redirect login) ให้สม่ำเสมอกับหน้า Home | `cis-api/internal/handlers/handlers.go` |
| 2 | Buyer — ดึง `isTicketAlive`/`clearSsoCookies` ออกเป็น `auth/sso-guard.ts` (shared) + เพิ่ม check ใน `/orders/page` | `buyer-api/src/auth/sso-guard.ts` (ใหม่), `home.controller.ts`, `orders.controller.ts` |
| 3 | `stt-test.sh` — เพิ่ม **sub-preservation check** (sub ของ token หลัง exchange == sub ของ subject token) ปิดคำถาม Q4 | `scripts/stt-test.sh` |
| 4 | **dual-store revoke** — `/apikeys/revoke` ตรวจทั้ง apiKeyStore และ ssoStore (เดิม revoke SSO ticket ได้ 404) | `central-id/internal/handlers/apikeys.go` |
| 5 | **Store backend Redis (2026-11-25)** — SSO ticket/API key/STT code เป็น interface 2 backends (`STORE_BACKEND=redis|memory`) + service redis:7-alpine (AOF) — ปิด gap "restart = kick ทุกคน" พร้อมพิสูจน์ restart จริง | `central-id/internal/{sso,apikeys,stt}/{store,redis,factory}.go`, `main.go`, `docker-compose.yml`, `.env.example` |
| 6 | **แก้ cookie ชื่อเก่าค้าง** — `clearSsoCookies` (buyer) และ `clearLocal` (CIS ProjectsPage) เคลียร์ `allkons_sso` (ชื่อเดิม) → แก้เป็น `central_sso` (ชื่อจริงปัจจุบัน) | `buyer-api/src/auth/sso-guard.ts`, `cis-api/internal/handlers/handlers.go` |
| 7 | ยอมรับ + บันทึกช่องว่าง production ที่เหลือ: refresh token plaintext, fail-open บน broker timeout, Kong cache 15s vs MCP 0s (SLA ต่างกัน), Redis ตัวเดี่ยว (ต้อง HA/TLS ก่อน prod) | ADR-005 + SPoF-ANALYSIS §4.2 + หัวข้อข้างบน |
| 8 | **Authentication policy รวมเป็น SDK กลาง (2026-11-25)** — guard/middleware ที่เคยกระจายในแต่ละ service ย้ายมาอยู่ที่ `@central/auth-nestjs` + `central/auth-go` ที่เดียว พร้อม unit test ครอบ 401/403 — ตอนรวมพบ policy ที่เพี้ยนจากกัน 6 จุด (leeway 5ns, token ไร้ `exp` ผ่านได้ที่ buyer, ฯลฯ) และแก้เป็นชุดเดียวแล้ว · นโยบาย "ตรวจ ticket ทุก request หรือไม่" (Q2) ยังเหมือนเดิม — เปลี่ยนได้ที่จุดเดียวคือ SDK | ADR-008 + finding 61 |

## การทดสอบหลังแก้ (สรุป — 2026-11-25 บน store backend Redis)

- sweep ทุก suite: **162/162 PASS** — `sso-test` 10 · `stt-test` **34** (รวม sub-preservation) · `openapi-test` **31** (รวม central-apikey) · `mcp-test` **12** · smoke 14+12 · revocation 10 · dual-validation 6 · mobile 12 · CIBA 16 · fintech 5
- **พิสูจน์ restart** (Q1): ออกตั๋ว → restart central-id → `/sso/check` alive:true → restart Redis (AOF) → alive:true
- CIS ProjectsPage หลังเพิ่ม check ยัง render และ redirect ถูกต้อง (sso-test + ทดสอบ revoke propagate)
