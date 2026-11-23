# Security Audit — ตรวจ Source Code ตามคำถามของ Reviewer (4 จุด)

> ตอบคำถามจาก code review: "Design Intent เข้าใจชัดแล้ว — Implementation ทำได้ตรงตาม Design หรือไม่"
> วิธีตอบ: **อ่านจากโค้ดจริง + พิสูจน์ด้วย test ที่รันได้** (ทุกข้ออ้างอิง file:line) — audit เมื่อ 2026-11-23
> ผลรวม: **ทุกคำถามมี implementation จริง** · พบช่องโหว่/ช่องว่าง 3 จุด → แก้ใน audit นี้ 2 จุด + บันทึกยอมรับ 1 จุด · test รวมเพิ่ม 3 checks (198 → 201)

---

## Q1 — Ticket Broker: Ticket เก็บที่ไหน · Atomic Revocation · Restart แล้วเป็นอย่างไร

**ไฟล์:** `services/central-id/internal/sso/sso.go`

| คำถาม | คำตอบจากโค้ด | หลักฐาน |
| ------ | ------------- | ------- |
| เก็บที่ไหน | **in-memory map** ใน process ของ ID Portal (`Store.byID/byKey/byUser` + `sync.Mutex`) | sso.go:31-36 |
| Atomic Revocation | ✅ **atomic ภายใน single process** — `Revoke`/`RevokeAll` ครองด้วย mutex เดียวกับ read; ตั๋วเดียว: `Revoke(owner,id)` · global: `RevokeAll()` (logout กลาง) | sso.go:113-131 |
| Validate consume ไหม | **ไม่ consume** (reusable ตลอด TTL 30 นาที) — `Get` อ่านอย่างเดียว + stamp `LastUsed` | sso.go:135-148 |
| Restart ID Portal | **ตั๋วหายทั้งหมด** → `/sso/check` ตอบ `alive:false` → ทุก session ที่ผูกตั๋ว **fail-closed** (บังคับ login ใหม่ — ปลอดภัย แต่ kick ผู้ใช้) | พฤติกรรม map ว่าง; ยืนยันผ่าน stt-test หลัง restart stack |
| Refresh token ในตั๋ว | เก็บ **plaintext refresh token** ใน memory (เพื่อ renew) — POC ยอมรับ; **production ต้องเปลี่ยน** | ดูช่องว่างด้านล่าง |

**ช่องว่างที่ยอมรับ (production gaps):** restart = kick ทุกคน (availability) · in-memory ไม่ทน HA · refresh token อยู่ใน memory ไม่เข้ารหัส → **production ต้องใช้ Redis (TLS + persistence + replication) เก็บ hash ของ token** ตามที่ ADR-005 ระบุ

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
| 4 | ยอมรับ + บันทึกช่องว่าง production: ticket store in-memory (restart = kick ทุกคน), refresh token plaintext in memory, fail-open บน broker timeout, Kong cache 15s vs MCP 0s (SLA ต่างกัน) | ADR-005 + หัวข้อข้างบน |

## การทดสอบหลังแก้ (สรุป)

- `stt-test.sh` — **34/34 PASS** (รวม sub-preservation + revoke-aware checks)
- `openapi-test.sh` — **31/31 PASS** (รวม central-apikey + introspect ครบ)
- `sso-test.sh` — **10/10** · CIS ProjectsPage หลังเพิ่ม check ยัง render และ redirect ถูกต้อง
