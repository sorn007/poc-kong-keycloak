# SPoF Analysis — จุดที่เป็นคอขวด/Single Point of Failure ของ POC

> ตรวจจากโค้ดจริงทุก service (file:line อ้างอิงได้) · วัตถุประสงค์: แยกให้ชัดว่า **อะไรอยู่ใน memory ล้วน** · **อะไรล่มแล้วกระทบอะไร** · **ต้องย้ายไปไหน (Redis/tools) ก่อนขึ้น production**
> วันที่ตรวจ: 2026-11-25 · อ่านคู่กับ [ARCHITECTURE.md](ARCHITECTURE.md) §10 และ [SECURITY-AUDIT.md](SECURITY-AUDIT.md)

---

## 1. สรุปผู้บริหาร — SPOF อันดับตามความเสียหาย

| อันดับ | SPOF | ล่มแล้วเกิดอะไร | ทางแก้ (tool) |
| ----- | ---- | -------------- | ------------- |
| 🔴 1 | **Keycloak** (single instance) | ทุก flow ตายหมด — login, token, exchange, introspection, CIBA | Keycloak HA: รันหลาย node + **Postgres HA** (KC เก็บ state ใน DB อยู่แล้ว → scale แนวนอนได้) |
| 🔴 2 | **Postgres** (single instance) | KC ล่มทั้งขบวน (realm/session อยู่ที่นี่) | **Patroni / Cloud SQL / RDS Multi-AZ** |
| 🔴 3 | **ID Portal :3000** — 4 in-memory stores (SSO tickets · API keys · STT codes · PKCE states) | tickets/keys/code หายหมด → new-tab SSO พัง, API key 401 ทั้งหมด, revoke ทำไม่ได้ (แต่ JWT ยัง valid ถึง exp ≤5 นาที) | **Redis** (ย้าย 4 store) + รัน ID Portal หลาย replica |
| 🟠 4 | **Kong** (single instance) | เส้น Open API + portal routing ตาย (แต่ยิง :3010/:3020 ตรงได้) | Kong หลาย node + LB (DB-less ทำง่าย — config เดียวกันทุก node) |
| 🟠 5 | **Buyer :3010** — PKCE states Map | login ที่ค้างอยู่พัง (retry ได้) | sticky session หรือย้ายลง Redis |
| 🟡 6 | Fintech/Headless/ID-Device session stores | session ของ demo apps หาย (retry ได้) | Redis (pattern เดียวกัน) |
| 🟡 7 | Kong custom-plugin caches (per-worker) | JWKS/validate cache หายตอน reload → refetch (ไม่ใช่ SPOF แต่ latency พุ่งชั่วขณะ) | ngx.shared.DICT หรือ Redis |

> หลักการเดิมของ POC (ADR/CLAUDE.md): "ห้ามสร้าง middleware กลางที่ทุก request ต้องวิ่งผ่าน" — **ID Portal ในบทบาท ticket/key broker คือข้อยกเว้นที่ตั้งใจ** (หัวใจของ Central Identity) — จึงต้องทำ HA ให้เขา ไม่ใช่ตัดออก

---

## 2. ทะเบียน In-Memory State ทั้งหมด (ตรวจจากโค้ด)

### ID Portal :3000 — ศูนย์กลาง (🔴 สำคัญสุด)

| Store | ไฟล์ | เก็บอะไร | ใครใช้ | ล่ม/restart แล้ว |
| ----- | ---- | ------- | ------ | --------------- |
| `sso.Store` (SSO Tickets) | `central-id/internal/sso/sso.go` | ตั๋ว `central_sso` + **refresh token** + owner | new-tab SSO ทุก portal · logout propagation (`/sso/check`) | **ticket หาย → session ทุก portal fail-closed** (ผู้ใช้โดน kick ไป login) |
| `apikeys.Store` (API Keys) | `central-id/internal/apikeys/apikeys.go` | Central API Keys + scopes + owner | Kong `central-apikey` · MCP `/mcp` | **key หาย → ทุก API-key call 401** (MCP/CI ที่ใช้ key ตาย) |
| `stt.Store` (STT codes) | `central-id/internal/stt/stt.go` | one-time code 60s + dest binding | STT cross-app | code หาย → transfer ล้ม (retry ได้ — ผู้ใช้ยิงใหม่) |
| `oidc.stateStore` (PKCE) | `central-id/internal/oidc/oidc.go` | state→verifier ระหว่าง login | login ค้างระหว่าง AC flow | login นั้นพัง (ผู้ใช้กดใหม่ — minor) |

### Buyer :3010

| Store | ไฟล์ | ผลกระทบ |
| ----- | ---- | ------- |
| PKCE states Map | `auth/oidc.controller.ts:16` | login ค้างพัง (ผู้ใช้กดใหม่ — minor) |

### CIS :3020 / Fintech :3050 / Headless :3030 / ID Device :3040

| Store | ผลกระทบ |
| ----- | ------- |
| CIS `oidc.stateStore` (PKCE) | เดียวกับ Buyer |
| Fintech `session.Store` | session ของ fintech หาย → ผู้ใช้ login ใหม่ (minor) |
| Headless CIBA store / ID-Device pending+sessions | คำขอ CIBA ที่ค้างอยู่หาย (minor — ผู้ใช้เริ่ม flow ใหม่) |

### Kong (custom plugin caches — per-worker)

| Cache | ผลกระทบตอนหมด |
| ----- | ------------- |
| oidc-central JWKS cache | refetch จาก KC ทันที (latency พุ่ง 1 request) |
| oidc-introspect / central-apikey cache | refetch — revoke SLA ไม่เปลี่ยน |

> สรุป: plugin caches **ไม่ใช่ SPOF** (refill ได้) — แต่ถ้า Kong รันหลาย worker/node แล้วต้องการ consistency ให้ย้ายลง `ngx.shared.DICT` (same-node) หรือ Redis (cross-node)

---

## 3. พฤติกรรมเมื่อ ID Portal ล่ม (ตรวจจากโค้ด — fail-open vs fail-closed)

| ผู้เรียก | เรียกอะไร | ถ้า ID Portal ตอบไม่ได้ | นโยบาย |
| ------- | -------- | ---------------------- | ------ |
| Buyer/CIS/Fintech (page render) | `POST /sso/check` (ticket liveness) | **fail-open** — ปล่อยผ่าน, JWT exp ยังกำกับ ≤5 นาที | `catch → return true` (buyer home.controller:20-24 · cis oidc.go:489 · fintech sso-guard.ts:24) |
| Buyer `/orders/page`, `/auth/login` | `POST /sso/redeem` | fail — redirect ไป login ปกติ | error path |
| Kong `central-apikey` plugin | `POST /apikeys/validate` | **503** (fail-closed — ไม่ปล่อย request ไป upstream) | handler.lua lookup_key error |
| MCP `/mcp` | `POST /apikeys/validate` | **401** (fail-closed) | validateKey catch |
| Headless CIBA poll | token endpoint ที่ KC | n/a (KC ตรง) | — |

> Trade-off ที่ตั้งใจ: **liveness = fail-open** (อย่าเอา ID Portal ล่มไปทำให้ทุก portal ใช้ไม่ได้ — JWT exp ยังเป็นกรอบ), **key validation = fail-closed** (ความปลอดภัยมาก่อน) — production ควรตั้งนโยบายให้ชัดและ monitor hit-rate

---

## 4. แผนย้าย State ออกจาก Memory — ใช้ Redis เป็นหลัก

### 4.1 ทำไม Redis คือคำตอบสำหรับ POC นี้

| คุณสมบัติ | ตรงกับ state ตัวไหน |
| --------- | ------------------ |
| TTL ต่อ key (`EXPIRE`) | SSO tickets (30 นาที) · STT codes (60 วิ) · PKCE states (5 นาที) |
| `GETDEL` / atomic consume | STT one-time code (redeem ครั้งเดียว) |
| Persistence (RDB/AOF) | ticket/key รอดการ restart (แก้ Q1 ข้อ restart) |
| Replication + Sentinel/Cluster | HA ของ broker — แก้ SPOF ข้อ 3 |
| High throughput (~100k ops/s บน single node) | validate/ check ต่อ request ไหวสบาย |
| Lua scripting / pub-sub | revoke propagation ไป node อื่นได้ |

### 4.2 ตารางย้ายงาน (migration map)

| # | State ปัจจุบัน (Go map) | ย้ายไป Redis เป็น | TTL | ข้อควรระวัง |
| - | ---------------------- | ---------------- | --- | ----------- |
| 1 | `sso.Store` (SSO tickets + refresh token) | `SETEX sso:ticket:<id>` | 30 นาที | **เก็บ hash ของ refresh token** ไม่ใช่ plaintext · revoke = `DEL` |
| 2 | `apikeys.Store` (API keys + scopes) | `HSET apikey:<id>` + `SET apikey:lookup:<key>` | ไม่มี TTL (revoke = DEL) | เก็บ **hash ของ key** ไม่ใช่ key ดิบ · ยกเลิกได้ทันที |
| 3 | `stt.Store` (one-time codes) | `SETEX stt:code:<id> 60` | 60 วิ | consume = `GETDEL` (atomic ในตัว) |
| 4 | PKCE states (buyer/cis/central-id) | `SETEX pkce:<state> 300` | 5 นาที | ต่อ service prefix กันชน |
| 5 | Fintech/ID-Device sessions | `SETEX sess:<id>` | ตาม exp | — |
| 6 | Kong plugin caches (JWKS/validate) | คง per-worker ไปก่อน → ภายหลัง Redis | 300s/15s | ไม่ด่วน — refill ได้เอง |

### 4.3 ลำดับการทำ (roadmap)

| Phase | งาน | ผลลัพธ์ | สถานะ |
| ----- | --- | ------ | ------ |
| P1 | เพิ่ม `redis:7-alpine` ใน compose + Go client (`go-redis/v9`) + abstraction `Store` interface (swap ได้ระหว่าง memory/redis ด้วย env `STORE_BACKEND=redis`) | ID Portal restart ไม่ kick ผู้ใช้ · HA พร้อม scale | ✅ **เสร็จ 2026-11-25** — 3 store (SSO ticket/API key/STT) + พิสูจน์ restart central-id และ restart Redis (AOF) ตั๋วยัง alive · sweep 162/162 |
| P2 | ย้าย store ที่เหลือของ ID Portal (PKCE/session ถ้ามีเพิ่ม) ตามตาราง §4.2 (interface เดิม — handler ไม่ต้องแก้) | stateless จริง | ⬜ |
| P3 | Kong หลาย node (DB-less, config เดียวกัน) หลัง LB | gateway HA | ⬜ |
| P4 | Keycloak หลาย node + Postgres HA (Patroni/RDS) | แก้ SPOF อันดับ 1-2 | ⬜ |
| P5 | Buyer/CIS หลาย replica (stateless แล้วหลังย้าย PKCE) | full HA | ⬜ |

> **หมายเหตุความปลอดภัย:** refresh token ใน Redis ต้อง **เก็บแบบเข้ารหัส** (AES-GCM ด้วย key จาก env) และใช้ ACL + `requirepass`/TLS ของ Redis เอง — ทุกค่า key/token ห้ามอยู่ใน plaintext ข้าม process

---

## 5. SPOF อื่นที่ยังไม่ต้องใช้ Redis (แต่ต้องอยู่ใน roadmap)

| SPOF | ทางแก้ | หมายเหตุ |
| ---- | ------ | ------- |
| Keycloak single node | รัน ≥2 node (รับ traffic ผ่าน LB) — KC 26 share state ผ่าน DB + Infinispan | ยังต้องมี Postgres HA ก่อน |
| Postgres single | Patroni (self-healing replication) หรือ managed DB | ก่อน scale Keycloak |
| Kong single | multi-node DB-less: ไฟล์ config เดียวกัน + LB (ง่ายสุดใน OSS) | ต่างจาก DB mode ที่ sync ผ่าน DB |
| ID Portal single | หลังย้าย state ลง Redis → scale ได้ (stateless จริง) | ต้องแก้ fail-open policy ให้ชัด |
| Gateway-trust shared secret (X-Gateway-Auth) | secret ใช้ร่วม Kong↔Buyer — rotate ผ่าน env/secrets manager | ถ้ามี Kong หลาย node: secret เดียวกันทุก node |

---

## 6. สิ่งที่ "ไม่ใช่ SPOF" (ตรวจแล้ว — ไม่ต้องย้าย)

- **Session cookies แบบ JWT** (buyer_session, central_session ฯลฯ): stateless — ตรวจด้วย JWKS ทุก request ✅
- **MCP /mcp**: stateless transport ✅ (แต่ auth ผูกกับ ID Portal — อยู่ในข้อ 3 ของ §3)
- **Prometheus metrics / caches ของ Kong plugin**: refill ได้เอง ✅
- **Theme files / static assets**: static ✅

---

## 7. Monitoring ที่ต้องมีคู่ไปกับ HA (จะรู้ได้อย่างไรว่า SPOF ใกล้ล่ม)

| อะไร | Tool | สัญญาณ |
| ---- | ---- | ------ |
| ID Portal / Kong / Keycloak up + latency | Prometheus (`kong_http_requests_total`, `up`, `kong_nginx_*`) + Grafana + Alertmanager | 5xx พุ่ง · p99 latency · `up == 0` |
| Redis memory/eviction/latency | redis_exporter | `used_memory` ใกล้ maxmemory · evicted_keys พุ่ง |
| Keycloak event log (login/revoke ผิดปกติ) | KC event logging → Loki/ELK | failed login spike |
| Postgres replication lag | postgres_exporter | lag > threshold |

---

## 8. สรุป decision สำหรับ template นี้

| สถานะ | รายการ |
| ----- | ------ |
| ✅ ทำแล้วใน POC | Trust boundaries ชัด · JWT stateless sessions · fail-open/fail-closed แยกนโยบาย · Prometheus hook · explicit ids workaround |
| 🔜 ควรทำก่อน production | Redis ย้าย 4 store (ตาราง §4.2) · Keycloak/Postgres HA · Back-Channel Logout · secrets manager · LICENSE |
| 📝 บันทึกยอมรับ (documented trade-off) | per-page ticket check (ไม่ใช่ทุก API request) · fail-open บน liveness · Kong cache 15s (SLA ต่างจาก MCP 0s) · JWT valid ถึง exp หลัง revoke |
