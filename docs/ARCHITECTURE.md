# Architecture — Central Identity POC (Keycloak + Kong Gateway)

ภาพรวมการทำงานทั้งระบบแบบ diagram (Mermaid — render ได้ใน GitHub) ครอบคลุมทุก flow ที่ POC นี้พิสูจน์ไว้
ทุก flow มี test script ครอบอยู่แล้ว (ดู [test-results.md](test-results.md) — 14 scripts / 198 checks PASS)

> อ่านคู่กับ: [README.md](../README.md) (EN, default) · [README-TH.md](../README-TH.md) (ไทย) · ADR-001..005

---

## 1. ภาพรวมระบบ (System Overview)

```mermaid
flowchart TB
    subgraph USER["👤 ผู้ใช้ / AI Agent"]
        BR["Browser (SSO cookie central_sso + lang)"]
        AG["AI Agent / MCP Client"]
        DEV["อุปกรณ์ ID (:3040)"]
    end

    subgraph GW["Kong Gateway OSS :8000 (DB-less)"]
        direction TB
        K1["oidc-central<br/>JWKS + aud + scope"]
        K2["oidc-introspect<br/>RFC 7662 revoke-aware"]
        K3["central-apikey<br/>Central API Key + scope"]
        K4["jwt · key-auth · rate-limit<br/>cors · request-size · prometheus"]
    end

    subgraph KC["🔑 Keycloak realm central (+ upstream central-id-upstream)"]
        AS["Authorization Server<br/>AC+PKCE · Direct Grant · CIBA<br/>Token Exchange · Introspection · Revocation"]
        UP["Upstream realm (ธีมเขียว)<br/>จำลอง Central ID เดิม"]
    end

    subgraph APPS["Services"]
        ID["ID Portal :3000<br/>บัญชีกลาง · API Keys registry<br/>SSO Ticket broker · STT broker"]
        BUY["Buyer :3010 (NestJS)<br/>Orders · Gateway-trust API<br/>MCP Server /mcp"]
        CIS["CIS :3020 (Go Fiber)<br/>Projects"]
        FIN["Fintech :3050<br/>Embedded Login + ออก SSO Ticket"]
        HD["Headless :3030<br/>CIBA client"]
        DV["ID Device :3040<br/>CIBA approver"]
    end

    PG[(Postgres<br/>Keycloak state)]

    BR -->|"AC + PKCE (ผ่าน brokering)"| AS
    AG -->|"apikey / Bearer central_…"| K3
    BR -->|"browser (SSO ticket)"| ID
    DEV -->|"CIBA approve"| AS
    AS <-->|"delegation / introspect"| DV
    K1 -->|"JWKS (cache + rotation)"| AS
    K2 -->|"introspect (RFC 7662)"| AS
    K3 -->|"POST /apikeys/validate"| ID
    AS --- PG
    K4 --> GW
```

**ขอบเขตความเชื่อใจ (Trust boundaries):** เส้นแบ่งสีเทา = ไม่เชื่อถือ — ทุก service ตรวจ token/key ด้วยตัวเอง (JWKS หรือ validate endpoint) ไม่มี middleware กลางที่ต้อง "เชื่อ" โดยไม่ตรวจ

---

## 2. Flow ที่ 1 — Browser SSO (Authorization Code + PKCE + Identity Brokering)

ผู้ใช้ login ครั้งเดียวที่ upstream realm (ธีมเขียว — จำลอง Central ID เดิม) → realm `central` ออก token ให้ทุกแอป · session ตายเมื่อ logout กลาง

```mermaid
sequenceDiagram
    autonumber
    actor U as ผู้ใช้ (Browser)
    participant P as Portal (Buyer/CIS/ID)
    participant KC as Keycloak realm central
    participant UP as Upstream realm (Central ID จริง)

    U->>P: เปิดหน้าแรก (ยังไม่มี session)
    P->>KC: 302 /auth (AC + PKCE, client_id ของแอป)
    KC->>UP: 302 brokering (client central-broker)
    U->>UP: กรอก username/password (ธีมเขียว)
    UP->>KC: token/callback (identity ผูก email — auto-link)
    KC->>KC: mint RS256 token (aud/scope ตาม client + stt-bridge)
    KC->>P: 302 callback?code=…
    P->>KC: แลก code (PKCE verifier) → access/refresh/id token
    P->>U: cookie session ของแอป (JWKS verify ทุก request ต่อจากนี้)

    note over U,CIS: เปิดแอปอื่นในแท็บใหม่ → SSO ต่อเนื่อง (cookie กลางของ KC)
    U->>KC: Logout กลาง (id_token_hint)
    KC->>UP: ยุติ session ปลายทาง
    note over U: ทุกแอปต้อง login ใหม่ (token เดิม valid ถึง exp — ข้อจำกัด JWT)
```

> ทดสอบ: `scripts/sso-test.sh` (10 checks) · screenshots 01–15

---

## 3. Flow ที่ 2 — Embedded Login + Central SSO Ticket (new-tab SSO)

แอปที่ต้องการฟอร์ม login ของตัวเอง (Fintech) ใช้ Direct Grant แล้ว **ออก SSO Ticket ให้ browser** — เปิดแอปอื่นในแท็บใหม่จะ SSO อัตโนมัติ และ **logout กลาง propagate จริง** (session ปลายทางผูกกับ ticket)

```mermaid
sequenceDiagram
    autonumber
    actor U as ผู้ใช้ (Browser — แท็บ fintech)
    participant F as Fintech :3050 (Direct Grant)
    participant ID as ID Portal :3000 (ticket broker)
    participant C as CIS :3020 (แท็บใหม่)
    participant KC as Keycloak

    U->>F: POST /login (username/password)
    F->>KC: Direct Grant (grant_type=password)
    KC-->>F: access/refresh token + brute-force policy
    F->>ID: POST /sso/ticket (token) — ขอตั๋ว SSO
    ID-->>F: ticket (central_sso cookie — host-wide)
    note over F,U: cookie แชร์ทุก port (host localhost เดียวกัน)
    U->>C: เปิด CIS ในแท็บใหม่ (มี central_sso cookie)
    C->>ID: ตรวจ ticket (single-use + ผูก session ปลายทาง)
    C->>U: ✅ SSO เข้าเลย ไม่ถามรหัสผ่าน
    note over U,KC: Logout กลางจากแอปใดก็ได้ → revoke ทุก ticket<br/>→ แอปอื่นตายตั้งแต่ request ถัดไป (propagate จริง)
    U->>F: POST /logout (แอปใดก็ได้)
    F->>ID: revoke ตั๋วทั้งหมด
    ID-->>F: ยืนยัน — ทุก session ที่ผูก ticket จะถูกบังคับ logout
```

> ทดสอบ: `scripts/stt-test.sh` (33 checks) · screenshots 21–24 · brute force: ผิด 5 ครั้ง → ล็อกข้ามแอป 30s

---

## 4. Flow ที่ 3 — Central API Key (ID Portal ออก key ผูก scope → Kong → MCP)

ออก API key จาก ID Portal ผูก scope → ใช้ยิง Open API ผ่าน Kong (plugin ตรวจ key กับ ID Portal) — **MCP server ใช้ contract เดียวกัน**

```mermaid
sequenceDiagram
    autonumber
    actor U as ผู้ใช้ (ID Portal /apikeys)
    participant ID as ID Portal (key registry + validate)
    participant K as Kong :8000 (central-apikey plugin)
    participant B as Buyer API (gateway-trust endpoints)

    U->>ID: POST /apikeys/create (name, scopes=orders.read,orders.write)
    ID-->>U: key = central_… (แสดงเต็มครั้งเดียว — เก็บ hash ฝั่ง registry)
    U->>K: GET /openapi/apikey/orders (header apikey)
    K->>ID: POST /apikeys/validate (cache 15s)
    ID-->>K: {active:true, owner, scopes:[orders.read, orders.write]}
    K->>K: บังคับ scope ตาม method (GET→orders.read / POST→orders.write)
    K->>B: ส่งต่อ + gateway-trust header (X-Gateway-Auth ลับ + X-Central-Scopes/Owner)
    B-->>U: 200 (data) — zero-trust: ไม่มี header ลับ = ปฏิเสธทันที
    note over U,ID: revoke ที่ ID Portal → cache หมด (≤15s) → gateway ปฏิเสธทันที<br/>MCP server ใช้ validate endpoint เดียวกัน + บังคับ scope ต่อ tool
```

> ทดสอบ: `scripts/openapi-test.sh` (31 checks — รวม 10 เช็ค apikey) · ใช้กับ MCP ได้ (ข้อ 5)

---

## 5. Flow ที่ 4 — MCP Server (AI agents)

`POST :3010/mcp` (Streamable HTTP, โหมด stateless JSON) — ทุก request ตรวจ key ก่อน แล้ว tools/list **กรอง tool ตาม scope ของ key** และ tools/call บังคับซ้ำตอน execute

```mermaid
sequenceDiagram
    autonumber
    actor A as AI Agent / MCP Client
    participant M as Buyer /mcp (MCP Server)
    participant ID as ID Portal (validate)
    participant KC as Keycloak

    A->>M: POST initialize (Accept: application/json, text/event-stream)
    M-->>A: protocolVersion 2025-03-26 + capabilities.tools
    A->>M: tools/list (apikey: central_…)
    M->>ID: POST /apikeys/validate
    ID-->>M: {active:true, owner, scopes}
    note over M: กรอง tool: orders.write ไม่อยู่ใน scopes<br/>→ create_order ไม่ถูกเสนอใน tools/list
    M-->>A: tools: whoami + list_orders (ไม่มี create_order)
    A->>M: tools/call list_orders
    M-->>A: content: orders JSON ✅
    note over A,M: key แบบ read+write → tools/list จะเสนอ create_order ด้วย<br/>(บังคับซ้ำตอน execute — 403 ถ้า scope ไม่พอ)
```

> ทดสอบ: `scripts/mcp-test.sh` (12 checks) · เชื่อมจาก Claude Code/Cursor ดู README §11

---

## 6. Flow ที่ 5 — Headless CIBA (login โดยไม่กรอกรหัสผ่านบนอุปกรณ์ client)

```mermaid
sequenceDiagram
    autonumber
    actor U as ผู้ใช้ (Seller App :3030)
    participant HD as Headless (CIBA client)
    participant KC as Keycloak (CIBA + delegation)
    participant DV as ID Device :3040 (approver)

    U->>HD: กรอก login_hint + binding message
    HD->>KC: POST /ext/ciba/auth (backchannel auth request)
    KC->>DV: delegation request (login_hint + binding message)
    DV->>DV: ผู้ใช้กด "ยืนยัน" บนอุปกรณ์ (มี login gate)
    DV->>KC: callback (อนุมัติ)
    HD->>KC: poll token (grant_type=ciba)
    KC-->>HD: token (aud=buyer-api) → เรียก Buyer ได้ทันที
    note over U,DV: ปฏิเสธ/หมดเวลา → error ชัดเจน (access_denied / expired_token)
```

> ทดสอบ: `scripts/ciba-test.sh` (16 checks) · screenshots 16–20

---

## 7. Flow ที่ 6 — STT Session Transfer (Token Exchange ข้าม audience)

```mermaid
sequenceDiagram
    autonumber
    actor U as ผู้ใช้ (mobile มี session)
    participant SRC as แอปต้นทาง (token aud=buyer-api<br/>scope รวม stt-bridge)
    participant ID as ID Portal (STT broker)
    participant DST as CIS :3020 (aud=cis-api)

    U->>SRC: มี session อยู่แล้ว
    SRC->>ID: POST /stt/create (token + dest=cis-web)
    ID-->>SRC: one-time code (60s, ผูกปลายทาง)
    U->>DST: เปิด /auth/stt?code=…
    DST->>ID: redeem code (ตรวจ dest + aud ปลายทาง)
    DST->>KC: **Token Exchange (KC Standard V2)**<br/>subject_token → token ใหม่ aud=cis-api
    KC-->>DST: token (user เดิม, claims ครบ)
    DST-->>U: ✅ SSO โดยไม่กรอกรหัสผ่าน
    note over U,KC: token ต้นทาง (aud=buyer-api) ไม่มีทางใช้กับ CIS API ตรง ๆ<br/>— Token Exchange คือทางถูกต้องตามมาตรฐาน
```

> ทดสอบ: `scripts/stt-test.sh` (33 checks) · ADR-004

---

## 8. Kong Custom Plugins (Lua PDK)

```mermaid
flowchart LR
    REQ["Request เข้า Kong"] --> ROUTE{"ตาม route"}
    ROUTE -->|"openapi/buyer"| P_JWT["jwt plugin<br/>(signature+iss+exp)"]
    ROUTE -->|"openapi/oidc"| P_OC["oidc-central<br/>JWKS live + aud + scope"]
    ROUTE -->|"openapi/introspect"| P_OI["oidc-introspect<br/>RFC 7662 revoke-aware"]
    ROUTE -->|"openapi/apikey"| P_CA["central-apikey<br/>Central API Key + scope"]
    ROUTE -->|"openapi/keyauth"| P_KA["key-auth (คู่เทียบ OAuth)"]
    ROUTE -->|"openapi/ratelimit"| P_RL["rate-limiting 3/min"]
    P_JWT --> UP["Buyer/CIS upstream<br/>(defense in depth —<br/>service ตรวจซ้ำอีกชั้น)"]
    P_OC --> UP
    P_OI --> UP
    P_CA -->|"gateway-trust headers"| UP
    P_KA --> UP
    P_RL --> UP
```

| Plugin | ไฟล์ | หน้าที่ | จุดเด่น |
| ------ | ---- | ------ | ------ |
| `oidc-central` | `kong/custom/kong/plugins/oidc-central/` | JWKS (live fetch + cache) + ตรวจ aud + scope ที่ gateway | เติมสิ่งที่ jwt plugin OSS ข้าม |
| `oidc-introspect` | `kong/custom/kong/plugins/oidc-introspect/` | เรียก `/introspect` ตรวจ revocation | revoke → 401 ทันทีที่ gateway |
| `central-apikey` | `kong/custom/kong/plugins/central-apikey/` | ตรวจ Central API Key กับ ID Portal + scope ต่อ method | เพิ่ม/ยกเลิก key ไม่ต้องแตะ kong.yml |

---

## 9. แผนที่ Flow → Script → เอกสาร

| Flow | Script | Checks | ADR | หมายเหตุ |
| ---- | ------ | ------ | --- | -------- |
| Browser SSO + Brokering | `sso-test.sh` | 10 | ADR-001 | upstream realm ธีมเขียว |
| Embedded Login + Brute Force | `fintech-test.sh` | 5 | — | realm-wide lockout |
| SSO Ticket + Global Logout | `stt-test.sh` (ส่วน 7-8) | รวมใน 33 | ADR-004 | propagate จริง |
| STT + Token Exchange | `stt-test.sh` (ส่วน 1-6) | รวมใน 33 | ADR-004 | KC Standard V2 |
| Central API Keys | `openapi-test.sh` (ส่วน apikey) | รวมใน 31 | ADR-005 | dual header apikey/X-API-Key |
| MCP Server | `mcp-test.sh` | 12 | ADR-005 | scope-gated tools |
| Introspection gateway | `openapi-test.sh` (ส่วน introspect) | รวมใน 31 | ADR-005 | revoke-aware |
| Mobile PKCE | `mobile-test.sh` | 12 | — | RFC 8252 + rotation |

---

## 10. การตั้งค่าและข้อจำกัดสำคัญ

- **DNS บน Docker Desktop (Windows):** `KONG_DNS_ORDER: "A"` — ไม่งั้น Kong resolve ช้า 4–8s (SRV โดน SERVFAIL)
- **Kong 3.9 declarative flaky:** config ใหญ่ parse สุ่มล้ม `table index is nil` — `setup.sh` ฉีด explicit `id` ทุก entity เป็น workaround
- **cookie host-wide (`central_sso`, `lang`):** ใช้ได้เพราะทุกแอปอยู่ host `localhost` ต่าง port — production ใช้ subdomain เดียวกัน (เช่น `*.central.example`)
- **JWT limitation:** revoke/disable แล้ว access token เดิม valid ถึง exp — ปลายทางที่ตรวจด้วย introspection (route introspect) ปิดจุดนี้ได้
- **production hardening ที่ยังไม่อยู่ใน POC:** backchannel logout, HA, WAF, mTLS, per-key quota

รายละเอียดทั้งหมด (รวมสิ่งที่เจอจริงระหว่างทำ): [test-results.md](test-results.md) findings 1–55 · ADR-001..005
