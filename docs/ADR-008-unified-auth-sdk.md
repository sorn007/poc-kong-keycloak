# ADR-008 — Unified Auth SDK ต่อ Backend Service (`@central/auth-nestjs` + `central/auth-go`)

## บริบท

ทุก service ทำหน้าที่เหมือนกันต่อ request ขาเข้า: ตรวจ JWKS/gateway-trust, ตรวจ `aud` + scope, และตรวจว่า session/ticket ยังไม่ถูก revoke — แต่เดิมแต่ละตัวเขียน Guard/Middleware ของตัวเอง (copy ไปแล้วดัดแก้ตามเวลา):

- **TypeScript:** guard/verifier 9 ไฟล์ใน `services/buyer-api/src/auth` + gateway controller + `validateKey` ใน MCP — `isTicketAlive` ซ้ำ 2 ฉบับใน service เดียว (ฉบับหนึ่งเป็น private method ที่ไม่มีใครเรียก)
- **Go:** `VerifyCentral` 3 สำเนา (`central-id`, `cis-api`, `id-device`) + ตรวจ ticket อีก 2 สำเนา (`cis-api`, `fintech-web`)

ตอนไล่รวมโค้ด **พบว่า policy เพี้ยนจากกันแล้วจริง** ทั้งที่ comment เขียนเหมือนกัน:

| # | เรื่อง | ที่พบ | ผลของการรวม |
| - | ----- | ---- | ----------- |
| 1 | clock skew (leeway) | `central-id` ส่ง `jwt.WithLeeway(5)` = 5 **นาโนวินาที** (ตัวเลขไม่มีหน่วย) ส่วน `cis-api`/buyer ใช้ 5 วินาที | 5 วินาทีทุก service (`auth.Leeway`) |
| 2 | บังคับมี `exp` | Go ใช้ `WithExpirationRequired()` ปฏิเสธ token ไร้อายุ แต่ buyer (jose) **รับ token ที่ไม่มี `exp`** = ไม่มีวันหมดอายุ | บังคับมี `exp` ทั้งสองฝั่ง — **รวม legacy verifier ด้วย** (รอบแรกบังคับเฉพาะ central token: `LegacyVerifier` ฝั่ง TS ยังรับ token legacy ไร้ `exp`/`sub` — code review พบ แก้แล้ว ดูหัวข้อท้าย) |
| 3 | บังคับมี `sub` | `cis-api` บังคับ, `central-id` ไม่บังคับใน `VerifyCentral` | บังคับสำหรับ token ที่ผูก audience (`VerifyIssuerOnly` ไม่บังคับ — เป็น verify สำหรับ Session Transfer ข้าม client) |
| 4 | เคลียร์ cookie เมื่อตั๋วตาย | buyer หน้า `/` เคลียร์ 4  cookie (ค้าง `buyer_id_token`) แต่ `/orders/page` เคลียร์ 5 | ชุดเดียวจาก `sessionCookieNames()` ทุกหน้า (รอบแรกหน้า `/` ของ Buyer ลืมเรียกฟังก์ชันจน redirect วนไม่รู้จบ — code review พบ แก้แล้ว + เพิ่ม E2E check) |
| 5 | เทียบ gateway secret | buyer ใช้ `!==` | constant-time (`timingSafeEqual` / `subtle.ConstantTimeCompare`) |
| 6 | timeout ตอนตรวจ ticket | buyer 5s · fintech 10s · cis ไม่มี timeout (`http.DefaultClient`) และ fintech ไม่ดู HTTP status | 5s + non-200 = ตรวจไม่ได้ → fail-open |

## ทางเลือก

| | ทางเลือก | ผลดี | ผลเสีย |
| - | ------- | ---- | ------ |
| A | คงให้แต่ละ service เขียน Guard/Middleware เอง (ของเดิม) | ไม่มี dependency ร่วม · แก้เฉพาะ service ได้อิสระ | policy ตกหล่นเมื่ออัปเดต (ตารางข้างบนคือหลักฐาน) · audit ต้องไล่ทุก service |
| B | **Shared library in-process ต่อภาษา** — `@central/auth-nestjs` (TS) + `central/auth-go` (Go) | แก้ policy ที่เดียว · unit test ครอบเคส 401/403 ที่เดียว · service ระบุเฉพาะตัวตนของตัวเอง | เพิ่ม 2 package ที่ต้องดูแล · ต้องผูกเข้า Docker build ของทุก service |
| C | Central auth service / middleware กลางที่ทุก request ต้องวิ่งผ่าน | policy รวมจริง | **ปฏิเสธ** — กฎข้อ 8 ของ repo (ห้าม service กลางที่ทุก request ผ่าน): เพิ่ม latency ต่อ request + SPoF อีกตัว + ขัดกับ "Buyer/CIS ตรวจ token เองผ่าน JWKS" |

## การตัดสินใจ

เลือก **B** — library แบบ in-process (ไม่มี hop ผ่านเครือข่าย · JWKS client ยังสร้างครั้งเดียวตอน startup ของแต่ละ service)

```text
packages/
├── auth-nestjs/            @central/auth-nestjs v0.1.0   (ผู้ใช้: buyer-api รวม MCP)
│   ├── verifier.ts           CentralVerifier — RS256 + iss + aud + exp บังคับ (+ tolerance 5s)
│   ├── legacy.ts             LegacyVerifier — HS256 shared secret (ช่วง migration)
│   ├── guards.ts             CentralAuthGuard · LegacyAuthGuard · DualAuthGuard · ScopeGuard · @RequireScope
│   ├── gateway.ts            verifyGatewayTrust — X-Gateway-Auth (constant-time) + X-Central-Scopes/Owner
│   ├── ticket.ts             TicketGuard.isAlive + sessionCookieNames/clearSessionCookies
│   ├── apikey.ts             ApiKeyVerifier — POST /apikeys/validate (fail-closed)
│   └── index.ts              createAuth() — จุดต่อเดียวของ service + VERSION
└── auth-go/                central/auth-go v0.1.0       (ผู้ใช้: cis-api, central-id, id-device, fintech-web)
    ├── auth.go               VerifyCentral · VerifyIssuerOnly · VerifyLegacy · Peek · Claims · Config · Leeway
    ├── gateway.go            VerifyGatewayTrust (ยังไม่มี service Go ใช้ — เพิ่มไว้ให้ header contract ตรงกับ TS)
    ├── ticket.go             TicketChecker / TicketAlive (FailOpen policy)
    └── fibermw/              CentralAuth · LegacyAuth · DualAuth · Scope (adapter ของ Go Fiber)
```

**ขอบเขต (สำคัญ):** SDK ทำเฉพาะ **Authentication** — "ใครคือ principal และถือ scope อะไร" · Authorization ระดับ business (tenant, บริษัท, order/project ของใคร) **อยู่ที่ service เองเสมอ** ตามกฎของ repo (ห้ามย้าย business authorization ไป shared library) — SDK ให้เฉพาะกลไก (เช่น `ScopeGuard` อ่าน `@RequireScope`) ส่วน "endpoint นี้ต้องการ scope ใด" ประกาศที่ controller ของ service

**การออกแบบที่ตั้งใจ:**

- `createAuth()` คืน **instance** ของ guard ให้ใช้กับ `@UseGuards(auth.guards.central, auth.guards.scope)` — ไม่ต้องลงทะเบียน provider ใน Nest module และไม่พึ่ง `Reflector` (อ่าน metadata ผ่าน `Reflect.getMetadata` ตรง ๆ) · service ต่อ SDK ที่ไฟล์เดียว (`services/buyer-api/src/central-auth.ts`)
- ไม่ส่ง `legacy` option = guard ของ legacy/dual ไม่ถูกสร้าง → ปิด path หลัง migration ได้ที่เดียว
- Core ของ Go ไม่ผูกกับ Fiber (adapter อยู่ subpackage `fibermw`) — service Go ที่ใช้ framework อื่นเรียก `VerifyCentral`/`Peek` ได้
- API key ตรวจกับ ID Portal **ทุก request** (fail-closed) ส่วน ticket liveness default **fail-open** — นโยบายทั้งสองเขียนไว้เป็น option เดียวใน SDK (`failOpen`) ไม่กระจายใน service

## การผูกเข้า Docker build (compose first)

- Go: แต่ละ service ใช้ `replace central/auth-go => ../../packages/auth-go` ใน `go.mod`
- TS: buyer ใช้ `"@central/auth-nestjs": "file:../../packages/auth-nestjs"` + `.npmrc` → `install-links=true`
- compose: `build.additional_contexts` (ต้องมี Compose v2 ที่รองรับ + BuildKit — default ของ Docker Desktop · `docker-compose` v1 ใช้ไม่ได้ · `scripts/00-check-env.sh` ตรวจให้) ส่งโฟลเดอร์ SDK เข้า Dockerfile แล้ววางตาม path สัมพัทธ์เดียวกับบนเครื่อง → build ได้เหมือนกันทั้งในเครื่องและใน image · **ผู้ใช้ไม่ต้องทำ step เพิ่ม** (SDK build ใน image เสมอ — `docker compose up -d` จากเครื่องเปล่ายังใช้ได้)

**ทำไมต้อง `install-links` (TS):** ถ้าติดตั้ง SDK เป็น symlink (default ของ npm สำหรับโฟลเดอร์นอก project), `require('@nestjs/common')` ของ SDK จะ resolve ไปคนละ instance กับของ service → `UnauthorizedException` ที่ SDK โยนไม่ใช่ `HttpException` ของ Nest ตัวนั้น → Nest ตอบ **500** แทน 401 · ตรวจใน image จริง: SDK เป็นโฟลเดอร์จริง (มีแค่ `dist` + `package.json`) และ SDK/service resolve `@nestjs/common` ไฟล์เดียวกัน

## เวอร์ชันและการอัปเดต

- ทุก service log รุ่นของ SDK ตอน startup (`auth-sdk=@central/auth-nestjs@0.1.0` / `auth-sdk=0.1.0`) — ใช้ตรวจว่า deploy รุ่นใด
- POC: dependency ชี้ path ใน repo → service ใด rebuild จะได้ SDK รุ่นล่าสุดทันที (ไม่มีเลขเวอร์ชันต้องตามอัปเดตแยก) · ขั้นตอนแก้ policy: แก้ที่ `packages/` → รัน unit test ของ SDK → `docker compose build` service ที่เกี่ยว
- **กับดักบนเครื่อง dev (TS):** `npm install` (รวม `--force`) **ไม่ refresh** สำเนา dependency แบบ `file:` เมื่อมีแค่ source ของ SDK เปลี่ยน — npm ถือว่ารายการเดิมยังตรงกับ spec ถ้ารัน service บนเครื่องต้องลบสำเนาก่อน: `rm -rf node_modules/@central/auth-nestjs && npm install` (ใน Docker ไม่กระทบ — SDK build ใหม่ใน image ทุกครั้ง)
- Production: publish เป็น private package (npm registry / Go module tag) แล้ว service ต่าง pin เวอร์ชันของตัวเอง — ตัด `replace`/`file:` ออก ไม่ต้องแก้โค้ด service

## ผลทดสอบ (2026-11-25)

- Unit test ใหม่ของ SDK: Go **46 เคส** (`packages/auth-go` — IdP จำลองผ่าน JWKS จริง: aud/iss/exp/alg confusion/kid ที่ไม่รู้จัก/sub ว่าง + middleware ทั้ง 4 ตัว + gateway-trust + ticket fail-open/fail-closed) · TS **23 เคส** (`packages/auth-nestjs` — ชุดเคสเดียวกัน + legacy ไร้ `exp`/`sub` + `requireLegacy` + cookie contract + API key fail-closed)
- Regression ทั้ง stack หลังย้าย: **170/170 PASS** (11 suites — `stt-test.sh` 42 checks รวม 8 checks ที่ตรวจ **response แรก**และ **redirect loop** ของหน้า page เมื่อตั๋วตาย) — เนื้อหา error 401/403 เดิมทุกจุด (`missing_access_token`, `invalid_access_token`, `unsupported_token`, `insufficient_scope` + `required`, ข้อความของ gateway controller)
- build จากไม่มี cache: `docker compose build --no-cache buyer-api` ผ่าน (SDK build ใน image — host ไม่ต้องมี `node_modules`/`dist` ของ SDK)

## สิ่งที่ code review พบหลังส่งมอบรอบแรก (แก้ครบแล้ว)

| # | สิ่งที่พบ | การตรวจสอบ | การแก้ |
| - | ------- | --------- | ------ |
| 1 | **regression จริง:** หน้า landing ของ Buyer (`/`) วน redirect ไม่รู้จบเมื่อตั๋ว SSO ตาย — ตอนย้ายมาใช้ SDK บรรทัด `res.clearCookie` เดิมถูกแทนด้วย comment โดยไม่ได้เรียก `clearSessionCookies` | ทดลองบน stack: response แรก `302 Location: /` ไม่มี Set-Cookie · ตาม redirect 10 ครั้งจน curl exit 47 | เรียก `clearSessionCookies(res, 'buyer')` ก่อน redirect + เพิ่ม helper `redirect_loop` / `clears_cookie` ใน `scripts/_lib.sh` และ 8 checks ใน `stt-test.sh` — ยืนยันแดง→เขียว (ก่อนแก้ FAIL 2 เฉพาะ `/` ของ Buyer · หลังแก้ 42/42) |
| 2 | `LegacyVerifier` ฝั่ง TS รับ token legacy ที่ไม่มี `exp`/`sub` ขณะที่ Go ปฏิเสธ | ทดลองกับ SDK build เก่า: "no exp → ACCEPTED" | บังคับ `exp` + `sub` เหมือน central token + unit test |
| 3 | `@UseGuards(auth.guards.dual!)` ปิดบัง type — reviewer ระบุว่า Nest ปล่อยผ่าน `undefined` guard เงียบ ๆ | **ทดลองจริงพบว่าไม่ใช่**: Nest 10.4 โยน `InvalidDecoratorItemException` ตั้งแต่โหลด module (service start ไม่ขึ้น) จึงไม่มีช่อง fail-open | ยังปรับให้ชัด: `requireLegacy(auth)` คืน guard แบบไม่ optional และ throw พร้อมข้อความบอกสาเหตุตอนถอด block `legacy` โดยลบ route ไม่หมด |
| 4 | `build.additional_contexts` ต้องมี Compose v2 + BuildKit แต่ `00-check-env.sh` ตรวจแค่มี docker และ README ไม่ได้ระบุข้อกำหนด | อ่าน script + README | เพิ่ม 2 checks (ให้ compose อ่านไฟล์ที่มี `additional_contexts` จริง + buildx/`DOCKER_BUILDKIT`) · เพิ่ม prerequisites ใน README §7 และ troubleshooting §13 |

**บทเรียน:** check ที่ตาม redirect อัตโนมัติ (`curl -L`) แล้ว grep ว่า "ไม่พบข้อความ X" พิสูจน์ไม่ได้ว่าหน้า page ทำงานถูก — ต้องตรวจ **response แรก** และ **exit code** แยกกัน และ check ใหม่ควรได้เห็น "แดง" กับโค้ดที่บั๊กจริงก่อนเชื่อว่ามันทำงาน

## สิ่งที่ **ไม่** อยู่ใน ADR นี้ (follow-up)

- `internal/oidc` (OIDC client: login/callback/PKCE/logout) ยังมีสำเนาของตัวเองใน buyer, cis-api, central-id, fintech-web, id-device — เป็น client flow ของแต่ละแอป ไม่ใช่การตรวจ request ขาเข้า จึงยังไม่รวมในรอบนี้
- `VerifyGatewayTrust` ฝั่ง Go ยังไม่มี service ใช้ (คงไว้ให้ header contract ตรงกับ TS) — เมื่อมี Go service อยู่หลัง route `central-apikey` ของ Kong จะใช้ตัวนี้ได้ทันที
