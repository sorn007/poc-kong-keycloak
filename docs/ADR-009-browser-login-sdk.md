# ADR-009 — Login SDK สำหรับแอปในเบราว์เซอร์ (`@central/login-js`) + แอปตัวอย่าง `claw-web`

## บริบท

ทุกแอปใน POC ก่อนหน้านี้เป็นเว็บที่ render ฝั่ง server (Go Fiber / NestJS) — token ถูกตรวจด้วย Guard ฝั่ง server ผ่าน `@central/auth-nestjs` หรือ `central/auth-go` (ADR-008) ยังไม่มีแอปที่ทำงานอยู่ในเบราว์เซอร์ทั้งหมด (SPA) ซึ่งเป็น pattern ที่ต้องพึ่ง **PKCE (RFC 7636)** อย่างเดียวในการป้องกัน authorization code ระหว่างทาง

โจทย์: สร้าง (1) Login SDK แบบ "สำเร็จรูป" สำหรับ SPA ที่ใช้ Central ID และ (2) แอป `claw-web` ที่ใช้ SDK นี้เข้าสู่ระบบแล้วเรียก API ที่มีอยู่

## ทางเลือก

| | ทางเลือก | ผลดี | ผลเสีย |
| - | ------- | ---- | ------ |
| A | ใช้ `keycloak-js` ตัวทางการ | ผ่านการใช้งานจริงมาก | ผูกกับกลไกภายในของ Keycloak (session iframe, legacy flow) · ตรวจ aud/azp/at_hash ไม่ครบตามนโยบายของ repo · ผู้ใช้ต้องการ SDK ของตัวเอง |
| B | **SDK ของตัวเอง (`@central/login-js`) — Authorization Code + PKCE S256 ล้วน ไม่มี dependency** | อ่านได้หมดทุกบรรทัด · บังคับนโยบายความปลอดภัยของ repo ได้ตรง ๆ · ใช้ได้กับ OP ที่ใช้ path แบบ Keycloak | ต้องดูแลโค้ด OIDC client เอง (ลดความเสี่ยงด้วย unit test + ใช้ WebCrypto ล้วน ไม่ implement เอง) |
| C | BFF — token เก็บฝั่ง server เบราว์เซอร์ถือ cookie เท่านั้น | ปลอดภัยที่สุด (XSS ขโมย token ไม่ได้) | ต้องมี backend ของแอป — ไม่ตรงกับโจทย์ "แอปในเบราว์เซอร์" |

## การตัดสินใจ

เลือก **B** สำหรับ POC (บันทึก C ไว้เป็นทางเลือกสำหรับ production ที่ต้องการความปลอดภัยสูงสุด)

### โครงสร้าง

```text
packages/login-js/           @central/login-js v0.1.0 — TypeScript → ESM · ไม่มี dependency · WebCrypto ล้วน
  src/client.ts              LoginClient: init / login / silentLogin / updateToken / logout / getUser / getTokenInfo
  src/pkce.ts                verifier 43 ตัวอักษร + challenge S256
  src/jwt.ts + jwks.ts       decode JWT · JWKS ของ issuer ที่กำหนด (cache 5 นาที, refetch เมื่อเจอ kid ใหม่)
  src/storage.ts             transaction (state/nonce/verifier) + LoopGuard ใน sessionStorage
  src/url.ts                 parse callback · sanitize returnTo
  test/                      48 unit tests (IdP จำลองเซ็น JWT ด้วย WebCrypto จริง)
services/claw-web/           static SPA (HTML + ES modules + CSS) · nginx non-root :3060
  html/                      index.html · js/app.js · js/i18n.js · js/config.js.template · css/app.css
  nginx/                     default.conf.template (CSP ใส่ origin ของ Keycloak/Kong จาก env) + security headers
scripts/setup-claw.sh        upsert public client claw-web (idempotent) — 13 checks
scripts/claw-test.sh         E2E ด้วย curl เล่นบทเป็นเบราว์เซอร์ + SDK — 43 checks
tools/screenshots/claw.mjs   ตรวจในเบราว์เซอร์จริง (Edge) — 17 checks + screenshots 31-33
```

### Contract ของ SDK

```ts
const login = createLogin({ issuer, clientId, redirectUri, scopes?, leewaySeconds?, tokenStore? });
await login.init();                 // จัดการ callback / กู้ SSO session ด้วย prompt=none
await login.login({ returnTo });    // redirect ไปหน้า login ของ ID
await login.updateToken(20);        // refresh ถ้าเหลืออายุ < 20 วิ · เรียกก่อนใช้ token ทุกครั้ง
login.getAccessToken(); login.getUser(); login.getTokenInfo();
await login.logout({ returnTo });   // RP-initiated logout
login.on('signedOut' | 'authenticated' | 'tokenRefreshed', handler);
```

ทุกอย่างที่ SDK แตะโลกภายนอก (fetch, storage, location, navigation, นาฬิกา) ฉีดผ่านพารามิเตอร์ที่สอง — แอปไม่ต้องส่ง · test ใช้ของจำลอง

### นโยบายความปลอดภัยที่ SDK บังคับ

| เรื่อง | นโยบาย | เหตุผล |
| ----- | ----- | ------ |
| PKCE | S256 เท่านั้น · verifier 43 ตัวอักษร | client เป็น public ไม่มี secret — code ที่รั่วไปใช้ไม่ได้ถ้าไม่มี verifier |
| state / nonce | สุ่ม 256-bit · transaction ใน sessionStorage ใช้ครั้งเดียว (ลบก่อนแลก code) · ตรวจ `iss` ใน callback (RFC 9207) | กัน CSRF / code injection / mix-up attack |
| id_token | RS256 เท่านั้น · `kid` จาก JWKS ของ issuer ที่กำหนด (ไม่ใช้ `jku`/`x5u`) · ตรวจ `iss` `aud` `azp` `exp` `iat` `sub` `nonce` `at_hash` | ห้ามเชื่อ claims ก่อน verify — กฎ 1-3 ของ repo |
| เก็บ token | **ในหน่วยความจำเท่านั้น** (ไม่เขียน localStorage/sessionStorage) · reload → silent login | XSS อ่าน token จาก storage ไม่ได้ |
| อายุ token | นับจาก `expires_in` (เวลาสัมพัทธ์) ไม่ใช่ `exp` เทียบนาฬิกาเครื่อง | นาฬิกาเครื่องผู้ใช้เดินไม่ตรงก็ไม่กระทบ |
| Refresh | single-flight ต่อแท็บ · refresh ถูกปฏิเสธ → เคลียร์ session + `signedOut` · network error → ทิ้ง refresh token แต่คง access token เดิม | Keycloak เปิด rotation + reuse detection: ใช้ refresh token ซ้ำ = session ถูกปฏิเสธ |
| Redirect loop | หยุด redirect อัตโนมัติหลัง OP ตอบ error (60 วิ), หลัง logout (จนกว่าผู้ใช้จะกด login), หรือ ≥ 3 ครั้งใน 30 วิ | callback ที่มี `error=login_required` จะวนกลับไป silent login ซ้ำได้ไม่รู้จบ |
| Callback ที่ state ไม่ตรง | ลบ code/state ออกจาก URL **ก่อน** I/O ใด ๆ · ไม่แลก code | login ข้ามแท็บ / เปิด callback ซ้ำ ต้องไม่ใช้ code ซ้ำ |
| Logout | RP-initiated logout ด้วย `id_token_hint` + `client_id` + `post_logout_redirect_uri` · เคลียร์ session ในเครื่องก่อน navigate | จบ SSO session จริง (Single Logout ส่งต่อถึง Central ID) |
| CSP ของแอป | `script-src 'self'` · `style-src 'self'` · `connect-src` เฉพาะ Keycloak + Kong · `Referrer-Policy: no-referrer` · nginx ไม่ log `/auth/callback` | URL ของ callback มี authorization code |

### Keycloak client

```json
{ "clientId": "claw-web", "publicClient": true, "standardFlowEnabled": true,
  "implicitFlowEnabled": false, "directAccessGrantsEnabled": false,
  "redirectUris": ["http://localhost:3060/auth/callback"], "webOrigins": ["http://localhost:3060"],
  "attributes": { "pkce.code.challenge.method": "S256", "post.logout.redirect.uris": "http://localhost:3060" },
  "defaultClientScopes": ["acr","basic","email","identity-buyer-web","orders.read","orders.write","profile","role_list","roles","web-origins"] }
```

ใช้ scope `identity-buyer-web` เดิม → token มี `aud=buyer-api` โดยไม่ต้องเพิ่ม Token Contract · `webOrigins` จำเป็น: Keycloak ใส่ CORS header ที่ token endpoint เฉพาะ origin ที่ลงทะเบียน

## สิ่งที่พิสูจน์บนระบบจริง (2026-11-26)

- **PKCE บังคับจริงกับทุก client ที่ใช้ Authorization Code Flow** (`buyer-web`, `cis-web`, `central-id-portal`, `mobile-app`, `claw-web`): authorize ที่ไม่ส่ง `code_challenge` → ถูกปฏิเสธ **ที่ authorization endpoint** ด้วย `error=invalid_request` (ไม่ออก code ไม่เข้าหน้า login) · `plain` → ปฏิเสธ
- **callback มี `iss`** (Keycloak ≥ 23 ส่งตาม RFC 9207) → SDK ตรวจได้
- **CORS**: Keycloak ส่ง `Access-Control-Allow-Origin` เฉพาะ origin ใน `webOrigins` (origin อื่นไม่มี header → เบราว์เซอร์ block) · JWKS endpoint อนุญาต origin ของแอป (SDK verify ลายเซ็นในเบราว์เซอร์ได้)
- **Silent login**: ขณะมี SSO session, `prompt=none` ได้ code ทันที · หลัง logout → `error=login_required`
- **Logout**: ส่ง `id_token_hint` → 3 redirects กลับมาที่แอป ไม่มีหน้า confirm และ session ของ Central ID จบด้วย (Single Logout)
- **Token จาก code ที่แลกด้วย verifier ผิด/ซ้ำ**: Keycloak เพิกถอน token ของ session นั้น (refresh token ใช้ไม่ได้หลังจากนี้) — negative test จึงต้องไว้ท้ายสุดของ session

## ผลทดสอบ

| ชั้น | ผล |
| --- | --- |
| Unit test ของ SDK (`npm test`) | **48/48** — RFC 7636, state/nonce, id_token ที่ถูกปฏิเสธ 13 กรณี, loop guard, refresh single-flight, key rotation |
| `setup-claw.sh` | **13/13** (รันซ้ำได้) |
| `claw-test.sh` (curl) | **43/43** — รันซ้ำ 2 รอบผ่านเท่ากัน |
| `tools/screenshots/claw.mjs` (Edge จริง) | **17/17** — login → dashboard → GET 200 / POST 201 ผ่าน Kong → refresh → reload แล้ว session กลับมา → logout · ไม่มี console error / CSP violation |
| Regression ทั้ง stack | **213/213** (12 suites) |

## ข้อจำกัดที่ยอมรับ / follow-up

- **Logout จากแอปอื่น**: SPA ไม่ได้ผูกกับ SSO ticket แบบแอปฝั่ง server — จะรู้ว่า session ถูกจบเมื่อ access token หมดอายุ (≤ 5 นาที) แล้ว refresh ถูกปฏิเสธ (ดู docs/SECURITY-AUDIT.md Q2)
- **หลายแท็บ**: token เป็นของแต่ละแท็บ (อยู่ในหน่วยความจำ) — logout ในแท็บหนึ่งไม่ได้แจ้งแท็บอื่นทันที (แท็บอื่นจะรู้ตอน refresh ครั้งถัดไป)
- **Session จาก fintech/embedded login** (ไม่มี browser SSO session): ยังไม่โดนพาเข้า SPA อัตโนมัติผ่าน SSO ticket — ต้องกดเข้าสู่ระบบ (ทาง Keycloak → Central ID)
- **Path ของ Keycloak**: endpoint ผูกกับรูปแบบ `<issuer>/protocol/openid-connect/*` (ไม่ได้อ่าน OIDC discovery) — เพิ่ม discovery ได้เมื่อต้องใช้กับ OP ตัวอื่น
- **Production**: พิจารณา BFF สำหรับแอปที่ข้อมูลอ่อนไหว · เพิ่ม `end_session`/Back-Channel Logout · ตรวจ `iss` ที่ token endpoint (RFC 9207 token binding)
