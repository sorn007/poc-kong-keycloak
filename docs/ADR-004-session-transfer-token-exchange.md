# ADR-004: STT ข้ามแอป (Session Transfer) ด้วย One-time Code + Token Exchange

วันที่: 2026-11-17 · สถานะ: ยอมรับ (นำไปใช้จริงใน POC แล้ว — `setup-stt.sh` + `stt-test.sh` 21/21)

## บริบท

แอปที่ login แบบไม่ผ่าน browser flow — Mobile (native session), Fintech (Embedded Login / Direct Grant) — ไม่สร้าง SSO session ใน browser จึงสลับไปเปิดแอปเว็บอื่น (Buyer/CIS Portal) แล้วต้อง login ใหม่เสมอ ผู้ใช้ต้องการ "user เดียวกัน ใช้ได้ทุกแอป" โดยที่ยังคงรักษากฎ aud ของ Token Contract (ห้ามใช้ token aud=buyer-api กับ CIS เด็ดขาด)

## ทางเลือก

| ทางเลือก | ข้อดี | ข้อเสีย |
| --- | --- | --- |
| A. ตัว token เองพกหลาย aud (buyer-api + cis-api) | ง่ายสุด ไม่ต้องแตะ KC | token รั่ว = ใช้ได้ทุกระบบทันที — ขัดหลัก minimal privilege |
| B. Token Exchange (KC Standard V2) ที่ปลายทาง | token ต้นทาง minimal; ปลายทางได้ token aud ของตัวเอง ออกใหม่/สั้นอายุ; เป็นมาตรฐาน RFC 8693 | ต้องตั้งค่า KC เพิ่ม (confidential client + เปิด switch ราย client + scope เติม aud bridge) |
| C. ส่ง identity แล้วปลายทาง login ซ้ำ (AC flow) | ปลอดภัยสุด | ผู้ใช้ต้อง login ใหม่ — ย้อนกลับไปแก้โจทย์เดิม |

## การตัดสินใจ

เลือก **B** ผสมกลไกโอน session ของเราเอง (STT — จำลอง Auth0 Native-to-Web SSO):

1. **Broker ที่ ID Portal**: `POST /stt/create` (Bearer token + `dest`) → one-time code อายุ 60 วิ ผูกปลายทาง; `POST /stt/redeem` (code + `dest`) → ปลายทางตรวจ `aud` ของตัวเองเสมอ
2. **aud เดียวกัน** (Buyer/fintech ใช้ buyer-api): ใช้ token ต้นทางต่อได้ทันที (ตรวจ aud ก่อน)
3. **aud ต่างกัน** (→ CIS ต้องการ cis-api): ปลายทางทำ **Token Exchange** (KC Standard V2) เอา subject token แลก token ใหม่ `aud=cis-api` — user (sub) คงเดิม, claims ครบจาก mappers ของ cis-web
4. Token ต้นทางที่ต้องการข้ามไป CIS ขอ optional scope **`stt-bridge`** (audience mapper เติม `cis-web` ลง aud) — เติมแค่ "ชื่อ client ที่รับสิทธิ์ exchange" ไม่เพิ่ม scope API ของ CIS; Guard ของ CIS ยังตรวจ `aud=cis-api` เสมอ ดังนั้น token นี้ใช้เรียก CIS API ตรง ๆ ไม่ได้

## เงื่อนไขของ KC 26 (จากการทดสอบจริง)

- Feature `token-exchange-standard:v2` เปิด default แต่**ต้องเปิด switch ราย client** ฝั่ง requester: attribute `standard.token.exchange.enabled="true"`
- requester ต้องเป็น **confidential client** → เลื่อน cis-web จาก public เป็น confidential (มี `CIS_CLIENT_SECRET`)
- requester ต้องอยู่ใน **aud ของ subject token** (ยกเว้น requester เป็นเจ้าของ token เอง) → ที่มาของ scope stt-bridge
- บังคับส่ง `subject_token_type=urn:ietf:params:oauth:token-type:access_token` ไม่งั้น error
- เป้าหมาย (aud ของ token ใหม่) มาจาก scopes ของ requester — cis-web มี identity-cis-web → `cis-api` พร้อม mappers principal_type/tenant_id ครบ

## ส่วนขยาย: SSO Ticket ของ ID กลาง (เปิดแท็บใหม่ตรง ๆ ไม่ต้อง login) — 2026-11-17

STT ข้างบนต้องมี "ต้นทางกด" ทุกครั้ง — ถ้าเปิด CIS ตรง ๆ ในแท็บใหม่ (ไม่ผ่าน fintech) ยังต้อง login เพราะต้นทางไม่ได้ถูกเรียกให้สร้าง code และ browser ไม่มี SSO session (Direct Grant ไม่ผ่าน browser flow) ทางแก้: **SSO Ticket** — ตั๋วระดับ ID กลางแบบ reusable:

1. fintech login สำเร็จ → ขอตั๋วจาก ID Portal (`POST /sso/ticket` + refresh_token ของ session) → set cookie **`central_sso`** — cookie ของ host `localhost` ซึ่ง browser ส่งให้ **ทุก port** (3000-3050) ใน POC
2. ปลายทาง (Buyer/CIS) เจอไม่มี session และมีตั๋ว → redeem (`POST /sso/redeem` + dest) → aud ตรง ใช้เลย / aud ต่าง แลกด้วย Token Exchange เหมือน STT — **ตั๋วใช้ซ้ำได้ตลอดอายุ (30 นาที)**
3. broker เก็บ refresh_token ไว้ — redeem ช่วงที่ token ใกล้หมดอายุ (<60 วิ) จะ **refresh ให้ใหม่อัตโนมัติ** (refresh grant ด้วย client ต้นทาง; broker ถือ secret ของ confidential client จาก env)
4. logout ที่ fintech → revoke ตั๋ว → แท็บใหม่ทุกแอปต้อง login ใหม่ (session ที่ได้ไปแล้วยังอยู่จน exp ตามข้อจำกัด JWT)

Production mapping: ตั๋วนี้คือ "SSO cookie ของ id.central.com" ที่ Universal Login ทำอยู่แล้ว — POC ใช้ cookie localhost ข้าม port จำลอง (cookie ไม่ผูก port ตาม RFC 6265) — production ต้องใช้ subdomain ร่วม เช่น *.central.com และ broker ควรเป็นตัว ID กลางเอง (Universal Login) ไม่ใช่แอปใดแอปหนึ่ง

## ผลกระทบ

- cis-web confidential: ทุก flow ที่แลก code ของ cis-web ต้องส่ง `client_secret` (CIS app, sso-test, smoke scripts — แก้ครบแล้ว)
- เพิ่ม `CIS_CLIENT_SECRET` ใน .env/.env.example + compose (keycloak env สำหรับ realm import ด้วย)
- ความเสี่ยงคงเหลือ (POC ยอมรับ): code ผูกปลายทางด้วย client id ที่ผู้ถือ code ประกาศเอง — production ควรเพิ่ม binding ที่แข็งแรงขึ้น (เช่น PKCE-like proof หรือ bind กับ redirect_uri + client auth ของปลายทาง)
- ทิศทาง production: ถ้ามี STT ข้าม realm/ข้ามองค์กร ควรย้าย broker ไปที่ ID กลางพร้อม consent จากผู้ใช้ก่อนออก code (จำลอง deny ที่ mobile ปัจจุบัน)

## Logout กลาง propagate จริง (ส่วนขยายที่สอง — 2026-11-17)

ตั๋ว reusable สร้างปัญหาใหม่: session ที่ปลายทางได้ไปแล้ว (cookie=token) ยังมีชีวิตถึง exp แม้ตั๋วถูก revoke → กด Logout กลางแล้วแอปอื่นยังใช้ได้ต่อ ทางแก้ 3 ชั้น: (1) **session ผูกตั๋ว** — fintech เก็บ ticket id ใน server session, Buyer/CIS set cookie `sso_bound` ตอนรับ session จากตั๋ว (2) **liveness check** — เปิดหน้า page แต่ละครั้งปลายทางถาม broker `POST /sso/check` (in-memory, fail-open เมื่อ broker ล่ม) → ตั๋วตาย = เคลียร์ session + พาไป login ทันที (3) **global logout** — `POST /sso/logout` revoke ทุกตั๋ว (ปุ่ม Logout กลางของทุกแอปเรียก พร้อม Bearer ของ session ตัวเอง)

ข้อจำกัดที่ยอมรับ: API request ที่ถือ Bearer อยู่ยังผ่านจน exp (ข้อจำกัด JWT ตาม rootcase §6); authN ยัง verify JWT จาก JWKS เองทุก request — Rule 8 ไม่ถูกละเมิด (ตรวจ liveness ของ SSO เป็นอีกเรื่อง) — **production: ใช้ OIDC Back-Channel Logout** (attribute `backchannel.logout.url` ต่อ client + แอป validate logout_token) แทน per-request check
