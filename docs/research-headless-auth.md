# Research: ความเป็นไปได้ของ Headless Authentication บน Keycloak (Custom Extension vs Built-in)

> สถานะ: **ฉบับร่างสำหรับประกอบการตัดสินใจ** · วันที่: 2026-11-15 · ผู้จัดทำ: Central Identity Engineer
> อ้างอิงเวอร์ชันทดสอบ: Keycloak **26.3.5** (image quay.io/keycloak/keycloak:26.3 — ทดสอบจริงใน POC นี้)
> เอกสารที่เกี่ยวข้อง: [rootcase.md](../rootcase.md) · [ADR-002 Token Contract](ADR-002-token-contract.md) · [migration-plan.md](migration-plan.md) · [test-results.md](test-results.md)

---

## 1. บทคัดย่อ (Executive Summary)

มีโจทย์ในอนาคตว่า **แอป (เช่น Mobile หรือ Seller) อาจต้องการทำหน้าจอ login ของตัวเองเต็มรูปแบบ** — ไม่ redirect ไปหน้า login กลางของ Keycloak เลย (เรียกว่า **Headless Authentication**)

ผลการวิจัยสรุปได้ว่า:

1. **Headless มีอยู่ใน Keycloak built-in แล้วผ่านมาตรฐาน OIDC: CIBA (Client Initiated Backchannel Authentication)** — แอปทำ UI เองทั้งหมด ผู้ใช้ยืนยันผ่านอุปกรณ์/แอปอื่น แล้วแอปรับ token ด้วยการ poll — **ไม่ต้องเขียน extension** (ประเมินแรงงาน ~3-5 วันทำการสำหรับ pilot)
2. **Custom Extension เทคนิคทำได้จริง** (SPI ครบ: RealmResourceProvider, Authenticator, CredentialProvider, ThemeSelector) แต่ถ้าใช้เพื่อ "สร้าง login protocol ใหม่ทั้งตัว" จะเป็น **งานขนาด 30-60+ วันทำการ ความเสี่ยงสูง** และสวนกระแสมาตรฐาน — **ไม่แนะนำ**
3. สิ่งที่ควรทำตามลำดับ: **Phase 0** pilot CIBA → ประเมิน UX จริง → **decision gate** → เฉพาะกรณียังขาดจริง ๆ จึงเขียน extension แบบ scope เล็ก (REST resource สั้น ๆ) ไม่ใช่ login protocol ทั้งตัว

> หมายเหตุ: แนวคิด "สร้าง Central Authentication Service กลางที่แอปเรียกเอง" ถูกวิเคราะห์และ**ไม่แนะนำ**แล้ว (แอปเก็บ/ส่ง credential แทน IdP = anti-pattern + ขัดกฎ repo ข้อ 8) — ดูสรุปใน §6

---

## 2. ที่มาและขอบเขต

### 2.1 ปัญหาที่ผลักดัน

- แอปอนาคต (Mobile, Seller และอื่น ๆ) อาจต้องการ **หน้าจอ login ของตัวเอง** (branding/UX เต็มรูปแบบ) ไม่ใช่แค่ธีม
- ไม่ต้องการให้เห็นว่าเบื้องหลังคือ Keycloak/Auth0/IdP อื่น (แนวคิด Auth Center ที่เคยวิเคราะห์ — สรุปว่า OIDC มาตรฐานคือ abstraction ที่ดีที่สุด)
- ต้องการรู้ **ต้นทุน/ความเสี่ยงจริง** ก่อนตัดสินใจลงทุนเขียน Keycloak Custom Extension

### 2.2 ขอบเขตการวิจัย (in scope)

- Built-in options ของ Keycloak 26.3 สำหรับ authentication แบบไม่ผ่านหน้า login page (headless)
- Custom Extension: SPI ที่เกี่ยวข้อง, วิธี build/deploy, effort, ความเสี่ยง
- ผลกระทบต่อสถาปัตยกรรมปัจจุบัน (Brokering, Token Contract ADR-002, Guard ฝั่งแอป)

### 2.3 นอกขอบเขต (out of scope)

- การเลือก IdP ภายนอก (Auth0/Okta) เทียบราคา
- HA/monitoring (เป็นขั้นตอนก่อน production — ดู migration-plan §3)
- การเขียน login protocol ใหม่ทั้งตัวบน Auth Center กลาง (วิเคราะห์แล้ว — ไม่แนะนำ)

---

## 3. สถาปัตยกรรมปัจจุบัน (หลักฐานจาก POC — ทดสอบจริง 2026-11-13)

```text
Mobile/Web Apps ──OIDC (PKCE)──▶ realm central (Keycloak ซ่อนเบื้องหลัง)
                                    │ Identity Brokering (auto-link)
                                    ▼
                        realm central-id-upstream = "Central ID จริง" (ธีมเขียว)
```

ความสามารถที่พิสูจน์แล้ว (อ้าง test-results §1/§4):

| ความสามารถ | สถานะ | หลักฐาน |
| --- | --- | --- |
| OIDC Authorization Code + PKCE (web) | ✅ | `sso-test.sh` 10/10 |
| Mobile public client + PKCE enforced + loopback redirect | ✅ | `mobile-test.sh` 12/12 |
| Refresh token rotation + reuse detection (ยกเลิกทั้งตระกูลเมื่อถูกขโมย) | ✅ | ข้อ 29 §4 |
| Identity Brokering + auto-link (เปลี่ยน IdP เบื้องหลัง = แก้ config จุดเดียว) | ✅ | ข้อ 15 §4, แถว 15 §1 |
| ธีม login ระดับ realm + ระดับ client (`login_theme` attribute) | ✅ built-in | ข้อ 24 §4 + source `DefaultThemeSelectorProvider` |
| Logout propagation downstream → upstream | ✅ | ข้อ 26 §4 |
| **Headless login (ไม่ผ่านหน้า login page)** | ✅ ทดสอบแล้วผ่าน (CIBA — ดู §4.1, §8 Phase 0, `ciba-test.sh` 13/13) |

**ข้อสังเกตสำคัญจาก POC**: แอปทุกช่องทาง (web/mobile) ตรวจ token ด้วย `iss` + JWKS จาก env — **ไม่มีโค้ดที่ผูกกับ Keycloak** ดังนั้น "การไม่รู้จัก techstack เบื้องหลัง" เป็นจริงที่ระดับโค้ดแอปแล้ว — คำถามเหลืออยู่เฉพาะ **UX ของหน้า login** ซึ่งเป็นหัวข้อของเอกสารนี้

---

## 4. ทางเลือกที่ 1 — Built-in Headless Options (ไม่ต้องเขียน extension)

### 4.1 CIBA — Client Initiated Backchannel Authentication ⭐ ตัวเลือกหลัก

กลไก (มาตรฐาน OIDC: OpenID Connect CIBA Core 1.0):

```text
1. แอป ──POST──▶ /realms/central/protocol/openid-connect/ext/ciba/auth
                 (login_hint=<ชื่อผู้ใช้>, scope) ──▶ ได้ auth_req_id
2. แอปแสดงหน้าจอ UI ของตัวเอง (สแกนใบหน้า/OTP/ปุ่มยืนยัน — ทำอะไรก็ได้)
3. ผู้ใช้ยืนยันผ่านช่องทางที่กำหนด (เช่น แอป ID ส่ง push → ผู้ใช้กดยอมรับ)
4. แอป poll token endpoint (ทุก interval วินาที) จนได้ access/refresh/id token
```

**ค่า config ที่ Keycloak 26.3 รองรับ (CIBA Policy ระดับ realm):**

| Config | ค่าที่รองรับ | Default |
| --- | --- | --- |
| Backchannel Token Delivery Mode | **"poll" เท่านั้น** (ping/push ไม่รองรับใน OSS) | poll |
| Expires In (อายุ auth_req_id) | วินาที | 120 |
| Interval (ระยะห่างขั้นต่ำของ poll) | วินาที | 5 |
| User Hint | **login_hint เท่านั้น** | login_hint |

**ข้อจำกัดที่ต้องรับ:**
- **confidential client เท่านั้น** — mobile public client จะเรียก CIBA ตรง ๆ ไม่ได้ (ต้องมี backend/BFF ช่วยยิงและเก็บ secret)
- poll-only: แอปต้อง implement polling loop (มี interval ขั้นต่ำ 5 วินาที)
- ประสบการณ์ผู้ใช้: ผู้ใช้ยืนยัน "ผ่านอุปกรณ์อื่น" เสมอ (CIBA ออกแบบมาแบบ no-redirect) — ไม่ใช่การพิมพ์รหัสผ่านในแอปเดียวกัน

**ความเป็นไปได้ (feasibility): สูง — ทำได้ทันที ไม่ใช้ extension**
- effort ประมาณการ: 3-5 วันทำการ (เปิด CIBA Grant ที่ client + backend approve endpoint + polling logic + ทดสอบ)
- เหมาะกับ: mobile app ที่มีแอป ID คู่กัน, UX แบบ "ยืนยันผ่านมือถือ"

### 4.2 Device Authorization Grant

- `/realms/{r}/protocol/openid-connect/auth/device` → ได้ device_code + user_code → ผู้ใช้เปิด URL อื่นพิมพ์ code → อุปกรณ์ poll ได้ token
- เหมาะ: TV/IoT/คอนโซล | **ไม่ใช่** headless แท้ (ยังต้องมี browser ที่อื่น)

### 4.3 Client Credentials (M2M)

- มีแล้วใน POC (partner-001 ผ่าน Kong) — headless แท้ ไม่มี user context

### 4.4 Direct Access Grants (ROPC) — ⛔ ห้ามใช้กับแอปจริง

- `grant_type=password`: headless แท้แต่**ส่งรหัสผ่านผ่านแอป** — ไม่มี MFA/SSO/broker, ฝ่าฝืน best practice, ขัดกฎ repo (credential handling) — ปิดไว้ที่ mobile-app อยู่แล้ว

---

## 5. ทางเลือกที่ 2 — Custom Extension (เขียน Java SPI เพิ่มใน Keycloak)

### 5.1 สิ่งที่ต้องเตรียม (checklist พื้นฐาน)

| ขั้น | รายการ | รายละเอียด |
| --- | --- | --- |
| 1 | **Maven/Gradle project** | Java 21, dependencies `keycloak-core` + `keycloak-server-spi` + `keycloak-server-spi-private` (scope=provided), version **ตรง KC เป๊ะ** (26.3.5) |
| 2 | **SPI ที่ implement** | ดูตาราง §5.2 — เลือกตามจุดประสงค์ |
| 3 | **ลงทะเบียน** | ไฟล์ใน `META-INF/services/` เช่น `org.keycloak.services.resource.RealmResourceProviderFactory` (เนื้อหา = FQCN ของ factory) |
| 4 | **Deploy** | copy JAR → `/opt/keycloak/providers/` → **`kc.sh build` ทุกครั้ง** (Quarkus re-index) — ลืมขั้นนี้ = provider ไม่โหลด |
| 5 | **Docker** | custom image `FROM quay.io/keycloak/keycloak:26.3` + COPY jar + `RUN kc.sh build` → compose เปลี่ยน `image:` เป็น `build:` |
| 6 | **ตั้งค่า/เปิดใช้** | Admin API หรือ flow config (รูปแบบเดียวกับ `setup-brokering.sh` ที่เขียนไว้) |
| 7 | **Regression suite** | script ทดสอบ 7 ตัวของ POC + mobile-test กลายเป็นมาตรฐานรันซ้ำทุกครั้งที่อัปเกรด KC |

### 5.2 SPI ที่เกี่ยวข้องตามจุดประสงค์

| จุดประสงค์ | SPI | หมายเหตุ |
| --- | --- | --- |
| เพิ่ม REST API ใน KC (headless login/OTP delivery/verify) | `RealmResourceProvider` + Factory | เขียน endpoint ใหม่ใน KC ได้ — **ตัวเลือกที่เหมาะที่สุดถ้าจะเขียนจริง** (scope เล็ก ไม่แตะ login protocol) |
| ขั้นตอนใหม่ใน login flow (เช่น OTP, คำถามยืนยัน) | `Authenticator` + `AuthenticatorFactory` | **อยู่ใน `server-spi-private`** — javadoc ยืนยันว่า custom authenticator (เช่น SMS OTP) เรนเดอร์หน้าใน flow เดิมได้ (action URL `/realms/{r}/login-actions/authenticate`) — เพิ่มเข้า flow ผ่าน Admin Console/Admin API (แบบที่เราทำใน setup-brokering) |
| Required action ใหม่ | `RequiredActionFactory` | — |
| Credential ประเภทใหม่ (biometric/OTP storage) | `CredentialProvider` + Factory | ซับซ้อนสุด |
| สลับธีมตาม client (เคส Seller) | `ThemeSelectorProvider` + Factory | **ไม่จำเป็นแล้ว** — KC 26.3 มี client attribute `login_theme` built-in (ยืนยันจาก source `DefaultThemeSelectorProvider` — ลำดับ client → realm → default) |
| ส่ง event/audit ออกภายนอก | `EventListenerProvider` + Factory | ใช้บ่อย ความเสี่ยงต่ำ |

### 5.3 ข้อจำกัดที่ยากต่อการหลีกเลี่ยง (hard limits)

| ข้อจำกัด | รายละเอียด |
| --- | --- |
| **ไม่มี "Headless Login Protocol" สำเร็จรูป** | ถ้าต้องการ login ผ่าน REST ล้วน (แอปพิมพ์ user/pass → ส่ง → ได้ token) ต้องเขียน extension ที่ขับ **AuthenticationSessionModel lifecycle** เอง — ใช้ API ภายในที่ไม่มี public contract, ต้องทำ security ทั้งชุดเอง (rate limit, lockout, replay, audit, MFA orchestration) → ประเมิน **30-60+ วันทำการ** + security review + ต้นทุน maintain ทุกอัปเกรด |
| Script authenticator (JS) ถูกถอดออกแล้ว | KC 26 ไม่รองรับ deploy JS — ต้องเป็น Java JAR เท่านั้น |
| path `/realms/{realm}/protocol/openid-connect/...` fixed | ไม่มี option เปลี่ยนรูปแบบ path (ซ่อน stack แบบ rewrite = ต้องทำที่ proxy ฝั่งเรา — fragile) |
| CIBA delivery mode = poll เท่านั้น (OSS) | ping/push เป็นของ KC Enterprise |
| ระดับ CIBA: confidential client เท่านั้น | mobile public client ใช้ตรงไม่ได้ (ต้องมี backend ช่วย) |
| upgrade cost | `server-spi-private` ไม่รับประกัน backward-compat — ทุกอัปเกรด KC ต้อง rebuild + test extension ใหม่ |

### 5.4 การประเมินความเป็นไปได้ของรูปแบบ extension ที่พิจารณา

| รูปแบบ extension | ความเป็นไปได้ | Effort (ประมาณ) | ความเสี่ยง | ความเห็น |
| --- | --- | --- | --- | --- |
| **REST resource เล็ก ๆ** (เช่น endpoint ส่ง OTP ของตัวเอง, verify ระบบภายนอก) | ✅ สูง | 3-7 วัน | ต่ำ | คุ้มถ้า requirement เจาะจง |
| **Custom Authenticator** (OTP/SMS/ผูกอุปกรณ์) | ✅ สูง (มี reference จาก docs: secret-question, SMS OTP) | 5-10 วัน | ต่ำ-กลาง | เพิ่มใน flow ที่มีอยู่ได้ |
| **Event listener** (audit ส่ง SIEM) | ✅ สูง | 2-4 วัน | ต่ำ | — |
| **Theme selector ตาม client/UA** | ⚠️ ไม่จำเป็น | 5-8 วัน | กลาง | ใช้ client attribute `login_theme` built-in แทน |
| **Headless login protocol ทั้งตัว** (REST login ล้วน) | ⚠️ ทำได้แต่**ไม่แนะนำ** | 30-60+ วัน | **สูงมาก** | สร้าง IdP ใหม่ซ้ำซ้อน + security liability + สวนมาตรฐาน |

---

## 6. ประเด็นความปลอดภัย (ต้องผ่านก่อนอนุมัติทุกกรณี)

1. **ห้ามแอปใดจัดการ credential แทน IdP** — ฟอร์ม login ของแอปที่ส่งรหัสผ่านไป API ของเรา/extension = รูปแบบ phishing + รับความเสี่ยง credential handling ทั้งหมด (สอดคล้องข้อ 24 ใน test-results §4)
2. Headless ทุกแบบต้องมี **user consent/step-up** ที่ผู้ใช้ควบคุม (CIBA ออกแบบมาเพื่อจุดนี้)
3. Extension ใด ๆ ต้องผ่าน: brute-force/lockout hook, rate limit, audit event, ทดสอบ replay
4. Token Contract (ADR-002) ต้องคงเดิม — claims (`principal_type`, `tenant_id`, `aud`) ต้องมาจาก mapper อย่างเดียว ไม่รับจาก API ภายนอก
5. ยึดกฎ repo ข้อ 8: ห้ามสร้าง middleware กลางที่ทุก request ต้องวิ่งผ่าน

---

## 7. ตารางเปรียบเทียบสรุป

| เกณฑ์ | CIBA (built-in) | Device Flow (built-in) | Extension: REST เล็ก | Extension: Headless login protocol |
| --- | --- | --- | --- | --- |
| Effort | 3-5 วัน | 1-2 วัน (เปิดใช้ + ทดสอบ) | 3-7 วัน | 30-60+ วัน |
| แอปทำ UI login เอง | ✅ ทั้งหน้า | บางส่วน (ยังมี browser จุดยืนยัน) | — | ✅ ทั้งหน้า |
| SSO/MFA/broker ครบ | ✅ | ✅ | — | ❌ ต้องทำเอง |
| ความเสี่ยง security | ต่ำ (มาตรฐาน OIDC) | ต่ำ | ต่ำ-กลาง | สูงมาก |
| ต้นทุน upgrade KC | ไม่มี | ไม่มี | ต่ำ | สูง (private SPI) |
| มาตรฐาน/อนาคต | ✅ OIDC CIBA | ✅ RFC 8628 | — | ❌ สวนกระแส |

---

## 8. ข้อเสนอ (Recommendation) และแผน

### ข้อเสนอหลัก

> **ใช้ CIBA (built-in) เป็นแนวทาง Headless ของระบบ — ไม่เขียน Custom Extension เพื่อสร้าง login protocol ใหม่** เปิดให้ Extension เข้ามาได้เฉพาะ scope เล็กที่มี requirement เจาะจง (REST เล็ก/Authenticator/EventListener) โดยผ่าน decision gate

### แผน 3 ระยะ

| Phase | งาน | Effort | Decision Gate |
| --- | --- | --- | --- |
| **Phase 0 — Pilot CIBA** | ✅ **ทำแล้ว (2026-11-15)**: client `headless-app` (realm central) + `id-device` :3040 (AD) + `headless-demo` :3030 (CD) + `ciba-test.sh` 13/13 + Playwright ภาพ 16-20 — **Buyer API เดิมยอมรับ CIBA token → 200 โดยไม่แก้ Guard** | 3-5 วัน (ใช้จริง ~0.5 วัน) | ✅ UX ผ่าน — ดูภาพ docs/screenshots 16-20 |
| **Phase 1 — ประเมินผล** | รวบรวม feedback ผู้ใช้/ทีมแอป, วัดว่า CIBA ครอบ requirement กี่ % | 1-2 วัน | ถ้าครอบ ≥ ตามที่ตกลง → จบ ไม่ต้อง extension |
| **Phase 2 — Extension เฉพาะจุด (เงื่อนไขเท่านั้น)** | เขียน RealmResourceProvider/Authenticator เฉพาะ requirement ที่ CIBA ครอบไม่ได้ + custom docker image + regression suite | ตามตาราง §5.4 | ต้องอนุมัติโดยทีม security |

### เกณฑ์ตัดสินใจที่ต้องมีคำตอบก่อนเริ่ม Phase 2

1. Requirement ใดที่ CIBA/ธีม/flows มาตรฐานครอบไม่ได้ (ระบุเป็นข้อ ๆ)
2. ยอมรับต้นทุน maintain extension ตลอดอายุระบบ (ทุกอัปเกรด KC) หรือไม่
3. มีทีม Java + งบ security review หรือไม่

---

## 9. คำถามเปิด (Open Questions)

1. แอป ID คู่สำหรับยืนยัน CIBA (approve จาก push) จะมีจริงไหมใน product plan ปัจจุบัน?
2. Seller/Mobile ต้องการ "own UI" ระดับไหน — แค่ธีม (เคส 90% แรก) หรือทั้ง flow?
3. โดเมน identity จริงตอน production (id.central.com?) — กระทบ iss ตาม ADR-002
4. ต้องการ compliance พิเศษไหม (FAPI) ที่จะบังคับ client policy เพิ่ม

> **อัปเดต 2026-11-17:** คำถามเรื่อง Native-to-Web SSO (โอน session mobile → เว็บ) ปิดแล้ว — ทำได้จริงและข้ามแอปครบ ดู §11 ภาคผนวก + ADR-004

---

## 10. อ้างอิง

- Keycloak 26.3.5 (source ยืนยันจาก tag จริง): `DefaultThemeSelectorProvider.java` (client `login_theme`), `RealmManager.java` (admin-cli lightweight), `FolderTheme.java` (resources dir), `OIDCAttributeMapperHelper.java` (config key เอกพจน์), `IdentityProviderAuthenticator.java` (`defaultProvider`), `IdpAutoLinkAuthenticatorFactory.java` (`idp-auto-link`), `AuthorizationEndpointChecker.java` (PKCE enforcement), `TokenManager.java` (rotation + `reuse_id`)
- Keycloak Server Administration: Identity Brokering, First Login Flow, Default Identity Provider, CIBA Policy, Device Grant, Hostname v2, Reverse Proxy (`proxy-headers`)
- Keycloak Server Development: Authentication SPI, RealmResourceProvider, Theme SPI, packaging (`META-INF/services` + `kc.sh build`)
- ผลทดสอบจริงใน POC: `docs/test-results.md` §1 (แถว 15-16), §4 (ข้อ 1-29) · สคริปต์: `scripts/sso-test.sh`, `scripts/mobile-test.sh`, `scripts/setup-brokering.sh`
- มาตรฐาน: OpenID Connect CIBA Core 1.0, RFC 7636 (PKCE), RFC 8252 (Native Apps), RFC 8628 (Device Flow)

## 11. ภาคผนวก: STT Session Transfer ข้ามแอป (ทดสอบจริงแล้ว 2026-11-17)

คำถามที่ค้างจาก §9 (Native-to-Web SSO) ปิดแล้วด้วยกลไกที่ประกอบจากชิ้นมาตรฐานของ Keycloak — การตัดสินใจที่ ADR-004, การตั้งค่าที่ `scripts/setup-stt.sh`, ผลที่ `docs/test-results.md` §1 ข้อ 19 (21/21 PASS)

**สถาปัตยกรรมสุดท้าย**

```text
ต้นทาง (mobile/fintech มี session อยู่แล้ว)          ปลายทาง (เว็บที่รับ session)
  │ 1. POST /stt/create + dest (ID Portal broker)     ▲ 3. redeem code + dest
  │    ◀── one-time code (60s, ใช้ครั้งเดียว)           │    ตรวจ aud ของตัวเอง
  │ 2. browser เปิด /auth/stt?code= ──────────────────▶│ 4. aud ตรง → session เลย
  ▲                                                   │ 4'. aud ต่างกัน → Token Exchange (KC V2)
  │                                        เป็น token aud ของปลายทาง (CIS: cis-api) ▶ /projects 200
```

**ชิ้นส่วนมาตรฐานที่ใช้**: one-time code + TTL (OAuth code ธรรมดา), Token Exchange = RFC 8693 / KC Standard V2, audience binding ผ่าน protocol mapper (scope `stt-bridge` เติม cis-web ลง aud — ไม่เพิ่มสิทธิ์ API)

**ข้อจำกัดที่บันทึกไว้**: code ยังไม่ bind ปลายทางแบบ cryptographic (ผู้ถือ code + รู้ dest ใช้ได้), ยังไม่มี consent ผู้ใช้ตอนออก code (deny เกิดก่อนสร้าง), broker ใช้ issuer-only verification — production ทั้งสามข้อต้องปิดก่อนขึ้นจริง

**SSO Ticket (ขยายต่อ — เปิดแท็บใหม่ตรง ๆ ไม่ต้อง login)**: ตั๋ว reusable 30 นาทีของ ID กลาง — แอปต้นทาง login สำเร็จแล้วขอตั๋ว (`POST /sso/ticket`) มา set เป็น cookie `central_sso` (host localhost → browser ส่งให้ทุก port ใน POC เพราะ cookie ไม่ผูก port ตาม RFC 6265) — ปลายทางเจอไม่มี session จะ redeem ตั๋วแทนการ login (broker เก็บ refresh_token ต้นทางไว้ต่ออายุ token ใหม่ให้อัตโนมัติ) — logout ต้นทาง = revoke — production mapping: นี่คือ SSO cookie ของ `id.central.com` ที่ Universal Login ถือเอง

**เทียบกับ Auth0 Native-to-Web SSO**: concept เดียวกัน (ต้นทางมี session → ออก ticket อายุสั้น → เว็บรับเป็น session) — Auth0 ซ่อน broker ไว้ใน platform; แบบ Keycloak เราประกอบ broker เองที่แอป ID กลาง แลกด้วยการคุม security เองครบทุกขั้น (one-time, dest binding, aud enforcement ที่ปลายทาง)
