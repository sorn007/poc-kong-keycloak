# ADR-003: บทบาทของ Kong Gateway และการจัดการ Signing Key

## บริบท

Kong OSS (Free) ไม่มี OIDC plugin (เป็น Enterprise Only) — jwt plugin ของ OSS ตรวจได้เพียง signature + `iss` (key_claim) + `exp`/`nbf` แต่ไม่ตรวจ `aud`, `scope`, revocation อีกทั้ง Kong DB-less ต้องรู้ public key ล่วงหน้าจากไฟล์ config

## การตัดสินใจ

1. **Kong ทำหน้าที่ gateway ไม่ใช่ authorization server**: routing, rate limiting, key-auth (API key ทางเลือกสำหรับ integration ง่าย) และ jwt plugin เป็น gate แรก (signature + iss) — การตรวจที่เชื่อถือได้ (`aud`/`scope`/tenant) ยังเป็นหน้าที่ Central Guard/Middleware ของ Buyer/CIS เสมอ (defense in depth)
2. **ให้ Keycloak สร้าง signing key เองตอน import realm ครั้งแรก** แล้ว `scripts/setup.sh` ดึง public key ผ่าน Admin REST (`GET /admin/realms/central/keys` — คืนค่าเป็น PEM) มา inject ลง `kong.yml` — private key ไม่ออกจาก Keycloak และไม่จำเป็นต้องจัดการ PEM ใน repo

## เหตุผล

- ไม่ต้องพึ่ง Kong Enterprise และไม่สร้าง middleware service กลาง (latency/SPOF)
- ลอง static key import ผ่าน realm JSON แล้ว KC 26 ปฏิเสธ (PemException ตอน decode) — การดึงผ่าน Admin API หลัง boot เชื่อถือได้กว่า
- Key เก็บใน postgres volume → คงที่ตลอด POC; ถ้า `down -v` ล้าง volume ต้องรัน `setup.sh` ใหม่เพื่อ sync kong.yml

## ข้อจำกัด / ก่อนขึ้น Production

- POC ยังไม่มี key rotation — production ต้องมี runbook rotation (kid ใหม่ co-exist กับ kid เดิมใน JWKS จน token เก่าหมดอายุ) และ sync public key เข้า Kong อัตโนมัติ (CI หรือ process กำกับ — ใช้ flow เดียวกับ setup.sh ได้)
- หากอนาคตต้องการ gateway enforcement ครบระดับ OIDC (aud/scope/introspection) ให้ประเมิน Kong Enterprise OIDC plugin หรือปล่อยให้ service-level guard เป็นตัวตัดสินเหมือนปัจจุบัน
- `key-auth` (API key) เทียบให้เห็นแล้วว่าพอสำหรับ integration เบา ๆ แต่ไม่มี scope/rotation/revoke ที่ระดับ OAuth — Open API ของ Partner จึงใช้ OAuth client credential เป็นหลัก (rootcase §5)
