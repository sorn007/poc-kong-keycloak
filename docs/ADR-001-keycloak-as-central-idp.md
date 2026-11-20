# ADR-001: ใช้ Keycloak เป็น Central Identity Provider

## บริบท

Central มีปัญหา (rootcase.md): Buyer/CIS นำ token จาก Central ID ไปออก token ของตัวเอง ทำให้ session ไม่สัมพันธ์กัน และไม่มี credential กลางสำหรับ Open API การพัฒนา Authorization Server เองให้ครบมาตรฐาน (OIDC, JWKS, revocation, back-channel logout) มีต้นทุนสูงและเสี่ยงความผิดพลาดด้านความปลอดภัย

ทีมต้องการใช้ซอฟต์แวร์ Free/Open Source

## ทางเลือก

1. **พัฒนา Authorization Server เอง** — ควบคุมเต็มที่ แต่ต้องรับผิดชอบ security-critical code ทั้งหมด
2. **Keycloak (Free)** — IAM มาตรฐาน OIDC/OAuth2/SAML สมบูรณ์, realm/client/scope/mapper, admin API, identity brokering, user federation
3. **บริการ SaaS (Auth0/...)** — สะดวกแต่มีค่าใช้จ่ายและข้อมูล identity อยู่นอกองค์กร

## การตัดสินใจ

ใช้ **Keycloak** เป็น Central Identity Provider ของ POC และเป็นฐานของสถาปัตยกรรมเป้าหมาย โดยผู้ใช้ login ผ่าน Keycloak (POC) และประเมินเชื่อมกับ Central ID เดิมด้วย Identity Brokering ใน production (Option B — ดู migration-plan.md)

## เหตุผล / ผลกระทบ

- ได้ token lifecycle ที่ถูกต้องตามมาตรฐานโดยไม่ต้องเขียนเอง: refresh rotation, revocation, introspection, JWKS
- Buyer (NestJS) / CIS (Go Fiber) ตรวจ JWT ด้วย JWKS เหมือนกันทั้งสองภาษา — contract เดียว
- ข้อจำกัด: ต้องดูแล instance เพิ่ม, ต้องปรับแต่ง realm ให้ตรง contract (aud mapper ต้องสร้างเอง — Keycloak ไม่ใส่ aud ตาม client โดย default), ควรกำหนด key rotation runbook ก่อน production
