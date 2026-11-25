# ADR-006 — Kong Custom Plugins แบบ "Shared Lua Library + Thin Plugins"

## บริบท

Custom plugins 3 ตัวของ POC (`oidc-central`, `oidc-introspect`, `central-apikey` — รวม 394 บรรทัด) เขียนแบบ **self-contained**: ทุกตัว copy logic ชุดเดิมซ้ำ — Bearer extraction (ซ้ำเป๊ะ 2 ที่), TTL cache per-worker + cap 500 (ซ้ำ 2 ที่), HTTP call + JSON decode + log (ซ้ำ 3 ที่), scope check (ซ้ำ 2 ที่ ต่างกันแค่ string/array), รูปแบบ error response (ซ้ำ 3 ที่)

ประเด็นเสี่ยงสำคัญที่สุดต่อ **การอัปเกรด Kong**: `oidc-central` require `kong.plugins.jwt.jwt_parser` — **Kong-internal API ที่ไม่รับประกัน stability ข้ามเวอร์ชัน** (finding 52 พบแล้วว่า resty.jwt ใน Kong 3.9 พฤติกรรมต่างจาก doc) — โค้ดกระจายใน handler ทำให้ทุกครั้งอัปเกรดต้องตรวจ 3 ไฟล์

## ทางเลือก

| | ทางเลือก | ผลดี | ผลเสีย |
| - | ------- | ---- | ------ |
| A | คง self-contained ตามเดิม | copy plugin ไปโปรเจกอื่นได้เดี่ยว ๆ · อ่านไฟล์เดียวจบ | logic ซ้ำ 5 ชุด — แก้ bug ต้องแก้ 3 ไฟล์ · Kong-internal dependency กระจาย |
| B | **Shared lib (`central_common`) + thin plugins** | กลไกซ้ำอยู่ที่เดียว · Kong-internal dependency isolate ใน 1 ไฟล์ · เปลี่ยน cache เป็น shm/redis แก้ที่เดียว | copy plugin เดี่ยว ๆ ต้องก๊อป lib ไปด้วย · อ่านต้องข้าม 2 ไฟล์ |

## การตัดสินใจ

เลือก **B** — โครงสร้างใหม่ (ไม่แตะ kong.yml / schema / KONG_LUA_PACKAGE_PATH / compose เลย):

```text
kong/custom/kong/lib/central_common/
  resp.lua    — error responses (401/403/503 shape เดียว)
  cache.lua   — TTL cache แบบเดียว (new(ttl, cap) → get/put)
  http.lua    — เรียก endpoint + decode JSON + log รูปแบบเดียว
  req.lua     — Bearer extraction · multi-header API key lookup
  claims.lua  — aud_ok · scope_ok (string) · scope_in_list (array)
  jwks.lua    — ⭐ DER/PEM + JWKS fetch/rotation + new_parser()
                (จุดเดียวที่แตะ kong.plugins.jwt.jwt_parser)
plugins/ (thin — เหลือเฉพาะ "ลำดับการตรวจ" ของตัวเอง)
  oidc-central/handler.lua    169 → ~60 บรรทัด
  oidc-introspect/handler.lua  68 → ~50 บรรทัด
  central-apikey/handler.lua  110 → ~65 บรรทัด
```

require path: `KONG_LUA_PACKAGE_PATH=/usr/local/custom/?.lua;;` ที่ตั้งไว้แล้ว resolve `require("kong.lib.central_common.<mod>")` → `/usr/local/custom/kong/lib/central_common/<mod>.lua` — ใช้ mount เดิม ไม่แตะ compose

## เหตุผล

1. **อัปเกรด Kong ปลอดภัยขึ้นจริง** — จุดที่พังข้ามเวอร์ชัน (internal API) มีไฟล์เดียว ตรวจจบ
2. production migration (cache per-worker → shm, fail-open → fail-closed) แก้ `cache.lua`/handler policy ที่เดียว
3. แก้ bug แถม: `central-apikey` เดิม shadow variable ทำให้ `X-Central-Owner` **เป็นค่าว่างเสมอ** (lookup ใหม่ได้ owner แต่โค้ดตั้ง `vowner = nil` ทับ) — refactor แก้พร้อม cache เก็บ {scopes, owner} ครบ

## ผลทดสอบ (2026-11-25)

- `openapi-test.sh` **31/31** (ครอบทั้ง 3 plugins: jwt/oidc-central · introspect · apikey 10 เช็ค) · `mcp-test.sh` **12/12** (contract กับ validate endpoint ไม่เปลี่ยน)
- log ยืนยัน: `jwks refreshed (keys=2)` มาจาก `jwks.lua:99` (lib ไม่ใช่ handler)

> หมายเหตุ: Kong 3.9 declarative bug "table index is nil" (finding 52) ไม่เกี่ยวกับ lib files — lib โหลดผ่าน require path ตอน request ไม่ใช่ตอน parse declarative config
