# ADR-007 — ยุบกลไก SSO Ticket + STT เป็น `ticketcore` เดียว (กลไกรวม · ความหมายแยก)

## บริบท

ID Portal มี store 2 ชุดที่เขียน duplicate กัน ~60% (466 บรรทัด):

- **SSO Ticket** (`internal/sso`) — ตั๋ว SSO reusable 30 นาที + refresh token ไว้ renew + Revoke/RevokeAll
- **STT Code** (`internal/stt`) — one-time code 60 วินาที + destination binding

ทั้งคู่มีโครงเหมือนกัน: mutex + map, ID สุ่ม 32 ไบต์ base64url, entry{username, accessToken, aud, issuedFor, ...}, lazy-cleanup, Redis JSON + SETEX/KeepTTL, Lua atomic consume — เขียนซ้ำสองชุดเต็ม ๆ (หลังเพิ่ม Redis backend ใน P1 ยิ่งซ้ำหนัก: `sso/redis.go` 141 บรรทัด vs `stt/redis.go` 90 บรรทัด)

## ทางเลือก

| | ทางเลือก | ผลดี | ผลเสีย |
| - | ------- | ---- | ------ |
| A | รวมเป็น struct เดียวมี flags (consumeOnRedeem/destRequired/allowRenew/revocable) | ไฟล์น้อย | **flag swamp** — ต้องจำว่า flag ชุดไหน valid รวมกันได้ · audit ยากขึ้น · ชื่อ "One-Time Exchange" ไม่ตรงเพราะ SSO ไม่ใช่ one-time |
| B | **ยุบเฉพาะกลไก (`ticketcore`) คงความหมายเป็น 2 adapters** | atomic/TTL/serialization/Lua เขียนครั้งเดียว · audit จบที่ package เดียว · public interface + handlers + tests ไม่เปลี่ยน | เพิ่ม 1 layer (ต้องอ่าน ticketcore + adapter) |

## การตัดสินใจ

เลือก **B** — กลไกรวม ความหมายแยก:

```text
internal/ticketcore/          ← กลไกเดียว (audit จบที่นี่)
  ticketcore.go — Payload(union fields) · Options{TTL, CleanupAfter, Prefix}
                  Issue · Peek (ไม่ consume) · Check · Consume (one-time + dest)
                  Update (renew) · Revoke · RevokeAll
  redis.go      — Lua atomic consume (GET→dest→DEL)
internal/sso/sso.go    ← adapter ~90 บรรทัด: TicketStore = ticketcore แบบ reusable+renew+revocable
internal/stt/stt.go    ← adapter ~70 บรรทัด: CodeStore = ticketcore แบบ one-time+dest binding
```

- **Public interface เดิมทุกจุด** — `sso.TicketStore` / `stt.CodeStore` (store.go) คงเดิม · handlers / `/sso/*` / `/stt/*` / Kong plugin / MCP ไม่แตะเลย
- sentinel errors เป็น **alias** ไปที่ ticketcore (`stt.ErrDestMismatch = ticketcore.ErrDestMismatch`) — `errors.Is` ทุกจุดทำงานเหมือนเดิม
- Revoke รวมเป็น **delete** ทั้งสอง backends (เดิม memory=delete, redis=flag+KeepTTL ต่างกัน — พฤติกรรมภายนอกเหมือนกันอยู่แล้ว รวมเป็นอันเดียวทำให้เหลือ concept เดียว)
- key prefix ใน Redis คงเดิม (`central:sso:ticket:*`, `central:stt:code:*`) — ตั๋วเดิมใน redis ใช้ต่อได้ทันทีหลัง deploy

## เหตุผล

1. บั๊กคลาส "อ่าน/serialize claim ผิด" (เช่น finding 55/56 jwtPayloadField) แก้ **ที่เดียวครบทั้งสอง flow**
2. เพิ่ม backend ใหม่ภายหลัง (เช่น DB) เขียนครั้งเดียวได้ทั้ง SSO และ STT
3. คง didactic value: เอกสาร/README ยังเล่า SSO Ticket กับ STT แยกกันได้ เพราะ semantics แยกจริงที่ adapter

## ผลทดสอบ (2026-11-25)

- unit test ใหม่ `ticketcore_test.go` 5 เคส (reusable peek · one-time consume · dest mismatch ไม่ consume · empty dest ปฏิเสธ · revoke/update/revokeall) + `stt_test.go` เดิมผ่านไม่แก้
- sweep ทุก suite **162/162 PASS** · พิสูจน์ restart ซ้ำ: ตั๋วรอดทั้ง `restart central-id` และ `restart redis` (AOF) ✅
- ผลพลอยได้จาก `go vet`: แก้ format string `%s` เกิน 1 ช่องในหน้า `/apikeys` (เรนเดอร์ `%!s(MISSING)` ใน card "วิธีใช้งาน" — pre-existing UI bug)
