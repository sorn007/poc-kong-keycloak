package ticketcore

import (
	"context"

	"github.com/redis/go-redis/v9"
)

// redis.go — ตัวช่วยของ Redis backend ของ Core (Lua atomic consume + ctx)

func ctx() context.Context { return context.Background() }

// Lua: GET → ไม่มี = false (not found) · dest ไม่ตรง = "MISMATCH" (ไม่ consume)
// dest ตรง = DEL แล้วคืน entry JSON (atomic consume — เทียบเท่า mutex ของ memory)
// หมายเหตุ: entry ไม่มี field "dest" (SSO) → e["dest"]=nil ไม่ตรง ARGV เสมอ → MISMATCH
// (SSO ไม่เรียก Consume อยู่แล้ว — กันเผื่อเรียกผิด)
const luaConsume = `
local v = redis.call('GET', KEYS[1])
if not v then return false end
local e = cjson.decode(v)
if e["dest"] ~= ARGV[1] then return "MISMATCH" end
redis.call('DEL', KEYS[1])
return v`

var consumeScript = redis.NewScript(luaConsume)
