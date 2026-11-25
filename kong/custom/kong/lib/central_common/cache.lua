-- central_common.cache — TTL cache แบบเดียวกันทุก plugin (per-worker, module-level)
-- รวม pattern เดิมที่ copy ซ้ำใน oidc-introspect และ central-apikey:
-- • ttl ต่อ entry (วินาที) · cap จำกัดจำนวนรายการ (เกินแล้วล้างทั้งหมดแบบง่าย)
-- • หมายเหตุ POC: per-worker — production เปลี่ยนที่ไฟล์เดียวนี้เป็น shm/redis + fail-closed
local _M = {}

-- new(ttl_seconds, cap) → cache object พร้อม get(key) / put(key, value)
-- value ต้องเป็น table ที่เทียบความสดด้วย timestamp ภายใน (เราเก็บ ts ให้เอง)
function _M.new(ttl, cap)
  cap = cap or 500
  local store = {}

  local function size()
    local n = 0
    for _ in pairs(store) do n = n + 1 end
    return n
  end

  local self = {}

  -- get(key, now) → cached value | nil (เมื่อไม่มี หรือหมดอายุ)
  function self.get(key, now)
    local e = store[key]
    if e and (now - e.ts) < ttl then
      return e.value
    end
    return nil
  end

  -- put(key, value, now)
  function self.put(key, value, now)
    store[key] = { value = value, ts = now }
    if size() > cap then
      store = {} -- ล้างทั้งหมดแบบง่าย (POC — production ใช้ LRU บน shm)
    end
  end

  return self
end

return _M
