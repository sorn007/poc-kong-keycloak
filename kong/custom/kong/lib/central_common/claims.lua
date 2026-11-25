-- central_common.claims — ตรวจ claims ของ token/API key แบบเดียวกันทุก plugin
-- รวม aud/scope check เดิมที่แยกซ้ำสองที่ (scope_ok รับ string, has_scope รับ array — semantics เดียวกัน)
local _M = {}

-- aud_ok(claims, audience) — aud อาจเป็น string เดียว หรือ array (JWT มาตรฐานยอมทั้งสองแบบ)
function _M.aud_ok(claims, audience)
  local a = claims.aud
  if type(a) == "string" then return a == audience end
  if type(a) == "table" then
    for _, v in ipairs(a) do if v == audience then return true end end
  end
  return false
end

-- scope_ok(scope_str, required) — scope ใน JWT เป็น space-separated string ("openid orders.read")
function _M.scope_ok(scope_str, required)
  if not required or required == "" then return true end
  for s in string.gmatch(scope_str or "", "%S+") do
    if s == required then return true end
  end
  return false
end

-- scope_in_list(scopes_arr, required) — scope จาก validate endpoint เป็น JSON array
function _M.scope_in_list(scopes_arr, required)
  if not required or required == "" then return true end
  for _, s in ipairs(scopes_arr or {}) do
    if s == required then return true end
  end
  return false
end

return _M
