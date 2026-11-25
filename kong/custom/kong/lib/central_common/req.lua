-- central_common.req — อ่าน credential จาก request แบบเดียวกันทุก plugin
-- รวม Bearer extraction (ซ้ำเป๊ะใน oidc-central และ oidc-introspect เดิม)
-- และ multi-header API key lookup (central-apikey เดิม)
local _M = {}

-- bearer_token() → token | nil — อ่านจาก Authorization: Bearer <token>
function _M.bearer_token()
  local authz = kong.request.get_header("Authorization")
  if not authz or authz:sub(1, 7):lower() ~= "bearer " then
    return nil
  end
  return authz:sub(8)
end

-- api_key(names_str) → key | nil — ลองหลาย header ตามลำดับ (names เป็น comma-separated)
-- เช่น "apikey,X-API-Key" — รองรับทั้งชื่อมาตรฐาน Kong และ de facto
function _M.api_key(names_str)
  for name in (names_str or "apikey"):gmatch("[^,]+") do
    local v = kong.request.get_header(name)
    if v and v ~= "" then
      return v
    end
  end
  return nil
end

return _M
