-- oidc-introspect — custom Kong plugin (POC): ตรวจ token ผ่าน Keycloak introspection
-- endpoint (RFC 7662) — ปิดจุดอ่อนของ JWKS: token ที่ถูก revoke / user ถูก disable
-- จะกลายเป็น active=false ทันทีที่ Keycloak ฝั่ง server รู้ (SLA = เร็วกว่า exp)
-- cache ผลต่อ token สั้น ๆ (default 10s) เพื่อไม่ยิง Keycloak ทุก request (Security Rule 8)
-- หมายเหตุ POC: cache per-worker module-level — production ใช้ shm/redis + fail-closed policy
local cjson = require("cjson.safe")
local httpc_mod = require("resty.http")

local OIDCIntrospectHandler = { VERSION = "1.0.0", PRIORITY = 900 }

local cache = {} -- token_md5 -> { active, ts }

local function token_hash(token)
  return ngx.md5(token)
end

function OIDCIntrospectHandler:access(conf)
  local authz = kong.request.get_header("Authorization")
  if not authz or authz:sub(1, 7):lower() ~= "bearer " then
    return kong.response.exit(401, { message = "Unauthorized: missing Bearer token" })
  end
  local token = authz:sub(8)
  local key = token_hash(token)

  local now = ngx.now()
  local cached = cache[key]
  if cached and (now - cached.ts) < (conf.cache_ttl or 10) then
    if not cached.active then
      return kong.response.exit(401, { message = "Unauthorized: token inactive (cached)" })
    end
    return -- ผ่าน (จาก cache)
  end

  local httpc = httpc_mod.new()
  local res, err = httpc:request_uri(conf.introspection_url, {
    method = "POST",
    body = "client_id=" .. conf.client_id
         .. "&client_secret=" .. conf.client_secret
         .. "&token=" .. ngx.escape_uri(token),
    headers = {
      ["Content-Type"] = "application/x-www-form-urlencoded",
      ["Accept"] = "application/json",
    },
  })
  if not res or res.status ~= 200 then
    kong.log.err("oidc-introspect: introspection failed: ", err or ("http " .. tostring(res and res.status)))
    return kong.response.exit(503, { message = "Service unavailable: introspection endpoint unreachable" })
  end

  local out, derr = cjson.decode(res.body)
  if not out or type(out.active) ~= "boolean" then
    kong.log.err("oidc-introspect: introspection decode failed: ", derr)
    return kong.response.exit(503, { message = "Service unavailable: introspection response malformed" })
  end

  cache[key] = { active = out.active, ts = now }
  -- กัน cache โตไม่จำกัด: เก็บสูงสุด 500 รายการ (ล้างแบบง่ายเมื่อเกิน)
  local n = 0
  for _ in pairs(cache) do n = n + 1 end
  if n > 500 then cache = {} end

  if not out.active then
    return kong.response.exit(401, { message = "Unauthorized: token inactive (revoked, disabled or expired)" })
  end
  -- ผ่าน: active=true (aud/scope ยังเป็นหน้าที่ของ service เสมอ)
end

return OIDCIntrospectHandler
