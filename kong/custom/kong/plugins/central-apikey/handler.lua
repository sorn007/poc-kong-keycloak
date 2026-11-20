-- central-apikey — custom Kong plugin (POC): ตรวจ Central API Key (ผูก scope จาก ID Portal)
-- อ่าน key จาก header (default: apikey) → ถาม ID Portal /apikeys/validate (cache TTL สั้น)
-- → บังคับ scope ที่ gateway — contract เดียวกันสำหรับ MCP server (validate endpoint เดียวกัน)
-- หมายเหตุ POC: cache per-worker module-level; key ไม่ถูก log
local cjson = require("cjson.safe")
local httpc_mod = require("resty.http")

local CentralAPIKeyHandler = { VERSION = "1.0.0", PRIORITY = 950 }

local cache = {} -- key_md5 -> { scopes, ts }

local function key_hash(k) return ngx.md5(k) end

local function cached(conf, k)
  local e = cache[key_hash(k)]
  if e and (ngx.now() - e.ts) < (conf.cache_ttl or 15) then
    return e.scopes
  end
  return nil
end

local function put_cache(conf, k, scopes)
  local h = key_hash(k)
  cache[h] = { scopes = scopes, ts = ngx.now() }
  -- กัน cache โตเกิน: ล้างง่ายเมื่อเกิน 500
  local n = 0
  for _ in pairs(cache) do n = n + 1 end
  if n > 500 then cache = {} end
end

local function lookup_key(conf, k)
  local httpc = httpc_mod.new()
  local res, err = httpc:request_uri(conf.validation_url, {
    method = "POST",
    body = "key=" .. ngx.escape_uri(k),
    headers = {
      ["Content-Type"] = "application/x-www-form-urlencoded",
      ["Accept"] = "application/json",
    },
  })
  if not res or res.status ~= 200 then
    kong.log.err("central-apikey: validation failed: ", err or ("http " .. tostring(res and res.status)))
    return nil, "error"
  end
  local out, derr = cjson.decode(res.body)
  if not out or type(out.active) ~= "boolean" then
    kong.log.err("central-apikey: validation decode failed: ", derr)
    return nil, "error"
  end
  if not out.active then
    return nil, "inactive", nil
  end
  return out.scopes or {}, nil, out.owner
end

local function has_scope(scopes, required)
  if not required or required == "" then return true end
  for _, s in ipairs(scopes) do
    if s == required then return true end
  end
  return false
end

function CentralAPIKeyHandler:access(conf)
  -- key_names รับเป็น string (comma-separated เผื่อหลาย header) — เลี่ยง array field ใน config
  -- (array field ใน custom plugin config + global plugin ทำ declarative parse ของ Kong 3.9 พังแบบสุ่ม)
  local names = (conf.key_names or "apikey"):lower() == "apikey" and "apikey" or conf.key_names
  local key = nil
  for name in names:gmatch("[^,]+") do
    local v = kong.request.get_header(name)
    if v then
      key = v
      break
    end
  end
  if not key or key == "" then
    return kong.response.exit(401, { message = "Unauthorized: missing API key (header: " .. tostring(conf.key_names or "apikey") .. ")" })
  end

  local scopes = cached(conf, key)
  local vowner
  if scopes == nil then
    local fetched, status, vowner = lookup_key(conf, key)
    if status == "error" then
      return kong.response.exit(503, { message = "Service unavailable: key validation endpoint unreachable" })
    end
    if status == "inactive" or fetched == nil then
      return kong.response.exit(401, { message = "Unauthorized: invalid or revoked API key" })
    end
    put_cache(conf, key, fetched)
    scopes = fetched
    vowner = nil
  end

  -- บังคับ scope ตาม method: GET/HEAD → read_scope, POST/PUT/PATCH/DELETE → write_scope
  local method = kong.request.get_method()
  local need = (method == "GET" or method == "HEAD") and conf.read_scope or conf.write_scope
  if not has_scope(scopes, need) then
    return kong.response.exit(403, { message = "Forbidden: api key lacks scope (" .. tostring(need) .. ")" })
  end

  -- gateway-trust: แนบหลักฐานว่าตรวจแล้ว + scopes/owner ให้ upstream (เฉพาะเมื่อตั้ง gateway_secret)
  if conf.gateway_secret and conf.gateway_secret ~= "" then
    kong.service.request.set_header("X-Gateway-Auth", conf.gateway_secret)
    kong.service.request.set_header("X-Central-Scopes", table.concat(scopes, ","))
    kong.service.request.set_header("X-Central-Owner", tostring(vowner or ""))
  end
end

return CentralAPIKeyHandler
