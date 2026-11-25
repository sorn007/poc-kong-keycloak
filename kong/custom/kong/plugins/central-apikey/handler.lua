-- central-apikey — thin Kong plugin (POC): ตรวจ Central API Key (ผูก scope จาก ID Portal)
-- อ่าน key จาก header (default: apikey, รับหลายชื่อ) → ถาม ID Portal /apikeys/validate
-- (cache TTL สั้น) → บังคับ scope ตาม HTTP method → แนบ gateway-trust headers ให้ upstream
-- contract เดียวกันสำหรับ MCP server (validate endpoint เดียวกัน)
-- กลไก cache/HTTP/error/scope อยู่ที่ lib central_common — handler เหลือเฉพาะ apikey flow
-- หมายเหตุ POC: cache per-worker — production เปลี่ยนที่ central_common/cache.lua
local cc_resp = require("kong.lib.central_common.resp")
local cc_req = require("kong.lib.central_common.req")
local cc_http = require("kong.lib.central_common.http")
local cc_cache = require("kong.lib.central_common.cache")
local cc_claims = require("kong.lib.central_common.claims")

local CentralAPIKeyHandler = { VERSION = "2.0.0", PRIORITY = 950 }

local cache = cc_cache.new(15, 500) -- ttl override ด้วย conf.cache_ttl ตอนเรียก

function CentralAPIKeyHandler:access(conf)
  -- key_names รับเป็น string (comma-separated เผื่อหลาย header) — เลี่ยง array field ใน config
  -- (array field ใน custom plugin config + global plugin ทำ declarative parse ของ Kong 3.9 พังแบบสุ่ม)
  local key = cc_req.api_key(conf.key_names or "apikey")
  if not key then
    return cc_resp.unauthorized("Unauthorized: missing API key (header: " .. tostring(conf.key_names or "apikey") .. ")")
  end

  local h = ngx.md5(key)
  local now = ngx.now()
  local ttl = conf.cache_ttl or 15
  local entry = cache.get(h, now)
  if entry and (now - entry.ts) < ttl then
    return CentralAPIKeyHandler.authorize(conf, entry)
  end

  local out, err = cc_http.post_form_json("central-apikey", conf.validation_url, { key = key })
  if not out or type(out.active) ~= "boolean" then
    kong.log.err("central-apikey: validation response malformed: ", err or "no active field")
    return cc_resp.unavailable("Service unavailable: key validation endpoint unreachable")
  end
  if not out.active then
    return cc_resp.unauthorized("Unauthorized: invalid or revoked API key")
  end

  entry = { scopes = out.scopes or {}, owner = out.owner, ts = now }
  cache.put(h, entry, now)
  return CentralAPIKeyHandler.authorize(conf, entry)
end

-- authorize — บังคับ scope ตาม method + แนบ gateway-trust headers (เมื่อตั้ง gateway_secret)
function CentralAPIKeyHandler.authorize(conf, entry)
  local method = kong.request.get_method()
  local need = (method == "GET" or method == "HEAD") and conf.read_scope or conf.write_scope
  if not cc_claims.scope_in_list(entry.scopes, need) then
    return cc_resp.forbidden("Forbidden: api key lacks scope (" .. tostring(need) .. ")")
  end

  if conf.gateway_secret and conf.gateway_secret ~= "" then
    kong.service.request.set_header("X-Gateway-Auth", conf.gateway_secret)
    kong.service.request.set_header("X-Central-Scopes", table.concat(entry.scopes, ","))
    kong.service.request.set_header("X-Central-Owner", tostring(entry.owner or ""))
  end
end

return CentralAPIKeyHandler
