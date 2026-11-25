-- oidc-introspect — thin Kong plugin (POC): ตรวจ token ผ่าน Keycloak introspection
-- endpoint (RFC 7662) — ปิดจุดอ่อนของ JWKS: token ที่ถูก revoke / user ถูก disable
-- กลายเป็น active=false ทันทีที่ Keycloak รู้ (SLA = เร็วกว่า exp) · cache ผลสั้น ๆ
-- (default 10s — ไม่ยิง Keycloak ทุก request ตาม Security Rule 8)
-- กลไก cache/HTTP/error อยู่ที่ lib central_common — handler เหลือเฉพาะ introspection flow
-- หมายเหตุ POC: cache per-worker — production เปลี่ยนที่ central_common/cache.lua + fail-closed
local cc_resp = require("kong.lib.central_common.resp")
local cc_req = require("kong.lib.central_common.req")
local cc_http = require("kong.lib.central_common.http")
local cc_cache = require("kong.lib.central_common.cache")

local OIDCIntrospectHandler = { VERSION = "2.0.0", PRIORITY = 900 }

local cache = cc_cache.new(10, 500) -- ttl override ด้วย conf.cache_ttl ตอนเรียก

function OIDCIntrospectHandler:access(conf)
  local token = cc_req.bearer_token()
  if not token then
    return cc_resp.unauthorized("Unauthorized: missing Bearer token")
  end

  local now = ngx.now()
  local ttl = conf.cache_ttl or 10
  local cached = cache.get(ngx.md5(token), now)
  if cached then
    if not cached.active and (now - cached.ts) < ttl then
      return cc_resp.unauthorized("Unauthorized: token inactive (cached)")
    end
    if cached.active and (now - cached.ts) < ttl then
      return -- ผ่าน (จาก cache)
    end
  end

  local out, err = cc_http.post_form_json("oidc-introspect", conf.introspection_url, {
    client_id = conf.client_id,
    client_secret = conf.client_secret,
    token = token,
  })
  if not out or type(out.active) ~= "boolean" then
    kong.log.err("oidc-introspect: introspection response malformed: ", err or "no active field")
    return cc_resp.unavailable("Service unavailable: introspection endpoint unreachable")
  end

  cache.put(ngx.md5(token), { active = out.active, ts = now }, now)

  if not out.active then
    return cc_resp.unauthorized("Unauthorized: token inactive (revoked, disabled or expired)")
  end
  -- ผ่าน: active=true (aud/scope ยังเป็นหน้าที่ของ service เสมอ)
end

return OIDCIntrospectHandler
