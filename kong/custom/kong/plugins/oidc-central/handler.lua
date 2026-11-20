-- oidc-central — custom Kong plugin (POC): OIDC/JWT validation ที่ gateway
-- ทำสิ่งที่ jwt plugin ตัว OSS ไม่ทำ: ดึง JWKS จาก Keycloak (cache ตาม TTL + รองรับ key
-- rotation ด้วย kid), แปลง RSA JWK เป็น PEM, ตรวจ signature/iss/exp และ **บังคับ aud/scope**
-- ใช้ jwt_parser ของ Kong เอง (รองรับ RS256 + exp validation)
-- หมายเหตุ POC: cache เป็น per-worker module-level (production ใช้ shm/redis + fail-closed policy)
local jwt_parser = require("kong.plugins.jwt.jwt_parser")
local cjson = require("cjson.safe")
local httpc_mod = require("resty.http")
local base64 = require("ngx.base64")

local OIDCCentralHandler = { VERSION = "1.0.0", PRIORITY = 1000 }

-- ---------- DER/PEM helpers: แปลง RSA JWK (n, e) เป็น PEM public key ----------
local function der_len(n)
  if n < 0x80 then return string.char(n) end
  local bytes = {}
  while n > 0 do
    table.insert(bytes, 1, string.char(n % 256))
    n = math.floor(n / 256)
  end
  return string.char(0x80 + #bytes) .. table.concat(bytes)
end
local function der_seq(p) return "\x30" .. der_len(#p) .. p end
local function der_int(p)
  if string.byte(p, 1) > 127 then p = "\x00" .. p end
  return "\x02" .. der_len(#p) .. p
end
local function der_bitstr(p) return "\x03" .. der_len(#p + 1) .. "\x00" .. p end
local function der_oid(s)
  -- base-128 big-endian พร้อม continuation bit (มาตรฐาน DER) — ครอบคลุม arc ใหญ่ เช่น 113549
  local parts = {}
  for v in s:gmatch("%d+") do parts[#parts + 1] = tonumber(v) end
  local out = string.char(math.floor(parts[1] * 40 + parts[2]))
  for i = 3, #parts do
    local v = math.floor(parts[i])
    if v < 128 then
      out = out .. string.char(v)
    else
      local bytes = {}
      while v > 0 do
        table.insert(bytes, 1, v % 128)
        v = math.floor(v / 128)
      end
      for j = 1, #bytes - 1 do bytes[j] = bytes[j] + 0x80 end
      for _, b in ipairs(bytes) do out = out .. string.char(math.floor(b)) end
    end
  end
  return "\x06" .. der_len(#out) .. out
end

local function jwk_to_pem(jwk)
  if jwk.kty ~= "RSA" or not jwk.n or not jwk.e then return nil end
  local n = base64.decode_base64url(jwk.n)
  local e = base64.decode_base64url(jwk.e)
  if not n or not e then return nil end
  local spki = der_seq(der_seq(der_oid("1.2.840.113549.1.1.1") .. "\x05\x00")
                       .. der_bitstr(der_seq(der_int(n) .. der_int(e))))
  local b64 = ngx.encode_base64(spki)
  local lines = {}
  for i = 1, #b64, 64 do lines[#lines + 1] = b64:sub(i, i + 63) end
  return "-----BEGIN PUBLIC KEY-----\n" .. table.concat(lines, "\n")
         .. "\n-----END PUBLIC KEY-----\n"
end

-- ---------- JWKS fetch + cache (kid -> PEM) ----------
local cache = { by_kid = {}, fetched = 0 }

local function fetch_jwks(conf, force)
  if not force and cache.by_kid and (ngx.now() - cache.fetched) < (conf.jwks_ttl or 300) then
    return cache.by_kid
  end
  local httpc = httpc_mod.new()
  local res, err = httpc:request_uri(conf.jwks_url, {
    method = "GET", headers = { ["Accept"] = "application/json" },
  })
  if not res or res.status ~= 200 then
    kong.log.err("oidc-central: jwks fetch failed: ", err or ("http " .. tostring(res and res.status)))
    return nil
  end
  local jwks, derr = cjson.decode(res.body)
  if not jwks or not jwks.keys then
    kong.log.err("oidc-central: jwks decode failed: ", derr)
    return nil
  end
  local by_kid = {}
  for _, k in ipairs(jwks.keys) do
    if k.kid then
      by_kid[k.kid] = jwk_to_pem(k)
    end
  end
  cache.by_kid = by_kid
  cache.fetched = ngx.now()
  kong.log.notice("oidc-central: jwks refreshed (keys=" .. tostring(#jwks.keys) .. ")")
  return by_kid
end

local function key_pem(conf, kid)
  local keys = fetch_jwks(conf, false)
  local pem = keys and keys[kid]
  if not pem then
    -- kid ไม่ตรง cache → อาจเพิ่ง rotate: ดึงใหม่แบบ force หนึ่งครั้ง
    keys = fetch_jwks(conf, true)
    pem = keys and keys[kid]
  end
  return pem
end

-- ---------- claims helpers ----------
local function aud_ok(claims, audience)
  local a = claims.aud
  if type(a) == "string" then return a == audience end
  if type(a) == "table" then
    for _, v in ipairs(a) do if v == audience then return true end end
  end
  return false
end

local function scope_ok(claims, required)
  if not required or required == "" then return true end
  for s in string.gmatch(claims.scope or "", "%S+") do
    if s == required then return true end
  end
  return false
end

-- ---------- access phase ----------
function OIDCCentralHandler:access(conf)
  local authz = kong.request.get_header("Authorization")
  if not authz or authz:sub(1, 7):lower() ~= "bearer " then
    return kong.response.exit(401, { message = "Unauthorized: missing Bearer token" })
  end
  local token = authz:sub(8)

  local parser, perr = jwt_parser:new(token)
  if not parser or not parser.header or not parser.header.kid then
    return kong.response.exit(401, { message = "Unauthorized: malformed token" })
  end

  local pem = key_pem(conf, parser.header.kid)
  if not pem then
    return kong.response.exit(401, { message = "Unauthorized: unknown signing key (kid)" })
  end

  if not parser:verify_signature(pem) then
    return kong.response.exit(401, { message = "Unauthorized: invalid signature" })
  end
  if not parser:verify_registered_claims({ "exp" }) then
    return kong.response.exit(401, { message = "Unauthorized: expired token" })
  end
  local claims = parser.claims or {}

  if conf.issuer and claims.iss ~= conf.issuer then
    return kong.response.exit(401, { message = "Unauthorized: invalid issuer" })
  end

  if not aud_ok(claims, conf.audience) then
    return kong.response.exit(403, { message = "Forbidden: audience mismatch (expected " .. conf.audience .. ")" })
  end

  if not scope_ok(claims, conf.required_scope) then
    return kong.response.exit(403, { message = "Forbidden: insufficient scope (expected " .. conf.required_scope .. ")" })
  end

  -- ผ่านแล้ว: ส่งข้อมูลประกอบต่อให้ upstream (audit/debug)
  kong.service.request.set_header("X-OIDC-Validated", "true")
  kong.service.request.set_header("X-OIDC-Client", tostring(claims.azp or claims.client_id or ""))
end

return OIDCCentralHandler
