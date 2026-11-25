-- central_common.jwks — JWKS fetch + JWK→PEM + JWT parser สำหรับ plugin ตรวจ OIDC token
--
-- ⭐ ไฟล์นี้คือ "จุดเดียว" ที่แตะ Kong-internal API (`kong.plugins.jwt.jwt_parser`) —
--   ตอนอัปเกรด Kong เวอร์ชันใหญ่ ให้ตรวจ/ปรับไฟล์นี้ก่อน แล้ว plugin handlers ที่เหลือ
--   (thin) ไม่ต้องแก้ เพราะไม่มีใครแตะ Kong internal โดยตรง
--   (หมายเหตุ finding 52: resty.jwt ใน Kong 3.9 ไม่มี decode/load — ใช้ jwt_parser
--   ด้วย colon call เสมอ — กฎนี้ถูก isolate อยู่ใน new_parser() ด้านล่าง)
--
-- รวมโค้ดเดิมจาก oidc-central/handler.lua (169 บรรทัด → เหลือ thin handler):
-- • DER encoder: แปลง RSA JWK (n,e) เป็น PEM — ระวัง OID arc ใหญ่ เช่น 113549
--   ต้อง encode base-128 multi-byte
-- • JWKS fetch + cache ตาม TTL + kid-miss → force refresh ครั้งเดียว (รองรับ rotation)
local jwt_parser = require("kong.plugins.jwt.jwt_parser")
local base64 = require("ngx.base64")

local cc_http = require("kong.lib.central_common.http")

local _M = {}

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

-- ---------- new_parser — จุดเดียวที่แตะ Kong-internal jwt_parser ----------
function _M.new_parser(token)
  return jwt_parser:new(token)
end

-- ---------- JWKS fetch + cache (kid -> PEM) — ต่อ plugin หนึ่ง cache ----------
-- คืน object ที่มี key_pem(conf, kid) — conf ต้องมี jwks_url + jwks_ttl (default 300)
function _M.new_store(plugin_name)
  local cache = { by_kid = {}, fetched = 0 }

  local function fetch(conf, force)
    if not force and cache.by_kid and (ngx.now() - cache.fetched) < (conf.jwks_ttl or 300) then
      return cache.by_kid
    end
    local jwks, err = cc_http.get_json(plugin_name, conf.jwks_url)
    if not jwks or not jwks.keys then
      kong.log.err(plugin_name, ": jwks fetch/decode failed: ", err or "no keys field")
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
    kong.log.notice(plugin_name, ": jwks refreshed (keys=", tostring(#jwks.keys), ")")
    return by_kid
  end

  return {
    -- key_pem(conf, kid) — kid ไม่ตรง cache → อาจเพิ่ง rotate: ดึงใหม่แบบ force หนึ่งครั้ง
    key_pem = function(conf, kid)
      local keys = fetch(conf, false)
      local pem = keys and keys[kid]
      if not pem then
        keys = fetch(conf, true)
        pem = keys and keys[kid]
      end
      return pem
    end,
  }
end

return _M
