-- oidc-central — thin Kong plugin (POC): OIDC/JWT validation ที่ gateway
-- ทำสิ่งที่ jwt plugin ตัว OSS ไม่ทำ: ตรวจ JWKS (cache + rotation) + บังคับ **aud/scope**
-- กลไกหนัก ๆ (DER/PEM, JWKS fetch, jwt_parser) อยู่ที่ lib central_common.jwks —
-- handler นี้เหลือเฉพาะ "ลำดับการตรวจ" ของ plugin นี้ (อ่านง่าย อัปเกรด Kong ไม่กระทบ)
-- ลำดับ: Bearer → parser+kid → signature (RS256 ผ่าน jwt_parser) → exp → iss → aud → scope
local cc_resp = require("kong.lib.central_common.resp")
local cc_req = require("kong.lib.central_common.req")
local cc_claims = require("kong.lib.central_common.claims")
local cc_jwks = require("kong.lib.central_common.jwks")

local OIDCCentralHandler = { VERSION = "2.0.0", PRIORITY = 1000 }

local jwks_store = cc_jwks.new_store("oidc-central")

function OIDCCentralHandler:access(conf)
  local token = cc_req.bearer_token()
  if not token then
    return cc_resp.unauthorized("Unauthorized: missing Bearer token")
  end

  local parser, perr = cc_jwks.new_parser(token)
  if not parser or not parser.header or not parser.header.kid then
    return cc_resp.unauthorized("Unauthorized: malformed token" .. (perr and (": " .. perr) or ""))
  end

  local pem = jwks_store.key_pem(conf, parser.header.kid)
  if not pem then
    return cc_resp.unauthorized("Unauthorized: unknown signing key (kid)")
  end

  if not parser:verify_signature(pem) then
    return cc_resp.unauthorized("Unauthorized: invalid signature")
  end
  if not parser:verify_registered_claims({ "exp" }) then
    return cc_resp.unauthorized("Unauthorized: expired token")
  end
  local claims = parser.claims or {}

  if conf.issuer and claims.iss ~= conf.issuer then
    return cc_resp.unauthorized("Unauthorized: invalid issuer")
  end

  if not cc_claims.aud_ok(claims, conf.audience) then
    return cc_resp.forbidden("Forbidden: audience mismatch (expected " .. conf.audience .. ")")
  end

  if not cc_claims.scope_ok(claims.scope, conf.required_scope) then
    return cc_resp.forbidden("Forbidden: insufficient scope (expected " .. conf.required_scope .. ")")
  end

  -- ผ่านแล้ว: ส่งข้อมูลประกอบต่อให้ upstream (audit/debug)
  kong.service.request.set_header("X-OIDC-Validated", "true")
  kong.service.request.set_header("X-OIDC-Client", tostring(claims.azp or claims.client_id or ""))
end

return OIDCCentralHandler
