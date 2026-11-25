-- central_common.resp — รูปแบบ error response มาตรฐานของทุก custom plugin
-- (รวม logic เดิมที่ copy ซ้ำใน 3 plugins — error shape เดียว: { message = ... })
local _M = {}

function _M.unauthorized(msg)
  return kong.response.exit(401, { message = msg })
end

function _M.forbidden(msg)
  return kong.response.exit(403, { message = msg })
end

function _M.unavailable(msg)
  return kong.response.exit(503, { message = msg })
end

return _M
