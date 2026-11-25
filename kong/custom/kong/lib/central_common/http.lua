-- central_common.http — เรียก HTTP endpoint + decode JSON แบบเดียวกันทุก plugin
-- รวม pattern เดิมที่ copy ซ้ำ (resty.http request_uri + cjson.safe decode + kong.log.err)
local cjson = require("cjson.safe")
local httpc_mod = require("resty.http")

local _M = {}

-- post_form_json(plugin_name, url, form_tbl) → decoded_json | nil, "error"
-- form_tbl = { key = value, ... } — encode เป็น application/x-www-form-urlencoded
function _M.post_form_json(plugin_name, url, form_tbl)
  local parts = {}
  for k, v in pairs(form_tbl) do
    parts[#parts + 1] = k .. "=" .. ngx.escape_uri(tostring(v))
  end
  local httpc = httpc_mod.new()
  local res, err = httpc:request_uri(url, {
    method = "POST",
    body = table.concat(parts, "&"),
    headers = {
      ["Content-Type"] = "application/x-www-form-urlencoded",
      ["Accept"] = "application/json",
    },
  })
  if not res or res.status ~= 200 then
    kong.log.err(plugin_name, ": endpoint failed: ", err or ("http " .. tostring(res and res.status)))
    return nil, "error"
  end
  local out, derr = cjson.decode(res.body)
  if not out then
    kong.log.err(plugin_name, ": decode failed: ", derr)
    return nil, "error"
  end
  return out, nil
end

-- get_json(plugin_name, url) → decoded_json | nil, "error"
function _M.get_json(plugin_name, url)
  local httpc = httpc_mod.new()
  local res, err = httpc:request_uri(url, {
    method = "GET",
    headers = { ["Accept"] = "application/json" },
  })
  if not res or res.status ~= 200 then
    kong.log.err(plugin_name, ": endpoint failed: ", err or ("http " .. tostring(res and res.status)))
    return nil, "error"
  end
  local out, derr = cjson.decode(res.body)
  if not out then
    kong.log.err(plugin_name, ": decode failed: ", derr)
    return nil, "error"
  end
  return out, nil
end

return _M
