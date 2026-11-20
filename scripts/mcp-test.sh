#!/usr/bin/env bash
# MCP Server (remote HTTP — Streamable HTTP) บน Buyer :3010/mcp
# Auth: Central API Key จาก ID Portal (header apikey หรือ X-API-Key)
# • tools/list กรองตาม scope ของ key (ไม่มี orders.write → ไม่เห็น create_order)
# • tools/call list_orders (orders.read) · create_order (orders.write)
# • ไม่มี/ผิด key → 401 · GET /mcp → 405 (stateless ไม่มี SSE)
# ต้องรันก่อน: setup.sh + setup-stt.sh (key registry อยู่ที่ ID Portal)
source "$(dirname "$0")/_lib.sh"
require_jq

wait_for "Buyer API" "$BUYER/" 60
wait_for "ID Portal" "http://localhost:3000/" 60
echo

MCP="$BUYER/mcp"
ACCEPT="Accept: application/json, text/event-stream"
UT="$(pwd_token buyer-web buyer-user 'openid')"

# keys ทดสอบ (reader = orders.read · writer = orders.read + orders.write)
K_READ="$(curl -s -X POST "http://localhost:3000/apikeys/create" -H "Authorization: Bearer $UT" -d "name=mcp-reader" -d "scopes=orders.read" | jq -r '.key // empty')"
K_FULL="$(curl -s -X POST "http://localhost:3000/apikeys/create" -H "Authorization: Bearer $UT" -d "name=mcp-writer" -d "scopes=orders.read,orders.write" | jq -r '.key // empty')"
check "สร้าง keys ทดสอบ (reader/writer) ผ่าน ID Portal" "yes" "$([ -n "$K_READ" ] && [ -n "$K_FULL" ] && echo yes || echo no)"

call_mcp() { # call_mcp <apikey_header_value> <json-body> → body
  curl -s -X POST "$MCP" -H "$ACCEPT" -H "apikey: $1" -H "Content-Type: application/json" -d "$2" --max-time 15
}

echo "--- 1) initialize + tools/list (key: orders.read เท่านั้น) ---"
INIT="$(call_mcp "$K_READ" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"mcp-test","version":"0"}}}')"
check "initialize → serverInfo central-buyer-mcp" "yes" "$(echo "$INIT" | jq -r '.result.serverInfo.name == "central-buyer-mcp"' | grep -q true && echo yes || echo no)"
TOOLS_READ="$(call_mcp "$K_READ" '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')"
check "tools/list มี list_orders (orders.read)" "yes" "$(echo "$TOOLS_READ" | jq -r '[.result.tools[].name] | index("list_orders") != null' | grep -q true && echo yes || echo no)"
check "tools/list แสดง create_order (บังคับ scope ตอน execute)" "yes" "$(echo "$TOOLS_READ" | jq -r '[.result.tools[].name] | index("create_order") != null' | grep -q true && echo yes || echo no)"
check "tools/list มี whoami (ไม่ต้องใช้ scope)" "yes" "$(echo "$TOOLS_READ" | jq -r '[.result.tools[].name] | index("whoami") != null' | grep -q true && echo yes || echo no)"

echo "--- 2) tools/call list_orders (orders.read) ---"
CALL1="$(call_mcp "$K_READ" '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_orders","arguments":{}}}')"
check "tools/call list_orders → มี ORD-001 ใน content" "yes" "$(echo "$CALL1" | grep -q 'ORD-001' && echo yes || echo no)"

echo "--- 3) tools/call create_order — key ไม่มี orders.write → tool error ระบุเหตุผล ---"
CALL2="$(call_mcp "$K_READ" '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"create_order","arguments":{}}}')"
check "create_order ด้วย key read-only → isError" "yes" "$(echo "$CALL2" | jq -r '.result.isError == true' | grep -q true && echo yes || echo no)"
check "ข้อความระบุ orders.write" "yes" "$(echo "$CALL2" | grep -q 'orders.write' && echo yes || echo no)"

echo "--- 4) key เต็ม (read+write) → create_order สำเร็จ ---"
CALL3="$(call_mcp "$K_FULL" '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"create_order","arguments":{}}}')"
CREATED="$(echo "$CALL3" | jq -r '.result.content[0].text | fromjson | .created // empty')"
check "create_order ด้วย key read+write → created" "true" "$CREATED"

echo "--- 5) ไม่มี/ผิด key → 401 ---"
check "ไม่ส่ง key → 401" "401" "$(curl -s -o /dev/null -w "%{http_code}" -X POST "$MCP" -H "$ACCEPT" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":9,"method":"tools/list"}' --max-time 15)"
check "key ปลอม → 401" "401" "$(curl -s -o /dev/null -w "%{http_code}" -X POST "$MCP" -H "$ACCEPT" -H "Content-Type: application/json" -H "apikey: central_totally_fake" -d '{"jsonrpc":"2.0","id":9,"method":"tools/list"}' --max-time 15)"

echo "--- 6) GET /mcp → 405 (stateless ไม่เปิด SSE stream) ---"
check "GET /mcp → 405" "405" "$(curl -s -o /dev/null -w "%{http_code}" "$MCP" --max-time 10)"

summary
