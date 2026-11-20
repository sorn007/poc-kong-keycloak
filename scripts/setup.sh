#!/usr/bin/env bash
# ============================================================
# ตั้งค่าครั้งแรก (แทนที่ setup-keys.sh)
# 1) เตรียม keycloak/central-realm.json จาก template
#    (Keycloak สร้าง signing key เองตอน boot แรก — เก็บใน postgres volume)
# 2) ขึ้น postgres + keycloak แล้วรอจนพร้อม
# 3) ดึง realm public key (PEM) ผ่าน Admin REST: GET /admin/realms/central/keys
# 4) inject public key ลง kong/kong.yml (ให้ Kong jwt plugin ตรวจ token ได้)
# 5) ขึ้น container ที่เหลือ (kong, buyer-api, cis-api)
# หมายเหตุ: ถ้าลบ postgres volume (docker compose down -v) realm และ key
# จะถูกสร้างใหม่ — ต้องรัน script นี้ซ้ำเพื่ออัปเดต kong.yml
# ============================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

[ -f .env ] || { echo "ไม่พบ .env — รัน cp .env.example .env ก่อน"; exit 1; }
set -a
source .env
set +a

KC="http://localhost:8080"
ISSUER="$KC/realms/central"

# jq fallback ผ่าน docker (MSYS_NO_PATHCONV — กัน git-bash แปลง /w เป็น W:/)
if ! command -v jq >/dev/null 2>&1; then
  jq() { MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm -i -v "$PWD:/w" -w /w ghcr.io/jqlang/jq "$@"; }
  docker pull ghcr.io/jqlang/jq >/dev/null
fi

# 1) realm.json จาก template
cp keycloak/central-realm.template.json keycloak/central-realm.json

# 2) ขึ้น postgres + keycloak แล้วรอพร้อม
docker compose up -d postgres keycloak
echo "รอ Keycloak เริ่มทำงาน (boot แรกใช้เวลา 1-2 นาที) ..."
until [ "$(curl -s -o /dev/null -w '%{http_code}' "$ISSUER/.well-known/openid-configuration")" = "200" ]; do
  sleep 3
done
echo "✓ Keycloak พร้อม"

# 3) ดึง public key ของ realm ผ่าน Admin REST
ADMIN_TOK="$(curl -s "$KC/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli \
  -d username="$KC_BOOTSTRAP_ADMIN_USERNAME" \
  -d password="$KC_BOOTSTRAP_ADMIN_PASSWORD" | jq -r '.access_token // empty')"
[ -n "$ADMIN_TOK" ] || { echo "login Admin API ไม่สำเร็จ — ตรวจ KC_BOOTSTRAP_ADMIN_* ใน .env"; exit 1; }

PUBLIC_RAW="$(curl -s "$KC/admin/realms/central/keys" \
  -H "Authorization: Bearer $ADMIN_TOK" |
  jq -r '[.keys[] | select(.algorithm == "RS256" and .publicKey != null)][0].publicKey // empty')"
[ -n "$PUBLIC_RAW" ] || { echo "ไม่พบ public key ของ realm — ดู docker compose logs keycloak"; exit 1; }

# KC 26 คืน base64 ดิบ (SubjectPublicKeyInfo ไม่มี header) — ห่อเป็น PEM มาตรฐานให้ Kong
if [[ "$PUBLIC_RAW" == -----* ]]; then
  PUBLIC_PEM="$PUBLIC_RAW"
else
  KEY_B64="$(mktemp)"
  printf '%s\n' "$PUBLIC_RAW" >"$KEY_B64"
  PUBLIC_PEM="$( { echo '-----BEGIN PUBLIC KEY-----'; fold -w 64 "$KEY_B64"; echo '-----END PUBLIC KEY-----'; } )"
  rm -f "$KEY_B64"
fi

# 4) inject ลง kong.yml (indent 10 ช่อง — ต้องลึกกว่า key line `rsa_public_key: |`)
#    + inject secret ของ introspection client (oidc-introspect plugin — ไม่ commit secret)
PEM_FILE="$(mktemp)"
printf '%s\n' "$PUBLIC_PEM" >"$PEM_FILE"
awk -v pub="$(sed 's/^/          /' "$PEM_FILE")" \
  '{ if ($0 ~ /__PARTNER_RSA_PUBLIC_KEY__/) print pub; else print }' \
  kong/kong.template.yml > kong/kong.yml
rm -f "$PEM_FILE"
# inject __INTROSPECT_CLIENT_SECRET__ (ใช้ partner-001 secret — ตรวจ introspect ด้วย client ตัวเอง)
# อ่านจาก kong.yml ผลล่าสุด (ห้ามอ่าน template ทับ injection แรก)
TMP_KONG="$(mktemp)"
awk -v sec="$PARTNER_001_CLIENT_SECRET" \
  '{ n = index($0, "__INTROSPECT_CLIENT_SECRET__")
     if (n > 0) print substr($0, 1, n-1) sec substr($0, n + 28); else print }' \
  kong/kong.yml > "$TMP_KONG" && mv "$TMP_KONG" kong/kong.yml

# 5) ใส่ explicit id ให้ "ทุก" entity (services/routes/plugins/consumers/credentials)
#    — workaround บั๊กของ Kong 3.9 declarative parse: "table index is nil" แบบสุ่ม
#      เมื่อ config มีหลาย entity ซ้อนกัน (populate_ids_for_validation ตอน startup ล้มเหลว)
#    — id สุ่มใหม่ทุกครั้งที่รัน setup.sh (DB-less reload ทั้งไฟล์ ไม่กระทบ behavior)
UUIDS_FILE="$(mktemp)"
node -e 'const c=require("crypto");let o="";for(let i=0;i<200;i++)o+=c.randomUUID()+"\n";process.stdout.write(o);' > "$UUIDS_FILE" 2>/dev/null \
  || { for i in $(seq 1 200); do openssl rand -hex 16 | sed 's/\(.\{8\}\)\(.\{4\}\)\(.\{4\}\)\(.\{4\}\)\(.\{12\}\)/\1-\2-\3-\4-\5/'; done > "$UUIDS_FILE"; }
TMP_IDED="$(mktemp)"
awk -v uf="$UUIDS_FILE" '
  {
    print $0
    if (match($0, /^[ ]*- name: /)) {
      ind = RLENGTH - 8
      pad = ""
      for (j = 0; j < ind + 2; j++) pad = pad " "
      if ((getline l < uf) > 0 && l != "") print pad "id: " l
    }
  }
' kong/kong.yml > "$TMP_IDED" && mv "$TMP_IDED" kong/kong.yml
rm -f "$UUIDS_FILE" "$TMP_IDED"

# inject __GATEWAY_SECRET__ (header ลับระหว่าง Kong กับ Buyer บนเส้นทาง api-key)
TMP_GW="$(mktemp)"
awk -v gw="$GATEWAY_SECRET" \
  '{ gsub(/__GATEWAY_SECRET__/, gw); print }' \
  kong/kong.yml > "$TMP_GW" && mv "$TMP_GW" kong/kong.yml
rm -f "$TMP_GW"
grep -q "__INTROSPECT_CLIENT_SECRET__\|__PARTNER_RSA_PUBLIC_KEY__\|__GATEWAY_SECRET__" kong/kong.yml \
  && { echo "✗ placeholder ยังไม่ถูกแทนค่าครบ"; exit 1; } || echo "✓ inject key + introspect secret + gateway secret ครบ"

# 5) ขึ้นที่เหลือ
docker compose up -d
echo
echo "✓ ตั้งค่าครบ — ต่อไปรัน bash scripts/10-keycloak-smoke.sh"
