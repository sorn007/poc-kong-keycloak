package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// Gateway-trust contract — header ที่ Kong แนบเมื่อตรวจ Central API Key ผ่านแล้ว
// (plugin central-apikey · kong/custom/kong/plugins/central-apikey) — เพิ่ม/เปลี่ยน header ให้แก้ที่นี่ที่เดียว
// ⚠️ ใช้ได้เฉพาะ service ที่ Kong เป็นทางเข้าเดียว (port ไม่เปิดสู่ client โดยตรง) — ไม่งั้นใครก็ปลอม header ได้
const (
	HeaderGatewayAuth   = "X-Gateway-Auth"   // shared secret ระหว่าง Kong กับ service
	HeaderCentralScopes = "X-Central-Scopes" // scope ของ API key (comma-separated)
	HeaderCentralOwner  = "X-Central-Owner"  // เจ้าของ API key
)

// GatewayPrincipal — principal ของ Central API Key หลังผ่าน gateway ที่เชื่อถือได้
type GatewayPrincipal struct {
	Owner  string
	Scopes []string
}

// VerifyGatewayTrust — ยืนยันว่า header มาจาก gateway ที่ถือ shared secret ตรงกัน
// (เทียบแบบ constant-time) คืน principal พร้อม scope ของ key — ไม่ผ่านคืน (nil, false)
// ถ้า secret ยังไม่ตั้ง (ค่าว่าง) = ไม่เชื่อถือใครเลย (fail-closed)
func VerifyGatewayTrust(h http.Header, secret string) (*GatewayPrincipal, bool) {
	if secret == "" || !secretEqual(h.Get(HeaderGatewayAuth), secret) {
		return nil, false
	}
	return &GatewayPrincipal{
		Owner:  h.Get(HeaderCentralOwner),
		Scopes: ParseScopeList(h.Get(HeaderCentralScopes)),
	}, true
}

// ParseScopeList — แตก scope แบบ comma-separated จาก header เป็น slice (ตัดช่องว่าง/ค่าว่าง)
func ParseScopeList(raw string) []string {
	out := []string{}
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// secretEqual — เทียบ secret แบบ constant-time (ความยาวต่างกันตอบ false ทันที — ความยาวไม่ใช่ความลับ)
func secretEqual(got, want string) bool {
	a, b := []byte(got), []byte(want)
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
