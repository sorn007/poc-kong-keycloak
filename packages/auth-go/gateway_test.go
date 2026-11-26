package auth

import (
	"net/http"
	"testing"
)

// Gateway-trust: เชื่อ header ของ Kong ได้ก็ต่อเมื่อ shared secret ตรงเท่านั้น
func TestVerifyGatewayTrust(t *testing.T) {
	h := http.Header{}
	h.Set(HeaderGatewayAuth, "gw-secret")
	h.Set(HeaderCentralScopes, "orders.read, orders.write")
	h.Set(HeaderCentralOwner, "buyer-user")

	p, ok := VerifyGatewayTrust(h, "gw-secret")
	if !ok || p.Owner != "buyer-user" || len(p.Scopes) != 2 || p.Scopes[1] != "orders.write" {
		t.Fatalf("trusted gateway: ok=%v principal=%+v", ok, p)
	}

	rejected := []struct {
		name   string
		header http.Header
		secret string
	}{
		{"secret ผิด", h, "wrong-secret"},
		{"ไม่มี header gateway", http.Header{}, "gw-secret"},
		{"ยังไม่ตั้ง secret ฝั่ง service (fail-closed)", h, ""},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			if p, ok := VerifyGatewayTrust(tc.header, tc.secret); ok || p != nil {
				t.Fatal("untrusted request accepted")
			}
		})
	}

	// ผ่าน gateway แล้วแต่ key ไม่มี scope → ต้องได้ slice ว่าง (service บังคับ scope ต่อเอง)
	empty := http.Header{}
	empty.Set(HeaderGatewayAuth, "gw-secret")
	if p, ok := VerifyGatewayTrust(empty, "gw-secret"); !ok || len(p.Scopes) != 0 {
		t.Fatalf("expected empty scopes, got %+v ok=%v", p, ok)
	}
}
