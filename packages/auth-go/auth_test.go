package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	"central/auth-go"
	"central/auth-go/internal/testidp"
)

// testKey — RSA key สำหรับเคส "legacy token ที่เซ็นด้วย RS256" (ต้องถูกปฏิเสธ: legacy รับ HS256 เท่านั้น)
func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return key
}

// withClaim — สำเนา claims มาตรฐานแล้ว override (value = nil คือลบ field)
func withClaim(base jwt.MapClaims, key string, value any) jwt.MapClaims {
	c := jwt.MapClaims{}
	for k, v := range base {
		c[k] = v
	}
	if value == nil {
		delete(c, key)
	} else {
		c[key] = value
	}
	return c
}

// tamper — แก้ signature ตัวแรก 1 ตัวอักษร
// (ห้ามแก้ตัวท้าย: base64url ของ RSA-2048 มี padding bits ที่ decoder ไม่ตรวจ —
//
//	แก้ตัวท้ายแล้วค่า signature จริงอาจไม่เปลี่ยน ทำให้ test ล้มเป็นพัก ๆ)
func tamper(tok string) string {
	i := strings.LastIndex(tok, ".") + 1
	if tok[i] == 'A' {
		return tok[:i] + "B" + tok[i+1:]
	}
	return tok[:i] + "A" + tok[i+1:]
}

func TestVerifyCentralAcceptsValidToken(t *testing.T) {
	idp := testidp.New(t)
	k, err := auth.NewJWKS(idp.Config)
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	claims, err := auth.VerifyCentral(k, idp.Config, idp.Sign(t, idp.Claims()))
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if claims.Subject != "user-1" || !claims.HasScope("orders.read") || claims.PrincipalType != "user" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

// token ที่ต้องถูกปฏิเสธ — ทุกข้อยืนยันว่า "signature ถูก" ไม่พอ (aud/iss/exp/alg/sub บังคับครบ)
func TestVerifyCentralRejects(t *testing.T) {
	idp := testidp.New(t)
	k, err := auth.NewJWKS(idp.Config)
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	cases := []struct{ name, token string }{
		{"audience อื่น (cross-audience token confusion)", idp.Sign(t, withClaim(idp.Claims(), "aud", "other-api"))},
		{"issuer อื่น", idp.Sign(t, withClaim(idp.Claims(), "iss", "https://evil.test/realms/central"))},
		{"หมดอายุเกิน leeway", idp.Sign(t, withClaim(idp.Claims(), "exp", time.Now().Add(-time.Minute).Unix()))},
		{"ไม่มี exp", idp.Sign(t, withClaim(idp.Claims(), "exp", nil))},
		{"ไม่มี sub", idp.Sign(t, withClaim(idp.Claims(), "sub", ""))},
		{"kid ไม่อยู่ใน JWKS", testidp.SignWith(t, jwt.SigningMethodRS256, idp.Key, "unknown-kid", idp.Claims())},
		{"alg confusion: HS256 เซ็นด้วย public key", testidp.SignWith(t, jwt.SigningMethodHS256, idp.Key.PublicKey.N.Bytes(), idp.KID, idp.Claims())},
		{"signature ถูกแก้", tamper(idp.Sign(t, idp.Claims()))},
		{"ไม่ใช่ JWT", "not-a-jwt"},
		{"token ว่าง", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if claims, err := auth.VerifyCentral(k, idp.Config, tc.token); err == nil {
				t.Fatalf("expected rejection, got claims %+v", claims)
			}
		})
	}
}

// clock skew: exp ผ่านไป 2 วินาที (ใน Leeway 5 วินาที) ต้องยังผ่าน — นโยบายเดียวทุก service
func TestVerifyCentralHonorsLeeway(t *testing.T) {
	idp := testidp.New(t)
	k, err := auth.NewJWKS(idp.Config)
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	expired := idp.Sign(t, withClaim(idp.Claims(), "exp", time.Now().Add(-2*time.Second).Unix()))
	if _, err := auth.VerifyCentral(k, idp.Config, expired); err != nil {
		t.Fatalf("token within leeway rejected: %v", err)
	}
}

// VerifyIssuerOnly — token ของ client อื่นใน realm เดียวกัน (aud อื่น/ไม่มี sub) ผ่าน
// แต่ iss อื่นและ alg อื่นยังปฏิเสธ
func TestVerifyIssuerOnly(t *testing.T) {
	idp := testidp.New(t)
	k, err := auth.NewJWKS(idp.Config)
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	other := withClaim(withClaim(idp.Claims(), "aud", "buyer-api"), "sub", "")
	if _, err := auth.VerifyIssuerOnly(k, idp.Config.Issuer, idp.Sign(t, other)); err != nil {
		t.Fatalf("same-realm token rejected: %v", err)
	}
	if _, err := auth.VerifyIssuerOnly(k, idp.Config.Issuer, idp.Sign(t, withClaim(idp.Claims(), "iss", "https://evil.test"))); err == nil {
		t.Fatal("foreign issuer accepted")
	}
	if _, err := auth.VerifyIssuerOnly(k, idp.Config.Issuer, testidp.SignWith(t, jwt.SigningMethodHS256, []byte("x"), idp.KID, idp.Claims())); err == nil {
		t.Fatal("HS256 token accepted")
	}
}

// legacy token (HS256 + shared secret + iss) — เฉพาะชุดที่ตรงเท่านั้น
func TestVerifyLegacy(t *testing.T) {
	cfg := auth.Config{LegacySecret: "s3cr3t", LegacyIssuer: "legacy-svc"}
	live := func() jwt.MapClaims {
		return jwt.MapClaims{"iss": "legacy-svc", "sub": "u1", "exp": time.Now().Add(5 * time.Minute).Unix()}
	}
	claims, err := auth.VerifyLegacy(cfg, testidp.SignWith(t, jwt.SigningMethodHS256, []byte("s3cr3t"), "", live()))
	if err != nil || claims.Subject != "u1" {
		t.Fatalf("valid legacy token rejected: %v", err)
	}
	rejected := []struct{ name, token string }{
		{"secret ไม่ตรง", testidp.SignWith(t, jwt.SigningMethodHS256, []byte("other"), "", live())},
		{"issuer ไม่ตรง", testidp.SignWith(t, jwt.SigningMethodHS256, []byte("s3cr3t"), "",
			jwt.MapClaims{"iss": "legacy-other", "sub": "u1", "exp": time.Now().Add(5 * time.Minute).Unix()})},
		{"เป็น RS256 แทน HS256", testidp.SignWith(t, jwt.SigningMethodRS256, testKey(t), "", live())},
		{"หมดอายุ", testidp.SignWith(t, jwt.SigningMethodHS256, []byte("s3cr3t"), "",
			jwt.MapClaims{"iss": "legacy-svc", "sub": "u1", "exp": time.Now().Add(-time.Minute).Unix()})},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := auth.VerifyLegacy(cfg, tc.token); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

// Peek — อ่าน iss/alg โดยไม่ verify (ใช้เลือก validator จาก allowlist เท่านั้น)
func TestPeek(t *testing.T) {
	idp := testidp.New(t)
	iss, alg, err := auth.Peek(idp.Sign(t, idp.Claims()))
	if err != nil || iss != idp.Config.Issuer || alg != "RS256" {
		t.Fatalf("peek = %q %q %v", iss, alg, err)
	}
	if _, _, err := auth.Peek("not-a-jwt"); err == nil {
		t.Fatal("expected error for malformed token")
	}
}

func TestParseScopeList(t *testing.T) {
	got := auth.ParseScopeList("orders.read, projects.write,,")
	if len(got) != 2 || got[0] != "orders.read" || got[1] != "projects.write" {
		t.Fatalf("ParseScopeList = %q", got)
	}
	if auth.ParseScopeList("") == nil {
		t.Fatal("empty header must give an empty slice, not nil")
	}
}
