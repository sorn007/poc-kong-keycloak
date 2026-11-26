// Package testidp — IdP จำลองสำหรับ unit test ของ SDK
// (JWKS server จริงผ่าน httptest + เครื่องมือเซ็น token — ไม่ถูก link เข้า binary ของ service)
package testidp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	"central/auth-go"
)

// IDP — realm จำลองพร้อม RSA key และ JWKS endpoint
type IDP struct {
	Config auth.Config // พร้อมใช้กับ auth.NewJWKS / auth.VerifyCentral
	Key    *rsa.PrivateKey
	KID    string
}

const JWKSPath = "/realms/central/protocol/openid-connect/certs"

// New — สตาร์ท JWKS server ของ realm central (ปิดอัตโนมัติเมื่อ test จบ)
func New(t testing.TB) *IDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	kid := "test-key-1"
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}}
	raw, _ := json.Marshal(jwks)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != JWKSPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	t.Cleanup(srv.Close)
	return &IDP{
		Config: auth.Config{
			Issuer: "https://idp.test/realms/central", Audience: "svc-api",
			InternalBase: srv.URL, Realm: "central",
		},
		Key: key,
		KID: kid,
	}
}

// Claims — claim มาตรฐานของ token ที่ผ่านทุกเงื่อนไข (ผู้เรียก override ฟิลด์ที่จะทดสอบ)
func (idp *IDP) Claims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss": idp.Config.Issuer, "sub": "user-1", "aud": idp.Config.Audience,
		"exp": time.Now().Add(5 * time.Minute).Unix(), "scope": "orders.read",
		"principal_type": "user",
	}
}

// Sign — เซ็น claims ด้วย RS256 (kid ตรงกับ JWKS)
func (idp *IDP) Sign(t testing.TB, claims jwt.MapClaims) string {
	t.Helper()
	return SignWith(t, jwt.SigningMethodRS256, idp.Key, idp.KID, claims)
}

// SignWith — เซ็นด้วย method/key/kid ที่กำหนดเอง (ใช้สร้าง token ที่ต้องถูกปฏิเสธ)
func SignWith(t testing.TB, method jwt.SigningMethod, key any, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}
