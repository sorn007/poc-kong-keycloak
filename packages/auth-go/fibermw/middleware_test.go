package fibermw_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	jwt "github.com/golang-jwt/jwt/v5"

	"central/auth-go"
	"central/auth-go/fibermw"
	"central/auth-go/internal/testidp"
)

const legacyScope = "profile" // scope ที่ไม่ตรงกับที่ /api ต้องการ

func newApp(t *testing.T) (*fiber.App, *testidp.IDP) {
	t.Helper()
	idp := testidp.New(t)
	k, err := auth.NewJWKS(idp.Config)
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	cfg := idp.Config
	cfg.LegacySecret, cfg.LegacyIssuer = "s3cr3t", "legacy-svc"
	ok := func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) }

	app := fiber.New()
	app.Get("/api", fibermw.CentralAuth(k, cfg), fibermw.Scope("orders.read"), ok)
	app.Get("/dual", fibermw.DualAuth(k, cfg), ok)
	app.Get("/legacy", fibermw.LegacyAuth(cfg), ok)
	return app, idp
}

// เคส 401/403 ของ middleware ทั้ง 4 ตัว — เนื้อหา error (รหัส + scope ที่ต้องการ) ต้องตรงตาม contract เดิม
func TestMiddlewareStatusCodes(t *testing.T) {
	app, idp := newApp(t)
	// claim — claims มาตรฐานของ IdP จำลอง + override 1 field
	base := idp.Claims()
	claim := func(key string, value any) jwt.MapClaims {
		c := jwt.MapClaims{}
		for k, v := range base {
			c[k] = v
		}
		c[key] = value
		return c
	}
	legacy := func(iss, secret string) string {
		return testidp.SignWith(t, jwt.SigningMethodHS256, []byte(secret), "",
			jwt.MapClaims{"iss": iss, "sub": "u1", "exp": time.Now().Add(5 * time.Minute).Unix()})
	}

	cases := []struct {
		name, path, token string
		wantStatus        int
		wantErr, wantSub  string
	}{
		{"ไม่มี token", "/api", "", 401, "missing_access_token", ""},
		{"token เสีย", "/api", "not-a-jwt", 401, "invalid_access_token", ""},
		{"aud อื่น", "/api", idp.Sign(t, claim("aud", "buyer-api")), 401, "invalid_access_token", ""},
		{"ผ่าน auth แต่ไม่มี scope", "/api", idp.Sign(t, claim("scope", legacyScope)), 403, "insufficient_scope", `"required":"orders.read"`},
		{"ผ่านครบ", "/api", idp.Sign(t, claim("scope", "orders.read")), 200, "", ""},

		{"dual: ไม่มี token", "/dual", "", 401, "missing_access_token", ""},
		{"dual: central token", "/dual", idp.Sign(t, claim("scope", "orders.read")), 200, "", ""},
		{"dual: legacy token", "/dual", legacy("legacy-svc", "s3cr3t"), 200, "", ""},
		{"dual: iss ไม่อยู่ใน allowlist", "/dual", idp.Sign(t, claim("iss", "https://evil.test")), 401, "unsupported_token", ""},
		{"dual: iss central แต่เซ็น HS256", "/dual", testidp.SignWith(t, jwt.SigningMethodHS256, []byte("x"), idp.KID, claim("scope", "orders.read")), 401, "unsupported_token", ""},
		{"dual: iss legacy แต่เซ็น RS256", "/dual", testidp.SignWith(t, jwt.SigningMethodRS256, idp.Key, "", claim("iss", "legacy-svc")), 401, "unsupported_token", ""},
		{"dual: legacy ปลอม (secret ผิด)", "/dual", legacy("legacy-svc", "wrong"), 401, "invalid_access_token", ""},
		{"dual: token พัง", "/dual", "not-a-jwt", 401, "unsupported_token", ""},

		{"legacy: ไม่มี token", "/legacy", "", 401, "missing_access_token", ""},
		{"legacy: ใช้ central token", "/legacy", idp.Sign(t, claim("scope", "orders.read")), 401, "invalid_legacy_token", ""},
		{"legacy: ผ่าน", "/legacy", legacy("legacy-svc", "s3cr3t"), 200, "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d want %d", resp.StatusCode, tc.wantStatus)
			}
			body, _ := io.ReadAll(resp.Body)
			if tc.wantErr != "" {
				var out map[string]any
				if json.Unmarshal(body, &out) != nil || out["error"] != tc.wantErr {
					t.Fatalf("body = %s want error %q", body, tc.wantErr)
				}
			}
			if tc.wantSub != "" && !contains(string(body), tc.wantSub) {
				t.Fatalf("body = %s missing %s", body, tc.wantSub)
			}
		})
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
