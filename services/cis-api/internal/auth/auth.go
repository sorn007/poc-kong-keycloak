// Package auth — Central/Legacy/Dual authentication + scope authorization
// ตาม Token Contract ของ Central (ดู CLAUDE.md + rootcase.md §4)
package auth

import (
	"fmt"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/gofiber/fiber/v2"
	jwt "github.com/golang-jwt/jwt/v5"
)

// Keyfunc — alias ของ keyfunc.Keyfunc สำหรับ package อื่นใช้อ้างอิง
type Keyfunc = keyfunc.Keyfunc

// Claims — claim ที่ service ตรวจ ตาม Token Contract (ไม่เชื่อ claim อื่นโดยไม่ตรวจ)
type Claims struct {
	Scope             string `json:"scope"`
	ClientID          string `json:"client_id"`
	PrincipalType     string `json:"principal_type"`
	TenantID          string `json:"tenant_id"`
	PreferredUsername string `json:"preferred_username"` // เอกสารสำหรับแสดงผล UI เท่านั้น
	Email             string `json:"email"`              // เอกสารสำหรับแสดงผล UI เท่านั้น
	jwt.RegisteredClaims
}

// Scopes — แตก scope string เป็น slice
func (c *Claims) Scopes() []string {
	return strings.Fields(c.Scope)
}

// Config — ค่าที่ต้อง match กับ Token Contract
type Config struct {
	Issuer       string // ค่า iss ที่ตรวจ (KC_HOSTNAME=localhost → http://localhost:8080/realms/central)
	Audience     string
	InternalBase string // URL เรียก JWKS จากใน docker network
	Realm        string
	LegacySecret string
	LegacyIssuer string
}

// NewJWKS — สร้าง JWKS client "ครั้งเดียวตอน startup" (cache + auto refresh ตาม key rotation)
func NewJWKS(cfg Config) (keyfunc.Keyfunc, error) {
	jwksURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", cfg.InternalBase, cfg.Realm)
	return keyfunc.NewDefault([]string{jwksURL})
}

func unauthorized(c *fiber.Ctx, code string) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": code})
}

func bearerToken(c *fiber.Ctx) string {
	parts := strings.Fields(c.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

// VerifyCentral — ตรวจ central token: RS256 + iss + aud + exp (+ leeway 5s)
func VerifyCentral(k keyfunc.Keyfunc, cfg Config, tokenStr string) (*Claims, error) {
	claims := new(Claims)
	tok, err := jwt.ParseWithClaims(
		tokenStr,
		claims,
		k.Keyfunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithAudience(cfg.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(5*time.Second),
	)
	if err != nil || !tok.Valid || claims.Subject == "" {
		return nil, fmt.Errorf("central token invalid: %w", err)
	}
	return claims, nil
}

// VerifyLegacy — ตรวจ legacy token จำลองของ CIS (HS256 + shared secret)
func VerifyLegacy(cfg Config, tokenStr string) (*Claims, error) {
	claims := new(Claims)
	_, err := jwt.ParseWithClaims(
		tokenStr,
		claims,
		func(*jwt.Token) (any, error) { return []byte(cfg.LegacySecret), nil },
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(cfg.LegacyIssuer),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(5*time.Second),
	)
	if err != nil || claims.Subject == "" {
		return nil, fmt.Errorf("legacy token invalid: %w", err)
	}
	return claims, nil
}

func nextWith(c *fiber.Ctx, claims *Claims) error {
	c.Locals("auth", claims)
	return c.Next()
}

// CentralAuth — middleware ตรวจ central token (Authentication)
func CentralAuth(k keyfunc.Keyfunc, cfg Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := bearerToken(c)
		if token == "" {
			return unauthorized(c, "missing_access_token")
		}
		claims, err := VerifyCentral(k, cfg, token)
		if err != nil {
			return unauthorized(c, "invalid_access_token")
		}
		return nextWith(c, claims)
	}
}

// LegacyAuth — middleware ตรวจ legacy token (ช่วง migration เท่านั้น)
func LegacyAuth(cfg Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := bearerToken(c)
		if token == "" {
			return unauthorized(c, "missing_access_token")
		}
		claims, err := VerifyLegacy(cfg, token)
		if err != nil {
			return unauthorized(c, "invalid_legacy_token")
		}
		return nextWith(c, claims)
	}
}

// DualAuth — เลือก validator จาก "allowlist คงที่" โดย peek iss/alg แบบไม่ verify
// ห้าม fallback อิสระ (กัน cross-issuer token confusion)
func DualAuth(k keyfunc.Keyfunc, cfg Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := bearerToken(c)
		if token == "" {
			return unauthorized(c, "missing_access_token")
		}

		claims := new(Claims)
		parser := jwt.NewParser(jwt.WithoutClaimsValidation())
		unverified, _, err := parser.ParseUnverified(token, claims)
		if err != nil {
			return unauthorized(c, "unsupported_token")
		}
		alg, _ := unverified.Header["alg"].(string)

		var resolved *Claims
		switch claims.Issuer {
		case cfg.Issuer: // central — RS256 เท่านั้น
			if alg != "RS256" {
				return unauthorized(c, "unsupported_token")
			}
			resolved, err = VerifyCentral(k, cfg, token)
		case cfg.LegacyIssuer: // legacy — HS256 เท่านั้น
			if alg != "HS256" {
				return unauthorized(c, "unsupported_token")
			}
			resolved, err = VerifyLegacy(cfg, token)
		default:
			// iss ไม่อยู่ใน allowlist → ปฏิเสธทันที
			return unauthorized(c, "unsupported_token")
		}
		if err != nil || resolved == nil {
			return unauthorized(c, "invalid_access_token")
		}
		return nextWith(c, resolved)
	}
}

// Scope — middleware ตรวจว่า token มี scope ที่ endpoint ต้องการ (Authorization)
func Scope(required string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, _ := c.Locals("auth").(*Claims)
		scopes := map[string]bool{}
		if claims != nil {
			for _, s := range claims.Scopes() {
				scopes[s] = true
			}
		}
		if !scopes[required] {
			return c.Status(fiber.StatusForbidden).JSON(
				fiber.Map{"error": "insufficient_scope", "required": required},
			)
		}
		return c.Next()
	}
}
