// Package fibermw — Authentication middleware ของ Central Auth SDK สำหรับ Go Fiber
// (adapter บน policy ในแพ็กเกจ central/auth-go — service ที่ใช้ framework อื่นเรียกใช้
// auth.VerifyCentral / auth.VerifyLegacy / auth.Peek เพื่อเขียน middleware ของตัวเองได้)
//
// ลำดับของ route: CentralAuth (Authentication) → Scope (Authorization ระดับ API) → handler
// Scope เป็นเพียง "อนุญาตให้เรียก API ประเภทนี้" — สิทธิ์ระดับ tenant/business ตรวจที่ handler ของ service เอง
package fibermw

import (
	"strings"

	"github.com/gofiber/fiber/v2"

	"central/auth-go"
)

// LocalsKey — key ที่เก็บ *auth.Claims ลง c.Locals (handler อ่านผ่าน c.Locals(LocalsKey))
const LocalsKey = "auth"

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

func nextWith(c *fiber.Ctx, claims *auth.Claims) error {
	c.Locals(LocalsKey, claims)
	return c.Next()
}

// CentralAuth — middleware ตรวจ central token (Authentication)
func CentralAuth(k auth.Keyfunc, cfg auth.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := bearerToken(c)
		if token == "" {
			return unauthorized(c, "missing_access_token")
		}
		claims, err := auth.VerifyCentral(k, cfg, token)
		if err != nil {
			return unauthorized(c, "invalid_access_token")
		}
		return nextWith(c, claims)
	}
}

// LegacyAuth — middleware ตรวจ legacy token (ช่วง migration เท่านั้น)
func LegacyAuth(cfg auth.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := bearerToken(c)
		if token == "" {
			return unauthorized(c, "missing_access_token")
		}
		claims, err := auth.VerifyLegacy(cfg, token)
		if err != nil {
			return unauthorized(c, "invalid_legacy_token")
		}
		return nextWith(c, claims)
	}
}

// DualAuth — เลือก validator จาก "allowlist คงที่" โดย peek iss/alg แบบไม่ verify
// ห้าม fallback อิสระ (กัน cross-issuer token confusion)
func DualAuth(k auth.Keyfunc, cfg auth.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := bearerToken(c)
		if token == "" {
			return unauthorized(c, "missing_access_token")
		}

		iss, alg, err := auth.Peek(token)
		if err != nil {
			return unauthorized(c, "unsupported_token")
		}

		var resolved *auth.Claims
		switch iss {
		case cfg.Issuer: // central — RS256 เท่านั้น
			if alg != "RS256" {
				return unauthorized(c, "unsupported_token")
			}
			resolved, err = auth.VerifyCentral(k, cfg, token)
		case cfg.LegacyIssuer: // legacy — HS256 เท่านั้น
			if alg != "HS256" {
				return unauthorized(c, "unsupported_token")
			}
			resolved, err = auth.VerifyLegacy(cfg, token)
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
		claims, _ := c.Locals(LocalsKey).(*auth.Claims)
		if claims == nil || !claims.HasScope(required) {
			return c.Status(fiber.StatusForbidden).JSON(
				fiber.Map{"error": "insufficient_scope", "required": required},
			)
		}
		return c.Next()
	}
}
