// ID Portal (Go Fiber) — แอปบัญชีกลางของ Central (POC)
// เป็น OIDC client หนึ่งของ Keycloak realm central เหมือน Buyer/CIS
// ทำหน้าที่: โปรไฟล์ / แอปที่เชื่อมต่อ / session / จุด logout กลาง — ตาม flow rootcase
package main

import (
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"

	"central/central-id/internal/apikeys"
	"central/central-id/internal/auth"
	"central/central-id/internal/handlers"
	"central/central-id/internal/oidc"
	"central/central-id/internal/sso"
	"central/central-id/internal/stt"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	cfg := auth.Config{
		Issuer:       env("KEYCLOAK_ISSUER", "http://localhost:8080/realms/central"),
		Audience:     "central-id", // Token Contract — audience ของ ID Portal เอง
		InternalBase: env("KEYCLOAK_INTERNAL_BASE", "http://keycloak:8080"),
		Realm:        "central",
	}
	port := env("PORT", "3000")

	// JWKS client สร้างครั้งเดียวตอน startup — cache + รองรับ key rotation
	jwks, err := auth.NewJWKS(cfg)
	if err != nil {
		log.Fatalf("jwks init: %v", err)
	}

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		// cookie session + cookie จาก Keycloak รวมกันใหญ่กว่า 4KB — กัน HTTP 431
		ReadBufferSize: 16 * 1024,
	})

	// SSO Ticket — ตั๋ว SSO ระดับ ID กลาง (เปิดแอปอื่นในแท็บใหม่ไม่ต้อง login)
	// สร้างก่อน Register เพราะ portal เองก็เป็น "ปลายทาง" ที่ redeem ตั๋วของตัวเองผ่าน store ตรง
	ssoStore := sso.NewStore()
	// secret ของ confidential client ที่ broker ใช้ตอน refresh grant แทนต้นทาง (public client ไม่ต้อง)
	clientSecrets := map[string]string{
		"fintech-web":       env("FINTECH_CLIENT_SECRET", ""),
		"cis-web":           env("CIS_CLIENT_SECRET", ""),
		"central-id-portal": env("IDPORTAL_CLIENT_SECRET", ""),
	}

	// Logout กลาง propagate สำหรับ portal เอง — session ผูกกับตั๋ว (sso_bound):
	// ตั๋วถูก revoke/logout-all ที่แอปอื่น → เคลียร์ session portal แล้วกลับหน้า landing
	// + Auto-SSO: ยังไม่ login แต่ browser มีตั๋ว (จาก fintech/แอปอื่น) → พาไป redeem ที่ /auth/login
	app.Use(func(c *fiber.Ctx) error {
		if c.Cookies("central_session") != "" && c.Cookies("sso_bound") != "" {
			if _, alive := ssoStore.Check(c.Cookies("sso_bound")); !alive {
				for _, name := range []string{"central_session", "central_id_token", "sso_bound", "sso_try_portal", "central_sso"} {
					c.Cookie(&fiber.Cookie{Name: name, Value: "", Path: "/", Expires: time.Now().Add(-time.Hour), MaxAge: -1, HTTPOnly: true, SameSite: "Lax"})
				}
				return c.Redirect("/", fiber.StatusFound)
			}
		}
		// ยังไม่มี session + มีตั๋ว + ไม่อยู่ในช่วงกันวน loop → พาไป /auth/login (redeem ของตัวเอง)
		// (ยกเว้นทางเข้า login/callback/logout กันวน loop)
		if c.Cookies("central_session") == "" && c.Cookies("central_sso") != "" && c.Cookies("sso_try_portal") == "" &&
			c.Path() != "/auth/login" && c.Path() != "/auth/callback" && c.Path() != "/auth/logout" {
			return c.Redirect("/auth/login", fiber.StatusFound)
		}
		return c.Next()
	})

	// OIDC flow (Authorization Code + PKCE) — client central-id-portal (confidential)
	oidc.Register(app, oidc.Config{
		Issuer:        cfg.Issuer,
		InternalBase:  cfg.InternalBase,
		Realm:         cfg.Realm,
		ClientID:      "central-id-portal",
		ClientSecret:  env("IDPORTAL_CLIENT_SECRET", ""),
		FrontURL:      env("APP_FRONT_URL", "http://localhost:3000"),
		SSOStore:      ssoStore,
		Keyfunc:       jwks,
		ClientSecrets: clientSecrets,
	})

	// หน้าจอของ portal
	app.Get("/", handlers.Home(jwks, cfg))
	app.Get("/apps", handlers.Apps(jwks, cfg))
	app.Get("/session", handlers.SessionPage(jwks, cfg))

	// Session Transfer Token (จำลอง Native-to-Web SSO):
	// mobile app ที่มี native session ส่ง token มาสร้าง one-time code (60 วินาที)
	// เพื่อเปิดเว็บแอปอื่นโดยไม่ต้องกรอกรหัสผ่านซ้ำ — ดู docs/research-headless-auth.md
	sttStore := stt.NewStore()
	app.Post("/stt/create", handlers.CreateSTT(sttStore, jwks, cfg.Issuer))
	app.Post("/stt/redeem", handlers.RedeemSTT(sttStore))

	app.Post("/sso/ticket", handlers.CreateSSOTicket(ssoStore, jwks, cfg.Issuer))
	app.Post("/sso/redeem", handlers.RedeemSSOTicket(ssoStore, jwks, cfg.Issuer, cfg.InternalBase, cfg.Realm, clientSecrets))
	app.Post("/sso/revoke", handlers.RevokeSSOTicket(ssoStore, jwks, cfg.Issuer))
	app.Post("/sso/check", handlers.CheckSSOTicket(ssoStore))
	app.Post("/sso/logout", handlers.LogoutAllSSO(ssoStore, jwks, cfg.Issuer))

	// Central API Keys — ออก API key ผูก scope จากหน้าเว็บ → ใช้กับ Open API (Kong) หรือ MCP server
	// (validate endpoint คือ contract เดียวกันสำหรับทั้ง Kong plugin และ MCP server)
	apiKeyStore := apikeys.NewStore()
	app.Get("/apikeys", handlers.ApiKeysPage(jwks, cfg, apiKeyStore))
	app.Post("/apikeys/create", handlers.CreateAPIKey(jwks, cfg, apiKeyStore))
	app.Get("/apikeys/list", handlers.ListAPIKeys(jwks, cfg, apiKeyStore))
	app.Post("/apikeys/revoke", handlers.RevokeAPIKey(jwks, cfg, apiKeyStore, ssoStore))
	app.Post("/apikeys/validate", handlers.ValidateAPIKey(apiKeyStore))

	log.Printf("central-id portal listening :%s — audience=%s", port, cfg.Audience)
	log.Fatal(app.Listen(":" + port))
}
