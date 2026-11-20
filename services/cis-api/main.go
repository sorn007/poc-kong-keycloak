// CIS API (Go Fiber) — POC Central Identity
// ตรวจ central token ของ ID (Keycloak) ผ่าน JWKS + รองรับ legacy token ช่วง migration
package main

import (
	"log"
	"os"

	"github.com/gofiber/fiber/v2"

	"central/cis-api/internal/auth"
	"central/cis-api/internal/handlers"
	"central/cis-api/internal/oidc"
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
		Audience:     "cis-api", // Token Contract — CIS รับเฉพาะ token ของตัวเอง
		InternalBase: env("KEYCLOAK_INTERNAL_BASE", "http://keycloak:8080"),
		Realm:        "central",
		LegacySecret: env("LEGACY_CIS_JWT_SECRET", "legacy-cis-secret-poc"),
		LegacyIssuer: "legacy-cis",
	}
	devMode := env("DEV_MODE", "0") == "1"
	port := env("PORT", "3000")

	// JWKS client สร้างครั้งเดียวตอน startup — cache + รองรับ key rotation
	jwks, err := auth.NewJWKS(cfg)
	if err != nil {
		log.Fatalf("jwks init: %v", err)
	}

	oidcCfg := oidc.Config{
		Issuer:        cfg.Issuer,
		InternalBase:  cfg.InternalBase,
		Realm:         cfg.Realm,
		ClientID:      "cis-web",
		// cis-web เป็น confidential client (มี secret) — ใช้กับ token endpoint ทั้ง AC flow
		// และ Token Exchange (KC V2 อนุญาตเฉพาะ confidential client เท่านั้น)
		ClientSecret:  env("CIS_CLIENT_SECRET", ""),
		SttBrokerBase: env("IDPORTAL_INTERNAL_BASE", "http://central-id:3000"),
		FrontURL:      env("APP_FRONT_URL", "http://localhost:3020"),
	}

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		// cookie session ของแอป + cookie จาก ID รวมกันใหญ่กว่า 4KB default
		// (JWT ~1KB ต่อใบ) — เพิ่ม buffer กัน HTTP 431
		ReadBufferSize: 16 * 1024,
	})

	// POC only — หน้าจอ demo เรียก API ด้วย cookie session: ยก cookie ขึ้นเป็น Authorization
	// header (จำลองพฤติกรรม BFF) เมื่อ request ไม่ได้แนบ header มาเอง
	// Middleware/Guard ยังตรวจ token เต็มรูปแบบ (JWKS/iss/aud/exp/scope) เหมือนเดิม — ไม่มีการเชื่อถือค่าใหม่
	app.Use(func(c *fiber.Ctx) error {
		if c.Get("Authorization") == "" {
			if tok := c.Cookies("cis_session"); tok != "" {
				// ตั้ง REQUEST header (c.Set เป็น response header — ห้ามใช้)
				c.Request().Header.Set("Authorization", "Bearer "+tok)
			}
		}
		return c.Next()
	})

	// Demo page + OIDC flow
	app.Get("/", handlers.Home(jwks, cfg))
	oidc.Register(app, oidcCfg)

	// เส้นทางเป้าหมาย — central token + scope
	app.Get("/projects", auth.CentralAuth(jwks, cfg), auth.Scope("projects.read"), handlers.ProjectsList())
	app.Post("/projects", auth.CentralAuth(jwks, cfg), auth.Scope("projects.write"), handlers.ProjectsCreate())

	// Dual Validation — รับทั้ง central และ legacy token (ช่วง migration)
	app.Get("/projects/dual", auth.DualAuth(jwks, cfg), handlers.ProjectsList())

	// Legacy เท่านั้น — พฤติกรรมระบบเดิมก่อน migration
	app.Get("/projects/legacy", auth.LegacyAuth(cfg), handlers.ProjectsList())

	// เส้นทาง Open API
	app.Get("/open-api/projects", auth.CentralAuth(jwks, cfg), auth.Scope("projects.read"), handlers.OpenApiProjects())

	// หน้า demo ที่ตรวจ token จาก cookie ด้วย central validation
	app.Get("/projects/page", handlers.ProjectsPage(jwks, cfg))

	// DEV ONLY — mint legacy token ให้ test script
	app.Post("/dev/mint-legacy-token", handlers.MintLegacyToken(cfg, devMode))

	log.Printf("cis-api (Go Fiber) listening :%s — audience=%s devMode=%v", port, cfg.Audience, devMode)
	log.Fatal(app.Listen(":" + port))
}
