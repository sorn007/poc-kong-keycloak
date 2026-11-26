// ID Device (Go Fiber) — จำลอง "มือถือของผู้ใช้" ที่รันแอป ID (POC)
// เป็น Authentication Device (AD) ของ CIBA flow:
// Keycloak POST คำขอ authentication delegation เข้ามาที่ /ciba/delegation
// ผู้ใช้ต้อง **ล็อกอินด้วยบัญชี ID ก่อน** (upstream realm central-id-upstream)
// จึงจะเห็นคำขอได้ — และอนุมัติได้เฉพาะคำขอของตัวเอง (login_hint ตรง username)
package main

import (
	"log"
	"os"

	"github.com/gofiber/fiber/v2"

	"central/auth-go"
	"central/id-device/internal/applogin"
	"central/id-device/internal/device"
	"central/id-device/internal/handlers"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	cfg := handlers.Config{
		KeycloakInternalBase: env("KEYCLOAK_INTERNAL_BASE", "http://keycloak:8080"),
		Realm:                "central",
	}
	// realm ต้นทางของบัญชีผู้อนุมัติ ("Central ID จริง")
	loginCfg := auth.Config{
		Issuer:       env("APPROVER_ISSUER", "http://localhost:8080/realms/central-id-upstream"),
		Audience:     "id-device-approver",
		InternalBase: env("KEYCLOAK_INTERNAL_BASE", "http://keycloak:8080"),
		Realm:        "central-id-upstream",
	}
	port := env("PORT", "3000")

	// JWKS client สร้างครั้งเดียวตอน startup — cache + รองรับ rotation
	jwks, err := auth.NewJWKS(loginCfg)
	if err != nil {
		log.Fatalf("jwks init: %v", err)
	}

	// store คำขอที่รออนุมัติ + session ผู้อนุมัติ — in-memory เท่านั้น (POC)
	store := device.NewStore()
	sessions := device.NewSessionStore()

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		// body/header จาก Keycloak อาจใหญ่กว่า default — กัน HTTP 431
		ReadBufferSize: 16 * 1024,
	})

	// login ผู้อนุมัติ (Authorization Code + PKCE ผ่าน upstream realm)
	applogin.Register(app, applogin.Config{
		Issuer:       loginCfg.Issuer,
		InternalBase: loginCfg.InternalBase,
		Realm:        loginCfg.Realm,
		FrontURL:     env("APP_FRONT_URL", "http://localhost:3040"),
	}, func(idToken string) string {
		claims, err := auth.VerifyCentral(jwks, loginCfg, idToken)
		if err != nil {
			log.Printf("approver login rejected: %v", err)
			return ""
		}
		sid := sessions.Save(claims.PreferredUsername)
		log.Printf("approver logged in: %s", claims.PreferredUsername)
		return sid
	})

	handlers.Register(app, store, cfg, sessions, jwks, loginCfg)

	log.Printf("id-device (CIBA authentication device) listening :%s — realm=%s approver-realm=%s",
		port, cfg.Realm, loginCfg.Realm)
	log.Fatal(app.Listen(":" + port))
}
