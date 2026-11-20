// Fintech Web (Go Fiber) — ตัวอย่าง "Embedded Login" (exception pattern) ของ Central POC
// แอป render ฟอร์ม username/password ของตัวเอง (หน้าตาแบบ fintech จริง) → backend แลก credential
// เป็น token ผ่าน Keycloak Direct Access Grant (grant_type=password, server-to-server ใน docker network)
// → เก็บ token ฝั่ง server ทั้งหมด (browser ถือเฉพาะ cookie รหัส session) → เรียก Buyer API ด้วย Bearer token
// หมายเหตุ: รูปแบบนี้เป็น exception โดยตั้งใจ — ปกติควรใช้ Authorization Code + PKCE (ดู ID Portal)
//
// นอกจากนี้ยังรองรับ **Session Transfer (STT)** — จำลอง Native-to-Web SSO ของ Auth0:
// mobile app ที่มี native session ส่ง one-time transfer code มาให้ (อายุ 60 วินาที ใช้ครั้งเดียว)
// แล้ว fintech ได้ session ทันทีโดยไม่ต้องกรอกรหัสผ่านซ้ำ — ดู /auth/stt + ID Portal /stt/create
package main

import (
	"log"
	"os"

	"github.com/gofiber/fiber/v2"

	"central/fintech-web/internal/handlers"
	"central/fintech-web/internal/kc"
	"central/fintech-web/internal/session"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	cfg := kc.Config{
		InternalBase: env("KEYCLOAK_INTERNAL_BASE", "http://keycloak:8080"), // ภายใน docker network เท่านั้น
		Realm:        env("REALM", "central"),
		ClientID:     env("FINTECH_CLIENT_ID", "fintech-web"),
		ClientSecret: env("FINTECH_CLIENT_SECRET", ""), // จาก .env เท่านั้น — ห้าม hardcode (Security Rule 6)
		BuyerAPIBase: env("BUYER_API_BASE", "http://buyer-api:3000"),
	}
	port := env("PORT", "3000")

	// token store ฝั่ง server (in-memory — POC: หายพร้อม process, production ใช้ Redis + TTL)
	store := session.NewStore()
	// login throttle ระดับแอป (per-username) — ล็อกก่อนยิงถึง Keycloak
	thr := handlers.NewThrottle()

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		// cookie + header รวมกันใหญ่กว่า 4KB ได้ — กัน HTTP 431 (เช่นเดียวกับ ID Portal)
		ReadBufferSize: 16 * 1024,
	})

	// หน้าจอ + flow ของ Embedded Login
	app.Get("/", handlers.LoginPage(store))
	app.Post("/login", handlers.Login(cfg, store, thr))
	app.Get("/home", handlers.Home(cfg, store))
	app.Get("/logout", handlers.Logout(store))
	app.Get("/healthz", handlers.Health())

	// โอน session ไปแอปอื่น (STT) — สร้าง one-time code แล้วพาไปจุดรับของปลายทาง
	app.Get("/stt/transfer", handlers.Transfer(store))

	// Session Transfer (STT) — รับ one-time code จากมือถือ -> redeem ที่ ID Portal -> session
	// (จำลอง Native-to-Web SSO — ดู docs/research-headless-auth.md)
	app.Get("/auth/stt", handlers.STTLogin(cfg, store))

	log.Printf("fintech-web listening :%s — embedded login (direct grant) realm=%s client=%s buyer=%s", port, cfg.Realm, cfg.ClientID, cfg.BuyerAPIBase)
	log.Fatal(app.Listen(":" + port))
}

