// Headless Demo (Go Fiber) — Seller App จำลองที่ทำหน้าที่เป็น Consumption Device (CD) ของ CIBA flow (POC)
// แอปนี้มีหน้า login ของตัวเอง — ไม่เคย redirect ไปหน้า login ของ Keycloak
// ขอ authentication ด้วย CIBA (Client Initiated Backchannel Authentication) แล้ว poll จนได้ token
// จากนั้นยิง Buyer API ที่มีอยู่จริง เพื่อพิสูจน์ว่า token จาก CIBA ใช้งานได้ (aud/scope/signature ถูกต้อง)
package main

import (
	"log"
	"os"

	"github.com/gofiber/fiber/v2"

	"central/headless-demo/internal/ciba"
	"central/headless-demo/internal/handlers"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	cfg := ciba.Config{
		Issuer:       env("KEYCLOAK_ISSUER", "http://localhost:8080/realms/central"),
		InternalBase: env("KEYCLOAK_INTERNAL_BASE", "http://keycloak:8080"),
		Realm:        "central",
		ClientID:     env("CIBA_CLIENT_ID", "headless-app"),
		ClientSecret: env("CIBA_CLIENT_SECRET", ""),
		BuyerAPIBase: env("BUYER_API_BASE", "http://buyer-api:3000"),
	}
	port := env("PORT", "3000")

	// CIBA session store สร้างครั้งเดียวตอน startup — in-memory (POC)
	// inject ผ่าน handler factories ตาม pattern เดียวกับ central-id
	store := ciba.NewStore()

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		// cookie + headers ของ browser รวมกันใหญ่กว่า 4KB — กัน HTTP 431 (เช่นเดียวกับ ID portal)
		ReadBufferSize: 16 * 1024,
	})

	// หน้าจอ + flow ของ Seller App (CIBA consumption device)
	app.Get("/", handlers.Home(store, cfg))                     // หน้า login ของแอปเอง (ไม่ redirect ไป Keycloak)
	app.Post("/ciba/request", handlers.RequestAuth(store, cfg)) // ขั้นที่ 1 — เริ่ม backchannel auth request
	app.Get("/ciba/waiting", handlers.Waiting(store, cfg))      // ขั้นที่ 2 — หน้ารอการยืนยันที่อุปกรณ์ ID
	app.Get("/ciba/poll", handlers.Poll(store, cfg))            // JSON สถานะ (JS เรียกทุก 2 วินาที)
	app.Get("/ciba/result", handlers.Result(store, cfg))        // ขั้นที่ 3 — claims + ผลการยิง Buyer API

	log.Printf("headless-demo (CIBA consumption device) listening :%s — client=%s issuer=%s", port, cfg.ClientID, cfg.Issuer)
	log.Fatal(app.Listen(":" + port))
}
