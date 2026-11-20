package web

// i18n แบบ lightweight — สลับ EN/ไทย ได้ทุกหน้า (รูปแบบเดียวกับ central-id/internal/web/i18n.go)
// • ลำดับความสำคัญ: ?lang=xx (แล้วจำลง cookie) → cookie "lang" → ค่าเริ่มต้น "th"
// • cookie "lang" เป็นของ host localhost — browser ส่งให้ทุก port จึงสลับทีเดียวได้ทุกแอป
// • การแปลใช้ helper T(lang, ข้อความไทย, ข้อความอังกฤษ) — คู่ข้อความอยู่ในบรรทัดเดียว ดูแลง่าย

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
)

// LangOf — อ่านภาษาของ request (?lang= มาก่อน แล้วจำลง cookie)
func LangOf(c *fiber.Ctx) string {
	if q := c.Query("lang"); q == "en" || q == "th" {
		c.Cookie(&fiber.Cookie{Name: "lang", Value: q, Path: "/", MaxAge: 31536000})
		return q
	}
	if ck := c.Cookies("lang"); ck == "en" || ck == "th" {
		return ck
	}
	return "th"
}

// T — เลือกข้อความตามภาษา
func T(lang, th, en string) string {
	if lang == "en" {
		return en
	}
	return th
}

// LangSwitchHTML — ปุ่มสลับภาษาใน header ทุกหน้า
// ลิงก์ชี้ "/?lang=<อีกภาษา>" เสมอ: หน้าใช้งานหลักของอุปกรณ์คือ "/" และหน้าผลลัพธ์
// หลังตัดสินใจมาจาก POST /ciba/* — ถ้าชี้ path เดิม browser จะ GET โดน route POST (405)
func LangSwitchHTML(lang string) string {
	other, label := "en", "EN"
	if lang == "en" {
		other, label = "th", "ไทย"
	}
	return fmt.Sprintf(`<div class="langsw"><span class="langcur">%s</span><a href="/?lang=%s" title="switch language">%s</a></div>`, lang, other, label)
}
