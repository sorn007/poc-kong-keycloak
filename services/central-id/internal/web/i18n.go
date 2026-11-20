package web

// i18n แบบ lightweight — สลับ EN/ไทย ได้ทุกหน้า
// • ลำดับความสำคัญ: ?lang=xx (แล้วจำลง cookie) → cookie "lang" → ค่าเริ่มต้น "th"
// • cookie "lang" เป็นของ host localhost — browser ส่งให้ทุก port จึงสลับทีเดียวได้ทุกแอป
// • การแปลใช้ helper T(lang, ข้อความไทย, ข้อความอังกฤษ) — คู่กันอยู่ในบรรทัดเดียว ดูแลง่าย

import (
	"fmt"
	"strings"

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

// LangSwitch — ปุ่มสลับภาษา (ลิงก์ไป path เดิม + ?lang=<อีกภาษา>)
func LangSwitch(c *fiber.Ctx, lang string) string {
	p := c.Path()
	other, label, cur := "en", "EN", "TH"
	if lang == "en" {
		other, label, cur = "th", "ไทย", "EN"
	}
	sep := "?"
	if strings.Contains(p, "?") {
		sep = "&"
	}
	return fmt.Sprintf(`<div class="langsw"><span class="langcur">%s</span><a href="%s%s%s=%s" title="switch language">%s</a></div>`, cur, p, sep, "lang", other, label)
}
