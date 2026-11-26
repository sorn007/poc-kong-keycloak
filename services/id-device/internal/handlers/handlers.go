// Package handlers — endpoints ของ "อุปกรณ์ ID" (Authentication Device ของ CIBA flow)
// ฝั่ง Keycloak: POST /ciba/delegation เมื่อมีคำขอ backchannel login เข้ามา
// ฝั่งผู้ใช้: GET / กดอนุมัติ/ปฏิเสธ → POST /ciba/approve, /ciba/deny
// ทุกครั้งที่ตัดสินใจ บริการนี้จะยิงผลกลับไป callback endpoint ของ Keycloak (POC)
// หน้าเว็บ (UI) รองรับสองภาษา ไทย/EN ผ่าน web.LangOf/web.T — default "th", route/cookie/logic คงเดิมทั้งหมด
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"central/auth-go"
	"central/id-device/internal/device"
	"central/id-device/internal/web"
)

const sessionCookie = "device_session" // cookie เก็บ session id ของผู้อนุมัติ

// Config — ค่าที่ใช้สร้าง URL callback ของ Keycloak
type Config struct {
	KeycloakInternalBase string
	Realm                string
}

// callbackURL — endpoint ที่ AD ต้อง POST แจ้งผลการอนุมัติ (CIBA authentication delegation)
func (cfg Config) callbackURL() string {
	return cfg.KeycloakInternalBase + "/realms/" + cfg.Realm + "/protocol/openid-connect/ext/ciba/auth/callback"
}

// delegationRequest — body ที่ Keycloak ส่งเข้ามาพร้อมคำขอ (login_hint/scope required)
// acr_values อาจไม่มีใน body — ยอมรับได้ (POC ยังไม่ใช้ค่านี้)
type delegationRequest struct {
	LoginHint         string `json:"login_hint"`
	Scope             string `json:"scope"`
	IsConsentRequired bool   `json:"is_consent_required"`
	BindingMessage    string `json:"binding_message"`
	AcrValues         string `json:"acr_values"`
}

// httpClient — client สำหรับยิง callback ไป Keycloak (มี timeout กันค้าง)
var httpClient = &http.Client{Timeout: 10 * time.Second}

// Register — ผูก routes ทั้งหมดของอุปกรณ์ ID เข้ากับ app (pattern เดียวกับ oidc.Register)
// sessions = session ของ "ผู้อนุมัติ" (ต้อง login ด้วยบัญชี ID ก่อนกดอนุมัติ — production security)
func Register(app *fiber.App, store *device.Store, cfg Config, sessions *device.SessionStore, k auth.Keyfunc, loginCfg auth.Config) {
	// POST /ciba/delegation — Keycloak แจ้งคำขอ login ให้อุปกรณ์ตัดสินใจ
	app.Post("/ciba/delegation", func(c *fiber.Ctx) error {
		authz := c.Get(fiber.HeaderAuthorization)
		// POC: ยังไม่ตรวจสอบ token ที่ KC แนบมา นอกจากรูปแบบ "Bearer " — production
		// ต้อง validate token (issuer/audience/signature) ก่อนเชื่อถือทุกครั้ง
		if !strings.HasPrefix(authz, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing_bearer_token"})
		}
		var req delegationRequest
		// ใช้ json.Unmarshal ตรง ๆ ไม่ง้อ Content-Type — กันเคส KC ยิงมา header เพี้ยน
		if err := json.Unmarshal(c.Body(), &req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_json_body"})
		}
		if req.LoginHint == "" || req.Scope == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "login_hint_and_scope_required"})
		}
		id := store.Save(&device.Pending{
			Bearer:            strings.Clone(strings.TrimPrefix(authz, "Bearer ")), // clone — กัน fasthttp buffer reuse
			LoginHint:         req.LoginHint,
			Scope:             req.Scope,
			BindingMessage:    req.BindingMessage,
			IsConsentRequired: req.IsConsentRequired,
			ReceivedAt:        time.Now(),
		})
		log.Printf("ciba delegation received: id=%s login_hint=%s scope=%s", id, req.LoginHint, req.Scope)
		// Keycloak คาดหวัง HTTP 201 จาก authentication delegation endpoint — ตอบอย่างอื่น flow จะ fail
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{"id": id})
	})

	// GET / — หน้าอนุมัติบน "จอมือถือ" — ต้อง login ด้วยบัญชี ID ก่อน
	// เห็นได้เฉพาะคำขอที่ login_hint ตรงกับผู้ใช้ที่ล็อกอิน (กันอนุมัติคำขอของผู้อื่น)
	app.Get("/", func(c *fiber.Ctx) error {
		lang := web.LangOf(c)
		username := sessions.UsernameOf(c.Cookies(sessionCookie))
		if username == "" {
			return sendLoginRequired(c, lang)
		}
		var mine []*device.Pending
		for _, p := range store.List() {
			if p.LoginHint == username {
				mine = append(mine, p)
			}
		}
		var b strings.Builder
		if len(mine) == 0 {
			b.WriteString(web.EmptyBody(lang))
		}
		for _, p := range mine {
			b.WriteString(renderRequest(p, lang))
		}
		return c.Type("html").SendString(web.Page(struct {
			Title       string
			Body        string
			AutoRefresh bool
			Lang        string
		}{
			Title:       web.T(lang, "ID — คำขอเข้าสู่ระบบของ ", "ID — Sign-in requests for ") + username,
			Body:        b.String(),
			AutoRefresh: len(mine) == 0,
			Lang:        lang,
		}))
	})

	// GET /pending — รายการคำขอแบบ JSON (สำหรับ script/test) — ต้อง login และกรองเฉพาะของตัวเอง
	app.Get("/pending", func(c *fiber.Ctx) error {
		username := sessions.UsernameOf(c.Cookies(sessionCookie))
		if username == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "login_required"})
		}
		list := store.List()
		out := make([]fiber.Map, 0, len(list))
		for _, p := range list {
			if p.LoginHint != username {
				continue
			}
			out = append(out, fiber.Map{
				"id":              p.ID,
				"login_hint":      p.LoginHint,
				"scope":           p.Scope,
				"binding_message": p.BindingMessage,
				"received_at":     p.ReceivedAt,
			})
		}
		return c.JSON(out)
	})

	// POST /ciba/approve — ผู้ใช้กดยืนยัน → แจ้ง KC ด้วย status SUCCEED
	app.Post("/ciba/approve", decide(sessions, store, cfg, "SUCCEED"))

	// POST /ciba/deny — ผู้ใช้กดปฏิเสธ → แจ้ง KC ด้วย status UNAUTHORIZED
	app.Post("/ciba/deny", decide(sessions, store, cfg, "UNAUTHORIZED"))
}

// sendLoginRequired — หน้าบังคับ login ก่อนอนุมัติ (production security: ห้ามอนุมัติโดยไม่รู้ว่าใคร)
func sendLoginRequired(c *fiber.Ctx, lang string) error {
	return c.Type("html").SendString(web.Page(struct {
		Title       string
		Body        string
		AutoRefresh bool
		Lang        string
	}{
		Title: web.T(lang, "ID — ต้องเข้าสู่ระบบก่อน", "ID — Sign in required"),
		Body: `<div class="empty"><div class="pulse"></div>
<div class="t">` + web.T(lang, "ต้องเข้าสู่ระบบด้วยบัญชี ID ก่อนอนุมัติคำขอ", "Sign in with your ID account before approving requests") + `</div>
<div class="s">` + web.T(lang, "การอนุมัติจะผูกกับบัญชีของคุณ — เห็นได้เฉพาะคำขอของตัวเอง", "Approvals are bound to your account — you only see your own requests") + `</div></div>
<div class="actions"><a class="approve" style="text-decoration:none;display:block" href="/auth/login">` + web.T(lang, "เข้าสู่ระบบด้วย ID", "Sign in with ID") + `</a></div>`,
		AutoRefresh: false,
		Lang:        lang,
	}))
}

// decide — logic ร่วมของ approve/deny: ต้อง login ก่อน + อนุมัติได้เฉพาะคำขอของตัวเอง
// (login_hint ของคำขอ ต้องตรงกับ username ที่ล็อกอิน — กันอนุมัติคำขอของผู้อื่น)
// - browser (form post ไม่มี ?id=) → ตอบหน้า HTML สถานะหลังตัดสินใจ
// - script/test (เรียกด้วย ?id=) → ตอบ JSON เหมือนเดิม
func decide(sessions *device.SessionStore, store *device.Store, cfg Config, status string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		lang := web.LangOf(c)
		id := c.FormValue("id")
		if id == "" {
			id = c.Query("id")
		}
		p, ok := store.Get(id)
		if !ok {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "request_not_found", "id": id})
		}
		username := sessions.UsernameOf(c.Cookies(sessionCookie))
		if username == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "login_required"})
		}
		if p.LoginHint != username {
			log.Printf("ciba approve blocked: %s tried to decide request of %s", username, p.LoginHint)
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "user_mismatch",
				"detail": web.T(lang, "อนุมัติได้เฉพาะคำขอของตัวเอง", "You can only decide on your own requests")})
		}
		cbStatus, err := postCallback(cfg.callbackURL(), p.Bearer, status)
		if err != nil {
			// ยังไม่ Remove — ให้ผู้ใช้กดซ้ำได้ถ้า KC เข้าถึงไม่ได้ชั่วคราว
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "callback_failed", "detail": err.Error()})
		}
		store.Remove(id)
		log.Printf("ciba request decided: id=%s status=%s by=%s callback_status=%d", id, status, username, cbStatus)

		// มาจากฟอร์ม HTML (browser) → ตอบหน้าสถานะหลังตัดสินใจ
		approved := status == "SUCCEED"
		if c.Query("id") == "" && c.FormValue("id") != "" {
			icon, title := "✓", web.T(lang, "อนุมัติคำขอแล้ว", "Request approved")
			note := web.T(lang, "ระบบได้แจ้ง Keycloak แล้ว — แอปที่ร้องขอจะได้รับ token โดยอัตโนมัติ",
				"Keycloak has been notified — the requesting app will receive tokens automatically")
			if !approved {
				icon, title = "✕", web.T(lang, "ปฏิเสธคำขอแล้ว", "Request denied")
				note = web.T(lang, "ระบบแจ้ง Keycloak ให้ยกเลิกคำขอนี้แล้ว — แอปที่ร้องขอจะได้รับ access_denied",
					"Keycloak was asked to cancel this request — the requesting app will receive access_denied")
			}
			return c.Type("html").SendString(web.Page(struct {
				Title       string
				Body        string
				AutoRefresh bool
				Lang        string
			}{
				Title: "ID — " + title,
				Body: `<div class="after"><div class="big ok">` + icon + `</div>
<h1>` + title + `</h1><p>` + note + `</p>
<p style="margin-top:10px">` + web.T(lang, "ผู้ใช้", "User") + `: <b>` + web.Esc(p.LoginHint) + `</b> · ` + web.T(lang, "แอป", "App") + `: <span class="appname">Seller App (headless-app)</span></p>
<div class="actions"><a class="approve" style="text-decoration:none;display:block" href="/">` + web.T(lang, "กลับหน้าอุปกรณ์ ID", "Back to ID device") + `</a></div></div>`,
				AutoRefresh: false,
				Lang:        lang,
			}))
		}
		return c.JSON(fiber.Map{"ok": true, "callback_status": cbStatus})
	}
}

// postCallback — POST ผลการตัดสินใจไปที่ callback endpoint ของ Keycloak
// ใช้ Bearer เดียวกับตอน KC ส่งคำขอเข้ามา และคืน HTTP status ที่ KC ตอบกลับ
func postCallback(url, bearer, status string) (int, error) {
	body, err := json.Marshal(map[string]string{"status": status})
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// renderRequest — การ์ดคำขอ 1 รายการบนหน้าอนุมัติ (ปุ่มยืนยัน/ปฏิเสธส่ง id แบบ hidden input)
func renderRequest(p *device.Pending, lang string) string {
	lblReceivedAt := web.T(lang, "รับคำขอเมื่อ", "Request received at")
	lblUser := web.T(lang, "ผู้ใช้", "User")
	lblApp := web.T(lang, "แอปที่ร้องขอ", "Requesting app")
	lblCode := web.T(lang, "ยืนยันด้วยรหัส", "Verification code")
	lblScope := web.T(lang, "scope ที่ขอ", "Requested scope")
	lblApprove := web.T(lang, "ยืนยัน", "Approve")
	lblDeny := web.T(lang, "ปฏิเสธ", "Deny")
	var chips strings.Builder
	for _, sc := range strings.Fields(p.Scope) {
		fmt.Fprintf(&chips, `<span class="chip">%s</span>`, web.Esc(sc))
	}
	consent := ""
	if p.IsConsentRequired {
		consent = `<span class="chip warn">` + web.T(lang, "ต้องขอความยินยอม (consent)", "Consent required") + `</span>`
	}
	binding := ""
	if p.BindingMessage != "" {
		binding = `<div class="code">` + web.Esc(p.BindingMessage) + `</div>`
	}
	return fmt.Sprintf(`<div class="req">
<div class="when" style="font-size:11.5px;color:#94a3b8;margin-bottom:10px">`+lblReceivedAt+` %s</div>
<div class="row"><div class="k">`+lblUser+`</div><div class="v"><b>%s</b></div></div>
<div class="row"><div class="k">`+lblApp+`</div><div class="v">Seller App <span style="color:#94a3b8">(headless-app)</span></div></div>
<div class="row"><div class="k">`+lblCode+`</div><div class="v" style="width:100%%;text-align:left">%s</div></div>
<div class="row"><div class="k">`+lblScope+`</div><div class="v"><span class="chips">%s%s</span></div></div>
<div class="actions">
<form method="post" action="/ciba/approve"><input type="hidden" name="id" value="%s"><button class="approve" type="submit">`+lblApprove+`</button></form>
<form method="post" action="/ciba/deny"><input type="hidden" name="id" value="%s"><button class="deny" type="submit">`+lblDeny+`</button></form>
</div>
</div>`,
		web.Esc(p.ReceivedAt.Format("02/01/2006 15:04:05")),
		web.Esc(p.LoginHint),
		binding,
		consent, chips.String(),
		web.Esc(p.ID), web.Esc(p.ID))
}
