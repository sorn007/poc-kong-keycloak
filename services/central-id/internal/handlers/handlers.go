// Package handlers — หน้าจอของ ID Portal (บัญชีกลางของ Central)
package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"central/central-id/internal/auth"
	"central/central-id/internal/sso"
	"central/central-id/internal/stt"
	"central/central-id/internal/web"
)

// currentSession — อ่าน + verify cookie session (คืน nil ถ้ายังไม่ login/หมดอายุ)
func currentSession(k auth.Keyfunc, cfg auth.Config, c *fiber.Ctx) *web.Session {
	token := c.Cookies("central_session")
	if token == "" {
		return nil
	}
	claims, err := auth.VerifyCentral(k, cfg, token)
	if err != nil {
		return nil
	}
	return sessionFromClaims(claims)
}

func sessionFromClaims(claims *auth.Claims) *web.Session {
	if claims == nil {
		return nil
	}
	username := claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}
	if username == "" {
		username = claims.Subject
	}
	var exp int64
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Unix()
	}
	return &web.Session{
		Username:      username,
		Email:         claims.Email,
		Sub:           claims.Subject,
		ClientID:      claims.ClientID,
		PrincipalType: claims.PrincipalType,
		TenantID:      claims.TenantID,
		Scopes:        claims.Scopes(),
		Exp:           exp,
		Issuer:        claims.Issuer,
		SID:           claims.ID,
		IssuedAt:      claims.IssuedAt.Unix(),
	}
}

// Home — หน้าแรกของ ID (flow ขั้นที่ 1)
func Home(k auth.Keyfunc, cfg auth.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		lang := web.LangOf(c)
		s := currentSession(k, cfg, c)
		if s == nil {
			// token ติดมาแต่ verify ไม่ผ่าน → แจ้ง session หมดอายุ (เช่น logout กลางไปแล้ว)
			warn := ""
			if c.Cookies("central_session") != "" {
				warn = `<div class="notice warn"><b>` + web.T(lang, "Session หมดอายุหรือถูก logout กลางแล้ว", "Session expired or globally logged out") + `</b> — ` + web.T(lang, "ล็อกอินอีกครั้งเพื่อใช้งานต่อ", "sign in again to continue") + `</div>`
			}
			body := warn + `<section class="hero">
<h1>ID</h1>
<p>` + web.T(lang, "บัญชีกลางของทุกระบบใน Central — ล็อกอินครั้งเดียว ใช้ได้ทั้ง Buyer และ CIS", "The central account for every system — sign in once, use both Buyer and CIS") + `<br>
` + web.T(lang, "ออกโดย Keycloak (realm", "Issued by Keycloak (realm") + ` <code>central</code>) · ` + web.T(lang, "token มาตรฐาน OIDC, RS256 + JWKS", "standard OIDC tokens, RS256 + JWKS") + `</p>
<a class="btn btn-primary" href="/auth/login">` + web.T(lang, "ล็อกอินด้วย ID", "Sign in with ID") + `</a>
<p style="margin-top:18px;font-size:13px;color:#a5b4fc">` + web.T(lang, "หน้า login ของ ID · Authorization Code + PKCE", "ID sign-in page · Authorization Code + PKCE") + `</p>
</section>
<div class="card"><h2>` + web.T(lang, "ทำอะไรได้บ้าง", "What you can do") + `</h2><p class="sub">` + web.T(lang, "หลังล็อกอิน", "After signing in") + `</p>
<ul style="font-size:14px;line-height:1.9">
<li>` + web.T(lang, "ดูโปรไฟล์และ session กลางของคุณ", "See your profile and central session") + `</li>
<li>` + web.T(lang, "เห็น <b>แอปที่เชื่อมต่อ</b> — Buyer Portal / CIS Portal พร้อมเข้าใช้แบบ SSO", "See <b>connected apps</b> — Buyer Portal / CIS Portal ready for SSO") + `</li>
<li><b>` + web.T(lang, "Logout กลาง", "Global logout") + `</b> — ` + web.T(lang, "ยุติ session ทุกระบบในคลิกเดียว", "end every system session in one click") + `</li>
</ul></div>`
			return send(c, "ID", body, 1, 0, nil, "home", lang)
		}

		body := `<div class="notice ok"><b>` + web.T(lang, "สวัสดี", "Hello") + ` ` + web.Esc(s.Username) + `</b> — ` + web.T(lang, "คุณล็อกอินผ่าน ID อยู่ · session นี้ใช้กับทุกแอปที่เชื่อมต่อ", "you are signed in via ID · this session works on every connected app") + `</div>
` + web.ProfileCards(s, lang) + `
<div class="card"><h2>` + web.T(lang, "ไปต่อใน flow", "Continue the flow") + `</h2><p class="sub">` + web.T(lang, "เส้นทางทดสอบตาม rootcase — ล็อกอินครั้งเดียว ใช้ได้ทุกระบบ", "Test path per rootcase — sign in once, use everywhere") + `</p>
<div class="actions" style="display:flex;gap:10px;flex-wrap:wrap">
<a class="btn btn-primary btn-sm" href="/apps">` + web.T(lang, "เปิดแอปที่เชื่อมต่อ (SSO)", "Open connected apps (SSO)") + `</a>
<a class="btn btn-ghost btn-sm" href="/session">` + web.T(lang, "ดูรายละเอียด Session", "Session details") + `</a>
<a class="btn btn-ghost btn-sm" href="http://localhost:8080/realms/central/account" target="_blank" rel="noreferrer">Account Console</a>
<a class="btn btn-ghost btn-sm" href="/auth/logout">` + web.T(lang, "Logout กลาง (ทุกระบบ)", "Global logout (all systems)") + `</a>
</div></div>
<script>` + `</script>`
		return send(c, "ID", body, 1, 1, s, "home", lang)
	}
}

// Apps — หน้า "แอปที่เชื่อมต่อ" — จำลองหน้า connected apps ของ identity provider จริง
func Apps(k auth.Keyfunc, cfg auth.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		lang := web.LangOf(c)
		s := currentSession(k, cfg, c)
		if s == nil {
			return needLogin(c, k, cfg, lang)
		}
		connected := web.T(lang, "เชื่อมต่อแล้ว", "Connected")
		open := web.T(lang, "เปิด", "Open")
		body := `<div class="notice ok"><b>` + web.T(lang, "แอปที่ใช้ ID เป็นบัญชีกลาง", "Apps using ID as their central account") + `</b> — ` + web.T(lang, "กดเปิดได้เลย จะ SSO อัตโนมัติโดยไม่ถามรหัสผ่าน", "click to open — SSO happens automatically without asking for a password") + `</div>
<div class="grid">
<div class="appcard">
  <div class="icon" style="background:#eef2ff">🛒</div>
  <h2 style="margin:0">Buyer Portal</h2>
  <p class="sub" style="margin:0">` + web.T(lang, "ระบบจัดซื้อ (NestJS)", "Procurement system (NestJS)") + ` — <code>aud=buyer-api</code>, scopes <code>orders.*</code></p>
  <div><span class="pill ok">` + connected + `</span> <span class="pill">SSO</span></div>
  <div style="margin-top:auto"><a class="btn btn-primary btn-sm" href="http://localhost:3010">` + open + ` Buyer Portal</a></div>
</div>
<div class="appcard">
  <div class="icon" style="background:#e0f2fe">📁</div>
  <h2 style="margin:0">CIS Portal</h2>
  <p class="sub" style="margin:0">` + web.T(lang, "ระบบข้อมูลโครงการ (Go Fiber)", "Project information system (Go Fiber)") + ` — <code>aud=cis-api</code>, scopes <code>projects.*</code></p>
  <div><span class="pill ok">` + connected + `</span> <span class="pill">SSO</span></div>
  <div style="margin-top:auto"><a class="btn btn-primary btn-sm" href="http://localhost:3020">` + open + ` CIS Portal</a></div>
</div>
<div class="appcard">
  <div class="icon" style="background:#fce7f3">📱</div>
  <h2 style="margin:0">Mobile App</h2>
  <p class="sub" style="margin:0">` + web.T(lang, "แอปมือถือ (iOS/Android)", "Mobile app (iOS/Android)") + ` — public client + <b>PKCE enforced (S256)</b>, refresh token rotation — <code>aud=buyer-api</code>, scopes <code>orders.read</code></p>
  <div><span class="pill ok">` + connected + `</span> <span class="pill">SSO</span> <span class="pill">PKCE</span></div>
  <div style="margin-top:auto"><span class="sub">` + web.T(lang, "login ผ่าน system browser ตาม RFC 8252 (ไม่ใช้ WebView)", "signs in via system browser per RFC 8252 (no WebView)") + `</span></div>
</div>
<div class="appcard">
  <div class="icon" style="background:#0a1f3c">💳</div>
  <h2 style="margin:0">Fintech App</h2>
  <p class="sub" style="margin:0">` + web.T(lang, "เว็บ fintech ที่ทำหน้า login เอง (Embedded Login — exception pattern)", "Fintech web with its own login form (Embedded Login — exception pattern)") + ` — <code>aud=buyer-api</code> + ` + web.T(lang, "ออก SSO Ticket ให้ทุกแอป", "issues the SSO ticket for every app") + `</p>
  <div><span class="pill ok">` + connected + `</span> <span class="pill">Embedded Login</span> <span class="pill">SSO Ticket</span></div>
  <div style="margin-top:auto"><a class="btn btn-primary btn-sm" href="http://localhost:3050">` + open + ` Fintech App</a></div>
</div>
<div class="appcard">
  <div class="icon" style="background:#fef3c7">🔌</div>
  <h2 style="margin:0">Open API (Partner)</h2>
  <p class="sub" style="margin:0">` + web.T(lang, "M2M ผ่าน Kong Gateway", "M2M via Kong Gateway") + ` — client_credentials, <code>aud=buyer-api</code> + rate limit</p>
  <div><span class="pill warn">` + web.T(lang, "ไม่แสดงในหน้านี้", "Not shown on this page") + `</span></div>
  <div style="margin-top:auto"><span class="sub">` + web.T(lang, "token ออกโดย client credential ของ partner-001", "token issued by partner-001 client credentials") + `</span></div>
</div>
</div>
<div class="card"><h2>` + web.T(lang, "จัดการการเข้าถึง", "Manage access") + `</h2><p class="sub">` + web.T(lang, "จำลองเฉพาะส่วนแสดงผล — revoke จริงทำที่ Admin Console/Account Console", "Display only — real revocation happens in Admin Console/Account Console") + `</p>
<div class="actions">
<a class="btn btn-ghost btn-sm" href="http://localhost:8080/realms/central/account" target="_blank" rel="noreferrer">Account Console — ` + web.T(lang, "จัดการอุปกรณ์/revoke", "manage devices / revoke") + `</a>
<a class="btn btn-ghost btn-sm" href="/auth/logout">` + web.T(lang, "Logout กลาง (ทุกระบบ)", "Global logout (all systems)") + `</a>
</div></div>`
		return send(c, web.T(lang, "ID — แอปที่เชื่อมต่อ", "ID — Connected apps"), body, 1, 1, s, "apps", lang)
	}
}

// SessionPage — รายละเอียด session ปัจจุบัน (flow ขั้น 4 — จุด logout กลาง)
func SessionPage(k auth.Keyfunc, cfg auth.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		lang := web.LangOf(c)
		s := currentSession(k, cfg, c)
		if s == nil {
			return needLogin(c, k, cfg, lang)
		}
		issued := fmt.Sprint(s.IssuedAt)
		body := web.ProfileCards(s, lang) + `
<div class="card"><h2>` + web.T(lang, "สิ้นสุด session", "End session") + `</h2><p class="sub">` + web.T(lang, "Logout กลางจะยุติ SSO session ที่ Keycloak — ทุกแอปต้องล็อกอินใหม่ (access token เดิมยัง valid ได้ถึง exp ตามข้อจำกัด JWT — ดู rootcase §6)", "Global logout ends the SSO session at Keycloak — every app must sign in again (existing access tokens stay valid until exp per JWT limits — see rootcase §6)") + `</p>
<div class="actions">
<a class="btn btn-primary btn-sm" href="/auth/logout">` + web.T(lang, "Logout กลาง (ทุกระบบ)", "Global logout (all systems)") + `</a>
<a class="btn btn-ghost btn-sm" href="http://localhost:8080/realms/central/account" target="_blank" rel="noreferrer">` + web.T(lang, "จัดการอุปกรณ์ทั้งหมดที่ Account Console", "Manage all devices in Account Console") + `</a>
</div></div>
<div class="card"><h2>` + web.T(lang, "ข้อมูลสำหรับผู้พัฒนา (POC)", "Developer info (POC)") + `</h2><p class="sub">` + web.T(lang, "issued-at ของ session นี้", "issued-at of this session") + `</p>
<table>
<tr><th>iat</th><td><code>` + web.Esc(issued) + `</code></td></tr>
<tr><th>issuer</th><td><code style="font-size:11.5px">` + web.Esc(s.Issuer) + `</code></td></tr>
</table></div>`
		return send(c, "ID — Session", body, 4, 3, s, "session", lang)
	}
}

// needLogin — หน้าที่ต้อง login ก่อน
func needLogin(c *fiber.Ctx, k auth.Keyfunc, cfg auth.Config, lang string) error {
	warn := `<div class="notice warn"><b>` + web.T(lang, "ยังไม่ได้ล็อกอิน", "Not signed in") + `</b> — ` + web.T(lang, "ล็อกอินด้วย ID ก่อนใช้หน้านี้", "sign in with ID before using this page") + `</div>
<div class="card"><div class="actions"><a class="btn btn-primary" href="/auth/login">` + web.T(lang, "ล็อกอินด้วย ID", "Sign in with ID") + `</a></div></div>`
	return send(c, web.T(lang, "ID — ต้องล็อกอิน", "ID — Sign in required"), warn, 1, 0, nil, "", lang)
}

func send(c *fiber.Ctx, title, body string, step, done int, s *web.Session, pageName, lang string) error {
	return c.Type("html").SendString(web.Page(struct {
		Title      string
		Body       string
		ActiveStep int
		DoneUntil  int
		Session    *web.Session
		PageName   string
		Lang       string
	}{
		Title: title, Body: body, ActiveStep: step, DoneUntil: done,
		Session: s, PageName: pageName, Lang: lang,
	}))
}

// ---------- Session Transfer Token (จำลอง Native-to-Web SSO ของ Auth0) ----------
// Mobile app ที่มี native session ส่ง token มาสร้าง one-time transfer code (อายุสั้น ใช้ครั้งเดียว)
// แล้วเปิดเว็บแอปอื่นด้วย code — เว็บ redeem ได้ session โดยไม่ต้องกรอกรหัสผ่านซ้ำ
// Security: code สุ่ม 32 ไบต์ · TTL 60 วินาที · ใช้ครั้งเดียว · POC ยังไม่ bind redirect_uri (production ต้องเพิ่ม)

// CreateSTT — mobile ส่ง Bearer token มา verify (RS256/iss/exp ไม่จำกัด aud เพราะ mobile
// อาจถือ token ของ client ใดก็ได้ใน realm) + form field `dest` (client id ของปลายทาง — REQUIRED)
// แล้วออก one-time code ที่ผูกกับปลายทางนั้นให้
func CreateSTT(sttStore stt.CodeStore, k auth.Keyfunc, issuer string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authz := c.Get(fiber.HeaderAuthorization)
		if !strings.HasPrefix(authz, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing_bearer_token"})
		}
		dest := c.FormValue("dest")
		if dest == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "dest_required", "detail": "dest = client id of destination app"})
		}
		token := strings.Clone(strings.TrimPrefix(authz, "Bearer "))
		// ⚠️ fasthttp reuse-pool: string ที่อ้าง buffer ของ request (FormValue/Get header) จะถูก
		// เขียนทับโดย request ถัดไปหลัง buffer ถูกคืน pool — ทุกค่าที่ "เก็บข้าม request"
		// (store/memory) ต้อง clone เป็น memory ใหม่ก่อน ไม่งั้นข้อมูลเงียบ ๆ เปลี่ยนเป็นของ request อื่น
		dest = strings.Clone(dest)
		claims, err := auth.VerifyIssuerOnly(k, issuer, token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_token", "detail": err.Error()})
		}
		issuedFor := claims.Azp
		if issuedFor == "" {
			issuedFor = claims.ClientID
		}
		code := sttStore.Create(claims.PreferredUsername, token, claims.AudList(), issuedFor, dest)
		log.Printf("stt created: user=%s dest=%s issued_for=%s code=%s...", claims.PreferredUsername, dest, issuedFor, code[:8])
		return c.JSON(fiber.Map{
			"code":       code,
			"username":   claims.PreferredUsername,
			"dest":       dest,
			"issued_for": issuedFor,
			"expires_in": 60,
		})
	}
}

// RedeemSTT — แลก one-time code (server-to-server จากแอปปลายทาง) -> username + access token
// ต้องส่ง `dest` (client id ของตัวเอง) — code ออกให้ปลายทางอื่นถูกปฏิเสธ (กัน interception ข้ามแอป)
func RedeemSTT(sttStore stt.CodeStore) fiber.Handler {
	return func(c *fiber.Ctx) error {
		code := c.FormValue("code")
		if code == "" {
			code = c.Query("code")
		}
		dest := c.FormValue("dest")
		if dest == "" {
			dest = c.Query("dest")
		}
		if code == "" || dest == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code_and_dest_required"})
		}
		username, accessToken, aud, issuedFor, err := sttStore.Redeem(code, dest)
		if err != nil {
			if errors.Is(err, stt.ErrDestMismatch) {
				// 403 ไม่ 404 — บอกปลายทางว่า code นี้ไม่ใช่ของตัว (และยังไม่นับว่าใช้แล้ว)
				log.Printf("stt redeem dest mismatch: %v (code=%s)", err, code[:8])
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "destination_mismatch"})
			}
			log.Printf("stt redeem failed: %v", err)
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "invalid_or_used_or_expired_code"})
		}
		log.Printf("stt redeemed: user=%s dest=%s", username, dest)
		return c.JSON(fiber.Map{
			"username":     username,
			"access_token": accessToken,
			"aud":          aud,
			"issued_for":   issuedFor,
			"token_type":   "Bearer",
		})
	}
}

// ---------- SSO Ticket (ตั๋ว SSO ระดับ ID กลาง — ทำให้ "เปิดแอปอื่นในแท็บใหม่ ไม่ต้อง login") ----------
// ต่างจาก STT: ตั๋วใช้ซ้ำได้ตลอดอายุ (30 นาที) และ broker เก็บ refresh_token ไว้ต่ออายุ token
// (access token อายุ 5 นาที — redeem ช่วงหลัง ๆ ต้องได้ token ใหม่ ไม่ใช่ token ตาย)
// cookie ฝั่งแอป (central_sso) set ที่ host localhost — browser ส่งให้ทุก port เพราะ cookie ไม่ผูก port

// jwtPayloadField — อ่าน field จาก payload โดยไม่ verify (ใช้กับ token ที่ broker ออกเอง/refresh มาเอง)
func jwtPayloadField(token, field string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 { // header.payload.signature
		return ""
	}
	p := parts[1]
	p = strings.ReplaceAll(p, "-", "+")
	p = strings.ReplaceAll(p, "_", "/")
	switch len(p) % 4 {
	case 2:
		p += "=="
	case 3:
		p += "="
	}
	raw, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	if v, ok := m[field].(string); ok {
		return v
	}
	// JSON number decode เป็น float64 — format ให้เป็นเลขจำนวนเต็ม (fmt.Sprint จะได้ e+09)
	if f, ok := m[field].(float64); ok {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	return ""
}

// CreateSSOTicket — แอปที่ login สำเร็จ (มี Bearer token) ขอตั๋ว SSO ให้ browser
// form: refresh_token (ไว้ต่ออายุ), client_id (client ต้นทาง — ใช้ตอน refresh)
func CreateSSOTicket(ssoStore sso.TicketStore, k auth.Keyfunc, issuer string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authz := c.Get(fiber.HeaderAuthorization)
		if !strings.HasPrefix(authz, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing_bearer_token"})
		}
		token := strings.Clone(strings.TrimPrefix(authz, "Bearer ")) // clone — กัน fasthttp buffer reuse
		claims, err := auth.VerifyIssuerOnly(k, issuer, token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_token", "detail": err.Error()})
		}
		clientID := strings.Clone(c.FormValue("client_id"))
		refreshToken := strings.Clone(c.FormValue("refresh_token")) // clone — เก็บข้าม request
		if clientID == "" {
			clientID = claims.Azp
		}
		issuedFor := claims.Azp
		if issuedFor == "" {
			issuedFor = claims.ClientID
		}
		ticket, exp := ssoStore.Create(claims.PreferredUsername, token, claims.AudList(), issuedFor, refreshToken, clientID)
		log.Printf("sso ticket created: user=%s issued_for=%s renew=%v expires=%d", claims.PreferredUsername, issuedFor, refreshToken != "", exp.Unix())
		return c.JSON(fiber.Map{
			"ticket":     ticket,
			"username":   claims.PreferredUsername,
			"expires_in": int(time.Until(exp).Seconds()),
		})
	}
}

// RedeemSSOTicket — ปลายทางแลกตั๋วเป็น session data (ใช้ซ้ำได้ — ไม่ consume)
// ถ้า token ที่เก็บใกล้หมดอายุ (< 60 วินาที) จะ refresh ให้ใหม่อัตโนมัติด้วย refresh_token ที่เก็บไว้
// RedeemTicketFor — แลกตั๋ว SSO เป็น token + renew อัตโนมัติถ้าใกล้หมดอายุ (core ที่ทั้ง HTTP
// handler และ ID Portal เองใช้ — portal เป็นทั้ง broker และปลายทาง) — ตั๋ว reusable ไม่ consume
// คืน (token, aud, issuedFor, สถานะ "ok" | "dead" (ตั๋วไม่มี/หมดอายุ/renew ไม่ได้) | "error" (ติดต่อ KC ไม่ได้))
func RedeemTicketFor(ssoStore sso.TicketStore, k auth.Keyfunc, issuer, internalBase, realm string, clientSecrets map[string]string, ticket, dest string) (string, []string, string, string) {
	username, accessToken, aud, issuedFor, refreshToken, clientID, err := ssoStore.Get(ticket)
	if err != nil {
		log.Printf("sso redeem failed: %v (dest=%s)", err, dest)
		return "", nil, "", "dead"
	}

	// token ใกล้หมดอายุ → ต่อด้วย refresh grant (client ต้นทาง; public client ไม่ต้อง secret)
	var exp int64
	if v := jwtPayloadField(accessToken, "exp"); v != "" {
		exp, _ = strconv.ParseInt(v, 10, 64)
	}
	if time.Now().Unix()+60 > exp {
		if refreshToken == "" {
			log.Printf("sso redeem: token near expiry but no refresh token (dest=%s)", dest)
			return "", nil, "", "dead"
		}
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {clientID},
			"refresh_token": {refreshToken},
		}
		if sec, ok := clientSecrets[clientID]; ok && sec != "" {
			form.Set("client_secret", sec)
		}
		resp, rerr := http.PostForm(internalBase+"/realms/"+realm+"/protocol/openid-connect/token", form)
		if rerr != nil {
			log.Printf("sso renew failed: %v", rerr)
			return "", nil, "", "error"
		}
		defer resp.Body.Close()
		var tr struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			Error        string `json:"error"`
		}
		if jerr := json.NewDecoder(resp.Body).Decode(&tr); jerr != nil || tr.AccessToken == "" {
			log.Printf("sso renew rejected: %s", tr.Error)
			ssoStore.Revoke(ticket)
			return "", nil, "", "dead"
		}
		// อัปเดตตั๋วด้วย token ใหม่ (refresh token อาจถูก rotate — เก็บใบใหม่แทน)
		newClaims, verr := auth.VerifyIssuerOnly(k, issuer, tr.AccessToken)
		newAud := aud
		if verr == nil {
			newAud = newClaims.AudList()
		}
		newRefresh := tr.RefreshToken
		if newRefresh == "" {
			newRefresh = refreshToken
		}
		ssoStore.Update(ticket, tr.AccessToken, newAud, newRefresh)
		accessToken, aud, refreshToken = tr.AccessToken, newAud, newRefresh
		log.Printf("sso renewed: user=%s for dest=%s", username, dest)
	}
	log.Printf("sso redeemed: user=%s dest=%s (ticket reusable)", username, dest)
	return accessToken, aud, issuedFor, "ok"
}

func RedeemSSOTicket(ssoStore sso.TicketStore, k auth.Keyfunc, issuer string, internalBase, realm string, clientSecrets map[string]string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ticket := strings.Clone(c.FormValue("ticket"))
		dest := c.FormValue("dest")
		if ticket == "" || dest == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "ticket_and_dest_required"})
		}
		accessToken, aud, issuedFor, status := RedeemTicketFor(ssoStore, k, issuer, internalBase, realm, clientSecrets, ticket, dest)
		switch status {
		case "dead":
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "invalid_or_expired_ticket"})
		case "error":
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "renew_failed"})
		}
		return c.JSON(fiber.Map{
			"username":     jwtPayloadField(accessToken, "preferred_username"),
			"access_token": accessToken,
			"aud":          aud,
			"issued_for":   issuedFor,
			"token_type":   "Bearer",
		})
	}
}

// RevokeSSOTicket — ยกเลิกตั๋ว (logout กลาง) — ต้องมี Bearer token ของ realm นี้ (ผู้ถือ session จริง)
func RevokeSSOTicket(ssoStore sso.TicketStore, k auth.Keyfunc, issuer string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authz := c.Get(fiber.HeaderAuthorization)
		if !strings.HasPrefix(authz, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing_bearer_token"})
		}
		token := strings.Clone(strings.TrimPrefix(authz, "Bearer "))
		if _, err := auth.VerifyIssuerOnly(k, issuer, token); err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_token"})
		}
		ticket := c.FormValue("ticket")
		if ticket == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "ticket_required"})
		}
		user, ok := ssoStore.Revoke(ticket)
		log.Printf("sso ticket revoked: user=%s found=%v", user, ok)
		return c.SendStatus(fiber.StatusNoContent)
	}
}

// CheckSSOTicket — ปลายทางเช็คว่า session ที่ผูกกับตั๋วยังมีชีวิตอยู่ไหม (propagate logout กลางแบบเรียลไทม์)
// ตั๋วถูก revoke/logout-all แล้ว → alive:false → ปลายทางจะเคลียร์ session ของตัวเองทันที
func CheckSSOTicket(ssoStore sso.TicketStore) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ticket := c.FormValue("ticket")
		if ticket == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "ticket_required"})
		}
		user, alive := ssoStore.Check(ticket)
		return c.JSON(fiber.Map{"alive": alive, "username": user})
	}
}

// LogoutAllSSO — logout กลางแบบ global: ยกเลิก "ทุก" ตั๋ว SSO ของ ID กลาง
// (เรียกโดยแอปที่กด Logout กลาง — ผูก Bearer token ของ session เพื่อพิสูจน์ตัวตน)
// ผลลัพธ์: แอปทุกตัวที่ session ผูกกับตั๋วจะถูกบังคับ logout ตั้งแต่ request หน้าถัดไป
func LogoutAllSSO(ssoStore sso.TicketStore, k auth.Keyfunc, issuer string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authz := c.Get(fiber.HeaderAuthorization)
		if !strings.HasPrefix(authz, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing_bearer_token"})
		}
		token := strings.Clone(strings.TrimPrefix(authz, "Bearer "))
		if _, err := auth.VerifyIssuerOnly(k, issuer, token); err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_token"})
		}
		n := ssoStore.RevokeAll()
		log.Printf("sso logout-all: revoked %d tickets (by %s)", n, jwtPayloadField(token, "preferred_username"))
		return c.JSON(fiber.Map{"revoked": n})
	}
}
