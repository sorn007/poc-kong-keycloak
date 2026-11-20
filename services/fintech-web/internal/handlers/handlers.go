// Package handlers — หน้าจอ + flow ของ Fintech App (Embedded Login — exception pattern)
// flow: แอป render ฟอร์ม username/password ของตัวเอง → backend แลก credential เป็น token
// ผ่าน Direct Access Grant (server-to-server) → เก็บ token ฝั่ง server (cookie มีเฉพาะรหัส session)
// → เรียก Buyer API ด้วย Bearer token เพื่อพิสูจน์ว่า token ใช้ได้จริง
package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"

	"central/fintech-web/internal/kc"
	"central/fintech-web/internal/session"
	"central/fintech-web/internal/web"
)

const (
	// cookieName — browser ถือเฉพาะรหัส session (HttpOnly, SameSite=Lax) — token ทั้งหมดอยู่บน server
	cookieName = "fintech_session"

	// Login throttle ระดับแอป — 5 ความล้มเหลวติดต่อกันต่อ username → ล็อก 35 วินาที
	// ตั้งให้เข้าเกณฑ์ก่อน lock ฝั่ง Keycloak (realm brute-force: 5 ครั้ง → 30 วินาที)
	// เพื่อไม่ให้ request ยิงถึง KC (แอป lock ที่ 35s > KC 30s — กันการ probe ผ่านแอป)
	maxFails      = 5
	appLockPeriod = 35 * time.Second
)

// lockState — สถานะ throttle ของ username หนึ่งคน (in-memory — หายพร้อม process)
type lockState struct {
	fails       int
	lockedUntil time.Time
}

// throttle — กัน brute-force ระดับแอป (per-username)
// POC note: Keycloak realm brute-force protection (5 ครั้ง → lock 30 วินาที) ทำงานซ้อนอีกชั้น —
// ถ้าผู้ใช้พ้น lock ของแอป (35 วินาที) แต่ KC ยัง lock อยู่ แอปจะได้ invalid_grant
// กลับมา (error_description "Account is temporarily locked") แล้วแสดงข้อความ locked —
// พฤติกรรมนี้ยอมรับได้ใน POC: ผู้ใช้เห็นว่า "ถูกระงับชั่วคราว" ทั้งสองชั้น และเคสนี้ยังเป็น
// สัญญาณ brute-force protection ทำงานอยู่ดี
type throttle struct {
	mu     sync.Mutex
	byUser map[string]*lockState
}

// NewThrottle — สร้าง throttle ต่อ process หนึ่งอัน (wire จาก main)
func NewThrottle() *throttle { return &throttle{byUser: make(map[string]*lockState)} }

// check — คืน (จำนวนวินาทีที่ยังล็อกเหลืออยู่, ยังล็อกอยู่หรือไม่)
func (t *throttle) check(username string) (int, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.byUser[username]
	if !ok {
		return 0, false
	}
	if remain := time.Until(st.lockedUntil); remain > 0 {
		return int(remain.Seconds()) + 1, true
	}
	return 0, false
}

// fail — นับความล้มเหลวอีก 1 ครั้ง — คืน (จำนวนครั้งที่ผิดล่าสุด, ถึงเกณฑ์ล็อกแล้วหรือยัง)
func (t *throttle) fail(username string) (int, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.byUser[username]
	if !ok {
		st = &lockState{}
		t.byUser[username] = st
	}
	st.fails++
	if st.fails >= maxFails {
		st.lockedUntil = time.Now().Add(appLockPeriod)
		st.fails = 0 // เริ่มนับใหม่หลังพ้นช่วง lock
		return maxFails, true
	}
	return st.fails, false
}

// success — ล็อกอินสำเร็จ → รีเซ็ต (ลบ) สถานะความล้มเหลวของ username นั้น
func (t *throttle) success(username string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.byUser, username)
}

// Health — liveness probe แบบ plain text
func Health() fiber.Handler {
	return func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).SendString("ok")
	}
}

// LoginPage — GET / — มี session ที่ใช้ได้อยู่แล้ว → 302 /home
// ไม่มี → render ฟอร์มล็อกอินของแอปเอง (Embedded Login) พร้อมข้อความ error จาก ?e=code
func LoginPage(store *session.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if currentSession(store, c) != nil {
			return c.Redirect("/home", fiber.StatusFound)
		}
		return renderLogin(c, loginView{}, web.LangOf(c))
	}
}

// Login — POST /login — รับ username/password จากฟอร์มของแอป แลกเป็น token ผ่าน Direct Grant
// สำเร็จ → เก็บ token ฝั่ง server + ออก cookie รหัส session → 302 /home
func Login(cfg kc.Config, store *session.Store, thr *throttle) fiber.Handler {
	return func(c *fiber.Ctx) error {
		lang := web.LangOf(c)
		username := strings.TrimSpace(c.FormValue("username"))
		password := c.FormValue("password")

		if username == "" || password == "" {
			return renderLogin(c, loginView{errCode: "required", username: username}, lang)
		}

		// throttle มาก่อนเสมอ — ถ้ายังล็อกอยู่ ไม่ยิงไป Keycloak (ไม่ให้ข้อมูลตอบกลับเป็น oracle)
		if waitSec, locked := thr.check(username); locked {
			return renderLocked(c, waitSec, lang)
		}

		tok, err := kc.DirectGrant(cfg, username, password)
		if err != nil {
			var ge *kc.GrantError
			if errors.As(err, &ge) && ge.IsInvalidGrant() {
				// บัญชีนี้ถูก brute-force lock ฝั่ง Keycloak อยู่ (แอปยังไม่ lock เอง)
				if ge.IsLocked() {
					return renderLogin(c, loginView{errCode: "locked", username: username}, lang)
				}
				// รหัสผ่านผิด — นับความล้มเหลวแล้ว render ฟอร์มใหม่พร้อมจำนวนครั้งที่เหลือ
				fails, nowLocked := thr.fail(username)
				if nowLocked {
					return renderLocked(c, int(appLockPeriod.Seconds()), lang)
				}
				return renderLogin(c, loginView{errCode: "invalid", username: username, fails: fails}, lang)
			}
			// error อื่น (Keycloak ล่ม/เครือข่ายขัดข้อง/ตอบไม่คาดคิด) → การ์ด error ทั่วไป
			return renderErrorCard(c, err, lang)
		}

		// ล็อกอินสำเร็จ — รีเซ็ต throttle แล้วเก็บ token ฝั่ง server เท่านั้น
		thr.success(username)
		sid, err := session.NewID()
		if err != nil {
			return renderErrorCard(c, err, lang)
		}
		expiresIn := tok.ExpiresIn
		if expiresIn <= 0 {
			expiresIn = 300 // กันค่า missing — access token ของ realm นี้ default 5 นาที
		}
		// ตั๋ว SSO ให้ browser — เปิด Buyer/CIS ในแท็บใหม่แล้วไม่ต้อง login ใหม่
		// (เก็บ ticket id ไว้กับ session เพื่อผูกอายุ — logout กลางจะ propagate ผ่าน /sso/check)
		ticket := issueSSOTicket(c, tok.AccessToken, tok.RefreshToken, clientIDSelf)
		store.Save(&session.Session{
			ID:           sid,
			Username:     username,
			AccessToken:  tok.AccessToken,
			RefreshToken: tok.RefreshToken,
			IDToken:      tok.IDToken,
			ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second),
			CreatedAt:    time.Now(),
			SSOTicket:    ticket,
		})
		c.Cookie(&fiber.Cookie{
			Name:     cookieName,
			Value:    sid,
			Path:     "/",
			HTTPOnly: true,
			SameSite: "Lax",
		})
		return c.Redirect("/home", fiber.StatusFound)
	}
}

// Home — GET /home — หน้าหลักหลังล็อกอิน: hero + claims + การ์ดพิสูจน์ Buyer API + logout
func Home(cfg kc.Config, store *session.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		lang := web.LangOf(c)
		sess := store.Get(c.Cookies(cookieName))
		if sess == nil {
			return c.Redirect("/", fiber.StatusFound)
		}
		if time.Now().After(sess.ExpiresAt) {
			// access token หมดอายุ — ทิ้ง session ฝั่ง server (POC ไม่ทำ refresh เพื่อความเรียบง่าย)
			store.Remove(sess.ID)
			c.ClearCookie(cookieName)
			return c.Redirect("/?e=expired", fiber.StatusFound)
		}
		// Logout กลาง propagate — session ผูกกับตั๋ว SSO: ตั๋วถูก revoke/logout-all ที่ไหนก็ได้
		// → session นี้ตายทันทีที่ถูกเรียกใช้ (authN ยัง verify JWT เองจาก JWKS — ตรงนี้คือ liveness ของ SSO)
		if sess.SSOTicket != "" && !ssoTicketAlive(sess.SSOTicket) {
			store.Remove(sess.ID)
			c.ClearCookie(cookieName)
			c.ClearCookie(ssoCookie)
			return c.Redirect("/?e=expired", fiber.StatusFound)
		}

		// claims แสดงเพื่อการศึกษา — decode อย่างเดียว ไม่ใช่การ verify
		claims, err := kc.DecodePayload(sess.AccessToken)
		if err != nil {
			claims = map[string]any{} // decode พัง = แสดง "—" — ยังพิสูจน์ด้วย Buyer call ด้านล่าง
		}

		// พิสูจน์ว่า token ใช้ได้จริง — Buyer API เป็นผู้ verify RS256/iss/aud/exp + scope เอง
		bStatus, bOK, bCount, bErr := kc.CallBuyer(cfg, sess.AccessToken)
		proofOK := bErr == nil && bStatus == fiber.StatusOK && bOK

		var expAt int64
		if f, ok := claims["exp"].(float64); ok {
			expAt = int64(f)
		}

		// toast แจ้งผลการเรียก Buyer API
		toastMsg := web.T(lang, "Buyer API ปฏิเสธ token หรือตอบกลับไม่สำเร็จ", "Buyer API rejected the token or failed to respond")
		toastKind := "warn"
		if proofOK {
			toastMsg = web.T(lang, "Buyer API ตอบกลับสำเร็จ — พิสูจน์ token ผ่าน (server-side call)", "Buyer API responded successfully — token proven (server-side call)")
			toastKind = "ok"
		}

		// ---- การ์ด Buyer API proof ----
		proofCls, proofPill, proofLine := "fail", `<span class="pill fail">FAIL</span>`, ""
		switch {
		case bErr != nil:
			proofLine = web.T(lang, `เรียก Buyer API ไม่สำเร็จ — <code>`, `Buyer API call failed — <code>`) + web.Esc(bErr.Error()) + `</code>`
		case proofOK:
			proofCls = "ok"
			proofPill = `<span class="pill ok">SUCCESS</span>`
			proofLine = web.T(lang,
				fmt.Sprintf(`เรียก GET /orders สำเร็จ — HTTP %d · ok=%v · orders ที่ได้กลับมา = %d รายการ`, bStatus, bOK, bCount),
				fmt.Sprintf(`GET /orders succeeded — HTTP %d · ok=%v · orders returned = %d`, bStatus, bOK, bCount))
		default:
			proofLine = web.T(lang,
				fmt.Sprintf(`Buyer API ตอบกลับ HTTP %d · ok=%v · orders=%d — token อาจถูกปฏิเสธ (401/403: ตรวจ aud/scope ฝั่ง Buyer)`, bStatus, bOK, bCount),
				fmt.Sprintf(`Buyer API responded HTTP %d · ok=%v · orders=%d — token may have been rejected (401/403: check aud/scope on the Buyer side)`, bStatus, bOK, bCount))
		}
		proofCard := `<div class="card"><h2>` + web.T(lang, "พิสูจน์การใช้ token จริง — Buyer API", "Prove the token really works — Buyer API") + `</h2><p class="sub">` + web.T(lang, "backend เรียก", "backend calls") + ` <code>` + web.Esc(cfg.BuyerAPIBase) + `/orders</code> ` + web.T(lang, "ด้วย", "with") + ` <code>Authorization: Bearer …</code> (server-to-server)</p>
<div class="proof ` + proofCls + `"><div>` + proofLine + `</div>` + proofPill + `</div></div>`

		// ---- การ์ด claims ----
		claimsCard := `<div class="card"><h2>` + web.T(lang, "Claims จาก access token", "Claims from the access token") + `</h2><p class="sub">` + web.T(lang, "decode เพื่อแสดงผลเท่านั้น — ความถูกต้องของ token พิสูจน์ด้วยการเรียก Buyer API (ซึ่ง verify RS256/iss/aud/exp เอง)", "decoded for display only — token validity is proven by calling the Buyer API (which verifies RS256/iss/aud/exp itself)") + `</p>
<table>
<tr><th>iss</th><td><code>` + web.Esc(claimStr(claims, "iss")) + `</code></td></tr>
<tr><th>sub</th><td><code>` + web.Esc(short(claimStr(claims, "sub"), 24)) + `…</code></td></tr>
<tr><th>preferred_username</th><td><b>` + web.Esc(claimStr(claims, "preferred_username")) + `</b></td></tr>
<tr><th>aud</th><td><code>` + web.Esc(claimStr(claims, "aud")) + `</code></td></tr>
<tr><th>azp / client_id</th><td><code>` + web.Esc(claimStr(claims, "azp", "client_id")) + `</code></td></tr>
<tr><th>principal_type</th><td><span class="pill">` + web.Esc(claimStr(claims, "principal_type")) + `</span></td></tr>
<tr><th>tenant_id</th><td><code>` + web.Esc(claimStr(claims, "tenant_id")) + `</code></td></tr>
<tr><th>scope</th><td>` + scopePills(claims["scope"]) + `</td></tr>
<tr><th>exp (unix)</th><td class="count">` + web.Esc(expText(expAt)) + `</td></tr>
</table></div>`

		// ---- การ์ด session ฝั่ง server ----
		sessionCard := `<div class="card"><h2>` + web.T(lang, "Session ฝั่ง server", "Server-side session") + `</h2><p class="sub">` + web.T(lang, "cookie", "cookie") + ` <code>` + cookieName + `</code> = ` + web.T(lang, "รหัส session (opaque) — token จริงอยู่ใน memory ของ server เท่านั้น", "opaque session id — the real tokens live only in server memory") + `</p>
<table>
<tr><th>session id</th><td><code>` + web.Esc(short(sess.ID, 12)) + `…</code></td></tr>
<tr><th>` + web.T(lang, "สร้างเมื่อ", "Created at") + `</th><td class="count">` + sess.CreatedAt.Format("2006-01-02 15:04:05") + `</td></tr>
<tr><th>` + web.T(lang, "access token หมดอายุใน", "access token expires in") + `</th><td class="count" id="exp-left">…</td></tr>
</table>
<div class="actions" style="margin-top:14px"><a class="btn-ghost" href="/logout">` + web.T(lang, "Logout กลาง (ทุกระบบ — revoke ตั๋ว SSO ทั้งหมด)", "Global logout (all systems — revoke every SSO ticket)") + `</a></div></div>`

		// ---- การ์ดโอน session ไปแอปอื่น (STT — จำลอง Native-to-Web SSO) ----
		// backend สร้าง one-time code ที่ ID Portal (dest = ปลายทาง) แล้ว redirect browser ไปรับ session
		// ปลายทาง redeem + ตรวจ aud ของตัวเอง (CIS แลกเป็น token aud=cis-api ด้วย Token Exchange ก่อน)
		transferCard := `<div class="card"><h2>` + web.T(lang, "โอน session ไปแอปอื่น (STT)", "Transfer the session to another app (STT)") + `</h2><p class="sub">` + web.T(lang, "one-time code อายุ 60 วินาที ใช้ครั้งเดียว ผูกปลายทาง — ปลายทางได้ session ด้วย user เดียวกันโดยไม่กรอกรหัสผ่าน", "a 60-second one-time code, single use, bound to one destination — the destination gets the same user's session without re-typing the password") + `</p>
<div class="actions" style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap">
<a class="btn-ghost" href="/stt/transfer?to=buyer">→ ` + web.T(lang, "เปิด Buyer Portal (โอน session)", "Open Buyer Portal (transfer session)") + `</a>
<a class="btn-ghost" href="/stt/transfer?to=cis">→ ` + web.T(lang, "เปิด CIS Portal (โอน session + Token Exchange)", "Open CIS Portal (transfer session + Token Exchange)") + `</a>
</div></div>`

		body := web.Topbar(sess.Username, lang) + `<main class="wrap">
<section class="hero">
<div class="herok">✓</div>
<h1>` + web.T(lang, "เข้าสู่ระบบสำเร็จ — Embedded Login", "Signed in — Embedded Login") + `</h1>
<p>` + web.T(lang, "สวัสดี", "Hello") + ` <b>` + web.Esc(sess.Username) + `</b> · ` + web.T(lang, "token ออกโดย Keycloak ผ่าน Direct Access Grant", "token issued by Keycloak via Direct Access Grant") + ` (<code>grant_type=password</code>)</p>
<div class="secnote">🔐 ` + web.T(lang, "Token เก็บฝั่ง server — browser ไม่เห็น token (cookie มีเฉพาะรหัส session)", "Tokens are stored server-side — the browser never sees them (the cookie holds only a session id)") + `</div>
</section>
<div id="toast-data" data-msg="` + web.Esc(toastMsg) + `" data-kind="` + toastKind + `"></div>
` + claimsCard + proofCard + sessionCard + transferCard + `</main>` + expScript(expAt, lang)

		return send(c, lang, web.T(lang, "Fintech App — หน้าหลัก", "Fintech App — Home"), body, fiber.StatusOK)
	}
}

// Logout — GET /logout — ทิ้ง session ฝั่ง server + เคลียร์ cookie → กลับหน้าแรก
func Logout(store *session.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// logout กลาง — revoke ตั๋วของเรา + ขอ ID กลางยกเลิก "ทุก" ตั๋ว (global)
		// → แอปทุกตัวที่ session ผูกกับตั๋วใด ๆ จะต้อง login ใหม่ตั้งแต่ request ถัดไป
		if sid := c.Cookies(cookieName); sid != "" {
			if sess := store.Get(sid); sess != nil {
				if ticket := c.Cookies(ssoCookie); ticket != "" {
					revokeSSOTicket(sess.AccessToken, ticket)
				}
				ssoLogoutAll(sess.AccessToken)
			}
		}
		if sid := c.Cookies(cookieName); sid != "" {
			store.Remove(sid)
		}
		c.ClearCookie(cookieName)
		c.ClearCookie(ssoCookie)
		return c.Redirect("/", fiber.StatusFound)
	}
}

// ---- helpers ----

// currentSession — อ่าน session ฝั่ง server จาก cookie id (คืน nil ถ้าไม่มี/หมดอายุ — เก็บกวาด session ตายด้วย)
func currentSession(store *session.Store, c *fiber.Ctx) *session.Session {
	sid := c.Cookies(cookieName)
	if sid == "" {
		return nil
	}
	sess := store.Get(sid)
	if sess == nil {
		return nil
	}
	if time.Now().After(sess.ExpiresAt) {
		store.Remove(sid)
		return nil
	}
	return sess
}

// loginView — ข้อมูลสำหรับ render ฟอร์มล็อกอิน
type loginView struct {
	errCode  string // invalid / locked / rate / expired / required / stt_invalid / stt_failed
	username string // คงค่า username ที่พิมพ์มาไว้บนฟอร์ม
	fails    int    // จำนวนครั้งที่ผิดล่าสุด (แสดง "พยายามผิด x/5")
}

// errMessage — map error code → (ข้อความ, รูปแบบของ error box) — คง code เดิมไว้ (test ใช้)
func errMessage(lang, code string) (string, string) {
	switch code {
	case "invalid":
		return web.T(lang, "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง", "Incorrect username or password"), "error"
	case "locked":
		return web.T(lang, "บัญชี/การล็อกอินถูกระงับชั่วคราว ลองใหม่ในภายหลัง", "The account/sign-in is temporarily suspended — try again later"), "warn"
	case "rate":
		return web.T(lang, "พยายามหลายครั้งเกินไป รอสักครู่", "Too many attempts — wait a moment"), "warn"
	case "expired":
		return web.T(lang, "Session หมดอายุแล้ว กรุณาเข้าสู่ระบบอีกครั้ง", "Session expired — please sign in again"), "warn"
	case "required":
		return web.T(lang, "กรุณากรอกชื่อผู้ใช้และรหัสผ่าน", "Please enter username and password"), "warn"
	case "stt_invalid":
		// STT code ปลอม/ใช้ซ้ำ/หมดอายุ — fallback ปลอดภัยคือให้ผู้ใช้กรอกรหัสผ่านเอง
		return web.T(lang, "ลิงก์โอน session ไม่ถูกต้องหรือหมดอายุ (ใช้ได้ครั้งเดียว) — กรุณาเข้าสู่ระบบด้วยรหัสผ่าน", "Session transfer link is invalid or expired (single use) — please sign in with your password"), "warn"
	case "stt_failed":
		return web.T(lang, "โอน session ไม่สำเร็จ — กรุณาเข้าสู่ระบบด้วยรหัสผ่าน", "Session transfer failed — please sign in with your password"), "warn"
	}
	return "", ""
}

// renderLogin — ฟอร์มล็อกอินของแอปเอง (production fintech look) + กล่องอธิบาย exception pattern
func renderLogin(c *fiber.Ctx, v loginView, lang string) error {
	// error มาได้ 2 ทาง: render หลัง POST /login ไม่สำเร็จ หรือ query ?e=code หลัง redirect
	code := v.errCode
	if code == "" {
		code = c.Query("e")
	}
	msg, kind := errMessage(lang, code)
	errBox := ""
	if msg != "" {
		errBox = `<div class="ebox ` + kind + `"><b>` + web.Esc(msg) + `</b></div>`
		if code == "invalid" && v.fails > 0 {
			errBox += `<div class="attempts">` + web.T(lang, "พยายามผิด", "Failed attempts") + ` ` + fmt.Sprint(v.fails) + `/` + fmt.Sprint(maxFails) + `</div>`
		}
	}

	body := `<section class="auth">
<div class="langtop"><div class="langsw">` + web.LangSwitchHTML(lang) + `</div></div>
<div class="auth-card">
<div class="brandrow"><span class="logo">F</span><div><div class="bname">Fintech App</div><div class="bbadge">EMBEDDED LOGIN · DIRECT GRANT</div></div></div>
<h1 class="atitle">` + web.T(lang, "เข้าสู่ระบบ", "Sign in") + `</h1>
<p class="asub">` + web.T(lang, `ใช้บัญชี Central เดียวกับระบบอื่น เช่น <code>buyer-user</code>`, `Use the same Central account as other systems, e.g. <code>buyer-user</code>`) + `</p>
` + errBox + `
<form class="loginform" method="post" action="/login" onsubmit="return submitWatch(this)">
<label for="f-username">` + web.T(lang, "ชื่อผู้ใช้", "Username") + `</label>
<input id="f-username" name="username" type="text" placeholder="` + web.T(lang, "ชื่อผู้ใช้ เช่น buyer-user", "Username e.g. buyer-user") + `" autocomplete="username" value="` + web.Esc(v.username) + `" required>
<label for="f-password">` + web.T(lang, "รหัสผ่าน", "Password") + `</label>
<input id="f-password" name="password" type="password" placeholder="` + web.T(lang, "รหัสผ่าน", "Password") + `" autocomplete="current-password" required>
<button class="btn-cta" type="submit"><span class="spin"></span><span>` + web.T(lang, "เข้าสู่ระบบ", "Sign in") + `</span></button>
</form>
<div class="except"><b>Embedded Login — exception pattern</b><br>
` + web.T(lang, "แอปนี้รับรหัสผ่านผ่าน backend โดยตรง (Direct Access Grant: <code>grant_type=password</code>) แล้วส่งต่อให้ Keycloak แบบ server-to-server ภายใน docker network — token ถูกเก็บฝั่ง server ทั้งหมด browser ถือเฉพาะรหัส session", "This app collects the password through its own backend (Direct Access Grant: <code>grant_type=password</code>) and forwards it to Keycloak server-to-server inside the docker network — tokens stay server-side; the browser only holds a session id") + `
<div class="exceptwarn">⚠️ ` + web.T(lang, "รูปแบบนี้ควรใช้อย่างจำกัด เพราะข้ามหน้า login ของ Keycloak จึงเสีย MFA/SSO และแอปต้องรับผิดชอบดูแลรหัสผ่านเอง — ปกติควรใช้ Authorization Code + PKCE (ดู ID Portal)", "Use this pattern sparingly — it bypasses the Keycloak login page, losing MFA/SSO, and the app must handle passwords itself — normally use Authorization Code + PKCE (see the ID Portal)") + `</div></div>
</div></section>
<script>function submitWatch(f){var b=f.querySelector('.btn-cta');if(b){b.classList.add('loading')}return true}</script>`

	return send(c, lang, web.T(lang, "Fintech App — เข้าสู่ระบบ", "Fintech App — Sign in"), body, fiber.StatusOK)
}

// renderLocked — การ์ดถูกล็อกชั่วคราว (throttle ระดับแอป) — HTTP 200 และไม่ยิงไป Keycloak
func renderLocked(c *fiber.Ctx, waitSec int, lang string) error {
	secs := fmt.Sprint(waitSec)
	body := `<section class="auth">
<div class="langtop"><div class="langsw">` + web.LangSwitchHTML(lang) + `</div></div>
<div class="auth-card center">
<div class="bigicon">🔒</div>
<h1 class="atitle">` + web.T(lang, "ถูกระงับชั่วคราว", "Temporarily locked") + `</h1>
<p class="asub">` + web.T(lang, "พยายามล็อกอินไม่สำเร็จหลายครั้ง — ระบบป้องกันการเดารหัสผ่าน (brute-force protection)<br>ลองอีกครั้งใน", "Too many failed sign-in attempts — brute-force protection<br>Try again in") + ` <b id="waitsec" class="count">` + secs + `</b> ` + web.T(lang, "วินาที", "seconds") + `</p>
<div class="lockbar"><div class="lockfill" id="lockfill" style="width:100%"></div></div>
<a class="btn-ghost" href="/">` + web.T(lang, "กลับไปหน้าล็อกอิน", "Back to sign-in") + `</a>
</div></section>
<script>(()=>{var s=` + secs + `,total=s,el=document.getElementById('waitsec'),fill=document.getElementById('lockfill');
var t=setInterval(()=>{s-=1;if(s<=0){clearInterval(t);location.href='/';return}
el.textContent=s;fill.style.width=Math.max(0,(s/total*100))+'%';},1000);})();</script>`

	return send(c, lang, web.T(lang, "Fintech App — ถูกระงับชั่วคราว", "Fintech App — Temporarily locked"), body, fiber.StatusOK)
}

// renderErrorCard — error ที่ไม่ใช่ invalid_grant (เช่น Keycloak ล่ม) → การ์ด error ทั่วไป
func renderErrorCard(c *fiber.Ctx, cause error, lang string) error {
	body := `<section class="auth">
<div class="langtop"><div class="langsw">` + web.LangSwitchHTML(lang) + `</div></div>
<div class="auth-card center">
<div class="bigicon">⚠️</div>
<h1 class="atitle">` + web.T(lang, "เกิดข้อผิดพลาด", "Something went wrong") + `</h1>
<p class="asub">` + web.T(lang, "ระบบยังไม่พร้อมใช้งานชั่วขณะ (ไม่ใช่ปัญหารหัสผ่าน) — ลองใหม่อีกครั้งภายหลัง", "The system is temporarily unavailable (not a password problem) — please try again later") + `</p>
<a class="btn-ghost" href="/">` + web.T(lang, "กลับไปหน้าล็อกอิน", "Back to sign-in") + `</a>
</div></section>`
	log.Printf("fintech-web login error: %v", cause)
	return send(c, lang, web.T(lang, "Fintech App — เกิดข้อผิดพลาด", "Fintech App — Error"), body, fiber.StatusInternalServerError)
}

// send — ครอบ body ด้วย web.Page แล้วส่งเป็น HTML
func send(c *fiber.Ctx, lang, title, body string, status int) error {
	return c.Type("html").Status(status).SendString(web.Page(struct {
		Title string
		Body  string
		Lang  string
	}{Title: title, Body: body, Lang: lang}))
}

// expScript — นับถอยหลังถึง exp ของ access token (แสดงในการ์ด session)
func expScript(expAt int64, lang string) string {
	expired := web.T(lang, "หมดอายุแล้ว", "expired")
	unit := web.T(lang, "วินาที", "s")
	return `<script>(()=>{const exp=` + fmt.Sprint(expAt) + `;const el=document.getElementById('exp-left');
if(!exp){el.textContent='—';return}
const tick=()=>{const left=exp-Math.floor(Date.now()/1000);if(left<=0){el.textContent='` + expired + `';location.href='/?e=expired';return}
el.textContent=left+' ` + unit + `'};tick();setInterval(tick,1000);})();</script>`
}

// claimStr — อ่าน claim เป็น string สำหรับแสดงผล (รองรับ string และ array เช่น aud)
func claimStr(claims map[string]any, keys ...string) string {
	for _, k := range keys {
		v, ok := claims[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			if t != "" {
				return t
			}
		case []any:
			parts := make([]string, 0, len(t))
			for _, item := range t {
				parts = append(parts, fmt.Sprint(item))
			}
			if len(parts) > 0 {
				return strings.Join(parts, ", ")
			}
		default:
			return fmt.Sprint(t)
		}
	}
	return "—"
}

// expText — แปลง exp (จาก JSON number เป็น float64) เป็นข้อความเลขจำนวนเต็ม
func expText(expAt int64) string {
	if expAt <= 0 {
		return "—"
	}
	return fmt.Sprint(expAt)
}

// scopePills — แสดง scope string เป็น pill ทีละ scope
func scopePills(v any) string {
	s, _ := v.(string)
	if s == "" {
		return `<span class="pill">—</span>`
	}
	var b strings.Builder
	for _, sc := range strings.Fields(s) {
		cls := ""
		if strings.Contains(sc, "write") {
			cls = "ok"
		}
		b.WriteString(`<span class="pill ` + cls + `">` + web.Esc(sc) + `</span>`)
	}
	return b.String()
}

// short — ตัด string ยาวไว้แสดงผล
func short(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---------- Session Transfer (STT) — จำลอง Native-to-Web SSO ----------
// Mobile app (native session) ส่ง one-time transfer code มาให้ (สร้างที่ ID Portal /stt/create)
// fintech แลก code เป็น session โดยผู้ใช้ไม่ต้องกรอกรหัสผ่านซ้ำ — จำลอง Native-to-Web SSO

const sttBrokerBase = "http://central-id:3000" // ID Portal (STT broker) — ภายใน docker network

// STTLogin — GET /auth/stt?code=xxx: แลก one-time code เป็น session แล้วพาไปหน้าหลัก
// ถ้า code ปลอม/หมดอายุ → กลับหน้า login พร้อม error ให้ผู้ใช้กรอกรหัสผ่านเอง (fallback ปลอดภัย)
func STTLogin(cfg kc.Config, store *session.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		code := c.Query("code")
		if code == "" {
			return c.Redirect("/", fiber.StatusFound)
		}
		// server-to-server redeem ที่ ID Portal (STT broker) — dest = ประกาศตัวเองเป็นปลายทาง
		// (code ผูกกับปลายทางตอน create — ปลายทางอื่น redeem ไม่ได้)
		req, err := http.NewRequest(http.MethodPost, sttBrokerBase+"/stt/redeem",
			strings.NewReader(url.Values{"code": {code}, "dest": {clientIDSelf}}.Encode()))
		if err != nil {
			return c.Redirect("/?e=stt_failed", fiber.StatusFound)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := httpClient.Do(req)
		if err != nil {
			return c.Redirect("/?e=stt_failed", fiber.StatusFound)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			// code ปลอม/หมดอายุ/ใช้ซ้ำ → กลับหน้า login ให้ผู้ใช้กรอกรหัสผ่านเอง (fallback ปลอดภัย)
			return c.Redirect("/?e=stt_invalid", fiber.StatusFound)
		}
		var out struct {
			Username    string `json:"username"`
			AccessToken string `json:"access_token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Username == "" || out.AccessToken == "" {
			return c.Redirect("/?e=stt_invalid", fiber.StatusFound)
		}

		sess := &session.Session{
			ID:          newSessionID(),
			Username:    out.Username,
			AccessToken: out.AccessToken,
			ExpiresAt:   time.Now().Add(time.Duration(300) * time.Second), // access token อายุ 5 นาที (realm policy)
			CreatedAt:   time.Now(),
		}
		store.Save(sess)
		c.Cookie(&fiber.Cookie{
			Name:     sessionCookie,
			Value:    sess.ID,
			Path:     "/",
			HTTPOnly: true,
			SameSite: "Lax",
		})
		log.Printf("stt login: user=%s", out.Username)
		return c.Redirect("/home", fiber.StatusFound)
	}
}


// ssoCookie — cookie ตั๋ว SSO ของ host localhost (ไม่ผูก port — browser ส่งให้ทุกแอปบน host เดียวกัน)
const ssoCookie = "central_sso"

// issueSSOTicket — ขอตั๋ว SSO จาก ID กลาง แล้ว set cookie ให้ browser
// ผลลัพธ์: เปิด Buyer/CIS ในแท็บใหม่ (หรือตรง ๆ) แล้วปลายทาง redeem ตั๋วแทนการ login
// issueSSOTicket — ขอตั๋ว SSO จาก ID กลาง แล้ว set cookie ให้ browser — คืน ticket id (ผูกกับ session)
func issueSSOTicket(c *fiber.Ctx, accessToken, refreshToken, clientID string) string {
	form := url.Values{"client_id": {clientID}}
	if refreshToken != "" {
		form.Set("refresh_token", refreshToken)
	}
	req, err := http.NewRequest(http.MethodPost, sttBrokerBase+"/sso/ticket", strings.NewReader(form.Encode()))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("sso ticket request failed: %v", err)
		return ""
	}
	defer resp.Body.Close()
	var out struct {
		Ticket string `json:"ticket"`
		Error  string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Ticket == "" {
		log.Printf("sso ticket rejected: %s", out.Error)
		return ""
	}
	c.Cookie(&fiber.Cookie{
		Name:     ssoCookie,
		Value:    out.Ticket,
		Path:     "/",
		HTTPOnly: true,
		SameSite: "Lax",
	})
	log.Printf("sso ticket issued to browser")
	return out.Ticket
}

// ssoTicketAlive — ตรวจกับ ID กลางว่าตั๋วยังมีชีวิตอยู่ไหม (propagate logout กลาง)
// false เมื่อตั๋วถูก revoke / logout-all / หมดอายุ — ปลายทางควรเคลียร์ session ทันที
func ssoTicketAlive(ticket string) bool {
	if ticket == "" {
		return true // ไม่ผูกตั๋ว (เช่น login ก่อนมีระบบตั๋ว) — ไม่ต้องตรวจ
	}
	req, err := http.NewRequest(http.MethodPost, sttBrokerBase+"/sso/check",
		strings.NewReader(url.Values{"ticket": {ticket}}.Encode()))
	if err != nil {
		return true // ตรวจไม่ได้ → ไม่ล็อกคน (fail-open — production ควร fail-closed ตามนโยบาย)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return true
	}
	defer resp.Body.Close()
	var out struct {
		Alive bool `json:"alive"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return true
	}
	return out.Alive
}

// ssoLogoutAll — ขอ ID กลางยกเลิก "ทุก" ตั๋ว SSO (logout กลางแบบ global) — best-effort
func ssoLogoutAll(accessToken string) {
	if accessToken == "" {
		return
	}
	req, err := http.NewRequest(http.MethodPost, sttBrokerBase+"/sso/logout", strings.NewReader(""))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("sso logout-all failed: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("sso logout-all done (http %d)", resp.StatusCode)
}

// revokeSSOTicket — แจ้ง ID กลางยกเลิกตั๋ว (ตอน logout — ทุกแอปจะต้อง login ใหม่) — best-effort
func revokeSSOTicket(accessToken, ticket string) {
	if ticket == "" || accessToken == "" {
		return
	}
	req, err := http.NewRequest(http.MethodPost, sttBrokerBase+"/sso/revoke", strings.NewReader(url.Values{"ticket": {ticket}}.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("sso revoke failed: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("sso ticket revoked (http %d)", resp.StatusCode)
}

// httpClient — client สำหรับ server-to-server calls (มี timeout กันค้าง)
var httpClient = &http.Client{Timeout: 10 * time.Second}

// clientIDSelf — client id ของแอปนี้ (ใช้เป็น dest ตอน redeem code ที่ ID Portal)
const clientIDSelf = "fintech-web"

// sttTargets — ปลายทางที่โอน session ได้: dest = client id สำหรับ bind code
// EntryURL = จุดรับของปลายทางฝั่ง browser (localhost)
var sttTargets = map[string]struct{ Dest, EntryURL string }{
	"buyer": {Dest: "buyer-web", EntryURL: "http://localhost:3010/auth/stt"},
	"cis":   {Dest: "cis-web", EntryURL: "http://localhost:3020/auth/stt"},
}

// Transfer — GET /stt/transfer?to=buyer|cis — โอน session ปัจจุบันไปแอปอื่นด้วย STT one-time code:
// backend ยิง POST /stt/create ที่ ID Portal (Bearer token ของ session + dest ปลายทาง)
// แล้ว redirect browser ไปจุดรับ /auth/stt?code= ของปลายทาง — ปลายทาง redeem + ตรวจ aud ของตัวเอง
func Transfer(store *session.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		sess := currentSession(store, c)
		if sess == nil {
			return c.Redirect("/", fiber.StatusFound)
		}
		t, ok := sttTargets[c.Query("to")]
		if !ok {
			return c.Redirect("/home", fiber.StatusFound)
		}
		req, err := http.NewRequest(http.MethodPost, sttBrokerBase+"/stt/create",
			strings.NewReader(url.Values{"dest": {t.Dest}}.Encode()))
		if err != nil {
			return c.Redirect("/?e=stt_failed", fiber.StatusFound)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+sess.AccessToken)
		resp, err := httpClient.Do(req)
		if err != nil {
			log.Printf("stt create failed: %v", err)
			return c.Redirect("/?e=stt_failed", fiber.StatusFound)
		}
		defer resp.Body.Close()
		var out struct {
			Code  string `json:"code"`
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Code == "" {
			log.Printf("stt create rejected: http=%d err=%s", resp.StatusCode, out.Error)
			return c.Redirect("/?e=stt_failed", fiber.StatusFound)
		}
		log.Printf("stt transfer: user=%s to=%s", sess.Username, t.Dest)
		return c.Redirect(t.EntryURL+"?code="+url.QueryEscape(out.Code), fiber.StatusFound)
	}
}

const sessionCookie = "fintech_session" // cookie เก็บ session id (token เก็บฝั่ง server)

// newSessionID — random hex 16 ไบต์ ด้วย crypto/rand
func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
