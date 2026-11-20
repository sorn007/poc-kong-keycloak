// Package handlers — หน้าจอของ Seller App (Headless Demo)
// Consumption Device (CD) ของ CIBA flow — แอปเป็นเจ้าของหน้า login ของตัวเอง
// ไม่มีการ redirect ไปหน้า login ของ Keycloak ตลอดทั้ง flow
package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"central/headless-demo/internal/ciba"
	"central/headless-demo/internal/web"
)

const (
	sessionCookie         = "headless_session"      // cookie เก็บเฉพาะ session id — token อยู่ฝั่ง server เท่านั้น
	defaultBindingMessage = "Seller-Login"          // ค่าเริ่มต้น (ASCII ผ่านเงื่อนไข KC: ≤50 ตัว ไม่มีช่องว่าง)
	idDeviceURL           = "http://localhost:3040" // อุปกรณ์ ID (Authentication Device) — จุดกดอนุมัติ
)

// newSessionID — random hex 16 ไบต์ ด้วย crypto/rand
func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// sessionFromCookie — อ่าน session จาก cookie (คืน nil ถ้าไม่มี cookie/id ไม่พบ)
func sessionFromCookie(store *ciba.Store, c *fiber.Ctx) *ciba.Session {
	id := c.Cookies(sessionCookie)
	if id == "" {
		return nil
	}
	return store.Get(id)
}

// setSessionCookie — ตั้ง cookie session (HTTPOnly + SameSite Lax — JS อ่านไม่ได้)
func setSessionCookie(c *fiber.Ctx, id string) {
	c.Cookie(&fiber.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HTTPOnly: true,
		SameSite: "Lax",
	})
}

// Home — หน้า login ของแอปเอง (ขั้นที่ 1 — ขออนุญาต)
// จุดสำคัญของ CIBA: form นี้ submit ในแอปตัวเอง ไม่มีการพา browser ไปหน้า login ของ Keycloak
func Home(store *ciba.Store, cfg ciba.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		lang := web.LangOf(c)
		body := `<h1>` + web.T(lang, "เข้าสู่ระบบด้วยบัญชี ID", "Sign in with your ID account") + `</h1>
<p class="lead">` + web.T(lang, "ใส่ชื่อผู้ใช้เพื่อขออนุญาตเข้าสู่ระบบ — แล้วยืนยันคำขอบน <b>อุปกรณ์ ID</b> ของคุณ", "Enter your username to request sign-in — then approve the request on your <b>ID device</b>") + `<br>
(` + web.T(lang, "แอปนี้ไม่รับรหัสผ่าน — การยืนยันเกิดบนอุปกรณ์ ID ตามมาตรฐาน CIBA", "this app never asks for a password — confirmation happens on the ID device per the CIBA standard") + `)</p>
<form method="post" action="/ciba/request">
<div class="field">
<label for="login_hint">` + web.T(lang, "ชื่อผู้ใช้ (login_hint)", "Username (login_hint)") + `</label>
<input id="login_hint" name="login_hint" placeholder="` + web.T(lang, "เช่น buyer-user", "e.g. buyer-user") + `" autocomplete="username" required>
</div>
<div class="field">
<label for="binding_message">` + web.T(lang, "ข้อความยืนยัน (แสดงบนอุปกรณ์ ID เพื่อกันการอนุมัติผิดคำขอ)", "Binding message (shown on the ID device to prevent approving the wrong request)") + `</label>
<input id="binding_message" name="binding_message" value="` + defaultBindingMessage + `" maxlength="50">
<div class="hint">` + web.T(lang, "อังกฤษ/ตัวเลข/ขีด ยาวไม่เกิน 50 ตัว ไม่มีช่องว่าง (เงื่อนไขของ Keycloak 26)", "letters/digits/dashes, max 50 characters, no spaces (Keycloak 26 requirement)") + `</div>
</div>
<button class="btn btn-primary" type="submit">` + web.T(lang, "ขออนุญาตเข้าสู่ระบบ", "Authorize sign-in") + `</button>
</form>
<div class="footnote"><span class="dot"></span> ` + web.T(lang, "ป้องกันด้วย CIBA — แอปนี้ไม่เห็นรหัสผ่านของคุณและไม่มีการ redirect ไปหน้า login ของ Keycloak", "Protected by CIBA — this app never sees your password and never redirects to a Keycloak login page") + `</div>`
		return sendLogin(c, web.T(lang, "Seller App — เข้าสู่ระบบ", "Seller App — Sign in"), body, lang)
	}
}

// sanitizeBinding — ทำ binding_message ให้ผ่านเงื่อนไขของ Keycloak 26:
// "max 50 characters and must contain only basic plain-text characters without spaces"
// (ตัวอักษรไทย/อื่น ๆ จะถูกกรองออก — production ควรให้ผู้ใช้กรอก ASCII เองหรือ map เพิ่ม)
func sanitizeBinding(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == ' ' || r == '\t':
			b.WriteByte('-')
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_':
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "login-" + time.Now().Format("150405")
	}
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

// RequestAuth — ขั้นที่ 1: ยิง backchannel auth request → เก็บ session → พาไปหน้ารอการยืนยัน
func RequestAuth(store *ciba.Store, cfg ciba.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		loginHint := strings.Clone(strings.TrimSpace(c.FormValue("login_hint")))                     // clone — กัน fasthttp buffer reuse
		binding := strings.Clone(sanitizeBinding(strings.TrimSpace(c.FormValue("binding_message")))) // clone — กัน fasthttp buffer reuse

		authReqID, interval, err := ciba.BeginAuth(cfg, loginHint, binding)
		if err != nil {
			lang := web.LangOf(c)
			detail := web.T(lang,
				"เช็คว่า client <code>%s</code> เปิด CIBA grant ไว้ และ client_secret ถูกต้อง · scope ที่ขอคือ <code>openid orders.read</code>",
				"Check that client <code>%s</code> has the CIBA grant enabled and the client_secret is correct · requested scope is <code>openid orders.read</code>")
			body := `<div class="card center">
<div class="bigicon err">⚠️</div>
<h1 style="font-size:20px;margin:0 0 8px">` + web.T(lang, "ขออนุญาตไม่สำเร็จ", "Sign-in request failed") + `</h1>
<p class="sub">` + web.T(lang, "Keycloak ไม่รับ backchannel auth request", "Keycloak rejected the backchannel auth request") + `</p>
<div class="notice err"><code>` + web.Esc(err.Error()) + `</code></div>
<p class="sub">` + fmt.Sprintf(detail, web.Esc(cfg.ClientID)) + `</p>
<div class="actions"><a class="btn btn-primary" href="/">` + web.T(lang, "กลับไปลองใหม่", "Back and try again") + `</a></div>
</div>`
			return sendApp(c, web.T(lang, "Seller App — ขออนุญาตไม่สำเร็จ", "Seller App — Sign-in request failed"), body, lang)
		}

		s := &ciba.Session{
			ID:             newSessionID(),
			AuthReqID:      authReqID,
			LoginHint:      loginHint,
			BindingMessage: binding,
			Interval:       interval, // ความถี่ขั้นต่ำที่ Keycloak แนะนำ — ใช้ rate-limit ที่ /ciba/poll
			Status:         ciba.StatusPending,
		}
		store.Save(s)
		setSessionCookie(c, s.ID)
		return c.Redirect("/ciba/waiting", fiber.StatusFound) // 302
	}
}

// Waiting — ขั้นที่ 2: หน้ารอการยืนยัน — JS เรียก /ciba/poll ทุก 2 วินาที
func Waiting(store *ciba.Store, cfg ciba.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		s := sessionFromCookie(store, c)
		if s == nil {
			return c.Redirect("/", fiber.StatusFound)
		}
		lang := web.LangOf(c)
		body := `<div class="card center">
<div class="steps3">
<div class="s done">1 · ` + web.T(lang, "ส่งคำขอแล้ว", "Request sent") + `</div>
<div class="s now">2 · ` + web.T(lang, "รอการยืนยัน", "Awaiting approval") + `</div>
<div class="s">3 · ` + web.T(lang, "เข้าใช้งาน", "Start using") + `</div>
</div>
<div class="binding">` + web.Esc(s.BindingMessage) + `</div>
<div class="spin"></div>
<p style="font-size:14px;margin:6px 0 10px">` + web.T(lang, "รอการยืนยันจาก <b>อุปกรณ์ ID</b> ของคุณ", "Waiting for approval on your <b>ID device</b>") + `</p>
<p class="sub" style="margin-bottom:0">` + web.T(lang, "เปิด", "Open") + ` <a href="` + idDeviceURL + `" target="_blank" rel="noreferrer"><b>` + idDeviceURL + `</b></a> ` + web.T(lang, "แล้วกด “ยืนยัน” ที่คำขอที่มีรหัสตรงกับด้านบน", "and press “Confirm” on the request whose code matches the one above") + `</p>
<div id="terminal"></div>
<p class="sub" style="margin-top:14px">login_hint: <code>` + web.Esc(s.LoginHint) + `</code> · client: <code>` + web.Esc(cfg.ClientID) + `</code> · ` + web.T(lang, "ตรวจสอบอัตโนมัติทุก 2 วินาที", "auto-checks every 2 seconds") + `</p>
<div class="actions" style="justify-content:center"><a class="btn btn-ghost btn-sm" href="/">` + web.T(lang, "ยกเลิก", "Cancel") + `</a></div>
</div>
<script>` + waitingJS(lang) + `</script>`
		return sendApp(c, web.T(lang, "Seller App — รอการยืนยัน", "Seller App — Awaiting approval"), body, lang)
	}
}

// waitingJS — poll สถานะทุก 2 วินาที — success → ไปหน้า result, denied/expired/error → สถานะสิ้นสุด
// (ข้อความสถานะสิ้นสุดแปลตามภาษาของหน้า — logic poll คงเดิมทั้งหมด)
func waitingJS(lang string) string {
	deniedHTML := `<div class="bigicon err">✕</div><h1 style="font-size:20px;margin:0 0 8px">` + web.T(lang, "คำขอถูกปฏิเสธ", "Request denied") + `</h1><p class="sub">` + web.T(lang, "ผู้ใช้ไม่อนุมัติการเข้าสู่ระบบบนอุปกรณ์ ID — หากไม่ใช่คุณ โปรดเปลี่ยนรหัสผ่านทันที", "The sign-in was not approved on the ID device — if this was not you, change your password immediately") + `</p><div class="actions" style="justify-content:center"><a class="btn btn-primary" href="/">` + web.T(lang, "ลองอีกครั้ง", "Try again") + `</a></div>`
	expiredHTML := `<div class="bigicon warn">⏱</div><h1 style="font-size:20px;margin:0 0 8px">` + web.T(lang, "คำขอหมดอายุ", "Request expired") + `</h1><p class="sub">` + web.T(lang, "ไม่ได้รับการยืนยันภายในเวลาที่กำหนด", "The request was not approved within the allowed time") + `</p><div class="actions" style="justify-content:center"><a class="btn btn-primary" href="/">` + web.T(lang, "เริ่มใหม่", "Start over") + `</a></div>`
	errorHTML := `<div class="bigicon err">⚠</div><h1 style="font-size:20px;margin:0 0 8px">` + web.T(lang, "เกิดข้อผิดพลาด", "Something went wrong") + `</h1><p class="sub">code: <code>' + (j.error || 'unknown') + '</code></p><div class="actions" style="justify-content:center"><a class="btn btn-primary" href="/">` + web.T(lang, "เริ่มใหม่", "Start over") + `</a></div>`
	return `(function () {
  let stopped = false;
  const stop = function (html) {
    if (stopped) return;
    stopped = true;
    document.querySelector('.spin').style.display = 'none';
    document.querySelector('.binding').style.opacity = '0.5';
    const term = document.getElementById('terminal');
    term.innerHTML = html;
    term.scrollIntoView({ behavior: 'smooth', block: 'center' });
  };
  const iv = setInterval(async function () {
    try {
      const r = await fetch('/ciba/poll');
      if (!r.ok) return;
      const j = await r.json();
      if (j.status === 'success') {
        clearInterval(iv);
        location = '/ciba/result';
      } else if (j.status === 'denied') {
        clearInterval(iv);
        stop('` + deniedHTML + `');
      } else if (j.status === 'expired') {
        clearInterval(iv);
        stop('` + expiredHTML + `');
      } else if (j.status === 'error') {
        clearInterval(iv);
        stop('` + errorHTML + `');
      }
    } catch (e) { /* network ชั่วคราว — รอรอบถัดไป */ }
  }, 2000);
})();`
}

// Poll — คืนสถานะล่าสุดเป็น JSON — เรียก Keycloak เมื่อครบ interval เท่านั้น (rate-limit)
// กันยิง token endpoint ถี่เกินจนโดน slow_down: ไม่ครบเวลา → คืนสถานะที่ cache ไว้
func Poll(store *ciba.Store, cfg ciba.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		s := sessionFromCookie(store, c)
		if s == nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"status": ciba.StatusError, "error": "unknown_session"})
		}
		// interval ขั้นต่ำ 2 วินาที (default 5 เมื่อ BeginAuth ไม่ได้ค่ามา)
		interval := s.Interval
		if interval < 2 {
			interval = 2
		}
		if s.Status == ciba.StatusPending && time.Since(s.LastPoll) >= time.Duration(interval)*time.Second {
			s.LastPoll = time.Now()
			if err := ciba.PollToken(cfg, s); err != nil {
				// network ล่มชั่วคราว — สถานะยังคง pending ให้รอบหน้าลองใหม่
				log.Printf("ciba poll: auth_req_id=%s error=%v", s.AuthReqID, err)
			}
		}
		out := fiber.Map{"status": s.Status}
		if s.Status == ciba.StatusError {
			out["error"] = s.ErrCode
		}
		return c.JSON(out)
	}
}

// Result — ขั้นที่ 3: แสดง claims ของ token + ผลการยิง Buyer API จริง
func Result(store *ciba.Store, cfg ciba.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		s := sessionFromCookie(store, c)
		if s == nil || s.Status != ciba.StatusSuccess {
			return c.Redirect("/ciba/waiting", fiber.StatusFound)
		}
		lang := web.LangOf(c)

		// ถอด payload เพื่อแสดงเท่านั้น — ไม่มีการ verify signature ที่นี่
		// ความถูกต้องของ token ถูกพิสูจน์ด้วยผลการเรียก Buyer API (ฝั่ง Buyer verify ผ่าน JWKS เอง)
		claimsCard := `<div class="card"><h2>` + web.T(lang, "Token ที่ได้รับ — payload (แสดงเพื่อการศึกษา)", "Received token — payload (shown for learning)") + `</h2>
<p class="sub">` + web.T(lang, "ถอดมาแสดงเท่านั้น ไม่ได้ verify signature ณ ที่นี้ — ความถูกต้องถูกพิสูจน์ด้วยผลการเรียก Buyer API ด้านล่าง", "Decoded for display only — the signature is not verified here; correctness is proven by the Buyer API result below") + `</p>
<table>`
		claims, err := ciba.DecodePayload(s.AccessToken)
		if err != nil {
			claimsCard += `<tr><td><div class="notice err">` + web.T(lang, "อ่าน payload ไม่สำเร็จ —", "Could not read the payload —") + ` <code>` + web.Esc(err.Error()) + `</code></div></td></tr>`
		} else {
			claimsCard += row("iss", claims["iss"], lang) +
				row("sub", claims["sub"], lang) +
				row("preferred_username", claims["preferred_username"], lang) +
				row("aud", claims["aud"], lang) +
				row("azp / client_id", claims["azp"], lang) +
				row("principal_type", claims["principal_type"], lang) +
				row("tenant_id", claims["tenant_id"], lang) +
				row("scope", claims["scope"], lang) +
				row("exp", claims["exp"], lang)
		}
		claimsCard += `</table></div>`

		buyerStatus, ok, ordersCount, buyerErr := ciba.CallBuyer(cfg, s.AccessToken)
		summary := `<span class="pill ok">` + web.T(lang, "SUCCESS — token ใช้ได้จริง", "SUCCESS — the token actually works") + `</span>`
		toastMsg, toastOK := web.T(lang, "SUCCESS — Buyer API รับ token นี้", "SUCCESS — Buyer API accepted this token"), "true"
		errNote := ""
		switch {
		case buyerErr != nil:
			summary = `<span class="pill fail">` + web.T(lang, "FAIL — เรียก Buyer API ไม่สำเร็จ", "FAIL — Buyer API call failed") + `</span>`
			toastMsg, toastOK = web.T(lang, "FAIL — เรียก Buyer API ไม่สำเร็จ", "FAIL — Buyer API call failed"), "false"
			errNote = `<div class="notice err"><code>` + web.Esc(buyerErr.Error()) + `</code></div>`
		case !ok:
			summary = `<span class="pill fail">` + web.T(lang, "FAIL — Buyer API ปฏิเสธ token", "FAIL — Buyer API rejected the token") + `</span>`
			toastMsg, toastOK = web.T(lang, "FAIL — Buyer API ปฏิเสธ token", "FAIL — Buyer API rejected the token"), "false"
		}
		buyerCard := fmt.Sprintf(`<div class="card"><h2>`+web.T(lang, "พิสูจน์ token กับ Buyer API", "Prove the token against the Buyer API")+`</h2>
<p class="sub">GET <code>%s</code> — header <code>Authorization: Bearer ...</code>%s</p>
<table>
<tr><th>HTTP status</th><td><code class="count">%d</code></td></tr>
<tr><th>ok</th><td><code>%t</code></td></tr>
<tr><th>`+web.T(lang, "จำนวน orders", "Orders returned")+`</th><td class="count">%d</td></tr>
<tr><th>`+web.T(lang, "สรุป", "Summary")+`</th><td>%s</td></tr>
</table></div>`, web.Esc(cfg.BuyerAPIBase)+"/orders", errNote, buyerStatus, ok, ordersCount, summary)

		body := `<div class="card center">
<div class="bigicon ok">✓</div>
<h1 style="font-size:22px;margin:0 0 8px">` + web.T(lang, "เข้าสู่ระบบสำเร็จ", "Sign-in successful") + `</h1>
<p class="sub" style="margin-bottom:0">` + web.T(lang, "ได้ token จากระบบ ID กลางโดยผู้ใช้อนุมัติที่อุปกรณ์ ID — <b>ไม่มีหน้า login ของ Keycloak ปรากฏเลยตลอด flow</b>", "Got a token from the central ID system after the user approved on the ID device — <b>no Keycloak login page appeared at any point in the flow</b>") + `</p>
</div>
` + claimsCard + buyerCard + `<div class="card"><h2>` + web.T(lang, "ขั้นถัดไป", "Next steps") + `</h2><p class="sub">` + web.T(lang, "จบ flow — ลองซ้ำได้ทันที (เช่น ทดสอบเคสปฏิเสธบนอุปกรณ์ ID)", "Flow complete — run it again anytime (e.g. test the deny case on the ID device)") + `</p>
<div class="actions"><a class="btn btn-primary" href="/">` + web.T(lang, "เริ่ม flow ใหม่", "Start a new flow") + `</a><a class="btn btn-ghost" href="` + idDeviceURL + `" target="_blank" rel="noreferrer">` + web.T(lang, "เปิดอุปกรณ์ ID", "Open the ID device") + `</a></div></div>
<script>showToast('` + toastMsg + `', ` + toastOK + `);</script>`
		return sendApp(c, web.T(lang, "Seller App — เข้าสู่ระบบสำเร็จ", "Seller App — Signed in"), body, lang)
	}
}

// row — แถวของตาราง claims (label เป็นชื่อ claim — คงภาษาอังกฤษตาม contract ของ token)
func row(label string, v any, lang string) string {
	return `<tr><th>` + web.Esc(label) + `</th><td>` + claimValue(lang, v) + `</td></tr>`
}

// claimValue — แสดงค่า claim แบบอ่านง่าย (ค่าจาก JSON จะเป็น string / []any / float64)
func claimValue(lang string, v any) string {
	switch t := v.(type) {
	case nil:
		return `<span class="pill fail">` + web.T(lang, "ไม่มี claim นี้", "claim not present") + `</span>`
	case string:
		if strings.TrimSpace(t) == "" {
			return `<span class="pill fail">` + web.T(lang, "ว่าง", "empty") + `</span>`
		}
		return `<code>` + web.Esc(t) + `</code>`
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			parts = append(parts, web.Esc(item))
		}
		return strings.Join(parts, " ")
	case float64:
		// ตัวเลขจาก JSON เป็น float64 เสมอ — จัด format ไม่ให้เป็นเลขวิทยาศาสตร์ (เช่น exp)
		return `<code class="count">` + strconv.FormatFloat(t, 'f', -1, 64) + `</code>`
	default:
		return `<code>` + web.Esc(t) + `</code>`
	}
}

// sendLogin — หน้าแรกใช้ layout แบบ split (brand panel + ฟอร์ม)
func sendLogin(c *fiber.Ctx, title, body, lang string) error {
	return c.Type("html").SendString(web.PageLogin(title, body, lang))
}

// sendApp — หน้าภายในใช้ layout navbar + container
func sendApp(c *fiber.Ctx, title, body, lang string) error {
	return c.Type("html").SendString(web.PageApp(title, body, lang))
}
