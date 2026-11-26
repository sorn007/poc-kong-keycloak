// Package oidc — Authorization Code + PKCE (S256) flow ระหว่าง CIS กับ ID
// state/verifier เก็บ in-memory เท่านั้น (POC) — production ใช้ session store จริง
package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"central/auth-go"
	"github.com/gofiber/fiber/v2"

	"central/cis-api/internal/web"
)

type Config struct {
	Issuer        string // สำหรับสร้าง authorize URL ที่ browser ใช้ (localhost)
	InternalBase  string // สำหรับเรียก token endpoint จากใน docker network
	Realm         string
	ClientID      string
	ClientSecret  string // cis-web เป็น confidential client — ใช้กับ token endpoint (AC + Token Exchange)
	SttBrokerBase string // ID Portal (STT broker) ภายใน docker network
	FrontURL      string // redirect_uri ตั้งต้น เช่น http://localhost:3020
}

type pkceState struct {
	verifier string
	nonce    string
}

type stateStore struct {
	mu sync.Mutex
	m  map[string]pkceState
}

var states = &stateStore{m: map[string]pkceState{}}

func randomB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func pkcePair() (verifier, challenge string) {
	verifier = randomB64(32)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge
}

func authorizeURL(cfg Config, scope, challenge, state, nonce string) string {
	q := url.Values{}
	q.Set("client_id", cfg.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", scope)
	q.Set("redirect_uri", cfg.FrontURL+"/auth/callback")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return cfg.Issuer + "/protocol/openid-connect/auth?" + q.Encode()
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error_description"`
}

func exchangeCode(cfg Config, code, verifier string) (*tokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", cfg.InternalBase, cfg.Realm)
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {cfg.ClientID},
		"code":          {code},
		"redirect_uri":  {cfg.FrontURL + "/auth/callback"},
		"code_verifier": {verifier},
	}
	// cis-web เป็น confidential client — KC บังคับ authenticate ที่ token endpoint
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	resp, err := http.PostForm(tokenURL, form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out := new(tokenResponse)
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return nil, err
	}
	if out.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint: %s", out.Error)
	}
	return out, nil
}

// exchangeToken — Token Exchange (KC Standard V2 — เปิดใช้ default ใน KC 26):
// เอา subject_token ของ client อื่น (เช่น token จาก fintech/mobile ที่มี aud รวม cis-web)
// แลกเป็น token ใหม่ของเรา (aud=cis-api จาก scopes ของ cis-web) — subject (user) คงเดิม
// เงื่อนไขของ KC V2: requester ต้องเป็น confidential client และอยู่ใน aud ของ subject token
func exchangeToken(cfg Config, subjectToken string) (*tokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", cfg.InternalBase, cfg.Realm)
	form := url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":     {cfg.ClientID},
		"subject_token": {subjectToken},
		// KC Standard Token Exchange V2 บังคับ subject_token_type (RFC 8693) — ถ้าไม่ส่ง
		// ได้ error "Parameter 'subject_token_type' required for standard token exchange"
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	}
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	resp, err := http.PostForm(tokenURL, form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out := new(tokenResponse)
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return nil, err
	}
	if out.AccessToken == "" {
		return nil, fmt.Errorf("token exchange: %s", out.Error)
	}
	return out, nil
}

// redeemSTT — redeem one-time code ที่ ID Portal (server-to-server) — dest ประกาศตัวเอง
// คืน username + access token ต้นทาง + aud ของ token ต้นทาง + client ที่ token ออกให้ (issued_for)
func redeemSTT(cfg Config, code string) (username, subjectToken string, aud []string, issuedFor string, err error) {
	resp, err := http.PostForm(cfg.SttBrokerBase+"/stt/redeem", url.Values{
		"code": {code},
		"dest": {cfg.ClientID},
	})
	if err != nil {
		return "", "", nil, "", err
	}
	defer resp.Body.Close()
	var out struct {
		Username    string   `json:"username"`
		AccessToken string   `json:"access_token"`
		Aud         []string `json:"aud"`
		IssuedFor   string   `json:"issued_for"`
		Error       string   `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", nil, "", err
	}
	if out.AccessToken == "" {
		return "", "", nil, "", fmt.Errorf("stt redeem: %s", out.Error)
	}
	return out.Username, out.AccessToken, out.Aud, out.IssuedFor, nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func setCookie(c *fiber.Ctx, name, value string) {
	c.Cookie(&fiber.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HTTPOnly: true,
		SameSite: "Lax",
	})
}

// sttSuccessHTML — หน้าสำเร็จของการโอน session (สไตล์เดียวกับหน้า callback)
func sttSuccessHTML(username, lang string) string {
	if lang != "en" {
		lang = "th"
	}
	title, h1, howMsg, goingMsg, nowMsg := "CIS Portal — โอน session สำเร็จ",
		"โอน session สำเร็จ — ยินดีต้อนรับ "+username,
		"ได้ session ของ CIS โดยไม่กรอกรหัสผ่าน (one-time code + <b>Token Exchange</b> เป็น token <code>aud=cis-api</code>)",
		"กำลังพาเข้า CIS Portal…", "เข้าเองตอนนี้"
	if lang == "en" {
		title, h1, howMsg, goingMsg, nowMsg = "CIS Portal — Session transfer complete",
			"Session transferred — welcome "+username,
			"Got a CIS session without typing a password (one-time code + <b>Token Exchange</b> into a token with <code>aud=cis-api</code>)",
			"Taking you into the CIS Portal…", "go now"
	}
	return `<!doctype html><html lang="` + lang + `"><meta charset="utf-8">
<meta http-equiv="refresh" content="1.5;url=/">
<title>` + title + `</title><style>
body{margin:0;font-family:'Segoe UI',system-ui,'Noto Sans Thai',sans-serif;background:linear-gradient(160deg,#022c22,#059669 70%,#0ea5e9);min-height:100vh;display:grid;place-items:center;color:#fff}
.box{background:#ffffff12;border:1px solid #ffffff22;border-radius:16px;padding:34px 40px;max-width:640px;backdrop-filter:blur(6px)}
h1{margin:0 0 8px;font-size:24px}
p{color:#d1fae5;font-size:14px;margin:6px 0}
code{background:#ffffff1a;padding:1px 6px;border-radius:6px;font-size:12px}
.spin{display:inline-block;width:14px;height:14px;border:2px solid #ffffff44;border-top-color:#fff;border-radius:50%;animation:r 1s linear infinite;vertical-align:-2px;margin-right:8px}
@keyframes r{to{transform:rotate(360deg)}}
a{color:#fff}
</style>
<div class="box">
<h1><span class="spin"></span>` + h1 + `</h1>
<p>` + howMsg + `</p>
<p>` + goingMsg + ` (<a href="/">` + nowMsg + `</a>)</p>
</div>`
}

// sttErrorHTML — หน้า error ของการโอน session — fallback ปลอดภัยคือล็อกอินตามปกติ
func sttErrorHTML(detail, lang string) string {
	if lang != "en" {
		lang = "th"
	}
	th := "โอน session ไม่สำเร็จ — กรุณาล็อกอินด้วย ID ตามปกติ"
	en := "Session transfer failed — please sign in with ID as usual"
	switch {
	case containsStr(detail, "audience_mismatch"):
		th = "token ต้นทางไม่ได้ตั้ง audience ให้ cis-web — โอนข้ามระบบที่ไม่เกี่ยวข้องจึงถูกปฏิเสธ (ต้องมี scope stt-bridge ใน token ต้นทาง)"
		en = "the source token does not set audience for cis-web — transferring across unrelated systems is rejected (the source token needs the stt-bridge scope)"
	case containsStr(detail, "destination_mismatch"):
		th = "code นี้ไม่ได้ออกให้ CIS Portal (destination_mismatch)"
		en = "this code was not issued to CIS Portal (destination_mismatch)"
	case containsStr(detail, "invalid_or_used_or_expired"):
		th = "code หมดอายุหรือถูกใช้ไปแล้ว (ใช้ได้ครั้งเดียว อายุ 60 วินาที)"
		en = "the code expired or was already used (single use, valid for 60 seconds)"
	case containsStr(detail, "forbidden"):
		th = "Keycloak ปฏิเสธ Token Exchange (forbidden) — token ต้นทางต้องมี cis-web ใน aud หรือออกให้ cis-web เอง"
		en = "Keycloak rejected the Token Exchange (forbidden) — the source token must include cis-web in aud or be issued to cis-web itself"
	}
	title, heading, normalMsg := "CIS Portal — โอน session ไม่สำเร็จ", "⚠️ โอน session ไม่สำเร็จ", th
	if lang == "en" {
		title, heading, normalMsg = "CIS Portal — Session transfer failed", "⚠️ Session transfer failed", en
	}
	return `<!doctype html><html lang="` + lang + `"><meta charset="utf-8">
<title>` + title + `</title><style>
body{margin:0;font-family:'Segoe UI',system-ui,'Noto Sans Thai',sans-serif;background:linear-gradient(160deg,#022c22,#059669 70%,#0ea5e9);min-height:100vh;display:grid;place-items:center;color:#fff}
.box{background:#ffffff12;border:1px solid #ffffff22;border-radius:16px;padding:34px 40px;max-width:640px;backdrop-filter:blur(6px)}
h1{margin:0 0 8px;font-size:22px}
p{color:#d1fae5;font-size:14px;margin:6px 0}
code{background:#ffffff1a;padding:1px 6px;border-radius:6px;font-size:12px;word-break:break-all}
a{color:#fff}
</style>
<div class="box">
<h1>` + heading + `</h1>
<p>` + normalMsg + `</p>
<p><code>` + detail + `</code></p>
<p style="margin-top:14px"><a href="/auth/login">` + web.T(lang, "ล็อกอินด้วย ID ตามปกติ", "Sign in with ID as usual") + ` →</a></p>
</div>`
}

func containsStr(s, sub string) bool {
	return strings.Contains(s, sub)
}

func Register(app *fiber.App, cfg Config) {
	app.Get("/auth/login", func(c *fiber.Ctx) error {
		// SSO Ticket — browser มีตั๋วของ ID กลาง (central_sso) → redeem แทนการ login
		// (ตั๋วถูก set โดยแอปต้นทาง เช่น Fintech; cookie ของ host localhost จึงมาถึงที่นี่ได้)
		if tk := c.Cookies(ssoCookieName); tk != "" && c.Cookies("sso_try_cis") == "" {
			tok, st := redeemSSOTicket(cfg, tk)
			if st == "ok" {
				// aud ต่างกัน → แลกเป็น token ของเราด้วย Token Exchange เหมือนกรณี STT
				exchanged, xerr := exchangeToken(cfg, tok)
				if xerr == nil {
					setCookie(c, "cis_session", exchanged.AccessToken)
					setCookie(c, "sso_bound", tk)                                                                                    // ผูก session กับตั๋ว — logout กลาง propagate ผ่านตั๋ว
					c.Cookie(&fiber.Cookie{Name: "sso_try_cis", Value: "1", Path: "/", HTTPOnly: true, SameSite: "Lax", MaxAge: 30}) // กันวน loop
					return c.Redirect("/", fiber.StatusFound)
				}
			} else if st == "dead" {
				// ตั๋วตาย (revoke/logout-all/หมดอายุ) — อย่าพาไป Keycloak:
				// เคลียร์ cookie ตั๋วแล้วกลับ "หน้า landing ของแอปเรา" ให้ผู้ใช้กด login เอง
				c.Cookie(&fiber.Cookie{Name: ssoCookieName, Value: "", Path: "/", Expires: time.Now().Add(-time.Hour), MaxAge: -1, HTTPOnly: true, SameSite: "Lax"})
				c.Cookie(&fiber.Cookie{Name: "sso_bound", Value: "", Path: "/", Expires: time.Now().Add(-time.Hour), MaxAge: -1, HTTPOnly: true, SameSite: "Lax"})
				c.Cookie(&fiber.Cookie{Name: "sso_try_cis", Value: "", Path: "/", Expires: time.Now().Add(-time.Hour), MaxAge: -1, HTTPOnly: true, SameSite: "Lax"})
				return c.Redirect("/", fiber.StatusFound)
			}
			// 'error' (broker ล่มชั่วคราว) → เดิน Authorization Code flow ปกติต่อได้
		}
		state := randomB64(12)
		verifier, challenge := pkcePair()
		nonce := randomB64(9)
		states.mu.Lock()
		states.m[state] = pkceState{verifier: verifier, nonce: nonce}
		states.mu.Unlock()
		return c.Redirect(authorizeURL(cfg, "openid projects.read projects.write", challenge, state, nonce), fiber.StatusFound)
	})

	app.Get("/auth/callback", func(c *fiber.Ctx) error {
		code := c.Query("code")
		states.mu.Lock()
		st, ok := states.m[c.Query("state")]
		if ok {
			delete(states.m, c.Query("state"))
		}
		states.mu.Unlock()
		if !ok || code == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unknown_state_or_code"})
		}

		tok, err := exchangeCode(cfg, code, st.verifier)
		if err != nil {
			// POC: แสดง error ให้อ่านง่าย (production ต้อง log และซ่อนรายละเอียด)
			return c.Status(fiber.StatusBadGateway).SendString("token exchange failed: " + err.Error())
		}
		setCookie(c, "cis_session", tok.AccessToken)
		setCookie(c, "cis_id_token", tok.IDToken)

		// หน้าสำเร็จของ flow — พากลับหน้าแรกของ portal อัตโนมัติ
		// lang อ่านจาก cookie "lang" (ตั้งโดยหน้าอื่นของ portal / แอปพอร์ตทางพี่ — default "th")
		lang := c.Cookies("lang")
		if lang != "en" {
			lang = "th"
		}
		title, doneMsg, goingMsg, nowMsg, nextMsg := "CIS Portal — Login สำเร็จ", "ล็อกอินผ่าน ID สำเร็จ", "กำลังพาเข้า CIS Portal…", "เข้าเองตอนนี้", "flow ถัดไป: ลองกลับไปที่ <a href=\"http://localhost:3010\"><b>Buyer Portal</b></a> — ต้องยังล็อกอินอยู่ (SSO session เดียวกัน)"
		if lang == "en" {
			title, doneMsg, goingMsg, nowMsg = "CIS Portal — Signed in", "Signed in via ID", "Taking you into the CIS Portal…", "go now"
			nextMsg = "next in the flow: go back to <a href=\"http://localhost:3010\"><b>Buyer Portal</b></a> — you must still be signed in (same SSO session)"
		}
		return c.Type("html").SendString(`<!doctype html><html lang="` + lang + `"><meta charset="utf-8">
<meta http-equiv="refresh" content="1.5;url=/">
<title>` + title + `</title><style>
body{margin:0;font-family:'Segoe UI',system-ui,'Noto Sans Thai',sans-serif;background:linear-gradient(160deg,#022c22,#059669 70%,#0ea5e9);min-height:100vh;display:grid;place-items:center;color:#fff}
.box{background:#ffffff12;border:1px solid #ffffff22;border-radius:16px;padding:34px 40px;max-width:640px;backdrop-filter:blur(6px)}
h1{margin:0 0 8px;font-size:24px}
p{color:#d1fae5;font-size:14px;margin:6px 0}
.spin{display:inline-block;width:14px;height:14px;border:2px solid #ffffff44;border-top-color:#fff;border-radius:50%;animation:r 1s linear infinite;vertical-align:-2px;margin-right:8px}
@keyframes r{to{transform:rotate(360deg)}}
a{color:#fff}
</style>
<div class="box">
<h1><span class="spin"></span>` + doneMsg + `</h1>
<p>` + goingMsg + ` (<a href="/">` + nowMsg + `</a>)</p>
<p>` + nextMsg + `</p>
</div>`)
	})

	// Session Transfer (STT) — จุดรับ one-time code จากแอปต้นทาง (จำลอง Native-to-Web SSO):
	// 1) redeem code ที่ ID Portal (dest=cis-web — code ผูกปลายทาง ปลายทางอื่นใช้ไม่ได้)
	// 2) subject token ของ client อื่น (aud รวม cis-web จาก scope stt-bridge) แลกเป็น token ของเรา
	//    ด้วย Token Exchange (KC Standard V2) — ได้ token ใหม่ aud=cis-api, user (sub) คงเดิม
	// 3) สร้าง session (cookie เดียวกับ AC flow) — ผู้ใช้ไม่กรอกรหัสผ่านเลย
	app.Get("/auth/stt", func(c *fiber.Ctx) error {
		lang := c.Cookies("lang")
		if lang != "en" {
			lang = "th"
		}
		code := c.Query("code")
		if code == "" {
			return c.Redirect("/auth/login", fiber.StatusFound)
		}

		username, subjectToken, aud, issuedFor, err := redeemSTT(cfg, code)
		if err != nil {
			return c.Type("html").Status(fiber.StatusForbidden).SendString(
				sttErrorHTML("redeem_failed: "+err.Error(), lang))
		}

		// เงื่อนไข exchange ของ KC V2 (ตรวจเบื้องต้นให้ข้อความชัด — ตัวจริงบังคับที่ KC):
		// subject token ต้องมี cis-web ใน aud หรือออกให้ cis-web เอง (tokenHolder == requester)
		if !contains(aud, cfg.ClientID) && issuedFor != cfg.ClientID {
			return c.Type("html").Status(fiber.StatusForbidden).SendString(
				sttErrorHTML("audience_mismatch", lang))
		}

		tok, err := exchangeToken(cfg, subjectToken)
		if err != nil {
			return c.Type("html").Status(fiber.StatusForbidden).SendString(
				sttErrorHTML("exchange_failed: "+err.Error(), lang))
		}
		_ = username // username จาก redeem (ไว้ log) — session สร้างจาก token ที่ exchange แล้วเท่านั้น
		setCookie(c, "cis_session", tok.AccessToken)
		// ผูก session กับตั๋ว SSO ของ browser (ถ้ามี) — logout กลางจะ propagate ผ่านตั๋ว
		if tk := c.Cookies(ssoCookieName); tk != "" {
			setCookie(c, "sso_bound", tk)
		}
		// id_token ไม่มีใน token exchange — logout ยังทำงาน (id_token_hint เป็น optional)
		return c.Type("html").SendString(sttSuccessHTML(username, lang))
	})

	app.Get("/auth/logout", func(c *fiber.Ctx) error {
		// logout กลาง — ขอ ID กลางยกเลิก "ทุก" ตั๋ว SSO (แอปอื่นตายตามใน request ถัดไป) — best-effort
		if sess := c.Cookies("cis_session"); sess != "" {
			logoutAllSSO(cfg, sess)
		}
		idToken := c.Cookies("cis_id_token")
		// ลบ cookie ต้องระบุ Path ให้ตรงกับตอน set ("/") — ClearCookie ปกติไม่มี Path
		// browser จะลบไม่ตรงตัว (ลบเฉพาะ path ปัจจุบัน) ทำให้ session ไม่หายจริง
		clearSession := func(name string) {
			c.Cookie(&fiber.Cookie{
				Name: name, Value: "", Path: "/",
				Expires: time.Now().Add(-time.Hour), MaxAge: -1,
				HTTPOnly: true, SameSite: "Lax",
			})
		}
		clearSession("cis_session")
		clearSession("cis_id_token")
		clearSession("sso_bound")
		clearSession("sso_try_cis")

		// Global logout — ยุติ SSO session ที่ Keycloak (กระทบทุกระบบ)
		// client_id + post_logout_redirect_uri ลงทะเบียนไว้ทำให้ KC ยุติ session ทันทีไม่ขึ้นหน้า confirm
		logoutURL := cfg.Issuer + "/protocol/openid-connect/logout?client_id=" + url.QueryEscape(cfg.ClientID)
		if idToken != "" {
			logoutURL += "&id_token_hint=" + url.QueryEscape(idToken)
		}
		logoutURL += "&post_logout_redirect_uri=" + url.QueryEscape(cfg.FrontURL)
		return c.Redirect(logoutURL, fiber.StatusFound)
	})
}

// ---------- SSO Ticket helpers (ตั๋วของ ID กลาง — ทำให้เปิดแท็บใหม่ไม่ต้อง login) ----------

// ssoCookieName — cookie ตั๋ว SSO ของ host localhost (ไม่ผูก port — browser ส่งให้ทุกแอป host เดียวกัน)
const ssoCookieName = "central_sso"

// SSOCookieName — ชื่อ cookie ตั๋ว SSO (ให้ handler package ใช้อ่าน)
const SSOCookieName = ssoCookieName

// redeemSSOTicket — redeem ตั๋วกับ ID Portal (server-to-server)
// คืน (subject token, สถานะ): "ok" | "dead" (ตั๋วตายชัดเจน — ปลายทางควรกลับหน้า landing)
// | "error" (ติดต่อ broker ไม่ได้ — เดิน AC flow ปกติ) — ปลายทางยังต้องตรวจ aud/ทำ Token Exchange เอง
func redeemSSOTicket(cfg Config, ticket string) (string, string) {
	form := url.Values{"ticket": {ticket}, "dest": {cfg.ClientID}}
	req, err := http.NewRequest(http.MethodPost, cfg.SttBrokerBase+"/sso/redeem", strings.NewReader(form.Encode()))
	if err != nil {
		return "", "error"
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "error"
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
		return "", "dead" // ตั๋วไม่มี/ใช้ไม่ได้/หมดอายุ — broker ปฏิเสธชัดเจน
	}
	if resp.StatusCode != http.StatusOK {
		return "", "error"
	}
	var out struct {
		AccessToken string   `json:"access_token"`
		Aud         []string `json:"aud"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.AccessToken == "" {
		return "", "error"
	}
	return out.AccessToken, "ok"
}

// revokeSSOTicket — แจ้ง ID กลางยกเลิกตั๋ว (logout) — best-effort
func revokeSSOTicket(cfg Config, sessionToken, ticket string) {
	if sessionToken == "" || ticket == "" {
		return
	}
	req, err := http.NewRequest(http.MethodPost, cfg.SttBrokerBase+"/sso/revoke", strings.NewReader(url.Values{"ticket": {ticket}}.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	log.Printf("sso ticket revoked (http %d)", resp.StatusCode)
}

// TicketAlive — ตรวจกับ ID กลางว่า session ที่ผูกกับตั๋วยังมีชีวิต (logout กลาง propagate)
// นโยบาย (timeout, fail-open) อยู่ที่ SDK central/auth-go — ทุก service ใช้ชุดเดียวกัน
func TicketAlive(ticket string) bool {
	return auth.TicketAlive(os.Getenv("IDPORTAL_INTERNAL_BASE"), ticket)
}

// logoutAllSSO — ขอ ID กลางยกเลิก "ทุก" ตั๋ว SSO (logout กลาง global) — best-effort
func logoutAllSSO(cfg Config, sessionToken string) {
	if sessionToken == "" {
		return
	}
	req, err := http.NewRequest(http.MethodPost, cfg.SttBrokerBase+"/sso/logout", strings.NewReader(""))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("sso logout-all failed: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("sso logout-all done (http %d)", resp.StatusCode)
}
