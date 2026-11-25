// Package oidc — Authorization Code + PKCE (S256) ของ ID Portal
// state/verifier เก็บ in-memory เท่านั้น (POC) — production ใช้ session store จริง
package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"

	"central/central-id/internal/auth"
	"central/central-id/internal/handlers"
	"central/central-id/internal/sso"
)

type Config struct {
	Issuer        string
	InternalBase  string
	Realm         string
	ClientID      string // central-id-portal
	ClientSecret  string // central-id-portal เป็น confidential (Token Exchange ของตั๋ว SSO)
	FrontURL      string // http://localhost:3000
	SSOStore      sso.TicketStore // broker ในตัว — portal redeem ตั๋วของตัวเองผ่าน store ตรง (ไม่ยิง HTTP หาตัวเอง)
	Keyfunc       auth.Keyfunc
	ClientSecrets map[string]string // secret ของ confidential client ต้นทาง — ใช้ renew ตอน redeem
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
	return verifier, base64.RawURLEncoding.EncodeToString(h[:])
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
	// central-id-portal เป็น confidential client — token endpoint บังคับ client_secret
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

func setCookie(c *fiber.Ctx, name, value string) {
	c.Cookie(&fiber.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HTTPOnly: true,
		SameSite: "Lax",
	})
}

func clearCookieNow(c *fiber.Ctx, name string) {
	c.Cookie(&fiber.Cookie{Name: name, Value: "", Path: "/", Expires: time.Now().Add(-time.Hour), MaxAge: -1, HTTPOnly: true, SameSite: "Lax"})
}

// exchangeTokenForSelf — Token Exchange (KC Standard V2): subject token ของ client อื่น
// (มี central-id-portal ใน aud จาก scope stt-bridge) แลกเป็น token ของ portal (aud=central-id)
func exchangeTokenForSelf(cfg Config, subjectToken string) (*tokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", cfg.InternalBase, cfg.Realm)
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {cfg.ClientID},
		"subject_token":      {subjectToken},
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

func audContains(list []string, want string) bool {
	for _, a := range list {
		if a == want {
			return true
		}
	}
	return false
}

// ชื่อ cookie กลางของระบบ SSO ticket
const ssoCookieName = "central_sso"
const ssoBoundName  = "sso_bound"
const ssoTryName    = "sso_try_portal"


func Register(app *fiber.App, cfg Config) {
	app.Get("/auth/login", func(c *fiber.Ctx) error {
		// SSO Ticket — ID Portal เป็นทั้ง broker และปลายทาง: browser มีตั๋ว → redeem ของตัวเอง
		// (ผ่าน store ใน process เดียวกัน + Token Exchange เป็น token aud=central-id)
		if tk := c.Cookies(ssoCookieName); tk != "" && c.Cookies(ssoTryName) == "" {
			tok, aud, _, st := handlers.RedeemTicketFor(cfg.SSOStore, cfg.Keyfunc, cfg.Issuer, cfg.InternalBase, cfg.Realm, cfg.ClientSecrets, tk, cfg.ClientID)
			if st == "ok" && audContains(aud, cfg.ClientID) {
				if ex, xerr := exchangeTokenForSelf(cfg, tok); xerr == nil {
					setCookie(c, "central_session", ex.AccessToken)
					setCookie(c, ssoBoundName, tk) // ผูก session กับตั๋ว — logout กลาง propagate ผ่านตั๋ว
					c.Cookie(&fiber.Cookie{Name: ssoTryName, Value: "1", Path: "/", HTTPOnly: true, SameSite: "Lax", MaxAge: 30}) // กันวน loop
					return c.Redirect("/", fiber.StatusFound)
				}
			} else if st == "dead" {
				// ตั๋วตาย — อย่าพาไป Keycloak: เคลียร์แล้วกลับหน้า landing ของ portal
				clearCookieNow(c, ssoCookieName)
				clearCookieNow(c, ssoBoundName)
				clearCookieNow(c, ssoTryName)
				return c.Redirect("/", fiber.StatusFound)
			}
			// 'error' / exchange fail → เดิน Authorization Code flow ปกติต่อได้
		}
		state := randomB64(12)
		verifier, challenge := pkcePair()
		nonce := randomB64(9)
		states.mu.Lock()
		states.m[state] = pkceState{verifier: verifier, nonce: nonce}
		states.mu.Unlock()
		return c.Redirect(authorizeURL(cfg, "openid profile email", challenge, state, nonce), fiber.StatusFound)
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
			return c.Status(fiber.StatusBadGateway).SendString("token exchange failed: " + err.Error())
		}
		setCookie(c, "central_session", tok.AccessToken)
		setCookie(c, "central_id_token", tok.IDToken)

		lang := c.Cookies("lang")
		doneMsg, goingMsg, nowMsg, ssoMsg, title := "ล็อกอิน ID สำเร็จ", "กำลังพาเข้าหน้าบัญชีของคุณ…", "เข้าเองตอนนี้", "session กลางนี้ใช้ได้ทั้ง Buyer Portal และ CIS Portal ทันที (SSO)", "ID — Login สำเร็จ"
		if lang == "en" {
			doneMsg, goingMsg, nowMsg = "Signed in with ID", "Taking you to your account…", "go now"
			ssoMsg, title = "this central session works on both Buyer Portal and CIS Portal instantly (SSO)", "ID — Signed in"
		}
		return c.Type("html").SendString(`<!doctype html><html lang="` + lang + `"><meta charset="utf-8">
<meta http-equiv="refresh" content="1.2;url=/">
<title>` + title + `</title><style>
body{margin:0;font-family:'Segoe UI',system-ui,'Noto Sans Thai',sans-serif;background:linear-gradient(160deg,#1e1b4b,#4f46e5 60%,#0ea5e9);min-height:100vh;display:grid;place-items:center;color:#fff}
.box{background:#ffffff12;border:1px solid #ffffff22;border-radius:16px;padding:34px 40px;max-width:640px;backdrop-filter:blur(6px);text-align:center}
h1{margin:0 0 8px;font-size:24px}
p{color:#c7d2fe;font-size:14px;margin:6px 0}
.spin{display:inline-block;width:14px;height:14px;border:2px solid #ffffff44;border-top-color:#fff;border-radius:50%;animation:r 1s linear infinite;vertical-align:-2px;margin-right:8px}
@keyframes r{to{transform:rotate(360deg)}}
a{color:#fff}
</style>
<div class="box">
<h1><span class="spin"></span>` + doneMsg + `</h1>
<p>` + goingMsg + ` (<a href="/">` + nowMsg + `</a>)</p>
<p>` + ssoMsg + `</p>
</div>`)
	})

	app.Get("/auth/logout", func(c *fiber.Ctx) error {
		// logout กลาง — portal เป็น broker เอง: revoke ตั๋วที่ผูก + ทุกตั๋ว (แอปอื่นตายตามใน request ถัดไป)
		if bound := c.Cookies(ssoBoundName); bound != "" {
			cfg.SSOStore.Revoke(bound)
		}
		cfg.SSOStore.RevokeAll()
		idToken := c.Cookies("central_id_token")
		clearCookieNow(c, ssoCookieName)
		clearCookieNow(c, ssoBoundName)
		clearCookieNow(c, ssoTryName)
		// ลบ cookie ต้องระบุ Path ให้ตรงกับตอน set (" /") — ClearCookie ปกติไม่มี Path
		// browser จะลบไม่ตรงตัว (ลบเฉพาะ path ปัจจุบัน) ทำให้ session ไม่หายจริง
		clearSession := func(name string) {
			c.Cookie(&fiber.Cookie{
				Name: name, Value: "", Path: "/",
				Expires: time.Now().Add(-time.Hour), MaxAge: -1,
				HTTPOnly: true, SameSite: "Lax",
			})
		}
		clearSession("central_session")
		clearSession("central_id_token")

		// Global logout — ยุติ SSO session ที่ Keycloak (กระทบทุกระบบ)
		// client_id + post_logout_redirect_uri ลงทะเบียนไว้ทำให้ KC ยุติ session ทันทีไม่ขึ้นหน้า confirm
		// id_token_hint ยืนยันตัวตน session เพิ่มเมื่อมี (ครอบคลุมเคส cookie หาย)
		logoutURL := cfg.Issuer + "/protocol/openid-connect/logout?client_id=" + url.QueryEscape(cfg.ClientID)
		if idToken != "" {
			logoutURL += "&id_token_hint=" + url.QueryEscape(idToken)
		}
		logoutURL += "&post_logout_redirect_uri=" + url.QueryEscape(cfg.FrontURL)
		return c.Redirect(logoutURL, fiber.StatusFound)
	})
}
