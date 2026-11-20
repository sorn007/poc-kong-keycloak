// Package applogin — OIDC login ของ "ผู้อนุมัติ" บนอุปกรณ์ ID
// ผู้ใช้ต้อง login ด้วยบัญชี ID ผ่าน upstream realm (central-id-upstream)
// ด้วย Authorization Code + PKCE (public client id-device-approver)
// ก่อนจะเห็น/อนุมัติคำขอ CIBA ใด ๆ — และเห็นได้เฉพาะคำขอของตัวเอง (login_hint ตรง username)
package applogin

import (

	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/gofiber/fiber/v2"
)

const (
	sessionCookie = "device_session"
	clientID      = "id-device-approver"
	scope         = "openid profile"
)

type Config struct {
	Issuer       string // upstream realm issuer เช่น http://localhost:8080/realms/central-id-upstream
	InternalBase string // http://keycloak:8080
	Realm        string // central-id-upstream
	FrontURL     string // http://localhost:3040
}

type pendingLogin struct {
	verifier string
	nonce    string
}

type store struct {
	mu sync.Mutex
	m  map[string]pendingLogin
}

var st = &store{m: map[string]pendingLogin{}}

type tokenResponse struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	ErrorMessage string `json:"error_description"`
}

func randomB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func pkcePair() (verifier, challenge string) {
	verifier = randomB64(32)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func authorizeURL(cfg Config, challenge, state, nonce string) string {
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("response_type", "code")
	q.Set("scope", scope)
	q.Set("redirect_uri", cfg.FrontURL+"/auth/callback")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return cfg.Issuer + "/protocol/openid-connect/auth?" + q.Encode()
}

func exchangeCode(cfg Config, code, verifier string) (*tokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", cfg.InternalBase, cfg.Realm)
	resp, err := http.PostForm(tokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {cfg.FrontURL + "/auth/callback"},
		"code_verifier": {verifier},
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out := new(tokenResponse)
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return nil, err
	}
	if out.IDToken == "" {
		return nil, fmt.Errorf("token endpoint: %s", out.ErrorMessage)
	}
	return out, nil
}

// Register — ผูก routes /auth/login, /auth/callback, /auth/logout
// onLogin = callback หลัง verify id_token สำเร็จ — คืน session id ของผู้อนุมัติ (caller ตั้ง cookie เอง)
func Register(app *fiber.App, cfg Config, onLogin func(idToken string) string) {
	app.Get("/auth/login", func(c *fiber.Ctx) error {
		state := randomB64(12)
		verifier, challenge := pkcePair()
		nonce := randomB64(9)
		st.mu.Lock()
		st.m[state] = pendingLogin{verifier: verifier, nonce: nonce}
		st.mu.Unlock()
		return c.Redirect(authorizeURL(cfg, challenge, state, nonce), fiber.StatusFound)
	})

	app.Get("/auth/callback", func(c *fiber.Ctx) error {
		code := c.Query("code")
		stateQ := c.Query("state")
		st.mu.Lock()
		p, ok := st.m[stateQ]
		if ok {
			delete(st.m, stateQ)
		}
		st.mu.Unlock()
		if !ok || code == "" {
			return c.Status(fiber.StatusBadRequest).SendString("state/code ไม่ถูกต้อง (POC: เริ่ม login ใหม่จากหน้า /)")
		}
		tok, err := exchangeCode(cfg, code, p.verifier)
		if err != nil {
			return c.Status(fiber.StatusBadGateway).SendString("token exchange failed: " + err.Error())
		}
		// onLogin คืน session id ของผู้อนุมัติ (verify id_token ภายใน callback) — แล้วตั้ง cookie
		sessionID := onLogin(tok.IDToken)
		c.Cookie(&fiber.Cookie{
			Name:     sessionCookie,
			Value:    sessionID,
			Path:     "/",
			HTTPOnly: true,
			SameSite: "Lax",
		})
		return c.Redirect("/", fiber.StatusFound)
	})

	app.Get("/auth/logout", func(c *fiber.Ctx) error {
		c.ClearCookie(sessionCookie)
		return c.Redirect("/", fiber.StatusFound)
	})

}
