// Package kc — ติดต่อ Keycloak แบบ server-to-server (Direct Access Grant)
// และเรียก Buyer API ด้วย bearer token — ทุก request เกิดภายใน docker network เท่านั้น
// (browser ไม่เห็น token และไม่เห็น request พวกนี้เลย — หัวใจของ Embedded Login pattern)
package kc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config — ค่าจาก env (wire จาก main.go) — ต้อง match Token Contract ของ POC
type Config struct {
	InternalBase string // เช่น http://keycloak:8080 — ชื่อ service ใน network เดียวกัน
	Realm        string // central
	ClientID     string // fintech-web (confidential client — เปิด Direct Access Grant)
	ClientSecret string // จาก .env เท่านั้น — ห้าม hardcode
	BuyerAPIBase string // เช่น http://buyer-api:3000
}

// Tokens — ชุด token ที่ได้จาก Direct Access Grant (ต้องเก็บฝั่ง server เสมอ)
type Tokens struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresIn    int // วินาที
}

// GrantError — error ที่ token endpoint ตอบกลับมาพร้อม body JSON (เช่น invalid_grant)
// handler ใช้ type assertion เพื่อแยกเคส "รหัสผ่านผิด/บัญชีถูก lock" ออกจาก error ระบบอื่น
type GrantError struct {
	Status      int    // HTTP status จาก Keycloak (เช่น 400, 401)
	Code        string // เช่น invalid_grant, invalid_client
	Description string // เช่น "Invalid user credentials", "Account is temporarily locked"
}

func (e *GrantError) Error() string {
	return fmt.Sprintf("grant failed: http %d %s: %s", e.Status, e.Code, e.Description)
}

// IsInvalidGrant — credential ไม่ผ่าน (รหัสผ่านผิด หรือ บัญชีถูก brute-force lock ชั่วคราว)
func (e *GrantError) IsInvalidGrant() bool { return e.Code == "invalid_grant" }

// IsLocked — Keycloak realm brute-force protection ล็อกบัญชีนี้อยู่ (error_description บอกชัด)
func (e *GrantError) IsLocked() bool {
	return strings.Contains(strings.ToLower(e.Description), "temporarily locked")
}

// tokenResponse — รูป body ตอบกลับของ token endpoint (ทั้ง success และ error)
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	IDToken          string `json:"id_token"`
	ExpiresIn        int    `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// DirectGrant — แลก username/password เป็น token ผ่าน grant_type=password
// เรียกจาก backend → Keycloak ภายใน docker network (browser ไม่เห็น request นี้)
// คืน *GrantError ถ้า endpoint ตอบ error (เช่น invalid_grant) — error อื่น = ปัญหาระบบ/เครือข่าย
func DirectGrant(cfg Config, username, password string) (*Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", cfg.ClientID)
	form.Set("client_secret", cfg.ClientSecret)
	form.Set("username", username)
	form.Set("password", password)
	// stt-bridge = optional client scope ที่เติม aud ของ client ปลายทาง (cis-web) ลง token
	// เพื่อให้แอปปลายทาง (CIS) เอา token นี้ไปทำ Token Exchange ได้ตามเงื่อนไขของ KC V2
	// (requester ต้องอยู่ใน aud ของ subject token) — ไม่เพิ่ม scope การใช้งาน API ของ CIS
	form.Set("scope", "openid orders.read stt-bridge")

	endpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", cfg.InternalBase, cfg.Realm)
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// timeout ชัดเจน — Keycloak ล่ม = fail fast เป็น generic error ไม่ค้าง request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keycloak unreachable: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("parse token response (http %d): %w", resp.StatusCode, err)
	}

	// ไม่ใช่ 200 = grant ไม่สำเร็จ — เช่น 400 invalid_grant (ผิด/locked), 401 invalid_client (secret ผิด)
	if resp.StatusCode != http.StatusOK {
		return nil, &GrantError{Status: resp.StatusCode, Code: tr.Error, Description: tr.ErrorDescription}
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("keycloak returned no access_token (http %d)", resp.StatusCode)
	}
	return &Tokens{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		IDToken:      tr.IDToken,
		ExpiresIn:    tr.ExpiresIn,
	}, nil
}

// DecodePayload — ถอด payload ของ JWT เพื่อ "แสดงผล" เท่านั้น (display-only)
// ไม่ใช่การ verify — ความถูกต้องของ token พิสูจน์ด้วยการเรียก Buyer API
// (ซึ่งตรวจ RS256 + iss + aud + exp เองตาม Security Rules) — ห้ามตัดสินใจจาก decode ที่นี่
func DecodePayload(jwtToken string) (map[string]any, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwt must have 3 segments, got %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode jwt payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("parse jwt payload: %w", err)
	}
	return claims, nil
}

// CallBuyer — เรียก Buyer API GET /orders ด้วย bearer token (พิสูจน์ว่า token ใช้ได้จริง)
// Buyer API เป็นผู้ verify RS256/iss/aud/exp + scope orders.read เอง — แอปนี้ decode เพื่อแสดงผลเท่านั้น
// คืน (HTTP status, ok จาก body, จำนวน orders, error ฝั่งเครือข่าย)
func CallBuyer(cfg Config, accessToken string) (status int, ok bool, ordersCount int, err error) {
	req, err := http.NewRequest(http.MethodGet, cfg.BuyerAPIBase+"/orders", nil)
	if err != nil {
		return 0, false, 0, fmt.Errorf("build buyer request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, false, 0, fmt.Errorf("buyer-api unreachable: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, false, 0, fmt.Errorf("read buyer response: %w", err)
	}

	var out struct {
		OK     bool   `json:"ok"`
		Orders []any  `json:"orders"`
		Error  string `json:"message"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		// ตอบกลับไม่ใช่ JSON (เช่น 401 plain text) — ยังถือว่าเรียกถึงปลายทาง แต่ไม่มีข้อมูลให้อ่าน
		return resp.StatusCode, false, 0, nil
	}
	return resp.StatusCode, out.OK, len(out.Orders), nil
}
