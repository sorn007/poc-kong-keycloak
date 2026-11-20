// Package ciba — client ฝั่ง Headless Demo (Consumption Device) สำหรับ CIBA flow
// CIBA = Client Initiated Backchannel Authentication — แอปขอ authentication ผ่าน
// backchannel auth endpoint (server-to-server) แล้ว poll ที่ token endpoint จนกว่า
// ผู้ใช้ยืนยันที่อุปกรณ์ ID (Authentication Device) — ตลอด flow ไม่มี browser redirect
// ไปหน้า login ของ Keycloak เลย
// หมายเหตุ (POC): session เก็บ in-memory — production ต้องใช้ store ที่ share ได้หลาย instance
package ciba

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config — ค่าที่กำหนดล่วงหน้าทั้งหมด (allowlist) — ไม่สร้าง URL/key จาก input ของ user
type Config struct {
	Issuer       string // เช่น http://localhost:8080/realms/central (ใช้อ้างอิง/แสดง log)
	InternalBase string // base URL สำหรับเรียกภายใน network เดียวกัน เช่น http://keycloak:8080
	Realm        string
	ClientID     string // client แบบ confidential ที่เปิด CIBA grant ไว้
	ClientSecret string
	BuyerAPIBase string // ปลายทางพิสูจน์ token เช่น http://buyer-api:3000
}

// สถานะของ CIBA session
const (
	StatusPending = "pending"
	StatusSuccess = "success"
	StatusError   = "error"
	StatusDenied  = "denied"
	StatusExpired = "expired"
)

// Session — หนึ่งการขอ authentication (ตั้งแต่เริ่ม request จนได้/พลาด token)
type Session struct {
	ID             string
	AuthReqID      string
	LoginHint      string
	BindingMessage string
	Interval       int    // ความถี่ขั้นต่ำที่ Keycloak แนะนำตอน BeginAuth (วินาที)
	Status         string // pending|success|error|denied|expired
	ErrCode        string
	AccessToken    string
	RefreshToken   string
	IDToken        string
	LastPoll       time.Time
}

// Store — in-memory session store (mutex + map) — เรียกจากหลาย goroutine ได้ปลอดภัย
type Store struct {
	mu sync.Mutex
	m  map[string]*Session
}

// NewStore — สร้าง store เปล่า (เรียกครั้งเดียวตอน startup แล้ว inject ผ่าน handler factory)
func NewStore() *Store {
	return &Store{m: make(map[string]*Session)}
}

// Save — เก็บ/ทับ session
func (st *Store) Save(s *Session) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.m[s.ID] = s
}

// Get — อ่าน session (คืน nil ถ้าไม่พบ)
func (st *Store) Get(id string) *Session {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.m[id]
}

// BeginAuth — ขั้นแรกของ CIBA: ยิง backchannel auth request ไปที่ Keycloak
// คืน auth_req_id กับ interval (วินาที — ใช้เป็นความถี่ขั้นต่ำในการ poll)
func BeginAuth(cfg Config, loginHint, bindingMessage string) (authReqID string, interval int, err error) {
	authURL := cfg.InternalBase + "/realms/" + cfg.Realm + "/protocol/openid-connect/ext/ciba/auth"
	resp, err := http.PostForm(authURL, url.Values{
		"client_id":       {cfg.ClientID},
		"client_secret":   {cfg.ClientSecret},
		"login_hint":      {loginHint},
		"scope":           {"openid orders.read"},
		"binding_message": {bindingMessage},
	})
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	var out struct {
		AuthReqID string `json:"auth_req_id"`
		ExpiresIn int    `json:"expires_in"`
		Interval  int    `json:"interval"`
		Error     string `json:"error"`
		ErrorDesc string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, fmt.Errorf("parse ciba auth response (http %d): %w", resp.StatusCode, err)
	}
	// trim space กันค่าจาก provider ที่มี whitespace เกิน
	if strings.TrimSpace(out.AuthReqID) == "" {
		msg := strings.TrimSpace(out.ErrorDesc)
		if msg == "" {
			msg = strings.TrimSpace(out.Error)
		}
		if msg == "" {
			msg = fmt.Sprintf("ciba auth endpoint returned http %d without auth_req_id", resp.StatusCode)
		}
		return "", 0, fmt.Errorf("ciba begin: %s", msg)
	}
	interval = out.Interval
	if interval <= 0 {
		interval = 5 // default ตาม CIBA spec เมื่อ Keycloak ไม่ส่ง interval มา
	}
	return strings.TrimSpace(out.AuthReqID), interval, nil
}

// PollToken — ยิง token endpoint ด้วย grant CIBA หนึ่งครั้ง แล้วอัปเดต Status ใน session
// mapping ตาม CIBA spec:
//   - authorization_pending / slow_down → ยังรออยู่ (คง Status=pending — ไม่ surface เป็น error)
//   - access_denied → ผู้ใช้ปฏิเสธ (Status=denied)
//   - expired_token → auth_req_id หมดอายุก่อนอนุมัติ (Status=expired)
//   - อื่น ๆ → Status=error + ErrCode
func PollToken(cfg Config, s *Session) error {
	tokenURL := cfg.InternalBase + "/realms/" + cfg.Realm + "/protocol/openid-connect/token"
	resp, err := http.PostForm(tokenURL, url.Values{
		"grant_type":    {"urn:openid:params:grant-type:ciba"},
		"auth_req_id":   {s.AuthReqID},
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
	})
	if err != nil {
		// network ล่มชั่วคราว — คงสถานะเดิมไว้ให้รอบ poll ถัดไปลองใหม่
		return err
	}
	defer resp.Body.Close()

	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		s.Status = StatusError
		s.ErrCode = "bad_response"
		return fmt.Errorf("parse token endpoint response (http %d): %w", resp.StatusCode, err)
	}

	switch strings.TrimSpace(out.Error) {
	case "":
		if strings.TrimSpace(out.AccessToken) == "" {
			s.Status = StatusError
			s.ErrCode = fmt.Sprintf("token endpoint returned http %d without access_token", resp.StatusCode)
			return nil
		}
		// ผู้ใช้ยืนยันที่อุปกรณ์ ID แล้ว — เก็บ token ไว้ฝั่ง server เท่านั้น (ไม่ลง cookie)
		s.Status = StatusSuccess
		s.ErrCode = ""
		s.AccessToken = strings.TrimSpace(out.AccessToken)
		s.RefreshToken = strings.TrimSpace(out.RefreshToken)
		s.IDToken = strings.TrimSpace(out.IDToken)
	case "authorization_pending", "slow_down":
		s.Status = StatusPending // ยังรอการยืนยัน — ไม่ถือเป็น error
	case "access_denied":
		s.Status = StatusDenied
		s.ErrCode = "access_denied"
	case "expired_token":
		s.Status = StatusExpired
		s.ErrCode = "expired_token"
	default:
		s.Status = StatusError
		s.ErrCode = strings.TrimSpace(out.Error)
	}
	return nil
}

// DecodePayload — ถอด payload ของ JWT มาแสดงผลเท่านั้น (ไม่ตรวจ signature ณ ที่นี้)
// ความถูกต้องของ token ถูกพิสูจน์โดย Buyer API ซึ่ง verify signature + aud ผ่าน JWKS เอง
func DecodePayload(jwtToken string) (map[string]any, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid jwt: expected 3 segments, got %d", len(parts))
	}
	// base64url ของ JWT ไม่มี padding — ตัด '=' ท้ายออกก่อน decode ด้วย RawURLEncoding (กัน token แบบมี padding)
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, fmt.Errorf("decode jwt payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("parse jwt payload: %w", err)
	}
	return claims, nil
}

// CallBuyer — ยิง Buyer API ด้วย access token ที่ได้จาก CIBA
// Buyer เป็นผู้ verify signature ผ่าน JWKS + ตรวจ aud=buyer-api + scope เองตามสถาปัตยกรรม POC
// ผลลัพธ์ที่คืนคือหลักฐานว่า token นี้ใช้งานได้จริง
func CallBuyer(cfg Config, accessToken string) (httpStatus int, ok bool, ordersCount int, err error) {
	req, err := http.NewRequest(http.MethodGet, cfg.BuyerAPIBase+"/orders", nil)
	if err != nil {
		return 0, false, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, false, 0, err
	}
	defer resp.Body.Close()

	var out struct {
		OK     bool  `json:"ok"`
		Orders []any `json:"orders"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return resp.StatusCode, false, 0, fmt.Errorf("parse buyer response (http %d): %w", resp.StatusCode, err)
	}
	return resp.StatusCode, out.OK, len(out.Orders), nil
}
