// Package auth — Central Auth SDK สำหรับ Go service (module central/auth-go · ADR-008)
//
// จุดเดียวของ "Authentication policy" ที่ทุก service ใช้ร่วมกัน — เดิมแต่ละ service ถือสำเนา
// VerifyCentral ของตัวเองจน policy เพี้ยนโดยไม่รู้ตัว (เช่น leeway: service หนึ่ง 5 วินาที
// อีก service ส่ง 5 นาโนวินาที ทั้งที่ comment เขียนเหมือนกัน) ตอนนี้แก้ที่นี่ที่เดียว แล้ว rebuild service
//
//   - ตรวจ central token — RS256 allowlist + iss allowlist + aud ของ service + exp (+ leeway 5s)
//   - ตรวจ legacy token (HS256 shared secret) ช่วง migration — Dual Validation เลือก validator จาก allowlist
//   - gateway-trust — ยืนยันว่า request ผ่าน Kong (plugin central-apikey) มาจริง
//   - session/ticket liveness — ตรวจกับ ID Portal ว่าตั๋วที่ session ผูกไว้ยังไม่ถูก revoke
//
// ขอบเขต: แพ็กเกจนี้ทำเฉพาะ **Authentication** (ใครคือ principal + ถือ scope อะไร)
// Authorization ระดับ business (tenant, บริษัท, order/project ของใคร) ต้องอยู่ที่ service เองเสมอ
// — Middleware ของ Fiber อยู่ที่แพ็กเกจย่อย fibermw
package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	// Version — รุ่นของ SDK (service log ค่านี้ตอน startup เพื่อรู้ว่า deploy รุ่นใด)
	Version = "0.1.0"

	// Leeway — clock skew ที่ยอมรับสำหรับ exp — นโยบายเดียวทุก service
	Leeway = 5 * time.Second
)

// Keyfunc — alias ของ keyfunc.Keyfunc สำหรับ package อื่นใช้อ้างอิง
type Keyfunc = keyfunc.Keyfunc

// Claims — claim ที่ service ตรวจ ตาม Token Contract (ไม่เชื่อ claim อื่นโดยไม่ตรวจ)
type Claims struct {
	Scope             string `json:"scope"`
	ClientID          string `json:"client_id"`
	Azp               string `json:"azp"` // client ที่ token ออกให้ (KC ใช้ azp ไม่ใช่ client_id)
	PrincipalType     string `json:"principal_type"`
	TenantID          string `json:"tenant_id"`
	PreferredUsername string `json:"preferred_username"` // เอกสารสำหรับแสดงผล UI เท่านั้น
	Email             string `json:"email"`              // เอกสารสำหรับแสดงผล UI เท่านั้น
	jwt.RegisteredClaims
}

// Scopes — แตก scope string เป็น slice
func (c *Claims) Scopes() []string {
	return strings.Fields(c.Scope)
}

// AudList — คืนรายการ aud ของ token (รองรับทั้ง string เดี่ยวและ array)
func (c *Claims) AudList() []string {
	out := make([]string, 0, len(c.Audience))
	for _, a := range c.Audience {
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}

// HasScope — token นี้ถือ scope ที่ต้องการหรือไม่ (mechanism — service เป็นผู้กำหนดว่า endpoint
// ไหนต้องการ scope ใด ผ่าน fibermw.Scope)
func (c *Claims) HasScope(scope string) bool {
	for _, s := range c.Scopes() {
		if s == scope {
			return true
		}
	}
	return false
}

// Config — ค่าที่ต้อง match กับ Token Contract (ค่าต่อ service — policy อยู่ที่ฟังก์ชันในแพ็กเกจนี้)
type Config struct {
	Issuer       string // ค่า iss ที่ยอมรับ (allowlist — ค่าเดียว) เช่น http://localhost:8080/realms/central
	Audience     string // aud ของ service นี้ (บังคับเสมอ — กัน Cross-Audience Token Confusion)
	InternalBase string // URL เรียก JWKS จากใน docker network เช่น http://keycloak:8080
	Realm        string

	LegacySecret string // ช่วง migration เท่านั้น: secret ของ token ที่ service ออกเอง (HS256)
	LegacyIssuer string // ช่วง migration เท่านั้น: iss ของ legacy token
}

// NewJWKS — สร้าง JWKS client "ครั้งเดียวตอน startup" (cache + auto refresh ตาม key rotation)
func NewJWKS(cfg Config) (Keyfunc, error) {
	jwksURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", cfg.InternalBase, cfg.Realm)
	return keyfunc.NewDefault([]string{jwksURL})
}

// VerifyCentral — ตรวจ central token: RS256 + iss + aud + exp (+ leeway) และต้องมี sub
// ใช้กับ token ที่ออกให้ service นี้โดยตรง (API ของ service, session cookie ของ service)
func VerifyCentral(k Keyfunc, cfg Config, token string) (*Claims, error) {
	return verify(k, cfg, token, true)
}

// VerifyIssuerOnly — ตรวจ token ของ realm นี้โดยไม่จำกัด audience (ใช้กับ Session Transfer:
// token ของ client ใดก็ได้ใน realm เดียวกัน เช่น token ของ mobile-app ที่มี aud=buyer-api)
// ยังบังคับ RS256 + iss + exp เหมือนเดิม — ต่างจาก VerifyCentral แค่ไม่อั้น aud และไม่บังคับ sub
// (service principal บางชนิดอาจไม่มี sub — ผู้เรียกต้องใช้ principal_type ตัดสินต่อเสมอ)
func VerifyIssuerOnly(k Keyfunc, issuer, token string) (*Claims, error) {
	return verify(k, Config{Issuer: issuer}, token, false)
}

func verify(k Keyfunc, cfg Config, token string, audienceBound bool) (*Claims, error) {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256"}), // algorithm allowlist — ห้ามรับ alg จาก header
		jwt.WithIssuer(cfg.Issuer),              // iss จาก allowlist — ไม่ใช้ค่าใน token สร้าง URL/key
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(Leeway), // clock skew
	}
	if audienceBound {
		opts = append(opts, jwt.WithAudience(cfg.Audience))
	}
	claims := new(Claims)
	parsed, err := jwt.ParseWithClaims(token, claims, k.Keyfunc, opts...)
	if err != nil {
		return nil, fmt.Errorf("central token invalid: %w", err)
	}
	if !parsed.Valid {
		return nil, errors.New("central token invalid")
	}
	if audienceBound && claims.Subject == "" {
		return nil, errors.New("central token invalid: missing subject")
	}
	return claims, nil
}

// VerifyLegacy — ตรวจ legacy token ของ service (HS256 + shared secret + iss) — ช่วง migration เท่านั้น
func VerifyLegacy(cfg Config, token string) (*Claims, error) {
	claims := new(Claims)
	_, err := jwt.ParseWithClaims(
		token,
		claims,
		func(*jwt.Token) (any, error) { return []byte(cfg.LegacySecret), nil },
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(cfg.LegacyIssuer),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(Leeway),
	)
	if err != nil || claims.Subject == "" {
		return nil, fmt.Errorf("legacy token invalid: %w", err)
	}
	return claims, nil
}

// Peek — อ่าน iss/alg จาก token "โดยไม่ verify" — ใช้ได้เฉพาะเลือก validator จาก allowlist
// ของ Dual Validation เท่านั้น ห้ามใช้ค่าที่ได้ไปตัดสินอะไรก่อน verify จริง
func Peek(token string) (iss, alg string, err error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	var c Claims
	unverified, _, perr := parser.ParseUnverified(token, &c)
	if perr != nil {
		return "", "", perr
	}
	alg, _ = unverified.Header["alg"].(string)
	return c.Issuer, alg, nil
}
