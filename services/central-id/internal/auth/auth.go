// Package auth — การตรวจ central token สำหรับ ID Portal
// Portal เป็น first-party app ของ IdP — ตรวจเต็มรูปแบบ (RS256/iss/aud/exp) เหมือนแอปอื่น
// โดย audience ของตัวเองคือ central-id (Token Contract — ดู ADR-002)
package auth

import (
	"fmt"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	jwt "github.com/golang-jwt/jwt/v5"
)

// Keyfunc — alias ของ keyfunc.Keyfunc
type Keyfunc = keyfunc.Keyfunc

// Claims — claim ที่ portal ตรวจ ตาม Token Contract
type Claims struct {
	Scope             string `json:"scope"`
	ClientID          string `json:"client_id"`
	Azp               string `json:"azp"` // client ที่ token ออกให้ (KC ใช้ azp ไม่ใช่ client_id)
	PrincipalType     string `json:"principal_type"`
	TenantID          string `json:"tenant_id"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	jwt.RegisteredClaims
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

// Scopes — แตก scope string เป็น slice
func (c *Claims) Scopes() []string {
	return strings.Fields(c.Scope)
}

// Config — ค่าที่ต้อง match กับ Token Contract
type Config struct {
	Issuer       string // http://localhost:8080/realms/central
	Audience     string // central-id
	InternalBase string // http://keycloak:8080 (สำหรับ JWKS จากใน network)
	Realm        string
}

// NewJWKS — JWKS client สร้างครั้งเดียวตอน startup (cache + รองรับ rotation)
func NewJWKS(cfg Config) (keyfunc.Keyfunc, error) {
	jwksURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", cfg.InternalBase, cfg.Realm)
	return keyfunc.NewDefault([]string{jwksURL})
}

// VerifyCentral — ตรวจ central token: RS256 + iss + aud + exp (+ leeway 5s)
func VerifyCentral(k Keyfunc, cfg Config, token string) (*Claims, error) {
	parsed, err := jwt.ParseWithClaims(token, new(Claims), k.Keyfunc,
		jwt.WithValidMethods([]string{"RS256"}), // algorithm allowlist — ห้ามรับ alg จาก header
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithAudience(cfg.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(5), // clock skew
	)
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("central token invalid: %v", err)
	}
	claims, _ := parsed.Claims.(*Claims)
	return claims, nil
}

// VerifyIssuerOnly — ตรวจ token ของ realm นี้โดยไม่จำกัด audience (ใช้กับ Session Transfer:
// token ของ client ใดก็ได้ใน realm เดียวกัน เช่น token ของ mobile-app ที่มี aud=buyer-api)
// ยังบังคับ RS256 + iss + exp เหมือนเดิม — ปลอดภัยเท่ากัน ต่างแค่ไม่อั้น aud
func VerifyIssuerOnly(k Keyfunc, issuer, token string) (*Claims, error) {
	parsed, err := jwt.ParseWithClaims(token, new(Claims), k.Keyfunc,
		jwt.WithValidMethods([]string{"RS256"}), // algorithm allowlist — ห้ามรับ alg จาก header
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(5), // clock skew
	)
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("token invalid: %v", err)
	}
	claims, _ := parsed.Claims.(*Claims)
	return claims, nil
}
