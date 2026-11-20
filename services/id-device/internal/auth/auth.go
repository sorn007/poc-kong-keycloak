// Package auth — ตรวจ token ของ "ผู้อนุมัติ" บนอุปกรณ์ ID
// ผู้ใช้ต้อง login ด้วยบัญชี ID (upstream realm central-id-upstream) ก่อนกดอนุมัติ
// token ที่ตรวจคือ id_token/access token ที่ออกให้ client id-device-approver
package auth

import (
	"fmt"

	"github.com/MicahParks/keyfunc/v3"
	jwt "github.com/golang-jwt/jwt/v5"
)

// Keyfunc — alias ของ keyfunc.Keyfunc
type Keyfunc = keyfunc.Keyfunc

// Claims — claim ที่อุปกรณ์ ID ใช้: ต้องรู้ว่า "ใคร" กำลังอนุมัติ เพื่อผูกกับ login_hint
type Claims struct {
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	jwt.RegisteredClaims
}

// Config — ค่าสำหรับตรวจ token ของ upstream realm
type Config struct {
	Issuer       string // http://localhost:8080/realms/central-id-upstream
	Audience     string // id-device-approver
	InternalBase string // http://keycloak:8080
	Realm        string // central-id-upstream
}

// NewJWKS — JWKS client สร้างครั้งเดียวตอน startup (cache + รองรับ rotation)
func NewJWKS(cfg Config) (keyfunc.Keyfunc, error) {
	jwksURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", cfg.InternalBase, cfg.Realm)
	return keyfunc.NewDefault([]string{jwksURL})
}

// VerifyApprover — ตรวจ token ผู้อนุมัติ: RS256 + iss + aud + exp (+ leeway 5s)
func VerifyApprover(k Keyfunc, cfg Config, token string) (*Claims, error) {
	parsed, err := jwt.ParseWithClaims(token, new(Claims), k.Keyfunc,
		jwt.WithValidMethods([]string{"RS256"}), // algorithm allowlist
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithAudience(cfg.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(5),
	)
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("approver token invalid: %v", err)
	}
	claims, _ := parsed.Claims.(*Claims)
	return claims, nil
}
