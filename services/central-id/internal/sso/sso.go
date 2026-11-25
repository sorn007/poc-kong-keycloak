// Package sso — SSO Ticket ระดับ ID กลาง (จำลอง "SSO session cookie" ของ Identity Provider จริง)
//
// ปัญหา: แอปที่ login ไม่ผ่าน browser flow (Embedded Login/Direct Grant, native app)
// ไม่สร้าง SSO session ใน browser — เปิดแอปอื่นในแท็บใหม่จึงต้อง login ซ้ำ
// ทางแก้: แอปต้นทาง login สำเร็จ → ขอ "ตั๋ว SSO" จาก ID กลาง → set เป็น cookie ของ host
// (POC ใช้ localhost ร่วมกันทุก port — browser ส่งให้ทุกแอป) → ปลายทาง redeem ตั๋วแทนการ login
//
// Policy ของ ticket นี้ (ADR-007 — implement บน ticketcore กลไกเดียวกับ STT):
// • **reusable** — ใช้ซ้ำได้ตลอดอายุ 30 นาที (redeem ไม่เสียตั๋ว)
// • **renew** — broker เก็บ refresh_token ของ session ต้นทาง ต่ออายุ token ใหม่ให้ตอน redeem
//   (access token อายุแค่ 5 นาที — ถ้าไม่ renew ปลายทางจะได้ token ตาย)
// • **revocable** — revoke ได้ทุกเมื่อ (logout กลาง) + RevokeAll แบบ global
//
// Security: ticket id สุ่ม 32 ไบต์ (จาก ticketcore)
package sso

import (
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"central/central-id/internal/ticketcore"
)

var (
	// alias ไป sentinel ของ ticketcore — errors.Is ที่เรียกใช้ทำงานเหมือนเดิมทุกจุด
	ErrNotFound = ticketcore.ErrNotFound
	ErrExpired  = ticketcore.ErrExpired
	ErrNoRenew  = errors.New("sso: no refresh token stored")
)

const ttl = 30 * time.Minute

var coreOpts = ticketcore.Options{
	TTL:          ttl,
	CleanupAfter: ttl + 30*time.Minute,
	Prefix:       "central:sso:ticket:",
}

// Store — TicketStore บน ticketcore (memory หรือ redis ตาม constructor)
type Store struct {
	core *ticketcore.Core
}

// NewStore — backend memory (default ของ POC)
func NewStore() *Store {
	return &Store{core: ticketcore.NewMemory(coreOpts)}
}

// NewRedisTicketStore — backend Redis (ทน restart · multi-replica)
func NewRedisTicketStore(rdb *redis.Client) *Store {
	return &Store{core: ticketcore.NewRedis(rdb, coreOpts)}
}

// Create — ออกตั๋วผูกกับ session ต้นทาง (username + token + refresh token ไว้ต่ออายุ)
func (s *Store) Create(username, accessToken string, aud []string, issuedFor, refreshToken, clientID string) (string, time.Time) {
	return s.core.Issue(ticketcore.Payload{
		Username:     username,
		AccessToken:  accessToken,
		Aud:          aud,
		IssuedFor:    issuedFor,
		RefreshToken: refreshToken,
		ClientID:     clientID,
	})
}

// Get — อ่านตั๋ว (ไม่ consume — ใช้ซ้ำได้) — คืน error ถ้าไม่เจอ/หมดอายุ
func (s *Store) Get(ticket string) (username, accessToken string, aud []string, issuedFor, refreshToken, clientID string, err error) {
	p, err := s.core.Peek(ticket)
	if err != nil {
		return "", "", nil, "", "", "", err
	}
	return p.Username, p.AccessToken, p.Aud, p.IssuedFor, p.RefreshToken, p.ClientID, nil
}

// Update — broker ต่ออายุ token แล้ว (เขียนกลับ token/refresh/aud ใหม่ — refresh token อาจถูก rotate)
func (s *Store) Update(ticket, newAccessToken string, newAud []string, newRefreshToken string) {
	s.core.Update(ticket, func(p *ticketcore.Payload) {
		p.AccessToken = newAccessToken
		if newAud != nil {
			p.Aud = newAud
		}
		if newRefreshToken != "" {
			p.RefreshToken = newRefreshToken
		}
	})
}

// Revoke — ยกเลิกตั๋ว (logout กลาง) — คืน username เพื่อ log
func (s *Store) Revoke(ticket string) (string, bool) {
	return s.core.Revoke(ticket)
}

// RevokeAll — ยกเลิก "ทุก" ตั๋ว (logout กลางแบบ global — ทุกแอปที่ผูกกับตั๋วจะตายหมด)
func (s *Store) RevokeAll() int {
	return s.core.RevokeAll()
}

// Check — ตั๋วยังมีชีวิตอยู่ไหม (ปลายทางใช้ propagate logout แบบเรียลไทม์) — ไม่ consume
func (s *Store) Check(ticket string) (string, bool) {
	return s.core.Check(ticket)
}
