// Package stt — Session Transfer Token store (จำลองกลไก Native-to-Web SSO ของ Auth0
// ด้วยชิ้นส่วนมาตรฐานของ Keycloak: one-time code อายุสั้น ผูกกับ username ที่ verify แล้ว)
//
// Flow: Mobile (native session) ──POST /stt/create (Bearer token + dest)──▶ ได้ code (TTL 60s, ใช้ครั้งเดียว)
//       Mobile เปิดเว็บปลายทางด้วย code ──▶ เว็บ redeem (code + dest ของตัวเอง) ──▶ ได้ session ไม่ต้องกรอกรหัสผ่านซ้ำ
//
// Policy ของ code นี้ (ADR-007 — implement บน ticketcore กลไกเดียวกับ SSO Ticket):
// • **one-time** — redeem สำเร็จ = Consume (ลบทันที กัน replay)
// • **dest binding** — ผูกปลายทาง (dest) ตอน create · redeem ผิดปลายทาง = ErrDestMismatch
//   **และไม่ consume** (code ยังใช้กับปลายทางจริงได้ — กัน interception ข้ามแอป)
// • อายุสั้น 60 วินาที — ไม่ต้องมี revoke (หมดอายุเองเร็ว)
//
// Security: code สุ่ม 32 ไบต์ เดาไม่ได้ · Consume เป็น atomic (จาก ticketcore)
package stt

import (
	"time"

	"github.com/redis/go-redis/v9"

	"central/central-id/internal/ticketcore"
)

// alias ไป sentinel ของ ticketcore — errors.Is(err, stt.ErrDestMismatch) ทำงานเหมือนเดิม
var (
	ErrNotFound     = ticketcore.ErrNotFound
	ErrExpired      = ticketcore.ErrExpired
	ErrDestMismatch = ticketcore.ErrDestMismatch
)

const ttl = 60 * time.Second

var coreOpts = ticketcore.Options{
	TTL:          ttl,
	CleanupAfter: 10 * time.Minute,
	Prefix:       "central:stt:code:",
}

// Store — CodeStore บน ticketcore (memory หรือ redis ตาม constructor)
type Store struct {
	core *ticketcore.Core
}

// NewStore — backend memory (default ของ POC)
func NewStore() *Store {
	return &Store{core: ticketcore.NewMemory(coreOpts)}
}

// NewRedisCodeStore — backend Redis (ทน restart · multi-replica)
func NewRedisCodeStore(rdb *redis.Client) *Store {
	return &Store{core: ticketcore.NewRedis(rdb, coreOpts)}
}

// Create — ผูก code กับ username ที่ verify แล้ว + access token + ปลายทาง (dest = client id ปลายทาง)
func (s *Store) Create(username, accessToken string, aud []string, issuedFor, dest string) string {
	handle, _ := s.core.Issue(ticketcore.Payload{
		Username:    username,
		AccessToken: accessToken,
		Aud:         aud,
		IssuedFor:   issuedFor,
		Dest:        dest,
	})
	return handle
}

// Redeem — แลก code เป็น session data (one-time: redeem แล้วลบทันที กันการใช้ซ้ำ)
// dest ต้องตรงกับตอน create — ไม่ตรงถือว่า code นี้ไม่ใช่ของปลายทางนี้ (ErrDestMismatch)
func (s *Store) Redeem(code, dest string) (username, accessToken string, aud []string, issuedFor string, err error) {
	p, err := s.core.Consume(code, dest)
	if err != nil {
		return "", "", nil, "", err
	}
	return p.Username, p.AccessToken, p.Aud, p.IssuedFor, nil
}
