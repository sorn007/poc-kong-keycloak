// Package session — in-memory session store: token ถูกเก็บฝั่ง server ทั้งหมด
// browser ถือเฉพาะ cookie รหัส session (opaque id แบบ crypto/rand) — นี่คือสิ่งที่ทำให้
// Embedded Login รับความเสี่ยงของ Direct Grant ได้ในระดับที่ยอมรับได้ (token ไม่หลุดไปฝั่ง client)
// POC: หายพร้อม process — production ควรใช้ Redis + TTL และ expire ตาม refresh token lifecycle
package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Session — token ชุดเต็มของผู้ใช้หนึ่งคน (อยู่บน server เท่านั้น — ห้ามส่งออกไป browser)
type Session struct {
	ID           string // opaque id เก็บใน cookie fintech_session
	Username     string
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresAt    time.Time // จาก expires_in ของ access token
	CreatedAt    time.Time
	SSOTicket    string    // ตั๋ว SSO ที่ผูกกับ session (ตรวจกับ ID กลางเพื่อ propagate logout กลาง)
}

// Store — in-memory store (thread-safe ด้วย mutex)
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewStore — สร้าง store ต่อ process หนึ่งอัน (wire จาก main)
func NewStore() *Store {
	return &Store{sessions: make(map[string]*Session)}
}

// NewID — รหัส session แบบสุ่ม cryptographically — crypto/rand hex 16 bytes (128 bit)
func NewID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// Save — เก็บ/ทับ session (key = session id)
func (s *Store) Save(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
}

// Get — อ่าน session ตาม id (คืน nil ถ้าไม่พบ)
func (s *Store) Get(id string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[id]
}

// Remove — ลบ session (logout / หมดอายุ)
func (s *Store) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}
