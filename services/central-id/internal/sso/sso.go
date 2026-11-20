// Package sso — SSO Ticket ระดับ ID กลาง (จำลอง "SSO session cookie" ของ Identity Provider จริง)
//
// ปัญหา: แอปที่ login ไม่ผ่าน browser flow (Embedded Login/Direct Grant, native app)
// ไม่สร้าง SSO session ใน browser — เปิดแอปอื่นในแท็บใหม่จึงต้อง login ซ้ำ
// ทางแก้: แอปต้นทาง login สำเร็จ → ขอ "ตั๋ว SSO" จาก ID กลาง → set เป็น cookie ของ host
// (POC ใช้ localhost ร่วมกันทุก port — browser ส่งให้ทุกแอป) → ปลายทาง redeem ตั๋วแทนการ login
//
// ต่างจาก STT (package stt): ตั๋วนี้ **ใช้ซ้ำได้** ตลอดอายุ (30 นาที) และ broker เก็บ
// refresh_token ของ session ต้นทางไว้ เพื่อ "ต่ออายุ" token ใหม่ให้ตอน redeem
// (access token อายุแค่ 5 นาที — ถ้าไม่ renew ปลายทางจะได้ token ตาย)
//
// Security: ticket id สุ่ม 32 ไบต์ · revoke ได้ทุกเมื่อ (logout กลาง) · redeem ไม่เสียตั๋ว
package sso

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var (
	ErrNotFound = errors.New("sso: ticket not found")
	ErrExpired  = errors.New("sso: ticket expired")
	ErrNoRenew  = errors.New("sso: no refresh token stored")
)

const ttl = 30 * time.Minute

type entry struct {
	username     string
	accessToken  string
	aud          []string
	issuedFor    string
	refreshToken string // ไว้ต่ออายุ token เมื่อ access token ใกล้หมด (อาจว่าง — ตั๋วแบบไม่ renew)
	clientID     string // client ต้นทาง (ใช้เป็น client_id ตอน refresh)
	createdAt    time.Time
}

type Store struct {
	mu sync.Mutex
	m  map[string]*entry
}

func NewStore() *Store {
	return &Store{m: make(map[string]*entry)}
}

// Create — ออกตั๋วผูกกับ session ต้นทาง (username + token + refresh token ไว้ต่ออายุ)
func (s *Store) Create(username, accessToken string, aud []string, issuedFor, refreshToken, clientID string) (string, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	// lazy-cleanup ตั๋วที่หมดอายุเกิน 1 ชั่วโมง
	for k, e := range s.m {
		if now.Sub(e.createdAt) > ttl+30*time.Minute {
			delete(s.m, k)
		}
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	id := base64.RawURLEncoding.EncodeToString(b)
	s.m[id] = &entry{
		username:     username,
		accessToken:  accessToken,
		aud:          aud,
		issuedFor:    issuedFor,
		refreshToken: refreshToken,
		clientID:     clientID,
		createdAt:    now,
	}
	return id, now.Add(ttl)
}

// Get — อ่านตั๋ว (ไม่ consume — ใช้ซ้ำได้) — คืน error ถ้าไม่เจอ/หมดอายุ
func (s *Store) Get(ticket string) (username, accessToken string, aud []string, issuedFor, refreshToken, clientID string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[ticket]
	if !ok {
		return "", "", nil, "", "", "", ErrNotFound
	}
	if time.Since(e.createdAt) > ttl {
		delete(s.m, ticket)
		return "", "", nil, "", "", "", ErrExpired
	}
	return e.username, e.accessToken, e.aud, e.issuedFor, e.refreshToken, e.clientID, nil
}

// Update — broker ต่ออายุ token แล้ว (เขียนกลับ token/refresh/aud ใหม่ — refresh token อาจถูก rotate)
func (s *Store) Update(ticket, newAccessToken string, newAud []string, newRefreshToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.m[ticket]; ok {
		e.accessToken = newAccessToken
		if newAud != nil {
			e.aud = newAud
		}
		if newRefreshToken != "" {
			e.refreshToken = newRefreshToken
		}
	}
}

// Revoke — ยกเลิกตั๋ว (logout กลาง) — คืน username เพื่อ log
func (s *Store) Revoke(ticket string) (username string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, found := s.m[ticket]; found {
		delete(s.m, ticket)
		return e.username, true
	}
	return "", false
}

// RevokeAll — ยกเลิก "ทุก" ตั๋ว (logout กลางแบบ global — ทุกแอปที่ผูกกับตั๋วจะตายหมด)
// คืนจำนวนตั๋วที่ยกเลิก
func (s *Store) RevokeAll() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.m)
	s.m = make(map[string]*entry)
	return n
}

// Check — ตั๋วยังมีชีวิตอยู่ไหม (ใช้โดยปลายทางเพื่อ propagate logout แบบเรียลไทม์)
// ไม่ consume — ตั๋ว reusable
func (s *Store) Check(ticket string) (username string, alive bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[ticket]
	if !ok {
		return "", false
	}
	if time.Since(e.createdAt) > ttl {
		delete(s.m, ticket)
		return "", false
	}
	return e.username, true
}
