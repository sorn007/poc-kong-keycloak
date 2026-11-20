// Package stt — Session Transfer Token store (จำลองกลไก Native-to-Web SSO ของ Auth0
// ด้วยชิ้นส่วนมาตรฐานของ Keycloak: one-time code อายุสั้น ผูกกับ username ที่ verify แล้ว)
//
// Flow: Mobile (native session) ──POST /stt/create (Bearer token + dest)──▶ ได้ code (TTL 60s, ใช้ครั้งเดียว)
//       Mobile เปิดเว็บปลายทางด้วย code ──▶ เว็บ redeem (code + dest ของตัวเอง) ──▶ ได้ session ไม่ต้องกรอกรหัสผ่านซ้ำ
//
// Security: code สุ่ม 32 ไบต์ (เดาไม่ได้) · ใช้ได้ครั้งเดียว (redeem แล้วลบทันที) · หมดอายุ 60 วินาที
//           · code ผูกกับปลายทาง (dest) — redeem ด้วยปลายทางอื่นถูกปฏิเสธ (กัน code interception ข้ามแอป)
package stt

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrNotFound     = errors.New("stt: code not found")
	ErrExpired      = errors.New("stt: code expired")
	ErrDestMismatch = errors.New("stt: destination mismatch")
)

const ttl = 60 * time.Second

type entry struct {
	username    string
	accessToken string
	aud         []string // audience ของ token ต้นทาง (ปลายทางใช้ตรวจว่าใช้กับ API ของตัวเองได้หรือไม่)
	issuedFor   string   // azp — client ที่ token นี้ออกให้ (ต้นทาง)
	dest        string   // client id ของปลายทางที่ code นี้ใช้ได้เท่านั้น
	createdAt   time.Time
}

type Store struct {
	mu sync.Mutex
	m  map[string]*entry
}

func NewStore() *Store {
	return &Store{m: make(map[string]*entry)}
}

// Create — ผูก code กับ username ที่ verify แล้ว + access token + ปลายทาง (dest = client id ปลายทาง)
// พร้อม lazy-cleanup entry ที่หมดอายุเกิน 10 นาที
func (s *Store) Create(username, accessToken string, aud []string, issuedFor, dest string) string {
	s.mu.Lock()
	now := time.Now()
	for k, e := range s.m {
		if now.Sub(e.createdAt) > 10*time.Minute {
			delete(s.m, k)
		}
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	code := base64.RawURLEncoding.EncodeToString(b)
	s.m[code] = &entry{
		username:    username,
		accessToken: accessToken,
		aud:         aud,
		issuedFor:   issuedFor,
		dest:        dest,
		createdAt:   now,
	}
	s.mu.Unlock()
	return code
}

// Redeem — แลก code เป็น session data (one-time: redeem แล้วลบทันที กันการใช้ซ้ำ)
// dest ต้องตรงกับตอน create — ไม่ตรงถือว่า code นี้ไม่ใช่ของปลายทางนี้ (ErrDestMismatch)
func (s *Store) Redeem(code, dest string) (username, accessToken string, aud []string, issuedFor string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[code]
	if !ok {
		return "", "", nil, "", ErrNotFound
	}
	if time.Since(e.createdAt) > ttl {
		delete(s.m, code)
		return "", "", nil, "", ErrExpired
	}
	if dest == "" || e.dest != dest {
		// อย่าลบเมื่อ dest ไม่ตรง — code ยังใช้ได้กับปลายทางที่ถูกต้อง
		// (one-time นับเฉพาะ redeem ที่ถูกต้อง — production อาจนับพลาดเพื่อแจ้งเตือน)
		// wrap รายละเอียด entry เพื่อ debug (errors.Is ยังจับ ErrDestMismatch ได้)
		return "", "", nil, "", fmt.Errorf("%w (entry.dest=%q redeem.dest=%q)", ErrDestMismatch, e.dest, dest)
	}
	delete(s.m, code)
	return e.username, e.accessToken, e.aud, e.issuedFor, nil
}
