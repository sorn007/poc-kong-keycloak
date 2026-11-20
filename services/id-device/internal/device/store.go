// Package device — store คำขอ CIBA ที่รอผู้ใช้ตัดสินใจบน "อุปกรณ์ ID" (POC)
// เก็บ in-memory เท่านั้น — production ต้องมี TTL/หมดอายุของคำขอ และ store ที่รองรับหลาย instance
package device

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Pending — คำขอ authentication delegation ที่ Keycloak ส่งเข้ามาให้อุปกรณ์อนุมัติ
// Bearer เก็บ token ที่ KC แนบมาพร้อมคำขอ — ใช้ตอบกลับ callback endpoint ตอนแจ้งผล
type Pending struct {
	ID                string
	Bearer            string
	LoginHint         string
	Scope             string
	BindingMessage    string
	IsConsentRequired bool
	ReceivedAt        time.Time
}

// Store — in-memory store + slice ลำดับ id (เพื่อ list แบบเก่าสุดก่อนเสมอ)
type Store struct {
	mu    sync.Mutex
	byID  map[string]*Pending
	order []string
}

// NewStore — สร้าง store เปล่า (เรียกครั้งเดียวตอน startup)
func NewStore() *Store {
	return &Store{byID: map[string]*Pending{}}
}

// randomID — สุ่ม id แบบ hex จาก crypto/rand
func randomID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Save — เพิ่มคำขอใหม่; ถ้า p.ID ว่างจะสร้าง id ให้ และคืน id ที่ใช้จริง
func (s *Store) Save(p *Pending) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.ID == "" {
		p.ID = randomID()
	}
	s.byID[p.ID] = p
	s.order = append(s.order, p.ID)
	return p.ID
}

// Get — คืนคำขอตาม id
func (s *Store) Get(id string) (*Pending, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.byID[id]
	return p, ok
}

// List — คำขอทั้งหมดเรียงตามลำดับที่รับ (เก่าสุดก่อน)
func (s *Store) List() []*Pending {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Pending, 0, len(s.order))
	for _, id := range s.order {
		if p, ok := s.byID[id]; ok {
			out = append(out, p)
		}
	}
	return out
}

// Remove — ลบคำขอ; คืน true ถ้า id มีอยู่จริง
func (s *Store) Remove(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[id]; !ok {
		return false
	}
	delete(s.byID, id)
	for i, oid := range s.order {
		if oid == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	return true
}
