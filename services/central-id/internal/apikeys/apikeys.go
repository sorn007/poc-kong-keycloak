// Package apikeys — Central API Keys: ออก/เก็บ/ตรวจ API key ที่ผูก scope
// ผู้ใช้สร้าง key จาก ID Portal (เลือก scope จากชุดที่ระบบกำหนด) → นำ key ไปใช้:
//   • เรียก Open API ผ่าน Kong (plugin central-apikey ถาม validate endpoint ของเรา)
//   • ใช้กับ MCP server (validate endpoint เดียวกัน + บังคับ scope ต่อ tool)
//
// Format: "central_" + base64url(24 ไบต์สุ่ม) — แสดงเต็มครั้งเดียวตอนสร้าง จากนั้น mask
// Security (POC): เก็บใน memory — production ต้องเก็บ hash + DB + audit + quota
package apikeys

import (
	"crypto/rand"
	"encoding/base64"
	"sort"
	"sync"
	"time"
)

// AvailableScopes — ชุด scope ที่ระบบอนุญาตให้ออกได้ (ตรวจตอน create)
var AvailableScopes = []string{
	"orders.read", "orders.write",
	"projects.read", "projects.write",
}

// ValidScope — scope ที่ผู้ใช้ขออยู่ในชุดที่ระบบรองรับไหม
func ValidScope(s string) bool {
	for _, a := range AvailableScopes {
		if a == s {
			return true
		}
	}
	return false
}

// Key — ข้อมูลของ API key หนึ่งใบ
type Key struct {
	ID        string    // key id (แสดง/อ้างอิงตอน revoke)
	Key       string    // ค่า key เต็ม (central_...) — ใช้ตอน validate
	Name      string    // ชื่อที่ผู้ใช้ตั้ง
	Owner     string    // username ผู้สร้าง
	Scopes    []string
	CreatedAt time.Time
	Revoked   bool
	RevokedAt time.Time
	LastUsed  time.Time
}

// Store — in-memory key registry (POC)
type Store struct {
	mu     sync.Mutex
	byID   map[string]*Key
	byKey  map[string]*Key
	byUser map[string][]string // owner -> []key id
}

func NewStore() *Store {
	return &Store{
		byID:   map[string]*Key{},
		byKey:  map[string]*Key{},
		byUser: map[string][]string{},
	}
}

// Create — ออก key ใหม่ผูก owner + scopes; คืน (key เต็ม, key record)
func (s *Store) Create(owner, name string, scopes []string) (*Key, string) {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	full := "central_" + base64.RawURLEncoding.EncodeToString(b)
	id := full[len(full)-12:]

	s.mu.Lock()
	defer s.mu.Unlock()
	k := &Key{
		ID:        id,
		Key:       full,
		Name:      name,
		Owner:     owner,
		Scopes:    append([]string(nil), scopes...),
		CreatedAt: time.Now(),
	}
	s.byID[id] = k
	s.byKey[full] = k
	s.byUser[owner] = append(s.byUser[owner], id)
	return k, full
}

// List — keys ของ owner (เรียงใหม่สุดก่อน)
func (s *Store) List(owner string) []*Key {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := append([]string(nil), s.byUser[owner]...)
	sort.Slice(ids, func(i, j int) bool {
		a, b := s.byID[ids[i]], s.byID[ids[j]]
		if a == nil || b == nil {
			return false
		}
		return a.CreatedAt.After(b.CreatedAt)
	})
	out := make([]*Key, 0, len(ids))
	for _, id := range ids {
		if k := s.byID[id]; k != nil {
			out = append(out, k)
		}
	}
	return out
}

// Get — อ่าน key record ด้วย id (เฉพาะเจ้าของ)
func (s *Store) Get(owner, id string) *Key {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.byID[id]
	if k == nil || k.Owner != owner {
		return nil
	}
	return k
}

// Revoke — ยกเลิก key (เฉพาะเจ้าของ) — คืน true ถ้า revoke สำเร็จ
func (s *Store) Revoke(owner, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.byID[id]
	if k == nil || k.Owner != owner || k.Revoked {
		return false
	}
	k.Revoked = true
	k.RevokedAt = time.Now()
	return true
}

// Validate — ตรวจ key (ใช้โดย Kong plugin / MCP server): คืน key record ถ้า active
// ไม่ consume — ใช้ซ้ำได้ตลอดอายุ; บันทึก LastUsed
func (s *Store) Validate(fullKey string) *Key {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.byKey[fullKey]
	if k == nil || k.Revoked {
		return nil
	}
	k.LastUsed = time.Now()
	return k
}
