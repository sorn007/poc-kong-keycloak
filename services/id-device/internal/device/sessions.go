// Session store ของผู้อนุมัติ — จำลอง "แอป ID ที่ล็อกอินอยู่" บนอุปกรณ์นี้
// เก็บเฉพาะ session id -> username (POC in-memory)
package device

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
)

type ApproverSession struct {
	ID       string
	Username string
	LoginAt  int64
}

type SessionStore struct {
	mu   sync.Mutex
	m    map[string]*ApproverSession
	byID map[string]string // sessionID -> username (ดัชนีเสริม)
}

func NewSessionStore() *SessionStore {
	return &SessionStore{m: map[string]*ApproverSession{}, byID: map[string]string{}}
}

func newHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *SessionStore) Save(username string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := newHex()
	s.m[id] = &ApproverSession{ID: id, Username: username}
	s.byID[id] = username
	return id
}

// UsernameOf — อ่าน username จาก session id (คืน "" ถ้าไม่พบ)
func (s *SessionStore) UsernameOf(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.byID[id]; ok {
		return u
	}
	return ""
}

func (s *SessionStore) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
	delete(s.byID, id)
}
