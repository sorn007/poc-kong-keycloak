package sso

import "time"

// TicketStore — interface ของ SSO ticket storage
// 2 backends: Store (in-memory, default) · RedisStore (redis.go — ทน restart / multi-replica)
// เลือกด้วย env STORE_BACKEND ใน main.go (default: memory)
type TicketStore interface {
	Create(username, accessToken string, aud []string, issuedFor, refreshToken, clientID string) (string, time.Time)
	Get(ticket string) (username, accessToken string, aud []string, issuedFor, refreshToken, clientID string, err error)
	Update(ticket, newAccessToken string, newAud []string, newRefreshToken string)
	Revoke(ticket string) (username string, ok bool)
	RevokeAll() int
	Check(ticket string) (username string, alive bool)
}

// compile-time check: memory Store ต้อง implement TicketStore
var _ TicketStore = (*Store)(nil)
