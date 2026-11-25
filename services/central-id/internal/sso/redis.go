package sso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisTicketStore — SSO ticket storage บน Redis (ทน ID Portal restart · multi-replica ใช้ redis เดียวกัน)
// • TTL 30 นาที ต่อ ticket (SETEX) · Update/Revoke คง TTL เดิม (KEEPTTL)
// • หลัง restart: tickets ยังอยู่ถ้า Redis เปิด AOF (compose ตั้ง appendonly yes แล้ว)
// • entry serialize เป็น JSON — fields ตรงกับ memory entry
type RedisTicketStore struct {
	rdb *redis.Client
}

func NewRedisTicketStore(rdb *redis.Client) *RedisTicketStore {
	return &RedisTicketStore{rdb: rdb}
}

const redisTicketPrefix = "central:sso:ticket:"

func ticketKey(ticket string) string {
	return redisTicketPrefix + ticket
}

type ticketEntry struct {
	Username     string   `json:"username"`
	AccessToken  string   `json:"accessToken"`
	Aud          []string `json:"aud"`
	IssuedFor    string   `json:"issuedFor"`
	RefreshToken string   `json:"refreshToken,omitempty"`
	ClientID     string   `json:"clientID"`
	CreatedAt    int64    `json:"createdAt"`
	Revoked      bool     `json:"revoked,omitempty"`
	RevokedAt    int64    `json:"revokedAt,omitempty"`
}

func (s *RedisTicketStore) Create(username, accessToken string, aud []string, issuedFor, refreshToken, clientID string) (string, time.Time) {
	ctx := context.Background()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", time.Now()
	}
	ticket := base64.RawURLEncoding.EncodeToString(b)
	now := time.Now()
	e := ticketEntry{
		Username: username, AccessToken: accessToken, Aud: aud, IssuedFor: issuedFor,
		RefreshToken: refreshToken, ClientID: clientID, CreatedAt: now.Unix(),
	}
	raw, _ := json.Marshal(e)
	s.rdb.Set(ctx, ticketKey(ticket), raw, 30*time.Minute)
	return ticket, now.Add(30 * time.Minute)
}

func (s *RedisTicketStore) Get(ticket string) (username, accessToken string, aud []string, issuedFor, refreshToken, clientID string, err error) {
	ctx := context.Background()
	raw, gerr := s.rdb.Get(ctx, ticketKey(ticket)).Result()
	if gerr != nil {
		return "", "", nil, "", "", "", ErrNotFound
	}
	var e ticketEntry
	if json.Unmarshal([]byte(raw), &e) != nil {
		return "", "", nil, "", "", "", ErrExpired
	}
	return e.Username, e.AccessToken, e.Aud, e.IssuedFor, e.RefreshToken, e.ClientID, nil
}

func (s *RedisTicketStore) Update(ticket, newAccessToken string, newAud []string, newRefreshToken string) {
	ctx := context.Background()
	raw, gerr := s.rdb.Get(ctx, ticketKey(ticket)).Result()
	if gerr != nil {
		return
	}
	var e ticketEntry
	if json.Unmarshal([]byte(raw), &e) != nil {
		return
	}
	e.AccessToken = newAccessToken
	if newAud != nil {
		e.Aud = newAud
	}
	if newRefreshToken != "" {
		e.RefreshToken = newRefreshToken
	}
	updated, _ := json.Marshal(e)
	// คง TTL เดิม (KEEPTTL) — อายุตั๋วไม่ต่ออายุเพราะ renew
	s.rdb.Set(ctx, ticketKey(ticket), updated, redis.KeepTTL)
}

func (s *RedisTicketStore) Revoke(ticket string) (string, bool) {
	ctx := context.Background()
	raw, gerr := s.rdb.Get(ctx, ticketKey(ticket)).Result()
	if gerr != nil {
		return "", false
	}
	var e ticketEntry
	if json.Unmarshal([]byte(raw), &e) != nil {
		return "", false
	}
	e.Revoked = true
	e.RevokedAt = time.Now().Unix()
	updated, _ := json.Marshal(e)
	// คง TTL เดิม — revoked ticket หมดอายุพร้อมตั๋วเดิม
	s.rdb.Set(ctx, ticketKey(ticket), updated, redis.KeepTTL)
	return e.Username, true
}

func (s *RedisTicketStore) RevokeAll() int {
	ctx := context.Background()
	keys, err := s.rdb.Keys(ctx, redisTicketPrefix+"*").Result()
	if err != nil {
		return 0
	}
	if len(keys) == 0 {
		return 0
	}
	n, _ := s.rdb.Del(ctx, keys...).Result()
	return int(n)
}

func (s *RedisTicketStore) Check(ticket string) (string, bool) {
	ctx := context.Background()
	raw, gerr := s.rdb.Get(ctx, ticketKey(ticket)).Result()
	if gerr != nil {
		return "", false
	}
	var e ticketEntry
	if json.Unmarshal([]byte(raw), &e) != nil {
		return "", false
	}
	if e.Revoked {
		return e.Username, false
	}
	return e.Username, true
}
