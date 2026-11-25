package apikeys

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisKeyStore — Central API Key storage บน Redis
// • ไม่มี TTL (key ใช้ได้จน revoke) · revoke = ตั้ง revoked flag
// • หลัง restart: keys ยังอยู่ถ้า Redis เปิด AOF (compose ตั้ง appendonly yes แล้ว)
// • entry เก็บเป็น JSON string (Key struct fields unexported — ใช้ mirror struct ตอน serialize)
// • index: SET apikey:full:<key> → id · SET apikey:owner:<owner> = set ของ id
type RedisKeyStore struct {
	rdb *redis.Client
}

func NewRedisKeyStore(rdb *redis.Client) *RedisKeyStore {
	return &RedisKeyStore{rdb: rdb}
}

const (
	keyEntryPrefix  = "central:apikey:id:"   // <id> → entry JSON
	keyLookupPrefix = "central:apikey:full:" // <full key> → <id>
	ownerSetPrefix  = "central:apikey:owner:" // <owner> → set ของ id
)

// keyJSON — mirror struct แบบ exported สำหรับ serialize (Key struct เป็น unexported fields)
type keyJSON struct {
	ID        string   `json:"id"`
	Key       string   `json:"key"`
	Name      string   `json:"name"`
	Owner     string   `json:"owner"`
	Scopes    []string `json:"scopes"`
	CreatedAt int64    `json:"createdAt"`
	Revoked   bool     `json:"revoked,omitempty"`
	RevokedAt int64    `json:"revokedAt,omitempty"`
	LastUsed  int64    `json:"lastUsed,omitempty"`
}

func (s *RedisKeyStore) Create(owner, name string, scopes []string) (*Key, string) {
	ctx := context.Background()
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	full := "central_" + base64.RawURLEncoding.EncodeToString(b)
	id := full[len(full)-12:]
	now := time.Now()

	e := keyJSON{ID: id, Key: full, Name: name, Owner: owner, Scopes: scopes, CreatedAt: now.Unix()}
	raw, _ := json.Marshal(e)
	pipe := s.rdb.TxPipeline()
	pipe.Set(ctx, keyEntryPrefix+id, raw, 0)
	pipe.Set(ctx, keyLookupPrefix+full, id, 0)
	pipe.SAdd(ctx, ownerSetPrefix+owner, id)
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, ""
	}
	return &Key{ID: id, Key: full, Name: name, Owner: owner, Scopes: scopes, CreatedAt: now}, full
}

func (s *RedisKeyStore) entryJSON(ctx context.Context, id string) (*keyJSON, bool) {
	raw, err := s.rdb.Get(ctx, keyEntryPrefix+id).Result()
	if err != nil {
		return nil, false
	}
	var e keyJSON
	if json.Unmarshal([]byte(raw), &e) != nil {
		return nil, false
	}
	return &e, true
}

func (s *RedisKeyStore) List(owner string) []*Key {
	ctx := context.Background()
	ids, err := s.rdb.SMembers(ctx, ownerSetPrefix+owner).Result()
	if err != nil {
		return nil
	}
	out := make([]*Key, 0, len(ids))
	for _, id := range ids {
		if e, ok := s.entryJSON(ctx, id); ok {
			out = append(out, e.toKey())
		}
	}
	// เรียงใหม่สุดก่อน (ตาม memory impl)
	for i := 1; i < len(out); i++ {
		for j := 0; j < len(out)-i; j++ {
			if out[j].CreatedAt.Before(out[j+1].CreatedAt) {
				out[j], out[j+1] = out[j+1], out[j]
			}
		}
	}
	return out
}

func (s *RedisKeyStore) Get(owner, id string) *Key {
	ctx := context.Background()
	e, ok := s.entryJSON(ctx, id)
	if !ok || e.Owner != owner {
		return nil
	}
	return e.toKey()
}

func (s *RedisKeyStore) Revoke(owner, id string) bool {
	ctx := context.Background()
	e, ok := s.entryJSON(ctx, id)
	if !ok || e.Owner != owner || e.Revoked {
		return false
	}
	e.Revoked = true
	e.RevokedAt = time.Now().Unix()
	raw, _ := json.Marshal(e)
	s.rdb.Set(ctx, keyEntryPrefix+id, raw, 0)
	return true
}

func (s *RedisKeyStore) Validate(fullKey string) *Key {
	ctx := context.Background()
	id, err := s.rdb.Get(ctx, keyLookupPrefix+fullKey).Result()
	if err != nil {
		return nil
	}
	e, ok := s.entryJSON(ctx, id)
	if !ok || e.Revoked {
		return nil
	}
	e.LastUsed = time.Now().Unix()
	raw, _ := json.Marshal(e)
	s.rdb.Set(ctx, keyEntryPrefix+id, raw, 0)
	return e.toKey()
}

func (e *keyJSON) toKey() *Key {
	created := time.Unix(e.CreatedAt, 0)
	k := &Key{ID: e.ID, Key: e.Key, Name: e.Name, Owner: e.Owner, Scopes: e.Scopes, CreatedAt: created}
	if e.Revoked {
		k.Revoked = true
		k.RevokedAt = time.Unix(e.RevokedAt, 0)
	}
	if e.LastUsed > 0 {
		k.LastUsed = time.Unix(e.LastUsed, 0)
	}
	return k
}
