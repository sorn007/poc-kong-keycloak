package stt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCodeStore — STT one-time code storage บน Redis
// • TTL 60 วินาที ต่อ code (SETEX — redis เอา key ออกเองเมื่อหมดอายุ)
// • redeem เป็น **atomic Lua**: ตรวจ dest ก่อน แล้วจึง DEL (ผิด dest ไม่ consume — เหมือน memory impl)
// • หลัง restart: codes ยังอยู่ถ้า Redis เปิด AOF (แต่ TTL 60s สั้น — ส่วนใหญ่หมดอายุก่อน restart อยู่แล้ว)
type RedisCodeStore struct {
	rdb *redis.Client
}

func NewRedisCodeStore(rdb *redis.Client) *RedisCodeStore {
	return &RedisCodeStore{rdb: rdb}
}

const (
	redisCodePrefix = "central:stt:code:"

	// Lua: GET → ไม่มี = false (not found) · dest ไม่ตรง = "MISMATCH" (ไม่ consume)
	// dest ตรง = DEL แล้วคืน entry JSON (atomic consume)
	luaRedeem = `
local v = redis.call('GET', KEYS[1])
if not v then return false end
local e = cjson.decode(v)
if e["dest"] ~= ARGV[1] then return "MISMATCH" end
redis.call('DEL', KEYS[1])
return v`
)

var redeemScript = redis.NewScript(luaRedeem)

type codeEntry struct {
	Username    string   `json:"username"`
	AccessToken string   `json:"accessToken"`
	Aud         []string `json:"aud"`
	IssuedFor   string   `json:"issuedFor"`
	Dest        string   `json:"dest"`
	CreatedAt   int64    `json:"createdAt"`
}

func (s *RedisCodeStore) Create(username, accessToken string, aud []string, issuedFor, dest string) string {
	ctx := context.Background()
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	code := base64.RawURLEncoding.EncodeToString(b)
	e := codeEntry{
		Username: username, AccessToken: accessToken, Aud: aud,
		IssuedFor: issuedFor, Dest: dest, CreatedAt: time.Now().Unix(),
	}
	raw, _ := json.Marshal(e)
	s.rdb.Set(ctx, redisCodePrefix+code, raw, 60*time.Second)
	return code
}

func (s *RedisCodeStore) Redeem(code, dest string) (username, accessToken string, aud []string, issuedFor string, err error) {
	ctx := context.Background()
	res, rerr := redeemScript.Run(ctx, s.rdb, []string{redisCodePrefix + code}, dest).Result()
	if rerr != nil {
		if errors.Is(rerr, redis.Nil) {
			return "", "", nil, "", ErrNotFound
		}
		return "", "", nil, "", ErrNotFound
	}
	switch v := res.(type) {
	case string:
		if v == "MISMATCH" {
			return "", "", nil, "", ErrDestMismatch
		}
		var e codeEntry
		if json.Unmarshal([]byte(v), &e) != nil {
			return "", "", nil, "", ErrNotFound
		}
		return e.Username, e.AccessToken, e.Aud, e.IssuedFor, nil
	default:
		return "", "", nil, "", ErrNotFound
	}
}
