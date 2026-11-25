// Package ticketcore — กลไกกลางของ "session exchange handle" ทั้งหมดใน ID Portal
// (ADR-007): ออก handle แบบ opaque (สุ่ม 32 ไบต์) ผูกกับ Payload + TTL แล้วให้
// policy layer (package sso / stt) เลือกใช้ต่างกัน:
//
//   SSO Ticket  = ticketcore แบบ **reusable** (ไม่ consume, renew ได้, revoke ได้)
//   STT Code    = ticketcore แบบ **one-time** (Consume ลบทันที + dest binding)
//
// กลไกที่เคย duplicate สองชุด (memory map + mutex, Redis SETEX/KeepTTL, Lua atomic
// consume, lazy-cleanup, JSON serialization) อยู่ที่นี่ที่เดียว — audit/แก้ bug จบที่ package นี้
//
// Security: handle สุ่ม 32 ไบต์ (เดาไม่ได้) · Consume เป็น atomic (ตรวจ dest → delete →
// คืน payload ใน lock/Lua เดียว — concurrent redeem ซ้อนเข้ามาได้ handle เดียว) ·
// dest ไม่ตรง = **ไม่ consume** (code ยังใช้กับปลายทางจริงได้ — พฤติกรรมเดิมของ STT)
package ticketcore

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrNotFound     = errors.New("ticketcore: handle not found")
	ErrExpired      = errors.New("ticketcore: handle expired")
	ErrDestMismatch = errors.New("ticketcore: destination mismatch")
)

// Payload — ข้อมูล session ที่ผูกกับ handle (fields เป็น union ของ SSO/STT —
// field ที่ policy นั้นไม่ใช้จะทิ้งว่าง เช่น STT ไม่มี RefreshToken)
type Payload struct {
	Username     string    `json:"username"`
	AccessToken  string    `json:"accessToken"`
	Aud          []string  `json:"aud,omitempty"`
	IssuedFor    string    `json:"issuedFor,omitempty"`
	Dest         string    `json:"dest,omitempty"`         // STT — ปลายทางเดียวที่ Consume ได้
	RefreshToken string    `json:"refreshToken,omitempty"` // SSO — ไว้ renew ตอน redeem
	ClientID     string    `json:"clientID,omitempty"`     // SSO — client ต้นทางตอน refresh
	CreatedAt    time.Time `json:"createdAt"`
}

// Options — policy ของ store แต่ละชนิด (กำหนดโดย adapter เช่น sso/stt)
type Options struct {
	TTL          time.Duration // อายุ handle (SSO 30 นาที · STT 60 วินาที)
	CleanupAfter time.Duration // memory: lazy-cleanup entry ที่เกินอายุนี้ตอน Issue
	Prefix       string        // redis key prefix เช่น "central:sso:ticket:"
}

// Core — กลไกเดียว 2 backends: rdb == nil → memory · rdb != nil → redis
type Core struct {
	opts Options
	rdb  *redis.Client // nil = memory

	mu sync.Mutex
	m  map[string]*Payload // memory backend
}

// NewMemory — backend ใน process (default ของ POC — restart เสีย state)
func NewMemory(opts Options) *Core {
	return &Core{opts: opts, m: make(map[string]*Payload)}
}

// NewRedis — backend บน Redis (ทน restart + multi-replica — ดู docs/SPoF-ANALYSIS.md §4)
func NewRedis(rdb *redis.Client, opts Options) *Core {
	return &Core{opts: opts, rdb: rdb}
}

// Issue — ออก handle ใหม่ผูกกับ payload · คืน (handle, เวลาหมดอายุ)
func (c *Core) Issue(p Payload) (string, time.Time) {
	now := time.Now()
	p.CreatedAt = now
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	handle := base64.RawURLEncoding.EncodeToString(b)

	if c.rdb == nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		// lazy-cleanup entry เกินอายุ (กัน map โตไม่จำกัดใน memory backend)
		for k, e := range c.m {
			if now.Sub(e.CreatedAt) > c.opts.CleanupAfter {
				delete(c.m, k)
			}
		}
		c.m[handle] = &p
	} else {
		raw, _ := json.Marshal(p)
		c.rdb.Set(ctx(), c.key(handle), raw, c.opts.TTL)
	}
	return handle, now.Add(c.opts.TTL)
}

// Peek — อ่าน payload (ไม่ consume — reusable เช่น SSO) · ErrNotFound/ErrExpired
func (c *Core) Peek(handle string) (*Payload, error) {
	if c.rdb == nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		p, ok := c.m[handle]
		if !ok {
			return nil, ErrNotFound
		}
		if time.Since(p.CreatedAt) > c.opts.TTL {
			delete(c.m, handle)
			return nil, ErrExpired
		}
		cp := *p
		return &cp, nil
	}
	raw, err := c.rdb.Get(ctx(), c.key(handle)).Result()
	if err != nil {
		// redis TTL เป็นตัวกำหนดอายุ — key หาย = หมดอายุหรือไม่มี (ตอบเดียวกัน ไม่ leak สถานะ)
		return nil, ErrNotFound
	}
	var p Payload
	if json.Unmarshal([]byte(raw), &p) != nil {
		return nil, ErrNotFound
	}
	return &p, nil
}

// Check — handle ยังมีชีวิตอยู่ไหม (ใช้โดยปลายทางเพื่อ propagate logout เรียลไทม์)
// ไม่ consume
func (c *Core) Check(handle string) (username string, alive bool) {
	p, err := c.Peek(handle)
	if err != nil {
		return "", false
	}
	return p.Username, true
}

// Consume — แลก handle เป็น payload แบบ **one-time** (ลบทันทีเมื่อสำเร็จ)
// dest != "" ต้องตรงกับตอน Issue — ไม่ตรง = ErrDestMismatch **และไม่ consume**
// (handle ยังใช้ได้กับปลายทางที่ถูกต้อง — หนึ่งครั้งนับเฉพาะ redeem ที่ถูกต้อง)
func (c *Core) Consume(handle, dest string) (*Payload, error) {
	if c.rdb == nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		p, ok := c.m[handle]
		if !ok {
			return nil, ErrNotFound
		}
		if time.Since(p.CreatedAt) > c.opts.TTL {
			delete(c.m, handle)
			return nil, ErrExpired
		}
		if dest == "" || p.Dest != dest {
			// อย่าลบเมื่อ dest ไม่ตรง — wrap รายละเอียดเพื่อ debug (errors.Is ยังจับ ErrDestMismatch ได้)
			return nil, fmt.Errorf("%w (entry.dest=%q redeem.dest=%q)", ErrDestMismatch, p.Dest, dest)
		}
		delete(c.m, handle)
		cp := *p
		return &cp, nil
	}

	// redis: Lua atomic — GET → ตรวจ dest → DEL → คืน JSON (ทุกขั้นใน command เดียว
	// กัน concurrent redeem — เทียบเท่า mutex ของ memory backend)
	res, err := consumeScript.Run(ctx(), c.rdb, []string{c.key(handle)}, dest).Result()
	if err != nil {
		return nil, ErrNotFound
	}
	switch v := res.(type) {
	case string:
		if v == "MISMATCH" {
			return nil, ErrDestMismatch
		}
		var p Payload
		if json.Unmarshal([]byte(v), &p) != nil {
			return nil, ErrNotFound
		}
		return &p, nil
	default:
		return nil, ErrNotFound
	}
}

// Update — แก้ payload ในที่ (SSO renew: เขียน token/aud/refresh ใหม่ — คงอายุเดิม)
func (c *Core) Update(handle string, mutate func(*Payload)) {
	if c.rdb == nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		if p, ok := c.m[handle]; ok {
			mutate(p)
		}
		return
	}
	raw, err := c.rdb.Get(ctx(), c.key(handle)).Result()
	if err != nil {
		return
	}
	var p Payload
	if json.Unmarshal([]byte(raw), &p) != nil {
		return
	}
	mutate(&p)
	updated, _ := json.Marshal(p)
	// คง TTL เดิม (KeepTTL) — อายุ handle ไม่ต่ออายุเพราะ renew
	c.rdb.Set(ctx(), c.key(handle), updated, redis.KeepTTL)
}

// Revoke — ยกเลิก handle (logout) · คืน username เพื่อ log · ไม่มี handle คืน ok=false
func (c *Core) Revoke(handle string) (string, bool) {
	if c.rdb == nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		if p, found := c.m[handle]; found {
			delete(c.m, handle)
			return p.Username, true
		}
		return "", false
	}
	raw, err := c.rdb.GetDel(ctx(), c.key(handle)).Result()
	if err != nil {
		return "", false
	}
	var p Payload
	if json.Unmarshal([]byte(raw), &p) != nil {
		return "", true
	}
	return p.Username, true
}

// RevokeAll — ยกเลิกทุก handle ของ prefix นี้ (logout กลางแบบ global) · คืนจำนวน
func (c *Core) RevokeAll() int {
	if c.rdb == nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		n := len(c.m)
		c.m = make(map[string]*Payload)
		return n
	}
	keys, err := c.rdb.Keys(ctx(), c.opts.Prefix+"*").Result()
	if err != nil || len(keys) == 0 {
		return 0
	}
	n, _ := c.rdb.Del(ctx(), keys...).Result()
	return int(n)
}

func (c *Core) key(handle string) string { return c.opts.Prefix + handle }
