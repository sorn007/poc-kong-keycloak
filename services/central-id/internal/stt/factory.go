package stt

import "github.com/redis/go-redis/v9"

// NewCodeStoreFor — เลือก backend ตามชื่อ (env STORE_BACKEND ใน main.go)
func NewCodeStoreFor(backend string, rdb *redis.Client) CodeStore {
	if backend == "redis" && rdb != nil {
		return NewRedisCodeStore(rdb)
	}
	return NewStore()
}
