package sso

import "github.com/redis/go-redis/v9"

// NewTicketStoreFor — เลือก backend ตามชื่อ (env STORE_BACKEND ใน main.go)
//   "redis"  → RedisTicketStore (ทน restart · multi-replica)
//   อื่น ๆ   → memory Store (in-process — default ของ POC)
func NewTicketStoreFor(backend string, rdb *redis.Client) TicketStore {
	if backend == "redis" && rdb != nil {
		return NewRedisTicketStore(rdb)
	}
	return NewStore()
}
