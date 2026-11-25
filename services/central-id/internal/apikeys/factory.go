package apikeys

import "github.com/redis/go-redis/v9"

// NewKeyStoreFor — เลือก backend ตามชื่อ (env STORE_BACKEND ใน main.go)
func NewKeyStoreFor(backend string, rdb *redis.Client) KeyStore {
	if backend == "redis" && rdb != nil {
		return NewRedisKeyStore(rdb)
	}
	return NewStore()
}
