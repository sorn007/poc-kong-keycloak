package apikeys

// KeyStore — interface ของ Central API Key storage
// 2 backends: Store (in-memory, default) · RedisStore (redis.go)
type KeyStore interface {
	Create(owner, name string, scopes []string) (*Key, string)
	List(owner string) []*Key
	Get(owner, id string) *Key
	Revoke(owner, id string) bool
	Validate(fullKey string) *Key
}

var _ KeyStore = (*Store)(nil)
