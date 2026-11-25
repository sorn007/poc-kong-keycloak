package stt

// CodeStore — interface ของ STT one-time code storage
// 2 backends: Store (in-memory, default) · RedisStore (redis.go)
// consume เป็น atomic (GETDEL/Lua) — dest mismatch ไม่ consume (code ยังใช้ได้กับปลายทางจริง)
type CodeStore interface {
	Create(username, accessToken string, aud []string, issuedFor, dest string) string
	Redeem(code, dest string) (username, accessToken string, aud []string, issuedFor string, err error)
}

var _ CodeStore = (*Store)(nil)
