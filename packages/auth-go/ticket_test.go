package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// newBroker — ID Portal จำลอง: ตอบ /sso/check ตาม ticket
func newBroker(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sso/check" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.Form.Get("ticket") {
		case "t-alive":
			_, _ = w.Write([]byte(`{"alive":true,"username":"u"}`))
		case "t-dead":
			_, _ = w.Write([]byte(`{"alive":false,"username":""}`))
		case "t-broken":
			_, _ = w.Write([]byte(`not json`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTicketCheckerAlive(t *testing.T) {
	broker := newBroker(t)
	checker := NewTicketChecker(broker.URL)
	if !checker.FailOpen {
		t.Fatal("default policy must be fail-open (documented trade-off)")
	}

	cases := []struct {
		ticket string
		want   bool
		why    string
	}{
		{"t-alive", true, "ตั๋วยังมีชีวิต"},
		{"t-dead", false, "ตั๋วถูก revoke/logout-all → ต้อง propagate logout"},
		{"", true, "session ไม่ได้ผูกตั๋ว → ไม่ตรวจ"},
	}
	for _, tc := range cases {
		if got := checker.Alive(tc.ticket); got != tc.want {
			t.Fatalf("ticket %q: got %v want %v (%s)", tc.ticket, got, tc.want, tc.why)
		}
	}
}

// ตรวจไม่ได้ (broker ตอบ 5xx / format เพี้ยน / ล่ม) → fail-open ตาม default; ตั้ง FailOpen=false แล้วต้อง fail-closed
func TestTicketCheckerFailOpenAndFailClosed(t *testing.T) {
	broker := newBroker(t)
	down := "http://127.0.0.1:1" // ไม่มีอะไรฟัง

	unreachable := []struct{ name, base, ticket string }{
		{"broker ตอบ 500", broker.URL, "t-500"},
		{"broker ตอบ format เพี้ยน", broker.URL, "t-broken"},
		{"path ไม่มีจริง (404)", broker.URL + "/nope", "t-alive"},
		{"broker ล่ม", down, "t-alive"},
	}
	for _, tc := range unreachable {
		t.Run(tc.name, func(t *testing.T) {
			if !TicketAlive(tc.base, tc.ticket) {
				t.Fatal("default policy is fail-open: unreachable broker must not lock users out")
			}
			strict := NewTicketChecker(tc.base)
			strict.FailOpen = false
			if strict.Alive(tc.ticket) {
				t.Fatal("FailOpen=false must reject when broker is unreachable")
			}
		})
	}
}
