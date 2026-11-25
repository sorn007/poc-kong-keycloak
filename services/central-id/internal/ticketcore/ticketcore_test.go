package ticketcore

import (
	"errors"
	"testing"
	"time"
)

func opts() Options {
	return Options{TTL: 60 * time.Second, CleanupAfter: 10 * time.Minute, Prefix: "test:core:"}
}

func payload() Payload {
	return Payload{Username: "u", AccessToken: "tok", Aud: []string{"aud-x"}, IssuedFor: "issued-x", Dest: "buyer-web"}
}

// Peek ต้อง reusable — อ่านกี่ครั้งก็ยังได้ (พฤติกรรมของ SSO Ticket)
func TestPeekReusable(t *testing.T) {
	c := NewMemory(opts())
	h, _ := c.Issue(payload())
	for i := 0; i < 3; i++ {
		p, err := c.Peek(h)
		if err != nil {
			t.Fatalf("peek round %d: %v", i, err)
		}
		if p.Username != "u" {
			t.Fatalf("peek round %d username=%q", i, p.Username)
		}
	}
}

// Consume เป็น one-time — ครั้งแรกได้ payload ครั้งที่สอง ErrNotFound (พฤติกรรมของ STT)
func TestConsumeOneTime(t *testing.T) {
	c := NewMemory(opts())
	h, _ := c.Issue(payload())
	if _, err := c.Consume(h, "buyer-web"); err != nil {
		t.Fatalf("first consume failed: %v", err)
	}
	if _, err := c.Consume(h, "buyer-web"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second consume expected ErrNotFound, got %v", err)
	}
}

// dest ไม่ตรง = ErrDestMismatch และ **ไม่ consume** — ยังใช้กับปลายทางจริงได้
func TestConsumeDestMismatchKeepsHandle(t *testing.T) {
	c := NewMemory(opts())
	h, _ := c.Issue(payload())
	if _, err := c.Consume(h, "cis-web"); !errors.Is(err, ErrDestMismatch) {
		t.Fatalf("expected ErrDestMismatch, got %v", err)
	}
	if _, err := c.Consume(h, "buyer-web"); err != nil {
		t.Fatalf("consume with correct dest after mismatch failed: %v", err)
	}
}

// dest ว่าง = ปฏิเสธเสมอ (พฤติกรรมเดิมของ stt memory impl)
func TestConsumeEmptyDestRejected(t *testing.T) {
	c := NewMemory(opts())
	h, _ := c.Issue(payload())
	if _, err := c.Consume(h, ""); !errors.Is(err, ErrDestMismatch) {
		t.Fatalf("expected ErrDestMismatch for empty dest, got %v", err)
	}
}

// Revoke/RevokeAll/Check/Update ทำงานครบ (พฤติกรรมของ SSO logout)
func TestRevokeAndCheck(t *testing.T) {
	c := NewMemory(opts())
	h, _ := c.Issue(payload())

	if u, ok := c.Revoke(h); !ok || u != "u" {
		t.Fatalf("revoke: ok=%v u=%q", ok, u)
	}
	if _, alive := c.Check(h); alive {
		t.Fatal("expected dead after revoke")
	}
	if _, ok := c.Revoke(h); ok {
		t.Fatal("revoke twice should be false")
	}

	h2, _ := c.Issue(payload())
	c.Update(h2, func(p *Payload) { p.AccessToken = "new" })
	p, _ := c.Peek(h2)
	if p.AccessToken != "new" {
		t.Fatalf("update failed: %q", p.AccessToken)
	}
	if n := c.RevokeAll(); n != 1 {
		t.Fatalf("revokeall=%d", n)
	}
	if _, alive := c.Check(h2); alive {
		t.Fatal("expected dead after revokeall")
	}
}
