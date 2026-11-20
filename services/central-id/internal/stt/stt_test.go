package stt

import "testing"

// ทดสอบพฤติกรรม dest binding — สร้างซ้ำหลายรอบ (เลียนแบบกรณีที่ map มี entry ค้าง)
func TestCreateRedeemDestBinding(t *testing.T) {
	s := NewStore()
	for i := 1; i <= 8; i++ {
		c := s.Create("u", "tok", []string{"aud-x"}, "issued-x", "fintech-web")
		u, _, _, _, err := s.Redeem(c, "fintech-web")
		if err != nil {
			t.Fatalf("round %d redeem failed: %v", i, err)
		}
		if u != "u" {
			t.Fatalf("round %d username=%q", i, u)
		}
	}
}

// redeem ด้วย dest อื่นต้อง mismatch และ code ยังใช้ได้กับ dest จริง
func TestDestMismatchKeepsEntry(t *testing.T) {
	s := NewStore()
	c := s.Create("u", "tok", nil, "issued-x", "buyer-web")
	if _, _, _, _, err := s.Redeem(c, "cis-web"); err == nil {
		t.Fatal("expected mismatch error")
	}
	if _, _, _, _, err := s.Redeem(c, "buyer-web"); err != nil {
		t.Fatalf("redeem with correct dest after mismatch failed: %v", err)
	}
}
