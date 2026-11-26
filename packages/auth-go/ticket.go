package auth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Ticket liveness — logout กลาง propagate: session ของแอป "ผูกกับตั๋ว SSO" (cookie sso_bound)
// ทุกครั้งที่ render หน้า page ให้ถาม ID Portal ว่าตั๋วยังมีชีวิตไหม (POST /sso/check)
// ตั๋วตาย (revoke / logout-all / หมดอายุ) = เคลียร์ session ของแอปทันที
//
// นโยบายเมื่อ "ตรวจไม่ได้" (broker ล่ม/timeout/ตอบไม่ผิด format): FailOpen = true → ปล่อยผ่าน
// (JWT exp ยังกำกับอยู่) — เลือกเพื่อ availability: ID Portal ล่มไม่ควรล็อกทุกแอป
// ถ้าต้องการ fail-closed ให้ตั้ง FailOpen = false ที่ TicketChecker — จุดตัดสินใจเดียวของทุก service
// หมายเหตุ: API routes ไม่ได้ตรวจตั๋วทุก request (พึ่ง JWT exp สั้น ๆ) — ดู docs/SECURITY-AUDIT.md Q2

const ticketTimeout = 5 * time.Second

// TicketChecker — ตรวจตั๋วกับ ID Portal (ใช้ http.Client ร่วมกัน — สร้างครั้งเดียวตอน startup)
type TicketChecker struct {
	BaseURL  string // URL ภายใน network ของ ID Portal เช่น http://central-id:3000
	Client   *http.Client
	FailOpen bool // true (default) = ตรวจไม่ได้ → ถือว่ายังมีชีวิต
}

// NewTicketChecker — checker พร้อมใช้ (timeout 5s + fail-open)
func NewTicketChecker(brokerBase string) *TicketChecker {
	return &TicketChecker{BaseURL: brokerBase, Client: newHTTPClient(), FailOpen: true}
}

// Alive — ตั๋วยังมีชีวิตอยู่ไหม (ไม่ consume — ตั๋ว reusable)
// ticket ว่าง = session ไม่ได้ผูกตั๋ว → true (ไม่ต้องตรวจ)
func (tc *TicketChecker) Alive(ticket string) bool {
	if ticket == "" {
		return true
	}
	alive, ok := tc.check(ticket)
	if !ok {
		return tc.FailOpen
	}
	return alive
}

func (tc *TicketChecker) check(ticket string) (alive, ok bool) {
	form := url.Values{"ticket": {ticket}}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(tc.BaseURL, "/")+"/sso/check", strings.NewReader(form.Encode()))
	if err != nil {
		return false, false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := tc.Client.Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, false
	}
	var out struct {
		Alive bool `json:"alive"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return false, false
	}
	return out.Alive, true
}

var defaultHTTPClient = newHTTPClient()

func newHTTPClient() *http.Client { return &http.Client{Timeout: ticketTimeout} }

// TicketAlive — ชุดสะดวกของ TicketChecker (ใช้ client ร่วมของแพ็กเกจ + นโยบาย fail-open)
func TicketAlive(brokerBase, ticket string) bool {
	return (&TicketChecker{BaseURL: brokerBase, Client: defaultHTTPClient, FailOpen: true}).Alive(ticket)
}
