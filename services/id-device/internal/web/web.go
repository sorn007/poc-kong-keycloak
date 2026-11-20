// Package web — UI ของ "อุปกรณ์ ID" (Authentication Device ของ CIBA flow)
// จอแบบ production: phone-frame + security banner + การ์ดคำขอ + สถานะหลังตัดสินใจ
// ข้อความผู้ใช้เป็นสองภาษา ไทย/EN (default "th" — ดู i18n.go), identifiers/log เป็นภาษาอังกฤษ
package web

import (
	"fmt"
	"html"
)

// Esc — escape HTML สำหรับค่าที่มาจาก token/user
func Esc(s interface{}) string { return html.EscapeString(fmt.Sprint(s)) }

// CSS — ดีไซน์จออุปกรณ์ ID (โทนเขียวแบรนด์ ID เดิม แต่จัดวางแบบแอปธนาคารจริง)
const CSS = `
:root{
  --ink:#0f172a; --muted:#64748b; --line:#e5e7eb;
  --ok:#059669; --okbg:#ecfdf5; --err:#dc2626; --errbg:#fef2f2; --warnbg:#fffbeb; --warn:#92400e;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,'Noto Sans Thai','Sarabun',sans-serif;
  background:radial-gradient(1100px 700px at 15% -10%,#064e3b 0%,#022c22 45%,#0f172a 100%);
  min-height:100vh;display:flex;align-items:center;justify-content:center;padding:32px 16px;
  color:#0f172a;-webkit-font-smoothing:antialiased}
.phone{width:100%;max-width:430px;background:#fff;border-radius:26px;
  box-shadow:0 30px 80px rgba(0,0,0,.5);overflow:hidden;border:6px solid #0b1220}
.head{background:linear-gradient(135deg,#059669,#047857);color:#fff;padding:18px 22px;
  display:flex;align-items:center;gap:12px}
.head .logo{width:38px;height:38px;border-radius:11px;background:rgba(255,255,255,.18);
  border:1px solid rgba(255,255,255,.3);display:grid;place-items:center;font-weight:800;font-size:19px}
.head .t{font-size:17px;font-weight:800}
.head .s{font-size:11.5px;color:#d1fae5;margin-top:2px}
.langsw{margin-left:auto;display:flex;gap:6px;align-items:center;font-size:12px}
.langsw .langcur{color:#fff;font-weight:700;padding:3px 8px;border-radius:6px}
.langsw a{color:#d1fae5;text-decoration:none;padding:3px 8px;border-radius:6px;border:1px solid rgba(255,255,255,.35)}
.langsw a:hover{color:#fff;background:rgba(255,255,255,.12)}
.body{padding:22px}
.banner{display:flex;gap:10px;align-items:flex-start;background:#f0fdf4;border:1px solid #a7f3d0;
  border-radius:12px;padding:11px 14px;font-size:12.5px;color:#065f46;line-height:1.6;margin-bottom:18px}
.banner .shield{font-size:16px}
.row{display:flex;justify-content:space-between;gap:12px;padding:9px 0;border-bottom:1px solid #f1f5f9;font-size:13.5px}
.row:last-child{border-bottom:none}
.row .k{color:#64748b;font-size:12px;letter-spacing:.4px;text-transform:uppercase;font-weight:600;padding-top:2px}
.row .v{text-align:right;font-weight:600}
.code{font-family:Consolas,monospace;font-size:19px;font-weight:800;letter-spacing:1px;
  background:#f0fdf4;border:1.5px dashed #34d399;color:#065f46;border-radius:10px;
  padding:12px;text-align:center;margin:4px 0 4px}
.chips{display:flex;flex-wrap:wrap;gap:6px;justify-content:flex-end}
.chip{font-size:11.5px;font-weight:700;background:#ecfdf5;color:#065f46;border-radius:999px;padding:3px 10px}
.chip.warn{background:#fef3c7;color:#92400e}
.actions{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:18px}
button{font-family:inherit;font-size:15px;font-weight:800;border-radius:12px;padding:14px;cursor:pointer;border:none;width:100%}
.approve{background:#059669;color:#fff;box-shadow:0 8px 20px rgba(5,150,105,.35)}
.approve:hover{background:#047857}
.deny{background:#fff;color:#b91c1c;border:1.5px solid #fecaca}
.deny:hover{background:#fef2f2}
.foot{margin-top:16px;font-size:11.5px;color:#64748b;line-height:1.7;
  border-top:1px solid #eef2f7;padding-top:12px;display:flex;gap:8px}
.empty{text-align:center;padding:26px 8px}
.empty .pulse{width:52px;height:52px;margin:6px auto 16px;border-radius:50%;
  background:#ecfdf5;border:2px solid #a7f3d0;animation:pulse 1.8s ease-in-out infinite}
@keyframes pulse{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.12);opacity:.6}}
.empty .t{font-size:14.5px;font-weight:700;color:#334155}
.empty .s{font-size:12.5px;color:#64748b;margin-top:6px;line-height:1.7}
.after{text-align:center;padding:10px 4px}
.after .big{width:64px;height:64px;border-radius:50%;display:grid;place-items:center;font-size:30px;margin:6px auto 16px}
.after .big.ok{background:#d1fae5;color:#059669}
.after .big.err{background:#fee2e2;color:#dc2626}
.after h1{font-size:20px;margin:0 0 8px}
.after p{font-size:13.5px;color:#475569;line-height:1.8;margin:0 0 4px}
.appname{font-weight:800;color:#065f46}
`

// Page — เฟรมโทรศัพท์ทั้งหน้า; autoRefresh=true จะ reload ทุก 2.5 วิ (ใช้ตอนหน้าว่างเพื่อรอคำขอ)
// lang = "th" (default) หรือ "en" — กำหนดภาษาของ header/footer + ปุ่มสลับภาษาในทุกหน้า
func Page(o struct {
	Title       string
	Body        string
	AutoRefresh bool
	Lang        string
}) string {
	refresh := ""
	if o.AutoRefresh {
		refresh = `<meta http-equiv="refresh" content="2.5">`
	}
	headTitle := T(o.Lang, "ID — การยืนยันตัวตน", "ID — Authentication")
	footWarn := T(o.Lang,
		"หากคุณ<b>ไม่ได้เป็นผู้กระทำ</b>ตามคำขอนี้ อย่ากดยืนยัน — และแจ้งผู้ดูแลระบบทันที (การยืนยันผิดพลาดอาจให้ผู้อื่นเข้าถึงบัญชีของคุณ)",
		"If you <b>did not initiate</b> this request, do not approve it — notify your administrator immediately (an accidental approval may give others access to your account)")
	return `<!doctype html><html lang="` + o.Lang + `"><meta charset="utf-8">` + refresh + `
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>` + Esc(o.Title) + `</title>
<style>` + CSS + `</style>
<div class="phone">
<div class="head"><div class="logo">A</div><div><div class="t">` + headTitle + `</div><div class="s">Central Central Identity</div></div>` + LangSwitchHTML(o.Lang) + `</div>
<div style="display:flex;gap:2px;padding:0 14px;border-bottom:1px solid #e2e8f0;background:#fff">
<a href="http://localhost:3000" style="flex:1;text-align:center;text-decoration:none;padding:8px 4px;font-size:11.5px;color:#64748b" title="ID Portal">ID ↗</a>
<a href="http://localhost:3010" style="flex:1;text-align:center;text-decoration:none;padding:8px 4px;font-size:11.5px;color:#64748b" title="Buyer Portal">Buyer ↗</a>
<a href="http://localhost:3020" style="flex:1;text-align:center;text-decoration:none;padding:8px 4px;font-size:11.5px;color:#64748b" title="CIS Portal">CIS ↗</a>
<a href="http://localhost:3050" style="flex:1;text-align:center;text-decoration:none;padding:8px 4px;font-size:11.5px;color:#64748b" title="Fintech App">Fintech ↗</a>
</div>
<div class="body">` + o.Body + `</div>
<div class="foot" style="padding:12px 22px 18px"><span>🛡️</span><span>` + footWarn + `</span></div>
</div>`
}

// EmptyBody — หน้าว่าง (รอคำขอจากระบบ)
func EmptyBody(lang string) string {
	return `<div class="empty"><div class="pulse"></div>
<div class="t">` + T(lang, "ไม่มีคำขอเข้าสู่ระบบที่รออนุมัติ", "No sign-in requests awaiting approval") + `</div>
<div class="s">` + T(lang, "หน้านี้จะรีเฟรชอัตโนมัติเมื่อมีคำขอใหม่จากระบบ ID", "This page refreshes automatically when a new request arrives from the ID system") + `</div></div>`
}
