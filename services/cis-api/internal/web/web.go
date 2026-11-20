// Package web — shared UI ของ CIS Portal (POC) — server-rendered HTML + vanilla JS
// ออกแบบภาษาเดียวกับ Buyer Portal เพื่อจำลอง flow จริงของ rootcase:
// [1] ล็อกอิน ID → [2] Buyer Portal → [3] CIS Portal (SSO) → [4] Logout กลาง
package web

import (
	"fmt"
	"html"
	"strings"
)

// Esc — escape HTML สำหรับค่าที่มาจาก token/user
func Esc(s interface{}) string { return html.EscapeString(fmt.Sprint(s)) }

// CSS — ดีไซน์เดียวกับ services/buyer-api/src/ui.ts (พอให้ POC ดูเป็นแอปจริง)
const CSS = `
:root{--brand:#4f46e5;--brand2:#0ea5e9;--bg:#f1f5f9;--ink:#0f172a;--muted:#64748b;--card:#fff}
*{box-sizing:border-box}
body{margin:0;font-family:'Segoe UI',system-ui,'Noto Sans Thai','Sarabun',sans-serif;background:var(--bg);color:var(--ink)}
.topbar{background:linear-gradient(90deg,#1e1b4b,#4f46e5);color:#fff;padding:0 24px;height:60px;display:flex;align-items:center;gap:18px;position:sticky;top:0;z-index:10}
.brand{font-weight:800;font-size:17px;display:flex;gap:10px;align-items:center;text-decoration:none;color:#fff}
.logo{width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,#22d3ee,#4f46e5);display:grid;place-items:center;font-size:15px;flex:none}
nav{display:flex;gap:4px;flex-wrap:wrap}
nav a{color:#c7d2fe;text-decoration:none;padding:6px 11px;border-radius:8px;font-size:13.5px}
nav a:hover{background:#ffffff1a;color:#fff}
nav a.active{background:#ffffff26;color:#fff;font-weight:600}
.spacer{flex:1}
.userchip{display:flex;align-items:center;gap:10px;font-size:13px;color:#e0e7ff}
.userchip .name{font-weight:700;color:#fff}
.badge{padding:2px 10px;border-radius:999px;font-size:12px;background:#ffffff26}
.btnlogout{background:transparent;border:1px solid #ffffff55;color:#fff;padding:5px 12px;border-radius:8px;cursor:pointer;font-size:13px}
.btnlogout:hover{background:#ffffff1a}
.wrap{max-width:960px;margin:26px auto 40px;padding:0 20px}
.steps{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}
.step{font-size:12.5px;padding:6px 12px;border-radius:999px;background:#e2e8f0;color:#475569}
.step.now{background:var(--brand);color:#fff;font-weight:700}
.step.done{background:#d1fae5;color:#065f46}
.card{background:var(--card);border-radius:14px;padding:20px 22px;box-shadow:0 1px 3px #0001;margin-bottom:18px}
.card h2{margin:0 0 6px;font-size:17px}
.card .sub{color:var(--muted);font-size:13.5px;margin:0 0 14px}
.hero{text-align:center;padding:60px 24px;background:linear-gradient(160deg,#022c22,#059669 70%,#0ea5e9);border-radius:16px;color:#fff;margin-bottom:18px}
.hero h1{margin:0 0 10px;font-size:30px}
.hero p{color:#d1fae5;font-size:15px;margin:0 0 26px}
.btn{display:inline-block;border:none;cursor:pointer;text-decoration:none;font-size:14.5px;padding:12px 24px;border-radius:10px;font-weight:700}
.btn-primary{background:linear-gradient(90deg,#0ea5e9,#4f46e5);color:#fff}
.btn-primary:hover{filter:brightness(1.08)}
.btn-ghost{background:#fff;color:var(--brand);border:1.5px solid #c7d2fe}
.btn-ghost:hover{background:#eef2ff}
.btn-sm{padding:8px 16px;font-size:13.5px;border-radius:8px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px}
td,th{padding:9px 10px;border-bottom:1px solid #eef2f7;vertical-align:top}
tr:last-child td{border-bottom:none}
code,kbd{background:#f1f5f9;padding:1px 7px;border-radius:6px;font-size:12.5px;font-family:Consolas,monospace}
.pill{display:inline-block;padding:3px 12px;border-radius:999px;font-size:12.5px;font-weight:700;background:#eef2ff;color:#3730a3;margin:2px 4px 2px 0}
.pill.ok{background:#d1fae5;color:#065f46}
.pill.svc{background:#e0f2fe;color:#075985}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:8px}
.notice{border-radius:12px;padding:14px 18px;font-size:14px;margin-bottom:18px}
.notice.warn{background:#fffbeb;border:1px solid #fde68a;color:#92400e}
.notice.err{background:#fef2f2;border:1px solid #fecaca;color:#991b1b}
.notice.ok{background:#ecfdf5;border:1px solid #a7f3d0;color:#065f46}
.foot{color:var(--muted);font-size:12.5px;text-align:center;margin-top:26px}
.toast{position:fixed;right:20px;bottom:20px;background:#0f172a;color:#fff;padding:12px 18px;border-radius:10px;font-size:14px;opacity:0;pointer-events:none;transition:opacity .3s;z-index:99}
.toast.show{opacity:1}
.count{font-variant-numeric:tabular-nums}
.langsw{display:flex;gap:6px;align-items:center;font-size:12.5px}
.langsw .langcur{color:#fff;font-weight:700;padding:4px 8px;border-radius:6px}
.langsw a{color:#c7d2fe;text-decoration:none;padding:4px 8px;border-radius:6px;border:1px solid #ffffff33}
.langsw a:hover{color:#fff;background:#ffffff1a}
`

// Session — ข้อมูลสำหรับแสดงบนหน้าจอ (controller verify token ก่อนแล้ว)
type Session struct {
	Username      string
	Email         string
	Sub           string
	ClientID      string
	PrincipalType string
	TenantID      string
	Scopes        []string
	Exp           int64
	Issuer        string
}

// Steps — แถบขั้นตอน flow ตาม rootcase (current: 1-4, doneUntil: ทำสำเร็จถึงลำดับไหน)
func Steps(current, doneUntil int, lang string) string {
	labels := []string{
		T(lang, "ล็อกอิน ID", "Sign in ID"),
		T(lang, "Buyer Portal", "Buyer Portal"),
		T(lang, "CIS Portal (SSO)", "CIS Portal (SSO)"),
		T(lang, "Logout กลาง", "Global logout"),
	}
	hrefs := []string{"http://localhost:3000", "http://localhost:3010", "http://localhost:3020", ""}
	var b strings.Builder
	for i, lb := range labels {
		n := i + 1
		cls := ""
		if n == current {
			cls = "now"
		} else if n <= doneUntil {
			cls = "done"
		}
		item := fmt.Sprintf("%d. %s", n, lb)
		if hrefs[i] != "" {
			fmt.Fprintf(&b, `<a class="step %s" style="text-decoration:none" href="%s">%s</a>`, cls, hrefs[i], item)
		} else {
			fmt.Fprintf(&b, `<span class="step %s">%s</span>`, cls, item)
		}
	}
	return `<div class="steps">` + b.String() + `</div>`
}

// Nav — แถบบน (app: ชื่อแอป, otherApp: ลิงก์ไปอีกแอปเพื่อทดสอบ SSO)
func Nav(app, page string, s *Session, otherAppURL, otherAppLabel, lang string) string {
	homeActive, dataActive := "", ""
	if page == "home" {
		homeActive = "active"
	} else {
		dataActive = "active"
	}
	dataLabel, dataHref := "Projects", "/projects/page"
	if app == "Buyer Portal" {
		dataLabel, dataHref = "Orders", "/orders/page"
	}
	user := `<div class="userchip"><span class="badge">` + T(lang, "ไม่ได้ล็อกอิน", "Not signed in") + `</span></div>`
	if s != nil {
		user = fmt.Sprintf(`<div class="userchip"><span class="name">%s</span> <span class="badge">%s</span> <a class="btnlogout" href="/auth/logout">%s</a></div>`,
			Esc(s.Username), Esc(s.PrincipalType), T(lang, "Logout กลาง", "Global logout"))
	}
	return fmt.Sprintf(`<header class="topbar">
<a class="brand" href="/"><span class="logo">A</span>%s</a>
<nav><a class="%s" href="/">%s</a><a class="%s" href="%s">%s</a><a href="http://localhost:3000" title="%s">ID ↗</a><a href="%s" title="%s">%s ↗</a><a href="http://localhost:3050" title="%s">Fintech ↗</a></nav>
<div class="spacer"></div>%s<div class="langsw">%s</div></header>`,
		Esc(app), homeActive, T(lang, "หน้าแรก", "Home"), dataActive, dataHref, dataLabel,
		T(lang, "ID — บัญชีกลาง", "ID — central account"), otherAppURL,
		T(lang, "ทดสอบ SSO — ต้องไม่ถามรหัสผ่าน", "Test SSO — must not ask for a password"), otherAppLabel,
		T(lang, "Fintech App — Embedded Login demo", "Fintech App — Embedded Login demo"),
		user, LangSwitchHTML(lang))
}

// Page — ครอบทั้งหน้า (topbar + steps + body + footer)
func Page(opt struct {
	Title      string
	Body       string
	ActiveStep int
	DoneUntil  int
	Session    *Session
	AppName    string
	DataPage   string // "home" หรือชื่อหน้า data เช่น "projects"
	OtherURL   string
	OtherLabel string
	Lang       string
}) string {
	lang := opt.Lang
	return `<!doctype html><html lang="` + lang + `"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>` + Esc(opt.Title) + `</title>
<style>` + CSS + `</style>
` + Nav(opt.AppName, opt.DataPage, opt.Session, opt.OtherURL, opt.OtherLabel, lang) + `
<main class="wrap">
` + Steps(opt.ActiveStep, opt.DoneUntil, lang) + `
` + opt.Body + `
<p class="foot">POC Central Identity — ` + T(lang, "token ตรวจสอบกลางที่ ID (Keycloak, JWKS RS256)", "tokens verified centrally at ID (Keycloak, JWKS RS256)") + ` · ` + T(lang, "แอปนี้ verify", "this app verifies") + ` <code>iss</code>/<code>aud</code>/<code>exp</code>/<code>scope</code> ` + T(lang, "เองทุก request", "itself on every request") + `</p>
</main>
<div class="toast" id="toast"></div>`
}

// ToastScript — ฟังก์ชัน toast ของหน้า (ใช้ร่วมกับ JS ในหน้า data)
const ToastScript = `function toast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2600);}`

// SessionCards — การ์ดโปรไฟล์ + token/session (แสดงจาก claims)
func SessionCards(s *Session, lang string) string {
	scopePills := strings.Builder{}
	for _, sc := range s.Scopes {
		cls := ""
		if strings.Contains(sc, "write") {
			cls = "ok"
		}
		fmt.Fprintf(&scopePills, `<span class="pill %s">%s</span>`, cls, Esc(sc))
	}
	userRow := Esc(s.Username)
	if s.Email != "" {
		userRow += ` <span style="color:var(--muted)">(` + Esc(s.Email) + `)</span>`
	}
	return fmt.Sprintf(`<div class="grid">
<div class="card"><h2>%s</h2><p class="sub">%s</p>
<table>
<tr><th>%s</th><td><b>%s</b></td></tr>
<tr><th>sub</th><td><code>%s…</code></td></tr>
<tr><th>%s</th><td><span class="pill">%s</span></td></tr>
<tr><th>tenant</th><td><code>%s</code></td></tr>
</table></div>
<div class="card"><h2>Token / Session</h2><p class="sub">%s</p>
<table>
<tr><th>client (azp)</th><td><code>%s</code></td></tr>
<tr><th>scopes</th><td>%s</td></tr>
<tr><th>%s (exp)</th><td class="count" id="exp-countdown">…</td></tr>
<tr><th>issuer</th><td><code style="font-size:11.5px">%s</code></td></tr>
</table></div></div>
<script>(()=>{const exp=%d;const el=document.getElementById('exp-countdown');
const tick=()=>{const left=exp-Math.floor(Date.now()/1000);if(left<=0){el.textContent='%s';return}
const m=Math.floor(left/60),sec=left%%60;el.textContent=left+' %s ('+m+':'+String(sec).padStart(2,'0')+')'};
tick();setInterval(tick,1000);})();</script>`,
		T(lang, "ผู้ใช้ (จาก central token)", "User (from central token)"), T(lang, "อ่านจาก claims — ไม่ใช่ session ของแอปเอง", "Read from claims — not the app's own session"),
		T(lang, "ผู้ใช้", "User"), userRow, Esc(short(s.Sub, 18)),
		T(lang, "ประเภท principal", "Principal type"), Esc(s.PrincipalType), Esc(s.TenantID),
		T(lang, "ออกโดย ID — แอปตรวจ signature ผ่าน JWKS ทุกครั้ง", "Issued by ID — the app verifies the signature via JWKS every time"),
		Esc(s.ClientID), scopePills.String(),
		T(lang, "หมดอายุ", "Expires"), Esc(s.Issuer), s.Exp,
		T(lang, "หมดอายุแล้ว", "expired"), T(lang, "วินาที", "s"))
}

func short(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
