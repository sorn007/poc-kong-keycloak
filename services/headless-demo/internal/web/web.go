// Package web — UI ของ Seller App (Headless Demo / CIBA Consumption Device)
// โครงแบบ production: split-layout login + inner pages พร้อม design tokens เดียวกันทั้ง flow
// ข้อความผู้ใช้เป็นภาษาไทย, identifiers/log เป็นภาษาอังกฤษ
package web

import (
	"fmt"
	"html"
)

// Esc — escape HTML สำหรับค่าที่มาจาก token/user
func Esc(s interface{}) string { return html.EscapeString(fmt.Sprint(s)) }

// CSS — design tokens + คอมโพเนนต์ทั้งหมด (production look)
const CSS = `
:root{
  --ink:#0f172a; --muted:#64748b; --bg:#f6f7f9; --card:#ffffff;
  --brand:#b45309; --brand2:#d97706; --deep:#1c1917; --line:#e5e7eb;
  --ok:#059669; --okbg:#ecfdf5; --warn:#b45309; --warnbg:#fffbeb;
  --err:#dc2626; --errbg:#fef2f2;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,'Noto Sans Thai','Sarabun',sans-serif;background:var(--bg);color:var(--ink);-webkit-font-smoothing:antialiased}
a{color:var(--brand)}

/* ---------- split-layout login (หน้าแรก) ---------- */
.split{display:grid;grid-template-columns:1fr;min-height:100vh}
@media(min-width:900px){.split{grid-template-columns:1.05fr 1fr}}
.brand{background:linear-gradient(160deg,#1c1917 0%,#7c2d12 55%,#d97706 130%);color:#fff;padding:56px 48px;display:flex;flex-direction:column;justify-content:space-between}
.brand .mark{display:flex;align-items:center;gap:14px}
.brand .mark .logo{width:46px;height:46px;border-radius:13px;background:linear-gradient(135deg,#fbbf24,#d97706);display:grid;place-items:center;font-size:24px;font-weight:800;box-shadow:0 10px 26px rgba(0,0,0,.35)}
.brand .mark .name{font-size:22px;font-weight:800;letter-spacing:.3px}
.brand .pitch{font-size:30px;font-weight:800;line-height:1.35;margin:0 0 14px}
.brand .pitchsub{color:#fde68a;font-size:15px;line-height:1.8;margin:0 0 30px}
.brand ol.flow{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:16px}
.brand ol.flow li{display:flex;gap:12px;align-items:flex-start;font-size:14px;color:#fde68a;line-height:1.6}
.brand ol.flow li .n{flex:none;width:26px;height:26px;border-radius:8px;background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.25);display:grid;place-items:center;font-weight:800;font-size:13px;color:#fff}
.brand ol.flow li b{color:#fff}
.brand .badge{margin-top:auto;font-size:12px;color:#fcd34d;border:1px solid rgba(252,211,77,.35);border-radius:999px;padding:6px 14px;align-self:flex-start}
.right{display:flex;align-items:center;justify-content:center;padding:40px 24px}
.loginbox{width:100%;max-width:430px}
.loginbox h1{font-size:24px;margin:0 0 6px}
.loginbox .lead{color:var(--muted);font-size:14px;margin:0 0 26px;line-height:1.7}
.field{margin-bottom:18px}
.field label{display:block;font-size:13px;font-weight:700;color:#334155;margin-bottom:7px}
.field input{width:100%;height:46px;border:1.5px solid #d8dee9;border-radius:10px;padding:0 14px;font-size:14.5px;background:#fff;color:var(--ink);outline:none;font-family:inherit}
.field input:focus{border-color:var(--brand2);box-shadow:0 0 0 3px rgba(217,119,6,.15)}
.field .hint{font-size:12px;color:var(--muted);margin-top:6px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:none;cursor:pointer;text-decoration:none;font-size:15px;font-weight:700;padding:13px 22px;border-radius:10px;font-family:inherit}
.btn-primary{width:100%;background:linear-gradient(90deg,#d97706,#b45309);color:#fff;box-shadow:0 8px 22px rgba(180,83,9,.28)}
.btn-primary:hover{filter:brightness(1.07)}
.btn-ghost{background:#fff;color:#7c2d12;border:1.5px solid #e7d8c4}
.btn-sm{padding:9px 16px;font-size:13.5px;border-radius:8px}
.footnote{display:flex;gap:8px;align-items:center;margin-top:22px;font-size:12px;color:var(--muted)}
.footnote .dot{width:7px;height:7px;border-radius:50%;background:var(--ok);flex:none}

/* ---------- inner pages (navbar + container) ---------- */
.nav{background:#fff;border-bottom:1px solid var(--line);padding:0 28px;height:58px;display:flex;align-items:center;gap:16px;position:sticky;top:0;z-index:5}
.nav .logo{width:30px;height:30px;border-radius:9px;background:linear-gradient(135deg,#fbbf24,#d97706);display:grid;place-items:center;color:#fff;font-weight:800;font-size:15px}
.nav .name{font-weight:800;font-size:15.5px}
.nav .tag{font-size:11px;font-weight:700;letter-spacing:.6px;background:#fff7ed;border:1px solid #fed7aa;color:#c2410c;padding:2px 10px;border-radius:999px}
.nav .sp{flex:1}
.container{max-width:860px;margin:30px auto 44px;padding:0 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:24px 26px;margin-bottom:18px;box-shadow:0 1px 2px rgba(15,23,42,.04)}
.card h2{margin:0 0 6px;font-size:16.5px}
.card .sub{color:var(--muted);font-size:13.5px;margin:0 0 14px;line-height:1.7}
.notice{border-radius:12px;padding:14px 18px;font-size:14px;margin-bottom:16px;line-height:1.7}
.notice.ok{background:var(--okbg);border:1px solid #a7f3d0;color:#065f46}
.notice.warn{background:var(--warnbg);border:1px solid #fde68a;color:#92400e}
.notice.err{background:var(--errbg);border:1px solid #fecaca;color:#991b1b}
.pill{display:inline-block;padding:3px 12px;border-radius:999px;font-size:12px;font-weight:700;background:#f1f5f9;color:#475569;margin:2px 4px 2px 0}
.pill.ok{background:#d1fae5;color:#065f46}
.pill.fail{background:#fee2e2;color:#991b1b}
.pill.warn{background:#fef3c7;color:#92400e}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{text-align:left;color:var(--muted);font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.5px;width:210px}
td,th{padding:9px 10px;border-bottom:1px solid #eef2f7;vertical-align:top}
tr:last-child td{border-bottom:none}
code,kbd{background:#f1f5f9;border:1px solid #e2e8f0;padding:2px 8px;border-radius:6px;font-size:12px;font-family:Consolas,'Cascadia Mono',monospace;word-break:break-all}
code.count{font-size:14px}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:6px}

/* binding code */
.binding{font-family:Consolas,monospace;font-size:20px;font-weight:800;letter-spacing:1px;background:#fffbeb;border:1.5px dashed #f59e0b;color:#92400e;border-radius:12px;padding:16px;text-align:center;margin:6px 0 18px}

/* steps (waiting page) */
.steps3{display:flex;gap:10px;margin:18px 0 8px}
.steps3 .s{flex:1;text-align:center;font-size:12px;color:var(--muted);padding:10px 6px;border-radius:10px;background:#f1f5f9}
.steps3 .s.done{background:#d1fae5;color:#065f46;font-weight:700}
.steps3 .s.now{background:var(--brand);color:#fff;font-weight:700}

/* spinner + big check/cross */
.spin{width:44px;height:44px;border:4px solid #fde68a;border-top-color:var(--brand2);border-radius:50%;animation:spin 1s linear infinite;margin:18px auto}
@keyframes spin{to{transform:rotate(360deg)}}
.bigicon{width:64px;height:64px;border-radius:50%;display:grid;place-items:center;margin:4px auto 14px;font-size:30px}
.bigicon.ok{background:#d1fae5;color:var(--ok)}
.bigicon.err{background:#fee2e2;color:var(--err)}
.bigicon.warn{background:#fef3c7;color:#92400e}
.center{text-align:center}
.count{font-variant-numeric:tabular-nums}
.toast{position:fixed;right:20px;bottom:20px;background:#0f172a;color:#fff;padding:12px 18px;border-radius:10px;font-size:14px;opacity:0;pointer-events:none;transition:opacity .3s;z-index:99}
.toast.show{opacity:1}
details{margin-top:6px}
summary{cursor:pointer;color:var(--muted);font-size:13px}
details[open] summary{margin-bottom:8px}

/* language switch (ทุกหน้า) */
.langsw{display:flex;gap:6px;align-items:center;font-size:12.5px}
.langsw .langcur{color:var(--deep);font-weight:700;padding:4px 8px;border-radius:6px;background:#f1f5f9}
.langsw a{color:#7c2d12;text-decoration:none;padding:4px 8px;border-radius:6px;border:1px solid #e7d8c4}
.langsw a:hover{color:#fff;background:var(--brand2);border-color:var(--brand2)}
/* ปุ่มสลับภาษาบนแผง brand (พื้นหลังเข้ม) ของหน้า login */
.brand{position:relative}
.brand .langsw{position:absolute;top:18px;right:22px}
.brand .langsw .langcur{background:rgba(255,255,255,.14);color:#fff}
.brand .langsw a{color:#fde68a;border-color:rgba(255,255,255,.35)}
.brand .langsw a:hover{color:#1c1917;background:#fbbf24;border-color:#fbbf24}
`

// ToastScript — ฟังก์ชันแสดง toast (ต้องมี <div class="toast" id="toast"> ในหน้า)
const ToastScript = `function showToast(msg, ok) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3200);
}`

// brandPanel — แผงซ้ายของหน้า login (เฉพาะ layout แบบ split)
func brandPanel(lang string) string {
	return `<aside class="brand">
<div class="langsw">` + LangSwitchHTML(lang) + `</div>
<div class="mark"><div class="logo">S</div><div class="name">Seller App</div></div>
<div>
<p class="pitch">` + T(lang, "ระบบจัดการร้านค้า<br>สำหรับผู้ขายออนไลน์", "Store management<br>for online sellers") + `</p>
<p class="pitchsub">` + T(lang, "เข้าสู่ระบบด้วยบัญชี ID กลางของ Central — ยืนยันผ่านอุปกรณ์ของคุณ<br>โดยไม่ต้องพิมพ์รหัสผ่านในแอปนี้", "Sign in with your Central ID account — approve on your own device<br>without typing a password in this app") + `</p>
<ol class="flow">
<li><span class="n">1</span><span>` + T(lang, "<b>กรอกชื่อผู้ใช้</b> แล้วส่งคำขอเข้าสู่ระบบ", "<b>Enter your username</b> and send the sign-in request") + `</span></li>
<li><span class="n">2</span><span>` + T(lang, "<b>ยืนยันที่อุปกรณ์ ID</b> — กดยืนยันคำขอที่แสดงบนอุปกรณ์ของคุณ", "<b>Approve on the ID device</b> — confirm the request shown on your device") + `</span></li>
<li><span class="n">3</span><span>` + T(lang, "<b>เข้าใช้งานทันที</b> — ระบบได้รับ token ที่ออกโดย ID กลาง", "<b>Start using the app</b> — it receives a token issued by the central ID") + `</span></li>
</ol>
</div>
<span class="badge">🔐 Headless Login — CIBA (OIDC Backchannel)</span>
</aside>`
}

// PageLogin — layout แบบ split สำหรับหน้าแรก (brand panel + ฟอร์มด้านขวา)
func PageLogin(title, body, lang string) string {
	return `<!doctype html><html lang="` + lang + `"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>` + Esc(title) + `</title>
<style>` + CSS + `</style>
<div class="split">
` + brandPanel(lang) + `
<div class="right"><div class="loginbox">` + body + `</div></div>
</div>`
}

// PageApp — layout สำหรับหน้าภายใน (navbar + container)
func PageApp(title, body, lang string) string {
	return `<!doctype html><html lang="` + lang + `"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>` + Esc(title) + `</title>
<style>` + CSS + `</style>
<header class="nav"><div class="logo">S</div><div class="name">Seller App</div>
<span class="tag">HEADLESS · CIBA</span><div class="sp"></div>
<nav style="display:flex;gap:4px">
<a href="http://localhost:3000" style="text-decoration:none;padding:6px 10px;border-radius:8px;font-size:13px;color:var(--muted)" title="ID Portal">ID ↗</a>
<a href="http://localhost:3010" style="text-decoration:none;padding:6px 10px;border-radius:8px;font-size:13px;color:var(--muted)" title="Buyer Portal">Buyer ↗</a>
<a href="http://localhost:3020" style="text-decoration:none;padding:6px 10px;border-radius:8px;font-size:13px;color:var(--muted)" title="CIS Portal">CIS ↗</a>
<a href="http://localhost:3050" style="text-decoration:none;padding:6px 10px;border-radius:8px;font-size:13px;color:var(--muted)" title="Fintech App">Fintech ↗</a>
</nav><div class="sp"></div>
<span class="userchip" style="font-size:13px;color:var(--muted)">` + T(lang, "บัญชีกลาง: <b>ID</b> (Keycloak เบื้องหลัง)", "Central account: <b>ID</b> (Keycloak behind)") + `</span>
<div class="langsw">` + LangSwitchHTML(lang) + `</div></header>
<main class="container">` + body + `</main>
<div class="toast" id="toast"></div>
<script>` + ToastScript + `</script>`
}
