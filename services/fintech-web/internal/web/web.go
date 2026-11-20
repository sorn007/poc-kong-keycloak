// Package web — โครงหน้าจอ + ดีไซน์ของ Fintech App (POC — Embedded Login demo)
// ธีม navy/deep-blue + cyan accent — หน้าตาแบบ fintech production
// (แยกออกจาก Seller สี amber และ ID Portal สี green ให้เห็นชัดว่าเป็นคนละแอป)
package web

import (
	"fmt"
	"html"
)

// Esc — escape HTML สำหรับค่าที่มาจาก token/user (กัน XSS จาก claim)
func Esc(s interface{}) string { return html.EscapeString(fmt.Sprint(s)) }

// CSS — ธีม fintech: navy/deep-blue + cyan — มีทั้งหน้า login เต็มจอ (auth), topbar หน้า home,
// spinner, toast และ error box ของฟอร์ม
const CSS = `
:root{--navy:#0a1f3c;--navy2:#12365e;--deep:#071527;--cyan:#22d3ee;--cyan2:#0891b2;--bg:#f2f6fa;--ink:#0f172a;--muted:#5b7089;--card:#fff;--line:#dce7f2}
*{box-sizing:border-box}
body{margin:0;font-family:'Segoe UI',system-ui,'Noto Sans Thai','Sarabun',sans-serif;background:var(--bg);color:var(--ink)}

/* ---- topbar (หน้า home) ---- */
.topbar{background:linear-gradient(90deg,#071527,#0a1f3c 55%,#12365e);color:#fff;padding:0 24px;height:60px;display:flex;align-items:center;gap:14px;position:sticky;top:0;z-index:10}
.brand{display:flex;gap:10px;align-items:center;font-weight:800;font-size:16.5px;color:#fff;text-decoration:none}
.logo{width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,#22d3ee,#0891b2);display:grid;place-items:center;font-weight:900;color:#062a33;font-size:15px;flex:none}
.bbadge{font-size:10px;letter-spacing:.12em;padding:3px 9px;border-radius:999px;background:#22d3ee22;border:1px solid #22d3ee55;color:#a5f3fc;font-weight:700;white-space:nowrap}
.topbar .spacer{flex:1}
.topbar .appnav{display:flex;gap:4px}
.topbar .appnav a{color:#bae6fd;text-decoration:none;padding:6px 11px;border-radius:8px;font-size:13.5px}
.topbar .appnav a:hover{background:#ffffff1a;color:#fff}
.topbar .user{font-size:13px;color:#bae6fd}
.btnout{background:transparent;border:1px solid #22d3ee66;color:#a5f3fc;padding:6px 13px;border-radius:8px;cursor:pointer;font-size:13px;text-decoration:none}
.btnout:hover{background:#22d3ee1a}

/* ---- หน้า login (full-bleed บนพื้นเข้ม) ---- */
.auth{min-height:100vh;display:grid;place-items:center;padding:34px 16px;background:radial-gradient(1100px 600px at 15% 0%,#12365e 0%,#0a1f3c 45%,#071527 100%);position:relative}
.auth-card{width:100%;max-width:430px;background:#fff;border-radius:18px;padding:30px 30px 24px;box-shadow:0 24px 60px #00000059}
.brandrow{display:flex;gap:12px;align-items:center;margin-bottom:20px}
.brandrow .logo{width:40px;height:40px;border-radius:11px;font-size:20px}
.bname{font-weight:800;font-size:17px;line-height:1.2}
.brandrow .bbadge{margin-top:4px;display:inline-block}
.atitle{margin:0 0 4px;font-size:23px}
.asub{color:var(--muted);font-size:13.5px;margin:0 0 16px}
.loginform{display:flex;flex-direction:column;gap:6px}
.loginform label{font-size:12.5px;font-weight:700;color:#33465e;margin-top:8px}
.loginform input{width:100%;padding:11px 13px;border:1.5px solid var(--line);border-radius:10px;font-size:14.5px;background:#f8fbfe;outline:none;transition:border .15s,box-shadow .15s}
.loginform input:focus{border-color:var(--cyan2);box-shadow:0 0 0 3px #0891b226;background:#fff}
.btn-cta{margin-top:16px;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:10px;width:100%;padding:13px;border-radius:10px;font-size:15px;font-weight:800;color:#fff;background:linear-gradient(90deg,#0891b2,#0e7490);box-shadow:0 6px 16px #0891b24d}
.btn-cta:hover{filter:brightness(1.07)}
.btn-ghost{display:inline-block;text-decoration:none;color:#0e7490;background:#ecfeff;border:1.5px solid #a5f3fc;padding:9px 16px;border-radius:9px;font-size:13.5px;font-weight:700;cursor:pointer}
.btn-ghost:hover{background:#cffafe}
.spin{width:15px;height:15px;border:2.5px solid #ffffff55;border-top-color:#fff;border-radius:50%;display:none;animation:spin .7s linear infinite}
.btn-cta.loading .spin{display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}

/* ---- error box ของฟอร์ม ---- */
.ebox{border-radius:10px;padding:11px 14px;font-size:13.5px;margin:2px 0 6px}
.ebox.error{background:#fef2f2;border:1px solid #fecaca;color:#b91c1c}
.ebox.warn{background:#fffbeb;border:1px solid #fde68a;color:#92400e}
.attempts{font-size:12.5px;color:#92400e;margin:-2px 0 6px;font-weight:700}

/* ---- กล่องอธิบาย exception pattern ---- */
.except{margin-top:18px;border-top:1px dashed var(--line);padding-top:14px;font-size:12.5px;color:#41566e;line-height:1.75}
.exceptwarn{margin-top:8px;background:#fff7ed;border:1px solid #fed7aa;color:#9a3412;border-radius:9px;padding:9px 12px;line-height:1.7}

/* ---- การ์ด locked / error (กลางจอ) ---- */
.auth-card.center{text-align:center;max-width:400px}
.bigicon{font-size:38px;margin-bottom:6px}
.lockbar{height:7px;background:#e2eef8;border-radius:999px;overflow:hidden;margin:16px 0 18px}
.lockfill{height:100%;background:linear-gradient(90deg,#0891b2,#22d3ee);border-radius:999px;transition:width 1s linear}

/* ---- หน้า home ---- */
.wrap{max-width:940px;margin:26px auto 44px;padding:0 20px}
.hero{position:relative;text-align:center;padding:44px 24px;background:linear-gradient(160deg,#071527,#0a1f3c 55%,#12365e);border-radius:16px;color:#fff;margin-bottom:18px;box-shadow:0 16px 40px #0a1f3c40}
.herok{width:52px;height:52px;margin:0 auto 12px;border-radius:50%;background:var(--cyan);display:grid;place-items:center;font-size:26px;font-weight:900;color:#062a33}
.hero h1{margin:0 0 8px;font-size:27px}
.hero p{color:#bae6fd;font-size:14.5px;margin:0}
.secnote{display:inline-block;margin-top:16px;background:#22d3ee1f;border:1px solid #22d3ee55;color:#a5f3fc;font-size:13px;padding:8px 16px;border-radius:999px}
.card{background:var(--card);border-radius:14px;padding:20px 22px;box-shadow:0 1px 3px #0001;margin-bottom:18px}
.card h2{margin:0 0 6px;font-size:17px}
.card .sub{color:var(--muted);font-size:13.5px;margin:0 0 14px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px}
td,th{padding:9px 10px;border-bottom:1px solid #eef4fa;vertical-align:top}
tr:last-child td{border-bottom:none}
code,kbd{background:#f1f5f9;padding:1px 7px;border-radius:6px;font-size:12.5px;font-family:Consolas,monospace}
.pill{display:inline-block;padding:3px 12px;border-radius:999px;font-size:12.5px;font-weight:700;background:#e0f2fe;color:#0c4a6e;margin:2px 4px 2px 0}
.pill.ok{background:#d1fae5;color:#065f46}
.pill.fail{background:#fee2e2;color:#b91c1c}
.proof{display:flex;align-items:center;justify-content:space-between;gap:14px;border-radius:12px;padding:14px 16px;font-size:14px}
.proof.ok{background:#ecfdf5;border:1px solid #a7f3d0;color:#065f46}
.proof.fail{background:#fef2f2;border:1px solid #fecaca;color:#b91c1c}
.count{font-variant-numeric:tabular-nums}

/* ---- toast ---- */
.toast{position:fixed;left:50%;bottom:26px;transform:translate(-50%,18px);background:#0a1f3c;color:#fff;padding:11px 20px;border-radius:12px;font-size:13.5px;box-shadow:0 10px 26px #0006;opacity:0;pointer-events:none;transition:all .25s;z-index:50;max-width:88vw}
.toast.show{opacity:1;transform:translate(-50%,0)}
.toast.warn{background:#92400e}

/* ---- ปุ่มสลับภาษา EN/ไทย (บนพื้นเข้ม — ทั้งหน้า login และ topbar หน้า home) ---- */
.langsw{display:flex;gap:6px;align-items:center;font-size:12.5px}
.langsw .langcur{color:#fff;font-weight:700;padding:4px 8px;border-radius:6px}
.langsw a{color:#a5f3fc;text-decoration:none;padding:4px 8px;border-radius:6px;border:1px solid #22d3ee55}
.langsw a:hover{color:#fff;background:#22d3ee1a}
.langtop{position:absolute;top:16px;right:20px;z-index:5}
`

// Topbar — แถบบนของหน้า home (brand + ลิงก์แอปอื่น + ผู้ใช้ + ปุ่มสลับภาษา + ปุ่ม logout)
func Topbar(username, lang string) string {
	return `<header class="topbar">
<a class="brand" href="/home"><span class="logo">F</span>Fintech App <span class="bbadge">EMBEDDED LOGIN · DIRECT GRANT</span></a>
<nav class="appnav">
<a href="http://localhost:3000" title="` + T(lang, "ID — บัญชีกลาง", "ID — central account") + `">ID ↗</a>
<a href="http://localhost:3010" title="` + T(lang, "Buyer Portal", "Buyer Portal") + `">Buyer ↗</a>
<a href="http://localhost:3020" title="` + T(lang, "CIS Portal", "CIS Portal") + `">CIS ↗</a>
</nav>
<div class="spacer"></div>
<div class="user">` + Esc(username) + `</div>
<div class="langsw">` + LangSwitchHTML(lang) + `</div>
<a class="btnout" href="/logout">` + T(lang, "ออกจากระบบ", "Sign out") + `</a>
</header>`
}

// ToastScript — toast แจ้งผล (auto-run ถ้ามี <div id="toast-data" data-msg data-kind> บนหน้า)
const ToastScript = `<script>
(function(){
  var el=document.getElementById('toast');
  window.showToast=function(msg,kind){
    el.textContent=msg;el.className='toast show '+(kind||'');
    clearTimeout(window.__toastT);
    window.__toastT=setTimeout(function(){el.className='toast';},4500);
  };
  var d=document.getElementById('toast-data');
  if(d){window.showToast(d.getAttribute('data-msg')||'',d.getAttribute('data-kind')||'');}
})();
</script>`

// Page — ครอบทั้งหน้า (full-HTML) — ทุกหน้าของ Fintech App ผ่าน helper นี้
func Page(opt struct {
	Title string
	Body  string
	Lang  string
}) string {
	lang := opt.Lang
	if lang != "en" && lang != "th" {
		lang = "th"
	}
	return `<!doctype html><html lang="` + lang + `"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>` + Esc(opt.Title) + `</title>
<style>` + CSS + `</style></head>
<body>
` + opt.Body + `
<div class="toast" id="toast"></div>
` + ToastScript + `
</body></html>`
}
