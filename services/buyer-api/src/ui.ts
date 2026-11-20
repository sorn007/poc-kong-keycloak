// Shared UI ของ Buyer Portal (POC) — server-rendered HTML + vanilla JS
// ออกแบบให้เป็นภาษาเดียวกับ CIS Portal เพื่อจำลอง flow จริงของ rootcase:
// [1] ล็อกอิน ID → [2] Buyer Portal → [3] CIS Portal (SSO) → [4] Logout กลาง
import type { Request } from 'express';
import * as jwt from 'jsonwebtoken';
import { t, langSwitch, type Lang } from './i18n';

export function esc(s: unknown): string {
  return String(s ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

export const CSS = `
:root{--brand:#4f46e5;--brand2:#0ea5e9;--bg:#f1f5f9;--ink:#0f172a;--muted:#64748b;--card:#fff;--ok:#059669;--warn:#b45309;--danger:#dc2626}
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
.hero{text-align:center;padding:60px 24px;background:linear-gradient(160deg,#1e1b4b,#4f46e5 70%,#0ea5e9);border-radius:16px;color:#fff;margin-bottom:18px}
.hero h1{margin:0 0 10px;font-size:30px}
.hero p{color:#c7d2fe;font-size:15px;margin:0 0 26px}
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
.pill.warn{background:#fef3c7;color:#92400e}
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
`;

/** Flow ตาม rootcase — แสดงเป็นแถบขั้นตอนทุกหน้า (current = ลำดับ 1-4, done = ทำแล้ว) */
export function steps(current: number, doneUntil: number, lang: Lang): string {
  const items = [
    [t(lang, 'ล็อกอิน ID', 'Sign in ID'), 'http://localhost:3000'],
    ['Buyer Portal', '/'],
    ['CIS Portal (SSO)', 'http://localhost:3020'],
    [t(lang, 'Logout กลาง', 'Global logout'), null],
  ] as const;
  const html = items.map(([label, href], i) => {
    const n = i + 1;
    const cls = n === current ? 'now' : n <= doneUntil ? 'done' : '';
    const inner = `${n}. ${label}`;
    return href
      ? `<a class="step ${cls}" style="text-decoration:none" href="${href}" title="${label}">${inner}</a>`
      : `<span class="step ${cls}">${inner}</span>`;
  });
  return `<div class="steps">${html.join('')}</div>`;
}

export interface Session {
  sub: string;
  username: string;
  email: string;
  clientId: string;
  principalType: string;
  tenantId: string;
  scopes: string[];
  exp: number;
  issuer: string;
  jti: string;
}

/** อ่าน session จาก cookie (decode เพื่อแสดงผล UI เท่านั้น — controller ต้อง verify ผ่าน JWKS ก่อนเชื่อถือ) */
export function readSession(req: Request): Session | null {
  const token = req.cookies?.['buyer_session'];
  if (!token) return null;
  try {
    const p = jwt.decode(token) as Record<string, unknown> | null;
    if (!p) return null;
    const scopes = String(p.scope ?? '').split(' ').filter(Boolean);
    return {
      sub: String(p.sub ?? ''),
      username: String(p.preferred_username ?? p.email ?? p.sub ?? ''),
      email: String(p.email ?? ''),
      clientId: String(p.azp ?? ''),
      principalType: String(p.principal_type ?? '?'),
      tenantId: String(p.tenant_id ?? '-'),
      scopes,
      exp: Number(p.exp ?? 0),
      issuer: String(p.iss ?? ''),
      jti: String(p.jti ?? ''),
    };
  } catch {
    return null;
  }
}

export function nav(
  app: 'Buyer Portal' | 'CIS Portal',
  page: 'home' | 'data',
  s: Session | null,
  otherAppUrl: string,
  otherAppLabel: string,
  lang: Lang,
): string {
  const links =
    app === 'Buyer Portal'
      ? `<a class="${page === 'home' ? 'active' : ''}" href="/">${t(lang, 'หน้าแรก', 'Home')}</a>
         <a class="${page === 'data' ? 'active' : ''}" href="/orders/page">Orders</a>
         <a href="http://localhost:3000" title="${t(lang, 'ID — บัญชีกลาง', 'ID — central account')}">ID ↗</a>
         <a href="${otherAppUrl}" title="${t(lang, 'ทดสอบ SSO — ต้องไม่ถามรหัสผ่าน', 'SSO test — must not ask for a password')}">${otherAppLabel} ↗</a>
         <a href="http://localhost:3050" title="${t(lang, 'Fintech App — Embedded Login demo', 'Fintech App — Embedded Login demo')}">Fintech ↗</a>`
      : `<a class="${page === 'home' ? 'active' : ''}" href="/">${t(lang, 'หน้าแรก', 'Home')}</a>
         <a class="${page === 'data' ? 'active' : ''}" href="/projects/page">Projects</a>
         <a href="http://localhost:3000" title="${t(lang, 'ID — บัญชีกลาง', 'ID — central account')}">ID ↗</a>
         <a href="${otherAppUrl}" title="${t(lang, 'ทดสอบ SSO — ต้องไม่ถามรหัสผ่าน', 'SSO test — must not ask for a password')}">${otherAppLabel} ↗</a>
         <a href="http://localhost:3050" title="${t(lang, 'Fintech App — Embedded Login demo', 'Fintech App — Embedded Login demo')}">Fintech ↗</a>`;
  const user = s
    ? `<div class="userchip"><span class="name">${esc(s.username)}</span>
       <span class="badge">${esc(s.principalType)}</span>
       <a class="btnlogout" href="/auth/logout">${t(lang, 'Logout กลาง', 'Global logout')}</a></div>`
    : `<div class="userchip"><span class="badge">${t(lang, 'ไม่ได้ล็อกอิน', 'Not signed in')}</span></div>`;
  return `<header class="topbar">
    <a class="brand" href="/"><span class="logo">A</span>${esc(app)}</a>
    <nav>${links}</nav>
    <div class="spacer"></div>
    ${user}
    <div class="langsw">${langSwitch(lang)}</div>
  </header>`;
}

export function page(opt: {
  title: string;
  body: string;
  activeStep: number;
  doneUntil: number;
  session: Session | null;
  appName: 'Buyer Portal' | 'CIS Portal';
  dataPage: string;
  otherAppUrl: string;
  otherAppLabel: string;
  lang: Lang;
}): string {
  const lang = opt.lang;
  return `<!doctype html><html lang="${lang}"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(opt.title)}</title>
<style>${CSS}</style>
${nav(opt.appName, opt.dataPage === '' ? 'home' : 'data', opt.session, opt.otherAppUrl, opt.otherAppLabel, lang)}
<main class="wrap">
${steps(opt.activeStep, opt.doneUntil, lang)}
${opt.body}
<p class="foot">${t(lang, 'POC Central Identity — token ตรวจสอบกลางที่ ID (Keycloak, JWKS RS256) · แอปนี้ verify', 'POC Central Identity — tokens verified centrally at ID (Keycloak, JWKS RS256) · this app verifies')} <code>iss</code>/<code>aud</code>/<code>exp</code>/<code>scope</code> ${t(lang, 'เองทุก request', 'itself on every request')}</p>
</main>
<div class="toast" id="toast"></div>`;
}

export function toastScript(): string {
  return `function toast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2600);}`;
}

export function sessionCards(s: Session, lang: Lang): string {
  const scopePills = s.scopes
    .map((x) => `<span class="pill ${x.includes('write') ? 'ok' : ''}">${esc(x)}</span>`)
    .join('');
  return `<div class="grid">
  <div class="card">
    <h2>${t(lang, 'ผู้ใช้ (จาก central token)', 'User (from central token)')}</h2>
    <p class="sub">${t(lang, 'อ่านจาก claims — ไม่ใช่ session ของแอปเอง', 'Read from claims — not an app-local session')}</p>
    <table>
      <tr><th>${t(lang, 'ผู้ใช้', 'User')}</th><td><b>${esc(s.username)}</b>${s.email ? ` <span class="sub">(${esc(s.email)})</span>` : ''}</td></tr>
      <tr><th>sub</th><td><code>${esc(s.sub.slice(0, 18))}…</code></td></tr>
      <tr><th>${t(lang, 'ประเภท principal', 'Principal type')}</th><td><span class="pill ${s.principalType === 'user' ? '' : 'svc'}">${esc(s.principalType)}</span></td></tr>
      <tr><th>tenant</th><td><code>${esc(s.tenantId)}</code></td></tr>
    </table>
  </div>
  <div class="card">
    <h2>Token / Session</h2>
    <p class="sub">${t(lang, 'ออกโดย ID — แอปตรวจ signature ผ่าน JWKS ทุกครั้ง', 'Issued by ID — the app verifies the signature via JWKS every time')}</p>
    <table>
      <tr><th>client (azp)</th><td><code>${esc(s.clientId)}</code></td></tr>
      <tr><th>scopes</th><td>${scopePills}</td></tr>
      <tr><th>${t(lang, 'หมดอายุ (exp)', 'Expires (exp)')}</th><td class="count" id="exp-countdown">…</td></tr>
      <tr><th>issuer</th><td><code style="font-size:11.5px">${esc(s.issuer)}</code></td></tr>
    </table>
  </div>
</div>
<script>
(() => {
  const exp = ${Math.round(s.exp)};
  const el = document.getElementById('exp-countdown');
  const expired = ${JSON.stringify(t(lang, 'หมดอายุแล้ว', 'Expired'))};
  const unit = ${JSON.stringify(t(lang, ' วินาที', 's'))};
  const tick = () => {
    const left = exp - Math.floor(Date.now()/1000);
    if (left <= 0) { el.textContent = expired; return; }
    const m = Math.floor(left/60), sec = left%60;
    el.textContent = left + unit + ' (' + m + ':' + String(sec).padStart(2,'0') + ')';
  };
  tick(); setInterval(tick, 1000);
})();
</script>`;
}
