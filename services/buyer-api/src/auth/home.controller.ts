import { Controller, Get, Header, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { verifyCentralToken } from './verify-central';
import { page, readSession, sessionCards, toastScript } from '../ui';
import { langOf, t } from '../i18n';

const broker =
  process.env.IDPORTAL_INTERNAL_BASE ?? 'http://central-id:3000';

// isTicketAlive — ตรวจกับ ID กลางว่า session ที่ผูกกับตั๋วยังมีชีวิต (logout กลาง propagate)
async function isTicketAlive(ticket: string): Promise<boolean> {
  if (!ticket) return true;
  try {
    const r = await fetch(`${broker}/sso/check`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ ticket }),
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) return true; // ตรวจไม่ได้ → fail-open
    const out = (await r.json()) as { alive?: boolean };
    return out.alive !== false;
  } catch {
    return true;
  }
}

// Buyer Portal — หน้าจอจำลองตาม flow rootcase:
// [1] ล็อกอิน ID (Keycloak login) → [2] Buyer Portal → [3] CIS Portal (SSO) → [4] Logout กลาง
@Controller()
export class HomeController {
  @Get()
  @Header('Content-Type', 'text/html; charset=utf-8')
  async home(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const lang = langOf(req, res);
    const raw = req.cookies?.['buyer_session'];

    // ยังไม่ login แต่ browser มีตั๋ว SSO ของ ID กลาง → พาไป /auth/login
    // (ตรงนั้นจะ redeem ตั๋วให้เงียบ ๆ แล้วพากลับมาที่นี่ — sso_try_buyer = กันวน loop)
    if (!raw && req.cookies?.['central_sso'] && !req.cookies?.['sso_try_buyer']) {
      return res.redirect('/auth/login');
    }

    // Logout กลาง propagate — session ผูกกับตั๋ว: ตั๋วตาย (revoke/logout-all ที่ไหนก็ได้)
    // → เคลียร์ session + cookie ตั๋ว แล้วกลับ "หน้า landing ของแอปเรา" (ไม่พาไปหน้า login ของ Keycloak เอง)
    if (raw && req.cookies?.['sso_bound']) {
      if (!(await isTicketAlive(req.cookies['sso_bound']))) {
        res.clearCookie('buyer_session');
        res.clearCookie('sso_bound');
        res.clearCookie('sso_try_buyer');
        res.clearCookie('central_sso');
        return res.redirect('/');
      }
    }

    // ยังไม่ login → hero + ปุ่มเข้าสู่ระบบผ่าน ID
    if (!raw) {
      const body = `<section class="hero">
  <h1>Central Buyer Portal</h1>
  <p>${t(lang, 'ระบบจัดซื้อของ Central (NestJS) — ล็อกอินผ่าน', "Central's procurement system (NestJS) — sign in once via")} <b>ID</b> ${t(lang, '(Central Identity) ครั้งเดียว', '(Central Identity)')}<br>
  ${t(lang, 'ใช้ได้ทั้ง Buyer และ CIS โดยไม่ต้องล็อกอินซ้ำ (SSO)', 'works across both Buyer and CIS without signing in again (SSO)')}</p>
  <a class="btn btn-primary" href="/auth/login">${t(lang, 'เข้าสู่ระบบด้วย ID', 'Sign in with ID')}</a>
  <p style="margin-top:18px;font-size:13px;color:#a5b4fc">${t(lang, 'จะพาไปหน้า login กลางของ ID (Authorization Code + PKCE)', 'Takes you to the ID central sign-in page (Authorization Code + PKCE)')}</p>
</section>
<div class="card"><h2>${t(lang, 'มีอะไรให้ทดลอง', 'What you can try')}</h2><p class="sub">${t(lang, 'ล็อกอินแล้วจะเห็น: โปรไฟล์จาก claims, Orders, ปุ่มสลับไป CIS (SSO) และ Logout กลาง', 'After signing in: profile from claims, Orders, a switch to CIS (SSO) and Global logout')}</p>
<ul style="font-size:14px;line-height:1.9">
<li><b>ID</b> = Keycloak realm <code>central</code> — ${t(lang, 'ผู้ออกและตรวจ session กลาง', 'issues and verifies the central session')}</li>
<li>${t(lang, 'Buyer ตรวจ token เองผ่าน JWKS:', 'Buyer verifies tokens itself via JWKS:')} <code>iss</code> + <code>aud=buyer-api</code> + <code>exp</code> + scope</li>
<li>${t(lang, 'เทียบกับระบบเดิม: แต่ละระบบออก token ของตัวเอง → session ไม่เกี่ยวข้องกัน (ดู rootcase.md)', 'Compared to the legacy way: each system minted its own token → unrelated sessions (see rootcase.md)')}</li>
</ul></div>`;
      return page({
        title: 'Central Buyer Portal',
        body,
        activeStep: 1,
        doneUntil: 0,
        session: null,
        appName: 'Buyer Portal',
        dataPage: '',
        otherAppUrl: 'http://localhost:3020',
        otherAppLabel: 'CIS Portal',
        lang,
      });
    }

    // มี cookie — verify ก่อนเชื่อถือ (signature/iss/aud/exp ผ่าน JWKS)
    try {
      await verifyCentralToken(raw);
    } catch {
      // token หมดอายุ/ไม่ถูกต้อง — ถ้า browser ยังมีตั๋ว SSO ให้ลอง redeem ใหม่ให้เงียบ ๆ
      // (ตั๋วยังอยู่ = broker renew token ใหม่ → กลับเข้าระบบได้เลย; ตั๋วตาย → กลับหน้า landing)
      if (req.cookies?.['central_sso'] && !req.cookies?.['sso_try_buyer']) {
        res.clearCookie('buyer_session');
        res.clearCookie('sso_bound');
        res.clearCookie('sso_try_buyer');
        return res.redirect('/auth/login');
      }
      const body = `<div class="notice warn"><b>${t(lang, 'Session หมดอายุหรือไม่ถูกต้อง', 'Session expired or invalid')}</b> — ${t(lang, 'token ในเครื่องไม่ผ่านการตรวจจาก JWKS ของ ID (อาจถูก logout กลางหรือ exp หมด)', 'the local token failed verification against the ID JWKS (globally logged out, or exp has passed)')}</div>
<div class="card"><h2>${t(lang, 'เริ่มใหม่', 'Start over')}</h2>
<div class="actions"><a class="btn btn-primary" href="/auth/login">${t(lang, 'ล็อกอินอีกครั้งด้วย ID', 'Sign in again with ID')}</a></div>
</div>`;
      return page({
        title: t(lang, 'Central Buyer Portal — Session หมดอายุ', 'Central Buyer Portal — Session expired'),
        body,
        activeStep: 1,
        doneUntil: 0,
        session: readSession(req),
        appName: 'Buyer Portal',
        dataPage: '',
        otherAppUrl: 'http://localhost:3020',
        otherAppLabel: 'CIS Portal',
        lang,
      });
    }

    const s = readSession(req)!;
    const body = `<div class="notice ok"><b>${t(lang, 'ล็อกอินผ่าน ID อยู่', 'Signed in via ID')}</b> — ${t(lang, 'session กลางนี้ใช้ได้ทั้ง Buyer และ CIS', 'this central session works across both Buyer and CIS')}</div>
${sessionCards(s, lang)}
<div class="card">
  <h2>${t(lang, 'ไปต่อใน flow', 'Continue the flow')}</h2>
  <p class="sub">${t(lang, 'เส้นทางทดสอบตาม rootcase — ล็อกอินครั้งเดียว ใช้ได้ทุกระบบ จนกว่าจะ logout กลาง', 'Test path per rootcase — sign in once, use every system, until a global logout')}</p>
  <div class="actions">
    <a class="btn btn-primary btn-sm" href="/orders/page">${t(lang, 'จัดการ Orders', 'Manage Orders')}</a>
    <a class="btn btn-ghost btn-sm" href="http://localhost:3000">${t(lang, 'ID — บัญชีกลาง', 'ID — central account')}</a>
    <a class="btn btn-ghost btn-sm" href="http://localhost:3020">${t(lang, 'เปิด CIS Portal (ทดสอบ SSO — ต้องไม่ถามรหัสผ่าน)', 'Open CIS Portal (SSO test — must not ask for a password)')}</a>
    <a class="btn btn-ghost btn-sm" href="/auth/logout">${t(lang, 'Logout กลาง (ทุกระบบ)', 'Global logout (all systems)')}</a>
  </div>
</div>
<script>${toastScript()}</script>`;
    return page({
      title: 'Central Buyer Portal',
      body,
      activeStep: 2,
      doneUntil: 2,
      session: s,
      appName: 'Buyer Portal',
      dataPage: '',
      otherAppUrl: 'http://localhost:3020',
      otherAppLabel: 'CIS Portal',
      lang,
    });
  }
}
