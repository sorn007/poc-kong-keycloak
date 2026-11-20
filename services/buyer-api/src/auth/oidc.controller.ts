import { Controller, Get, Query, Req, Res } from '@nestjs/common';
import * as crypto from 'crypto';
import type { Request, Response } from 'express';
import { config, tokenUrl } from '../config';
import { langOf, t, type Lang } from '../i18n';

interface PkceState {
  verifier: string;
  nonce: string;
}

// OIDC Authorization Code + PKCE (S256) — flow มาตรฐานที่ Buyer ต้องใช้กับ ID
// state/verifier เก็บ in-memory เท่านั้น (POC) — production ใช้ session store จริง
@Controller('auth')
export class OidcController {
  private readonly states = new Map<string, PkceState>();

  @Get('login')
  async login(@Req() req: Request, @Res() res: Response) {
    // SSO Ticket — ถ้า browser มีตั๋วของ ID กลาง (central_sso) ให้ redeem แทนการ login
    // (ตั๋วถูก set โดยแอปต้นทาง เช่น Fintech — cookie ของ host localhost จึงมาถึงที่นี่ได้)
    if (req.cookies?.['central_sso'] && !req.cookies?.['sso_try_buyer']) {
      const st = await this.trySSO(req, res);
      if (st === 'ok') {
        // ผูก session กับตั๋ว — ใช้ตรวจ liveness (logout กลาง propagate ผ่านตั๋ว)
        res.cookie('sso_bound', req.cookies['central_sso'], { httpOnly: true, sameSite: 'lax' });
        // marker กันวน loop: / → /auth/login → / (token ไม่ผ่าน → วนซ้ำ)
        res.cookie('sso_try_buyer', '1', { httpOnly: true, sameSite: 'lax', maxAge: 30000 });
        return res.redirect('/');
      }
      if (st === 'dead') {
        // ตั๋วตาย (revoke/logout-all/หมดอายุ) — อย่าพาไป Keycloak:
        // เคลียร์ cookie ตั๋วแล้วกลับ "หน้า landing ของแอปเรา" ให้ผู้ใช้กด login เอง
        res.clearCookie('central_sso');
        res.clearCookie('sso_bound');
        res.clearCookie('sso_try_buyer');
        return res.redirect('/');
      }
      // 'error' (broker ล่มชั่วคราว) → เดิน Authorization Code flow ปกติต่อได้
    }
    const state = crypto.randomBytes(12).toString('hex');
    const verifier = crypto.randomBytes(32).toString('base64url');
    const nonce = crypto.randomBytes(12).toString('base64url');
    const challenge = crypto
      .createHash('sha256')
      .update(verifier)
      .digest('base64url');

    this.states.set(state, { verifier, nonce });

    const url = new URL(
      `${config.keycloakIssuer}/protocol/openid-connect/auth`,
    );
    url.searchParams.set('client_id', config.clientId);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid orders.read orders.write');
    url.searchParams.set('redirect_uri', `${config.appFrontUrl}/auth/callback`);
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');

    res.redirect(url.toString());
  }

  @Get('callback')
  async callback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const st = this.states.get(state ?? '');
    if (!st || !code) {
      return res.status(400).json({ error: 'unknown_state_or_code' });
    }
    this.states.delete(state);

    try {
      const r = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: config.clientId,
          code,
          redirect_uri: `${config.appFrontUrl}/auth/callback`,
          code_verifier: st.verifier,
        }),
      });
      if (!r.ok) {
        // POC: แสดง error จาก IdP ให้อ่านง่าย (production ต้องซ่อนและ log)
        return res.status(502).type('text/plain').send(await r.text());
      }
      const tok = (await r.json()) as {
        access_token: string;
        id_token: string;
      };

      // POC: token อยู่ใน cookie HttpOnly เพื่อให้ demo ด้วย browser ได้ง่าย
      // production ควรใช้ BFF/session cookie และไม่ expose token ดิบไปยังฝั่ง browser
      res.cookie('buyer_session', tok.access_token, {
        httpOnly: true,
        sameSite: 'lax',
      });
      res.cookie('buyer_id_token', tok.id_token, {
        httpOnly: true,
        sameSite: 'lax',
      });

      const payload = JSON.parse(
        Buffer.from(tok.access_token.split('.')[1], 'base64url').toString(),
      );
      // หน้า callback render ตาม cookie "lang" (มาจากหน้าอื่นที่รับ ?lang ไว้แล้ว)
      res.type('html').send(callbackHtml(payload, tok, langOf(req)));
    } catch (e) {
      res
        .status(502)
        .type('text/plain')
        .send(`token exchange failed: ${(e as Error).message}`);
    }
  }

  // isTicketAlive — ตรวจกับ ID กลางว่า session ที่ผูกกับตั๋วยังมีชีวิต (logout กลาง propagate)
  private async isTicketAlive(ticket: string): Promise<boolean> {
    if (!ticket) return true; // session ไม่ได้ผูกตั๋ว → ไม่ตรวจ (JWT มีชีวิตถึง exp ตามข้อจำกัด)
    const broker =
      process.env.IDPORTAL_INTERNAL_BASE ?? 'http://central-id:3000';
    try {
      const r = await fetch(`${broker}/sso/check`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ ticket }),
        signal: AbortSignal.timeout(5000),
      });
      if (!r.ok) return true; // ตรวจไม่ได้ → fail-open (production ตั้งนโยบายเอง)
      const out = (await r.json()) as { alive?: boolean };
      return out.alive !== false;
    } catch {
      return true;
    }
  }

  // logoutAllSSO — ขอ ID กลางยกเลิก "ทุก" ตั๋ว (logout กลางแบบ global) — best-effort
  private logoutAllSSO(accessToken: string): void {
    const broker =
      process.env.IDPORTAL_INTERNAL_BASE ?? 'http://central-id:3000';
    void fetch(`${broker}/sso/logout`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        Authorization: `Bearer ${accessToken}`,
      },
      signal: AbortSignal.timeout(5000),
    }).catch(() => {});
  }

  // trySSO — redeem ตั๋ว SSO กับ ID Portal แล้วสร้าง session (ถ้า aud ตรงกับ audience ของเรา)
  // คืนสถานะ: 'ok' (ได้ session) | 'dead' (ตั๋วตายชัดเจน — เคลียร์แล้วกลับ landing) | 'error' (เดิน AC flow ต่อ)
  private async trySSO(req: Request, res: Response): Promise<'ok' | 'dead' | 'error'> {
    const broker =
      process.env.IDPORTAL_INTERNAL_BASE ?? 'http://central-id:3000';
    try {
      const r = await fetch(`${broker}/sso/redeem`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          ticket: req.cookies['central_sso'],
          dest: config.clientId,
        }),
        signal: AbortSignal.timeout(8000),
      });
      if (!r.ok) return 'dead'; // broker ปฏิเสธชัดเจน (404 ตั๋วไม่มี/หมดอายุ)
      const out = (await r.json()) as {
        username?: string;
        access_token?: string;
        aud?: string[];
      };
      // ตรวจ aud เสมอ (Security Rule 1) — ตั๋วมาจาก token ของ client ใดก็ได้
      if (!(out.aud ?? []).includes(config.audience)) return 'dead';
      res.cookie('buyer_session', out.access_token, {
        httpOnly: true,
        sameSite: 'lax',
      });
      return 'ok';
    } catch {
      return 'error'; // ติดต่อ broker ไม่ได้ — fail-open ไป AC flow ปกติ
    }
  }

  @Get('logout')
  logout(@Req() req: Request, @Res() res: Response) {
    const idToken = req.cookies?.['buyer_id_token'];
    // logout กลาง — ขอ ID กลางยกเลิก "ทุก" ตั๋ว SSO (แอปอื่นจะตายตามใน request ถัดไป) — best-effort
    if (req.cookies?.['buyer_session']) {
      this.logoutAllSSO(req.cookies['buyer_session']);
    }
    res.clearCookie('buyer_session');
    res.clearCookie('buyer_id_token');
    res.clearCookie('central_sso');
    res.clearCookie('sso_try_buyer');
    res.clearCookie('sso_bound');

    // Global logout — ยุติ SSO session ที่ Keycloak (กระทบทุกระบบ)
    // client_id + post_logout_redirect_uri ลงทะเบียนไว้ทำให้ KC ยุติ session ทันทีไม่ขึ้นหน้า confirm
    const url = new URL(
      `${config.keycloakIssuer}/protocol/openid-connect/logout`,
    );
    url.searchParams.set('client_id', config.clientId);
    if (idToken) url.searchParams.set('id_token_hint', idToken);
    url.searchParams.set('post_logout_redirect_uri', config.appFrontUrl);
    res.redirect(url.toString());
  }
}

function esc(s: unknown): string {
  return String(s ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

function callbackHtml(
  payload: Record<string, unknown>,
  tok: object,
  lang: Lang,
): string {
  const claims = Object.entries(payload)
    .map(
      ([k, v]) =>
        `<tr><td>${esc(k)}</td><td><code>${esc(
          typeof v === 'object' ? JSON.stringify(v) : v,
        )}</code></td></tr>`,
    )
    .join('');
  return `<!doctype html><html lang="${lang}"><meta charset="utf-8">
<meta http-equiv="refresh" content="1.5;url=/">
<title>${t(lang, 'Buyer — Login สำเร็จ', 'Buyer — Signed in')}</title><style>
:root{--brand:#4f46e5}
body{margin:0;font-family:'Segoe UI',system-ui,'Noto Sans Thai',sans-serif;background:linear-gradient(160deg,#1e1b4b,#4f46e5 70%,#0ea5e9);min-height:100vh;display:grid;place-items:center;color:#fff}
.box{background:#ffffff12;border:1px solid #ffffff22;border-radius:16px;padding:34px 40px;max-width:640px;backdrop-filter:blur(6px)}
h1{margin:0 0 8px;font-size:24px}
p{color:#c7d2fe;font-size:14px;margin:6px 0}
code{background:#ffffff1a;padding:1px 6px;border-radius:6px;font-size:12px}
details{margin-top:14px}summary{cursor:pointer;color:#a5b4fc;font-size:13px}
pre{white-space:pre-wrap;font-size:10px;color:#e0e7ff}
table{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:10px}
td{padding:4px 6px;border-bottom:1px solid #ffffff1a;color:#e0e7ff}
.spin{display:inline-block;width:14px;height:14px;border:2px solid #ffffff44;border-top-color:#fff;border-radius:50%;animation:r 1s linear infinite;vertical-align:-2px;margin-right:8px}
@keyframes r{to{transform:rotate(360deg)}}
a{color:#fff}
</style>
<div class="box">
  <h1><span class="spin"></span>${t(lang, 'ล็อกอินผ่าน ID สำเร็จ', 'Signed in via ID successfully')}</h1>
  <p>${t(lang, 'กำลังพาเข้า Buyer Portal…', 'Taking you to Buyer Portal…')} (<a href="/">${t(lang, 'เข้าเองตอนนี้', 'go now')}</a>)</p>
  <p>${t(lang, 'ขั้นถัดไปของ flow: เปิด', 'Next step of the flow: open')} <a href="http://localhost:3020"><b>CIS Portal</b></a> — ${t(lang, 'ต้องล็อกอินให้อัตโนมัติ (SSO) โดยไม่ถามรหัสผ่าน', 'it must sign you in automatically (SSO) without asking for a password')}</p>
  <details><summary>Access token claims (${t(lang, 'POC — token เก็บใน cookie HttpOnly', 'POC — token stored in an HttpOnly cookie')})</summary>
  <table>${claims}</table>
  <pre>${esc(JSON.stringify(tok, null, 2))}</pre></details>
</div>`;
}
