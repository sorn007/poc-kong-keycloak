import { Controller, Get, Query, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { config } from '../config';
import { langOf, t, type Lang } from '../i18n';

// Session Transfer (STT) — จุดรับ one-time code จากแอปต้นทาง (จำลอง Native-to-Web SSO ของ Auth0)
// ต้นทาง (เช่น Fintech/Mobile) สร้าง code ที่ ID Portal (POST /stt/create, ผูก dest=buyer-web)
// แล้วพา browser มาที่นี่ — เรา redeem (server-to-server) ตรวจ aud ของตัวเอง แล้วสร้าง session ทันที
// โดยไม่มีรหัสผ่านเกี่ยวข้อง — code ใช้ครั้งเดียว อายุ 60 วินาที ผูกปลายทาง (dest)
//
// หมายเหตุความปลอดภัย: ต้องตรวจ `aud` ของ token ที่ redeem ได้เสมอ (Security Rule 1) —
// token ที่ไม่ได้ออกให้ใช้กับ buyer-api ต้องถูกปฏิเสธ แม้ signature ถูก
@Controller('auth')
export class SttController {
  private readonly sttBrokerBase =
    process.env.IDPORTAL_INTERNAL_BASE ?? 'http://central-id:3000';

  @Get('stt')
  async stt(
    @Query('code') code: string,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    if (!code) {
      return res.redirect('/');
    }
    const lang = langOf(req, res);

    // 1) redeem ที่ ID Portal — ประกาศ dest = client ของเรา (code ออกให้ปลายทางอื่นจะถูกปฏิเสธ)
    let redeem: {
      username?: string;
      access_token?: string;
      aud?: string[];
      error?: string;
    };
    try {
      const r = await fetch(`${this.sttBrokerBase}/stt/redeem`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ code, dest: config.clientId }),
      });
      redeem = await r.json();
      if (!r.ok) {
        return res
          .status(r.status)
          .type('html')
          .send(sttErrorHtml(r.status, redeem?.error ?? 'redeem_failed', lang));
      }
    } catch {
      return res
        .status(502)
        .type('html')
        .send(sttErrorHtml(502, 'stt_broker_unreachable', lang));
    }

    // 2) ตรวจ aud — token ต้องออกให้ใช้กับ buyer-api ของเรา (กัน Cross-Audience Transfer)
    if (!(redeem.aud ?? []).includes(config.audience)) {
      return res
        .status(403)
        .type('html')
        .send(sttErrorHtml(403, 'audience_mismatch', lang));
    }

    // 3) สร้าง session แบบเดียวกับ Authorization Code callback (cookie HttpOnly ถือ token)
    res.cookie('buyer_session', redeem.access_token, {
      httpOnly: true,
      sameSite: 'lax',
    });
    // ผูก session กับตั๋ว SSO ของ browser (ถ้ามี) — logout กลางจะ propagate ผ่านตั๋ว
    // (ตั๋วถูก set โดยแอปต้นทางเช่น fintech; cookie ของ host localhost จึงมาถึง request นี้ด้วย)
    if (req.cookies?.['central_sso']) {
      res.cookie('sso_bound', req.cookies['central_sso'], {
        httpOnly: true,
        sameSite: 'lax',
      });
    }
    // id_token ไม่มีใน STT redeem — logout ยังทำงานได้ (id_token_hint เป็น optional)
    return res.redirect('/');
  }
}

function sttErrorHtml(status: number, error: string, lang: Lang): string {
  const messages: Record<string, [string, string]> = {
    audience_mismatch: [
      'token ต้นทางไม่ได้ตั้ง audience ให้ buyer-api — โอน session ข้ามระบบที่ไม่เกี่ยวข้องจึงถูกปฏิเสธ (audience_mismatch)',
      'the source token does not set the audience for buyer-api — transferring a session across unrelated systems is therefore rejected (audience_mismatch)',
    ],
    destination_mismatch: [
      'code นี้ไม่ได้ออกให้ Buyer Portal (destination_mismatch)',
      'this code was not issued for Buyer Portal (destination_mismatch)',
    ],
    invalid_or_used_or_expired_code: [
      'code หมดอายุหรือถูกใช้ไปแล้ว (ใช้ได้ครั้งเดียว อายุ 60 วินาที)',
      'the code expired or was already used (single use, valid for 60 seconds)',
    ],
  };
  const [th, en] =
    messages[error] ?? [
      'โอน session ไม่สำเร็จ — กรุณาล็อกอินด้วย ID ตามปกติ',
      'Session transfer failed — please sign in with ID as usual',
    ];
  return `<!doctype html><html lang="${lang}"><meta charset="utf-8">
<title>${t(lang, 'Buyer — โอน session ไม่สำเร็จ', 'Buyer — Session transfer failed')}</title><style>
body{margin:0;font-family:'Segoe UI',system-ui,'Noto Sans Thai',sans-serif;background:linear-gradient(160deg,#1e1b4b,#4f46e5 70%,#0ea5e9);min-height:100vh;display:grid;place-items:center;color:#fff}
.box{background:#ffffff12;border:1px solid #ffffff22;border-radius:16px;padding:34px 40px;max-width:640px;backdrop-filter:blur(6px)}
h1{margin:0 0 8px;font-size:22px}p{color:#c7d2fe;font-size:14px;margin:6px 0}
code{background:#ffffff1a;padding:1px 6px;border-radius:6px;font-size:12px}
a{color:#fff}
</style>
<div class="box">
<h1>⚠️ ${t(lang, 'โอน session ไม่สำเร็จ', 'Session transfer failed')}</h1>
<p>${t(lang, th, en)}</p>
<p><code>${error}</code> (HTTP ${status})</p>
<p style="margin-top:14px"><a href="/auth/login">${t(lang, 'ล็อกอินด้วย ID ตามปกติ →', 'Sign in with ID as usual →')}</a></p>
</div>`;
}
