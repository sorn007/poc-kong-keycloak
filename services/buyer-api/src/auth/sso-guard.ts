import type { Request, Response } from 'express';

// SSO ticket guard helpers — ใช้ร่วมกันทุก controller ของ Buyer
// (logout กลาง propagate: session ผูกกับตั๋ว SSO — ตั๋วตาย → เคลียร์ session ทันที)

const broker =
  process.env.IDPORTAL_INTERNAL_BASE ?? 'http://central-id:3000';

// isTicketAlive — ตรวจกับ ID กลางว่า session ที่ผูกกับตั๋วยังมีชีวิต (logout กลาง propagate)
export async function isTicketAlive(ticket: string): Promise<boolean> {
  if (!ticket) return true; // ไม่ผูกตั๋ว → ไม่ตรวจ (JWT ยังมี exp กำกับเอง)
  try {
    const r = await fetch(`${broker}/sso/check`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ ticket }),
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) return true; // ตรวจไม่ได้ → fail-open
    const out = (await r.json()) as { alive?: boolean };
    console.log("[sso-guard] alive:", out.alive, "ticket:", ticket.slice(0, 12));
    return out.alive !== false;
  } catch {
    return true;
  }
}

// clearSsoCookies — เคลียร์ session + cookie ที่ผูกกับตั๋ว (ตอนตั๋วตาย)
export function clearSsoCookies(res: Response) {
  res.clearCookie('buyer_session');
  res.clearCookie('buyer_id_token');
  res.clearCookie('sso_bound');
  res.clearCookie('sso_try_buyer');
  res.clearCookie('allkons_sso');
}
