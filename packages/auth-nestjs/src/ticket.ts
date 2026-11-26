/**
 * Ticket liveness — logout กลาง propagate: session ของแอป "ผูกกับตั๋ว SSO" (cookie sso_bound)
 * ทุกครั้งที่ render หน้า page ให้ถาม ID Portal ว่าตั๋วยังมีชีวิตไหม (POST /sso/check)
 * ตั๋วตาย (revoke / logout-all / หมดอายุ) = เคลียร์ session ของแอปทันที
 *
 * นโยบายเมื่อ "ตรวจไม่ได้" (broker ล่ม/timeout/ตอบไม่ผิด format): failOpen = true → ปล่อยผ่าน
 * (JWT exp ยังกำกับอยู่) — เลือกเพื่อ availability: ID Portal ล่มไม่ควรล็อกทุกแอป
 * ถ้าต้องการ fail-closed ตั้ง failOpen: false ตอนสร้าง — จุดตัดสินใจเดียวของทุก service
 * หมายเหตุ: API routes ไม่ได้ตรวจตั๋วทุก request (พึ่ง JWT exp สั้น ๆ) — ดู docs/SECURITY-AUDIT.md Q2
 */

export interface TicketGuardOptions {
  /** URL ภายใน network ของ ID Portal เช่น http://central-id:3000 */
  brokerUrl: string;
  /** timeout ต่อการตรวจ — default 5000 ms */
  timeoutMs?: number;
  /** true (default) = ตรวจไม่ได้ → ถือว่าตั๋วยังมีชีวิต */
  failOpen?: boolean;
}

export class TicketGuard {
  private readonly brokerUrl: string;
  private readonly timeoutMs: number;
  private readonly failOpen: boolean;

  constructor(options: TicketGuardOptions) {
    this.brokerUrl = options.brokerUrl.replace(/\/+$/, '');
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.failOpen = options.failOpen ?? true;
  }

  /** isAlive — ตั๋วยังมีชีวิตอยู่ไหม (ไม่ consume — ตั๋ว reusable) · ticket ว่าง = session ไม่ได้ผูกตั๋ว → true */
  async isAlive(ticket: string): Promise<boolean> {
    if (!ticket) return true;
    try {
      const r = await fetch(`${this.brokerUrl}/sso/check`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ ticket }),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (!r.ok) return this.failOpen;
      const out = (await r.json()) as { alive?: boolean };
      return out.alive !== false;
    } catch {
      return this.failOpen;
    }
  }
}

/** ชื่อ cookie ของระบบตั๋ว — ใช้ร่วมกันทุกแอปบน host เดียวกัน (cookie ไม่ผูก port — RFC 6265) */
export const SSO_COOKIE = 'central_sso';
export const SSO_BOUND_COOKIE = 'sso_bound';

/** sessionCookieNames — cookie ทั้งหมดที่ผูก session ของแอป `app` (เช่น 'buyer' → buyer_session, …) */
export function sessionCookieNames(app: string): string[] {
  return [
    `${app}_session`,
    `${app}_id_token`,
    SSO_BOUND_COOKIE,
    `sso_try_${app}`,
    SSO_COOKIE,
  ];
}

/**
 * clearSessionCookies — เคลียร์ session + cookie ที่ผูกกับตั๋ว (ใช้เมื่อตั๋วตาย)
 * ชุด cookie เดียวกันทุกจุดของแอป — ไม่ให้หน้าหนึ่งเคลียร์ครบแต่อีกหน้าค้าง id_token ไว้
 */
export function clearSessionCookies(
  res: { clearCookie(name: string): unknown },
  app: string,
): void {
  for (const name of sessionCookieNames(app)) res.clearCookie(name);
}
