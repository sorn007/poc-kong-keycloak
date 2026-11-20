// i18n แบบ lightweight — สลับ EN/ไทย ได้ทุกหน้า (รูปแบบเดียวกับ central-id internal/web/i18n.go)
// • ลำดับความสำคัญ: ?lang=xx (แล้วจำลง cookie) → cookie "lang" → ค่าเริ่มต้น "th"
// • cookie "lang" เป็นของ host localhost — browser ส่งให้ทุก port จึงสลับทีเดียวได้ทุกแอป
// • การแปลใช้ helper t(lang, ข้อความไทย, ข้อความอังกฤษ) — คู่กันอยู่ในบรรทัดเดียว ดูแลง่าย
import type { Request, Response } from 'express';

export type Lang = 'th' | 'en';

// MaxAge 1 ปี (express ใช้หน่วย millisecond)
const LANG_COOKIE_MAXAGE_MS = 31536000 * 1000;

/** langOf — อ่านภาษาของ request (?lang= มาก่อน แล้วจำลง cookie — ส่ง res เมื่อต้องการ set cookie) */
export function langOf(req: Request, res?: Response): Lang {
  const q = req.query?.lang;
  if (q === 'en' || q === 'th') {
    res?.cookie('lang', q, { path: '/', maxAge: LANG_COOKIE_MAXAGE_MS });
    return q;
  }
  const ck = req.cookies?.['lang'];
  if (ck === 'en' || ck === 'th') return ck;
  return 'th';
}

/** t — เลือกข้อความตามภาษา */
export function t(lang: Lang, th: string, en: string): string {
  return lang === 'en' ? en : th;
}

/** langSwitch — ปุ่มสลับภาษา (ลิงก์ไป path เดิม + ?lang=<อีกภาษา> — ครอบด้วย div.langsw ที่ nav) */
export function langSwitch(lang: Lang): string {
  const [cur, other, label] =
    lang === 'en' ? ['EN', 'th', 'ไทย'] : ['TH', 'en', 'EN'];
  return `<span class="langcur">${cur}</span><a href="?lang=${other}" title="switch language">${label}</a>`;
}
