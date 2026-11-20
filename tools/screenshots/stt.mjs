// Playwright — ถ่ายภาพการโอน session ข้ามแอป (STT v2): Fintech → CIS ผ่าน one-time code + Token Exchange
// 25 fintech home การ์ดโอน session · 26 หน้ารับของ CIS (โอน session สำเร็จ) · 27 CIS home หลังรับ
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.resolve(__dirname, '../../docs/screenshots');
const FT = 'http://localhost:3050';

const run = async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch({ channel: 'msedge' });
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 860 }, locale: 'en-US', deviceScaleFactor: 1.5 });
  // โหมด English สำหรับภาพทั้งชุด (cookie lang แชร์ทุกแอปบน host เดียวกัน)
  await ctx.addCookies([{ name: 'lang', value: 'en', domain: 'localhost', path: '/' }]);

  const page = await ctx.newPage();
  const shot = (name) => page.screenshot({ path: path.join(OUT, `${name}.png`) });

  // login ที่ fintech (Embedded Login — ฟอร์มของแอปเอง)
  await page.goto(FT);
  await page.fill('input[name="username"]', 'buyer-user');
  await page.fill('input[name="password"]', process.env.TEST_USER_PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL('**/home', { timeout: 15000 });
  await page.waitForTimeout(600);
  await shot('25-fintech-home-transfer');

  // กดปุ่มโอน session ไป CIS — backend สร้าง one-time code แล้วพาไปจุดรับของ CIS
  await page.click('a[href="/stt/transfer?to=cis"]');
  await page.waitForURL('**/auth/stt**', { timeout: 15000 });
  await page.waitForLoadState('domcontentloaded');
  await page.waitForTimeout(800);
  await shot('26-cis-stt-arrival');

  // หน้า success redirect เข้า CIS home อัตโนมัติ (meta refresh)
  await page.waitForURL(FT_home(), { timeout: 10000 }).catch(() => {});
  await page.goto('http://localhost:3020/');
  await page.waitForLoadState('domcontentloaded');
  await page.waitForTimeout(600);
  await shot('27-cis-home-after-stt');

  await browser.close();
  console.log('บันทึกภาพ STT 3 ภาพ: 25/26/27');
};
const FT_home = () => 'http://localhost:3020/';

run().catch(async (e) => {
  console.error('FAILED:', e.message);
  try { await page.screenshot({ path: path.join(OUT, '99-stt-failed.png') }); console.error('URL:', page.url()); } catch {}
  process.exit(1);
});
