// Playwright — ถ่ายภาพ Fintech App (Embedded Login exception demo)
// 1 ฟอร์ม login ของแอปเอง (มีรหัสผ่าน — exception pattern) 2 home หลัง login + Buyer 200
// 3 lock state หลังยิงผิด 5 ครั้ง
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

  // [1] ฟอร์ม login ของแอปเอง (production look)
  await page.goto(FT);
  await page.waitForLoadState('domcontentloaded');
  await page.waitForTimeout(400);
  await shot('21-fintech-login-form');

  // [2] login ด้วยรหัสผ่านจริง (ผ่าน backend — Direct Grant)
  await page.fill('input[name="username"]', 'buyer-user');
  await page.fill('input[name="password"]', process.env.TEST_USER_PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL('**/home', { timeout: 15000 });
  await page.waitForTimeout(600);
  await shot('22-fintech-home-buyer-200');

  // [3] ยิงรหัสผ่านผิด 5 ครั้ง -> ล็อกชั่วคราว (แอป + KC brute force)
  // หลังครบ 5 ครั้ง แอปแสดง "locked card" (ไม่มีฟอร์ม) — นี่คือพฤติกรรมที่ถูกต้อง
  await page.goto(`${FT}/logout`);
  await page.goto(FT);
  await page.waitForTimeout(300);
  for (let i = 1; i <= 5; i++) {
    const hasForm = (await page.locator('input[name="username"]').count()) > 0;
    if (!hasForm) break; // แอปล็อกแล้ว — หยุดยิง
    await page.fill('input[name="username"]', 'buyer-user');
    await page.fill('input[name="password"]', `wrong-${i}`);
    await page.click('button[type="submit"]');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(200);
  }
  await page.waitForTimeout(400);
  await shot('23-fintech-locked-state');

  // [4] รอพ้นรอบล็อก (แอป 35s + KC lock ที่ extend ได้) -> login ใหม่กลับมาได้
  await page.waitForTimeout(90000); // KC lock อาจ extend ระหว่างมี fail คาง — รอนานพอ
  await page.goto(FT);
  await page.fill('input[name="username"]', 'buyer-user');
  await page.fill('input[name="password"]', process.env.TEST_USER_PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL('**/home', { timeout: 15000 });
  await page.waitForTimeout(600);
  await shot('24-fintech-recovered');

  await browser.close();
  console.log('บันทึกภาพ Fintech 4 ภาพ: 21/22/23/24');
};

run().catch(async (e) => {
  console.error('FAILED:', e.message);
  try { await page.screenshot({ path: path.join(OUT, '99-fintech-failed.png') }); console.error('URL:', page.url()); } catch {}
  process.exit(1);
});
