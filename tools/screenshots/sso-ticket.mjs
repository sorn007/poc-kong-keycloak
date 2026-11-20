// Playwright — SSO Ticket ของ ID กลาง: fintech login → เปิด CIS/Buyer ในแท็บใหม่ตรง ๆ โดยไม่ login
// 28 fintech home (มีตั๋วแล้ว) · 29 CIS เปิดตรงในแท็บใหม่ → เข้าเลย
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
  // context เดียว = browser จริง (cookie central_sso ใช้ร่วมทุกแท็บเพราะ host localhost เดียวกัน)
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 860 }, locale: 'en-US', deviceScaleFactor: 1.5 });
  // โหมด English สำหรับภาพทั้งชุด (cookie lang แชร์ทุกแอปบน host เดียวกัน)
  await ctx.addCookies([{ name: 'lang', value: 'en', domain: 'localhost', path: '/' }]);

  const shot = (p, name) => p.screenshot({ path: path.join(OUT, `${name}.png`) });

  // แท็บ 1 — login fintech (Embedded Login) → ระบบออกตั๋ว central_sso ให้ browser
  const p1 = await ctx.newPage();
  await p1.goto(FT);
  await p1.fill('input[name="username"]', 'buyer-user');
  await p1.fill('input[name="password"]', process.env.TEST_USER_PASSWORD);
  await p1.click('button[type="submit"]');
  await p1.waitForURL('**/home', { timeout: 15000 });
  await p1.waitForTimeout(600);
  await shot(p1, '28-fintech-with-sso-ticket');

  // แท็บ 2 — เปิด CIS ตรง ๆ (ไม่ผ่าน fintech เลย) → ตั๋วทำให้ SSO เงียบ ๆ ไม่เจอหน้า login
  const p2 = await ctx.newPage();
  await p2.goto('http://localhost:3020/');
  await p2.waitForLoadState('domcontentloaded');
  await p2.waitForTimeout(1200);
  await shot(p2, '29-cis-newtab-sso');

  // แท็บ 3 — Buyer ก็เหมือนกัน
  const p3 = await ctx.newPage();
  await p3.goto('http://localhost:3010/');
  await p3.waitForLoadState('domcontentloaded');
  await p3.waitForTimeout(800);
  await shot(p3, '30-buyer-newtab-sso');

  await browser.close();
  console.log('บันทึกภาพ SSO Ticket 3 ภาพ: 28/29/30');
};

run().catch(async (e) => {
  console.error('FAILED:', e.message);
  process.exit(1);
});
