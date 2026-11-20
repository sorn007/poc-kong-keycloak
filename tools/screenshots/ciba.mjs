// Playwright — ถ่ายภาพ flow ของ CIBA Headless Pilot (Phase 0)
// จุดสำคัญ: ทั้ง flow **ไม่มีหน้า login ของ Keycloak ปรากฏเลย** — แอปทำหน้า login เอง
// และผู้ใช้ยืนยันผ่าน "อุปกรณ์ ID" (id-device :3040) — ตาม research-headless-auth.md §4.1
// รัน: cd tools/screenshots && node ciba.mjs (ไม่ต้องใช้ TEST_USER_PASSWORD)
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.resolve(__dirname, '../../docs/screenshots');
const DEMO = 'http://localhost:3030'; // CD — Seller App (headless)
const DEVICE = 'http://localhost:3040'; // AD — อุปกรณ์ ID

const shot = (page, name) =>
  page.screenshot({ path: path.join(OUT, `${name}.png`), fullPage: false });
const settled = async (page, extra = 0) => {
  await page.waitForLoadState('domcontentloaded');
  await page.waitForTimeout(400 + extra);
};

let page1, page2; // ประกาศนอก run เพื่อให้ catch ถ่ายสถานะตอนล้มได้

const run = async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch({ channel: 'msedge' });
  const ctx = await browser.newContext({
    viewport: { width: 1280, height: 860 },
    locale: 'en-US',
    deviceScaleFactor: 1.5,
  });
  // โหมด English สำหรับภาพทั้งชุด (cookie lang แชร์ทุกแอปบน host เดียวกัน)
  await ctx.addCookies([{ name: 'lang', value: 'en', domain: 'localhost', path: '/' }]);


  // tab1 = แอป Seller (CD), tab2 = อุปกรณ์ ID (AD) — จำลองสองอุปกรณ์ของผู้ใช้
  page1 = await ctx.newPage();
  page2 = await ctx.newPage();

  // เคลียร์ pending เก่าค้างบนอุปกรณ์ ID (จากรอบก่อน) — กดปฏิเสธตัวใหม่สุดสูงสุด 5 ครั้ง
  await page2.goto(DEVICE);
  await settled(page2);
  // อุปกรณ์ ID มี login gate — ต้อง login ด้วยบัญชี ID (upstream) ก่อนจึงจะเห็นคำขอของตัวเอง
  const loginLink = page2.locator('a.approve[href="/auth/login"]');
  if ((await loginLink.count()) > 0) {
    await loginLink.first().click();
    // ผ่าน downstream realm (auto-redirect ไป upstream) จนถึงหน้า login จริงของ Keycloak
    await page2.waitForURL('**/realms/**', { timeout: 20000 });
    await page2.waitForSelector('input[name="username"]', { timeout: 20000 });
    await page2.fill('input[name="username"]', 'buyer-user');
    await page2.fill('input[name="password"]', process.env.TEST_USER_PASSWORD);
    // KC login page ใช้ <input type="submit"> — รองรับทั้ง input/button
    const submit = page2.locator('input[type="submit"], button[type="submit"]').first();
    await submit.click();
    await page2.waitForLoadState('domcontentloaded');
    await page2.goto(DEVICE);
    await settled(page2);
  }
  for (let i = 0; i < 5; i++) {
    const denyBtn = page2.locator('form[action="/ciba/deny"] button').last();
    if ((await denyBtn.count()) === 0) break;
    await denyBtn.click();
    await settled(page2, 300);
    await page2.goto(DEVICE);
    await settled(page2);
  }

  // ---------- [1] หน้า login ของแอป Seller เอง ----------
  await page1.goto(DEMO);
  await settled(page1);
  await shot(page1, '16-headless-login-own-ui');

  // ---------- [2] กด "ขออนุญาตเข้าสู่ระบบ" → หน้ารอการยืนยัน ----------
  await page1.fill('input[name="login_hint"]', 'buyer-user');
  await page1.fill('input[name="binding_message"]', 'Seller-App-CIBA-demo');
  await page1.click('button[type="submit"]');
  await page1.waitForURL('**/ciba/waiting');
  await settled(page1, 300);
  await shot(page1, '17-headless-waiting-binding-message');

  // ---------- [3] อุปกรณ์ ID — หน้าอนุมัติ (AD) ----------
  await page2.goto(DEVICE);
  await settled(page2, 800); // รอ delegation request มาถึง
  await shot(page2, '18-id-device-approval');

  // ---------- [4] กดยืนยันในอุปกรณ์ ID (คำขอใหม่สุด = approve form ตัวล่าสุดในหน้า) ----------
  await page2.locator('form[action="/ciba/approve"] button.approve').last().click();
  await settled(page2, 500);
  await shot(page2, '19-id-device-approved');

  // ---------- [5] แอป Seller ได้ token → เรียก Buyer API สำเร็จ ----------
  await page1.waitForURL('**/ciba/result', { timeout: 20000 });
  await settled(page1, 600);
  await shot(page1, '20-headless-result-claims-orders');

  await browser.close();
  const files = fs.readdirSync(OUT).filter((f) => /^(16|17|18|19|20)-/.test(f)).sort();
  console.log(`บันทึกภาพ CIBA ${files.length} ภาพ:`);
  files.forEach((f) => console.log('  ' + f));
};

run().catch(async (e) => {
  console.error('FAILED:', e.message);
  try {
    const p = page1 ?? page2;
    if (p) {
      await p.screenshot({ path: path.join(OUT, '99-ciba-failed-state.png') });
      console.error('URL ตอนล้ม:', p.url());
    }
  } catch {}
  process.exit(1);
});
