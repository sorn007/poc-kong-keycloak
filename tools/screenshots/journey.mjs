// Playwright — เดิน flow จริงของ POC ทั้ง 3 แอป แล้วบันทึกภาพหน้าจอทุกขั้นไว้ที่ docs/screenshots/
// ใช้ Edge ที่ติดเครื่อง (channel msedge) — ไม่ต้องดาวน์โหลด browser และฟอนต์ไทยครบ
// รัน: set -a; source ../../.env; set +a; node journey.mjs
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.resolve(__dirname, '../../docs/screenshots');
const PASSWORD = process.env.TEST_USER_PASSWORD;
if (!PASSWORD) {
  console.error('ต้องมี TEST_USER_PASSWORD (source .env ก่อนรัน)');
  process.exit(1);
}

const PORTAL = 'http://localhost:3000';
const BUYER = 'http://localhost:3010';
const CIS = 'http://localhost:3020';
const USER = 'buyer-user';

const shot = (page, name) =>
  page.screenshot({ path: path.join(OUT, `${name}.png`), fullPage: false });

let page; // ให้ catch ตอนล้มใช้ถ่ายภาพสถานะสุดท้ายได้

const settled = async (page, extra = 0) => {
  await page.waitForLoadState('domcontentloaded');
  await page.waitForTimeout(350 + extra); // ให้ CSS/JS เล็กน้อย settle
};

const run = async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch({ channel: 'msedge' });
  const ctx = await browser.newContext({
    viewport: { width: 1280, height: 860 },
    locale: 'en-US',
    deviceScaleFactor: 1.5, // คมพอสำหรับสไลด์/เอกสาร
  });
  // โหมด English สำหรับภาพทั้งชุด (cookie lang แชร์ทุกแอปบน host เดียวกัน)
  await ctx.addCookies([{ name: 'lang', value: 'en', domain: 'localhost', path: '/' }]);

  page = await ctx.newPage();

  const loginAtKeycloak = async () => {
    await page.waitForSelector('#username');
    console.log('login page:', await page.title(), '|', page.url().slice(0, 60));
    await shot(page, '02-sign-in-to-central-id');
    await page.fill('#username', USER);
    await page.fill('#password', PASSWORD);
    await page.click('#kc-login');
  };

  // ---------- [1] Central ID Portal ----------
  await page.goto(PORTAL);
  await settled(page);
  await shot(page, '01-central-id-portal-guest');

  await page.click('a.btn-primary[href="/auth/login"]'); // พาไปหน้า login กลาง
  await loginAtKeycloak();
  await page.waitForURL(`${PORTAL}/`);
  await settled(page, 400);
  await shot(page, '03-central-id-portal-logged-in');

  await page.goto(`${PORTAL}/apps`);
  await settled(page);
  await shot(page, '04-central-id-connected-apps');

  await page.goto(`${PORTAL}/session`);
  await settled(page);
  await shot(page, '05-central-id-session');

  // ---------- [2] Buyer Portal (SSO — ไม่ถามรหัสผ่าน) ----------
  await page.goto(BUYER);
  await settled(page);
  await shot(page, '06-buyer-portal-guest');

  await page.click('a.btn-primary[href="/auth/login"]'); // SSO → กลับมาทันที
  await page.waitForURL(`${BUYER}/`);
  await settled(page, 400);
  await shot(page, '07-buyer-portal-dashboard-sso');

  await page.goto(`${BUYER}/orders/page`);
  await page.waitForSelector('#tbl', { state: 'visible' });
  await settled(page);
  await shot(page, '08-buyer-orders');

  await page.click('button:has-text("Create Order")');
  await page.waitForSelector('#toast.show');
  await shot(page, '09-buyer-order-created');

  // ---------- [3] CIS Portal (SSO อีกฝั่ง) ----------
  await page.goto(CIS);
  await settled(page);
  await shot(page, '10-cis-portal-guest');

  await page.click('a.btn-primary[href="/auth/login"]');
  await page.waitForURL(`${CIS}/`);
  await settled(page, 400);
  await shot(page, '11-cis-portal-dashboard-sso');

  await page.goto(`${CIS}/projects/page`);
  await page.waitForSelector('#tbl', { state: 'visible' });
  await settled(page);
  await shot(page, '12-cis-projects');

  await page.click('button:has-text("Create Project")');
  await page.waitForSelector('#toast.show');
  await shot(page, '13-cis-project-created');

  // ---------- [4] Logout กลางจาก CIS ----------
  await page.click('header a[href="/auth/logout"]');
  await page.waitForURL(`${CIS}/`);
  await settled(page, 400);
  await shot(page, '14-after-global-logout');

  // ---------- [5] login ใหม่ที่ CIS ต้องเจอหน้า login จริง ----------
  await page.click('a.btn-primary[href="/auth/login"]');
  await page.waitForSelector('#username');
  await shot(page, '15-cis-needs-login-after-logout');

  await browser.close();
  const files = fs.readdirSync(OUT).filter((f) => f.endsWith('.png')).sort();
  console.log(`บันทึกแล้ว ${files.length} ภาพที่ docs/screenshots/`);
  files.forEach((f) => console.log('  ' + f));
};

run().catch(async (e) => {
  console.error('FAILED:', e.message);
  try {
    await page.screenshot({ path: path.join(OUT, '99-failed-state.png') });
    console.error('URL ตอนล้ม:', page.url());
  } catch {}
  process.exit(1);
});
