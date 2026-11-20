// Playwright — หน้า Central API Keys ของ ID Portal (EN): สร้าง key ผูก scope ใช้กับ Open API/MCP
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.resolve(__dirname, '../../docs/screenshots');
const run = async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch({ channel: 'msedge' });
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 860 }, locale: 'en-US', deviceScaleFactor: 1.5 });
  await ctx.addCookies([{ name: 'lang', value: 'en', domain: 'localhost', path: '/' }]);
  const page = await ctx.newPage();
  const shot = (n) => page.screenshot({ path: path.join(OUT, `${n}.png`) });

  // login ผ่าน ID Portal (AC flow — หน้า login ของ upstream EN)
  await page.goto('http://localhost:3000/?lang=en');
  await page.click('a.btn-primary');
  await page.waitForSelector('input[name="username"]', { timeout: 20000 });
  await page.fill('input[name="username"]', 'buyer-user');
  await page.fill('input[name="password"]', process.env.TEST_USER_PASSWORD);
  await page.locator('input[type="submit"], button[type="submit"]').first().click();
  await page.waitForURL('http://localhost:3000/', { timeout: 20000 });
  await page.goto('http://localhost:3000/apikeys');
  await page.waitForLoadState('domcontentloaded');
  await page.waitForTimeout(500);
  await shot('34-apikeys-en');
  await browser.close();
  console.log('บันทึกภาพ API Keys: 34-apikeys-en');
};
run().catch((e) => { console.error('FAILED:', e.message); process.exit(1); });
