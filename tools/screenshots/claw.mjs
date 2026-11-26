// ตรวจ claw-web + @central/login-js ใน "เบราว์เซอร์จริง" (Edge ผ่าน Playwright) และถ่าย screenshot
// — เป็นการพิสูจน์ว่า SDK ทำงานได้ใต้ CSP ของแอป (WebCrypto, ES modules, CORS ไป Keycloak/Kong)
// ซึ่ง script curl ทำแทนไม่ได้ · รัน: cd tools/screenshots && set -a && source ../../.env && set +a && node claw.mjs
import { chromium } from 'playwright';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const OUT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'docs', 'screenshots');
const APP = process.env.CLAW_URL ?? 'http://localhost:3060';
const USER = process.env.TEST_USER ?? 'buyer-user';
const PASSWORD = process.env.TEST_USER_PASSWORD;
if (!PASSWORD) {
  console.error('missing TEST_USER_PASSWORD — run: set -a && source ../../.env && set +a && node claw.mjs');
  process.exit(2);
}

const shot = (page, name) => page.screenshot({ path: path.join(OUT, `${name}.png`), fullPage: false });
const results = [];
const check = (name, ok, extra = '') => {
  results.push(ok);
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? ` (${extra})` : ''}`);
};
const apiOutStartsWith = (method) =>
  page.waitForFunction((m) => (document.querySelector('#api-out')?.textContent ?? '').startsWith(m), method, { timeout: 20000 });

const browser = await chromium.launch({ channel: 'msedge' });
const context = await browser.newContext({
  viewport: { width: 1280, height: 860 },
  locale: 'en-US',
  deviceScaleFactor: 1.5,
});
await context.addCookies([{ name: 'lang', value: 'en', domain: 'localhost', path: '/' }]);
const page = await context.newPage();

// เก็บทุก console error / CSP violation / request ที่ล้ม (ยกเว้น navigation ที่ถูกแทนที่ด้วย redirect ปกติ)
const problems = [];
page.on('console', (m) => m.type() === 'error' && problems.push(`console.error: ${m.text()}`));
page.on('requestfailed', (r) => r.failure()?.errorText !== 'net::ERR_ABORTED' && problems.push(`request failed: ${r.url()} ${r.failure()?.errorText}`));

try {
  await page.goto(`${APP}/`, { waitUntil: 'load' });
  await page.waitForSelector('#view-landing:not(.hidden)', { timeout: 30000 });
  check('landing shown on first visit (no SSO session → silent check ends with login_required)', true, page.url());
  check('URL is clean after the silent check (no code/state/error left)', !/[?&](code|state|error)=/.test(page.url()), page.url());
  check('English UI (cookie lang=en)', (await page.textContent('#btn-login')) === 'Sign in with ID');
  await shot(page, '31-claw-landing-en');

  await page.click('#btn-login');
  await page.waitForSelector('#username', { timeout: 30000 });
  check('redirected to the Central ID login page (upstream realm, through Identity Brokering)', page.url().includes('central-id-upstream'));

  await page.fill('#username', USER);
  await page.fill('#password', PASSWORD);
  await Promise.all([page.waitForURL(`${APP}/`, { timeout: 30000 }), page.click('#kc-login')]);
  await page.waitForSelector('#view-dashboard:not(.hidden)', { timeout: 20000 });
  check('dashboard shown after the callback (code exchanged with PKCE verifier, id_token verified)', true, page.url());
  check('profile comes from the verified id_token', (await page.textContent('#p-username')) === USER, await page.textContent('#p-username'));
  check('access token audience is buyer-api', (await page.textContent('#t-aud')).includes('buyer-api'), await page.textContent('#t-aud'));
  const scopeText = await page.textContent('#t-scope');
  check('access token carries orders.read + orders.write', ['orders.read', 'orders.write'].every((s) => scopeText.includes(s)), scopeText);
  check(
    'no token written to any browser storage (sessionStorage/localStorage)',
    await page.evaluate(() => [sessionStorage, localStorage].every((s) => !/access_token|refresh_token|eyJ/.test(JSON.stringify(s)))),
  );
  await shot(page, '32-claw-dashboard-en');

  await page.click('#btn-api-get');
  await apiOutStartsWith('GET');
  const getOut = await page.textContent('#api-out');
  check('GET /openapi/oidc/orders through Kong with the SDK token → 200', /HTTP 200/.test(getOut), getOut.split('\n').find((l) => l.startsWith('HTTP')));
  check('the API sees the same user (principalType=user, subject = id_token sub)', getOut.includes('"principalType": "user"') && getOut.includes(await page.textContent('#p-sub')));
  await shot(page, '33-claw-api-en');

  await page.click('#btn-api-post');
  await apiOutStartsWith('POST');
  check('POST order (needs orders.write at the service) → 201', /HTTP 201/.test(await page.textContent('#api-out')));

  await page.click('#btn-refresh');
  await page.waitForFunction(() => Number(document.querySelector('#t-expires')?.textContent) > 290, null, { timeout: 15000 });
  check('refresh token rotation → countdown restarts with a fresh token', true, `${await page.textContent('#t-expires')}s`);

  await page.reload();
  await page.waitForSelector('#view-dashboard:not(.hidden)', { timeout: 30000 });
  check('after a reload the session is restored by silent login (tokens live in memory only)', (await page.textContent('#p-username')) === USER, page.url());

  await Promise.all([page.waitForURL(`${APP}/`, { timeout: 30000 }), page.click('#btn-logout')]);
  await page.waitForSelector('#view-landing:not(.hidden)', { timeout: 20000 });
  check('global logout → back to the landing page, signed out', true, page.url());
  await page.reload();
  await page.waitForSelector('#view-landing:not(.hidden)', { timeout: 20000 });
  check('still signed out after a reload (no automatic re-login after logout)', true);

  check('no console error, CSP violation or failed request during the whole journey', problems.length === 0, problems.join(' | ').slice(0, 400));
} catch (e) {
  await shot(page, '99-claw-failed').catch(() => {});
  check(`journey threw: ${e.message.split('\n')[0]}`, false, page.url());
  if (problems.length) console.log(`  browser problems:\n   ${problems.join('\n   ')}`);
} finally {
  await browser.close();
}

const failed = results.filter((ok) => !ok).length;
console.log(`\nสรุป claw.mjs: PASS=${results.length - failed} FAIL=${failed}`);
process.exit(failed ? 1 : 0);
