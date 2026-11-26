// Unit test ของ @central/login-js — init/silent login, กัน redirect loop, ต่ออายุ token (rotation)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as sdk from '../dist/index.js';
import { newIdP, createWorld, newClient, startLogin, navigateParams, arrive, signIn, makeTokens, ISSUER } from './_support/idp.js';

const TXN_KEY = 'central-login.transaction';
const GUARD_KEY = 'central-login.guard';
const settled = () => new Promise((resolve) => setImmediate(resolve));
const stillPending = (promise) => Promise.race([promise, new Promise((resolve) => setTimeout(() => resolve('still-pending'), 30))]);

async function fresh() {
  const idp = await newIdP();
  return { idp, world: createWorld({ idp }) };
}

// ───────────────────────── init / silent login ─────────────────────────

test('init(): ไม่มี session → redirect แบบ prompt=none และ promise ค้างระหว่างหน้าเปลี่ยน (แอปไม่ render สถานะค้าง)', async () => {
  const { world } = await fresh();
  world.location.pathname = '/orders';
  world.location.search = '?q=1';
  assert.equal(await stillPending(newClient(world).init()), 'still-pending');
  const url = new URL(world.calls.navigate.at(-1));
  assert.equal(url.searchParams.get('prompt'), 'none');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(JSON.parse(world.storage.getItem(TXN_KEY)).returnTo, '/orders?q=1');
});

test('init({ silent: false }) → unauthenticated โดยไม่ redirect', async () => {
  const { world } = await fresh();
  assert.deepEqual(await newClient(world).init({ silent: false }), { status: 'unauthenticated' });
  assert.equal(world.calls.navigate.length, 0);
});

test('init() เรียกซ้ำ → ใช้ promise เดิม (ไม่ redirect ซ้ำ)', async () => {
  const { world } = await fresh();
  const client = newClient(world);
  const first = client.init();
  assert.equal(client.init(), first);
});

test('หลังได้รับ login_required จาก OP → ไม่ redirect อัตโนมัติซ้ำภายใน 60 วินาที (กัน loop)', async () => {
  const { world } = await fresh();
  const params = await startLogin(world, newClient(world));
  const { result } = await arrive(world, { error: 'login_required', error_description: 'no SSO session', state: params.get('state'), iss: ISSUER });
  assert.equal(result.error.code, 'authorization_failed');
  world.location.pathname = '/'; // ผู้ใช้กด reload
  const before = world.calls.navigate.length;
  assert.deepEqual(await newClient(world).init(), { status: 'unauthenticated' });
  assert.equal(world.calls.navigate.length, before, 'ต้องไม่พาไป OP อีก');

  world.tick(61_000); // พ้นช่วง cooldown → ลอง silent login ได้อีกครั้ง
  assert.equal(await stillPending(newClient(world).init()), 'still-pending');
  assert.equal(world.calls.navigate.length, before + 1);
});

test('หลัง logout → init() ไม่ silent login ใหม่ จนกว่าผู้ใช้จะกด login เอง', async () => {
  const { idp, world } = await fresh();
  const { page } = await signIn(world, idp);
  page.logout({}).catch(() => {});
  await settled();
  world.location.pathname = '/';
  const before = world.calls.navigate.length;
  assert.deepEqual(await newClient(world).init(), { status: 'unauthenticated' });
  assert.equal(world.calls.navigate.length, before);
  assert.ok(await startLogin(world, newClient(world)), 'การกด login เองต้องไป OP ได้ตามปกติ');
});

test('กลับมาจาก logout พร้อม ?state= → เอาพารามิเตอร์ออกจาก URL และกลับไป path ที่ขอ', async () => {
  const { world } = await fresh();
  world.location.pathname = '/';
  world.location.search = '?state=%2Forders%3Fx%3D1';
  assert.deepEqual(await newClient(world).init({ silent: false }), { status: 'unauthenticated' });
  assert.deepEqual(world.calls.replaceState, ['/orders?x=1']);
});

test('redirect ไป OP 3 ครั้งใน 30 วินาที → ครั้งที่ 4 ถูกหยุด (loop_detected) · พ้น 30 วินาทีปลดล็อก', async () => {
  const { world } = await fresh();
  for (let i = 0; i < 3; i += 1) assert.ok(await startLogin(world, newClient(world)));
  await assert.rejects(newClient(world).login(), (e) => e instanceof sdk.LoginError && e.code === 'loop_detected');
  assert.deepEqual(await newClient(world).init(), { status: 'unauthenticated' }, 'silent login ก็ต้องไม่วิ่งไป OP');
  assert.equal(world.calls.navigate.length, 3);

  world.tick(31_000);
  assert.ok(await startLogin(world, newClient(world)));
});

test('login สำเร็จ → เริ่มนับ redirect ใหม่ (ไม่โดน loop_detected ทั้งที่ login บ่อยตามปกติ)', async () => {
  const { idp, world } = await fresh();
  await signIn(world, idp);
  assert.equal(world.storage.getItem(GUARD_KEY), '{"redirects":[]}');
});

test('silentLogin(): ส่ง prompt=none และจด returnTo ไว้กลับมา', async () => {
  const { world } = await fresh();
  world.location.pathname = '/dashboard';
  const q = await navigateParams(world, newClient(world).silentLogin());
  assert.equal(q.get('prompt'), 'none');
  assert.equal(JSON.parse(world.storage.getItem(TXN_KEY)).returnTo, '/dashboard');
});

// ───────────────────────── ต่ออายุ token ─────────────────────────

test('updateToken(): ไม่ยิง network เมื่อ token ยังอายุเหลือมากกว่าที่ขอ', async () => {
  const { idp, world } = await fresh();
  const { page } = await signIn(world, idp);
  world.calls.token.length = 0;
  assert.equal(await page.updateToken(20), false);
  assert.equal(world.calls.token.length, 0);
});

test('อายุ token นับจาก expires_in ไม่ใช่จากนาฬิกาเครื่องเทียบ exp ใน token', async () => {
  const { idp, world } = await fresh();
  // exp/iat ใน "access token" เพี้ยนจากนาฬิกาเครื่องโดยเจตนา — ต้องไม่กระทบการตัดสินใจว่าจะ refresh เมื่อไหร่
  // (id_token ยังต้องผ่านการตรวจ exp ตามนาฬิกาเครื่อง — SDK ไม่เชื่อ id_token ที่หมดอายุ)
  const { page } = await signIn(world, idp, { tokens: { access: { exp: 1, iat: 0 } } });
  assert.equal(await page.updateToken(20), false, 'เพิ่งได้ token ยังสดอยู่');
  world.tick(290_000);
  world.routes.push({ body: await makeTokens(idp, world) });
  assert.equal(await page.updateToken(20), true, 'ใกล้หมดอายุตาม expires_in → refresh');
});

test('ใกล้หมดอายุ → refresh ด้วย refresh_token ปัจจุบัน แล้วเปลี่ยน token ทั้งชุด', async () => {
  const { idp, world } = await fresh();
  const { page, issued } = await signIn(world, idp);
  const before = page.getAccessToken();
  const firstRefreshToken = issued.refresh_token;
  const refreshed = [];
  page.on('tokenRefreshed', () => refreshed.push('tokenRefreshed'));
  world.tick(290_000);
  world.calls.token.length = 0;
  const freshTokens = await makeTokens(idp, world);
  world.routes.push({ body: freshTokens });

  assert.equal(await page.updateToken(20), true);
  assert.deepEqual(world.calls.token, [{ client_id: 'claw-web', grant_type: 'refresh_token', refresh_token: firstRefreshToken }]);
  assert.equal(page.getAccessToken(), freshTokens.access_token);
  assert.notEqual(page.getAccessToken(), before);
  assert.equal(page.getTokenInfo().expiresIn, 300);
  assert.deepEqual(refreshed, ['tokenRefreshed']);
});

test('เรียก updateToken พร้อมกันหลายที่ → refresh จริงครั้งเดียว (กันใช้ refresh token ซ้ำจนโดน replay detection)', async () => {
  const { idp, world } = await fresh();
  const { page } = await signIn(world, idp);
  let release;
  world.routes.push({ body: await makeTokens(idp, world), gate: new Promise((resolve) => void (release = resolve)) });
  world.calls.token.length = 0; // นับเฉพาะ request ของการ refresh (ไม่รวมการแลก code ตอน login)

  const a = page.updateToken(-1);
  const b = page.updateToken(-1);
  const c = page.updateToken(-1);
  await settled();
  assert.equal(world.calls.token.length, 1, 'ต้องมี request เดียวระหว่างที่ refresh ยังไม่เสร็จ');
  release();
  assert.deepEqual(await Promise.all([a, b, c]), [true, true, true]);
  assert.equal(world.calls.token.length, 1);
  assert.equal(world.calls.token[0].grant_type, 'refresh_token');
});

test('refresh ถูกปฏิเสธ (invalid_grant) → เคลียร์ session, emit signedOut และโยน refresh_rejected', async () => {
  const { idp, world } = await fresh();
  const { page } = await signIn(world, idp);
  const signedOut = [];
  page.on('signedOut', (e) => signedOut.push(e.reason));
  world.routes.push({ status: 400, body: { error: 'invalid_grant', error_description: 'Session expired' } });
  await assert.rejects(page.updateToken(-1), (e) => e.code === 'refresh_rejected');
  assert.equal(page.isAuthenticated(), false);
  assert.equal(page.getAccessToken(), undefined);
  assert.deepEqual(signedOut, ['refresh_rejected']);
});

test('refresh ล้มเหลวเพราะ network → ทิ้ง refresh token (ไม่รู้ว่า server ใช้ไปแล้วหรือยัง) แต่คง access token เดิม และไม่ retry ด้วย token เดิม', async () => {
  const { idp, world } = await fresh();
  const { page } = await signIn(world, idp);
  const accessToken = page.getAccessToken();
  world.routes.push({ networkError: true });
  await assert.rejects(page.updateToken(-1), (e) => e.code === 'network_error');
  assert.equal(page.getAccessToken(), accessToken, 'access token เดิมยังใช้ได้จนหมดอายุ');

  world.calls.token.length = 0;
  await assert.rejects(page.updateToken(-1), (e) => e.code === 'refresh_rejected');
  assert.equal(world.calls.token.length, 0, 'ห้ามส่ง refresh token เดิมไปอีก');
  assert.equal(page.isAuthenticated(), false);
});

test('ไม่มี refresh token และ token หมดอายุ → signedOut', async () => {
  const { idp, world } = await fresh();
  const { page } = await signIn(world, idp, { tokens: { expiresIn: 1, refreshToken: null } }); // OP ไม่ออก refresh token
  world.tick(2_000);
  const signedOut = [];
  page.on('signedOut', (e) => signedOut.push(e.reason));
  await assert.rejects(page.updateToken(20), (e) => e.code === 'refresh_rejected');
  assert.deepEqual(signedOut, ['no_refresh_token']);
});

test('updateToken() ก่อน login → not_authenticated', async () => {
  const { world } = await fresh();
  await assert.rejects(newClient(world).updateToken(), (e) => e.code === 'not_authenticated');
});

test('key rotation: id_token ใบใหม่เซ็นด้วย kid ที่ยังไม่เคยเห็น → SDK ดึง JWKS ใหม่แล้วตรวจผ่าน', async () => {
  const { idp, world } = await fresh();
  const { page } = await signIn(world, idp);
  assert.equal(world.calls.jwks, 1);

  const rotated = await newIdP('key-2');
  idp.jwks.keys.push(rotated.jwks.keys[0]); // OP เพิ่ม key ใหม่เข้า JWKS
  world.tick(290_000);
  world.routes.push({ body: await makeTokens(idp, world, { signer: rotated }) });
  assert.equal(await page.updateToken(20), true);
  assert.equal(world.calls.jwks, 2, 'kid ไม่ตรง cache → ดึง JWKS ใหม่หนึ่งครั้ง');
});

test('id_token ใบใหม่เซ็นด้วย kid ที่ไม่มีใน JWKS → ไม่รับ session ใหม่ (signedOut)', async () => {
  const { idp, world } = await fresh();
  const { page } = await signIn(world, idp);
  const rogue = await newIdP('rogue-key');
  world.tick(290_000);
  world.routes.push({ body: await makeTokens(idp, world, { signer: rogue }) });
  const signedOut = [];
  page.on('signedOut', (e) => signedOut.push(e.reason));
  await assert.rejects(page.updateToken(20), (e) => e.code === 'invalid_id_token');
  assert.equal(page.isAuthenticated(), false);
  assert.deepEqual(signedOut, ['invalid_id_token']);
});

test('logout() ใช้ id_token "ใบล่าสุด" หลัง refresh', async () => {
  const { idp, world } = await fresh();
  const { page } = await signIn(world, idp);
  world.tick(290_000);
  const freshTokens = await makeTokens(idp, world);
  world.routes.push({ body: freshTokens });
  await page.updateToken(20);
  page.logout({}).catch(() => {});
  await settled();
  assert.equal(new URL(world.calls.navigate.at(-1)).searchParams.get('id_token_hint'), freshTokens.id_token);
});
