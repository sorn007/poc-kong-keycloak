// Unit test ของ @central/login-js — การเริ่ม login, การรับ callback, การตรวจ id_token, logout
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as sdk from '../dist/index.js';
import {
  newIdP, createWorld, memoryStorage, newClient, startLogin, arrive, signIn, makeTokens, tamperSignature,
  ISSUER, CLIENT_ID,
} from './_support/idp.js';

const sha256Url = (text) => createHash('sha256').update(text).digest('base64url');
const TXN_KEY = 'central-login.transaction';
const SESSION_KEY = 'central-login.session';
const REDIRECT = 'http://localhost:3060/auth/callback';
const settled = () => new Promise((resolve) => setImmediate(resolve));

async function fresh() {
  const idp = await newIdP();
  return { idp, world: createWorld({ idp }) };
}

// ───────────────────────── เริ่ม login + PKCE ─────────────────────────

test('login(): authorize URL ตรงตาม contract และ PKCE เป็น S256 ตาม RFC 7636', async () => {
  const { world } = await fresh();
  const q = await startLogin(world, newClient(world), { returnTo: '/orders?code=leak&state=leak' });
  const tx = JSON.parse(world.storage.getItem(TXN_KEY));

  assert.equal(q.get('response_type'), 'code');
  assert.equal(q.get('client_id'), CLIENT_ID);
  assert.equal(q.get('redirect_uri'), REDIRECT);
  assert.equal(q.get('code_challenge_method'), 'S256');
  assert.equal(q.get('code_challenge'), sha256Url(tx.verifier));
  assert.match(tx.verifier, /^[A-Za-z0-9_-]{43}$/); // 43 ตัวอักษร — ช่วง 43-128 ที่ spec กำหนด
  assert.equal(q.get('state'), tx.state);
  assert.equal(q.get('nonce'), tx.nonce);
  assert.match(q.get('state'), /^[A-Za-z0-9_-]{43}$/); // สุ่ม 256-bit
  assert.match(q.get('nonce'), /^[A-Za-z0-9_-]{43}$/);
  assert.equal(q.get('scope'), 'openid profile email');
  assert.equal(q.has('prompt'), false); // การกด login เองไม่บังคับให้กรอกรหัสซ้ำ — ปล่อยให้ SSO ทำงาน
  assert.equal(tx.returnTo, '/orders'); // พารามิเตอร์ OIDC ถูกตัดออกจาก returnTo
  assert.equal(world.calls.navigate.length, 1);
  assert.notEqual(tx.state, (await startLogin(world, newClient(world))).get('state'), 'state ต้องไม่ซ้ำกันทุกครั้ง');
});

test('returnTo ที่ไม่ปลอดภัยถูกเปลี่ยนเป็น path ในแอป (กัน open redirect / กันวน callback)', async () => {
  const { world } = await fresh();
  const cases = [
    ['https://evil.example/', '/'],
    ['//evil.example/', '/'],
    ['/\\evil.example', '/'],
    ['/orders?code=abc&state=xyz&iss=x#ok', '/orders#ok'],
    ['/auth/callback?code=abc', '/'],
    ['/auth/callback', '/'],
    ['/orders#?code=abc', '/orders'],
    [undefined, '/'],
    [123, '/'],
  ];
  for (const [input, expected] of cases) {
    world.tick(31_000); // เว้นหน้าต่าง 30 วินาทีของ loop guard — ไม่งั้นครั้งที่ 4 ถูกหยุดตามดีไซน์
    await startLogin(world, newClient(world), { returnTo: input });
    assert.equal(JSON.parse(world.storage.getItem(TXN_KEY)).returnTo, expected, `returnTo ${JSON.stringify(input)}`);
  }
});

test('sessionStorage เขียนไม่ได้ → login() ถูกปฏิเสธก่อน redirect (fail-closed: ไม่มี verifier = แลก code ไม่ได้)', async () => {
  const { idp } = await fresh();
  const storage = memoryStorage();
  storage.setItem = () => {
    throw new Error('QuotaExceededError');
  };
  const world = createWorld({ idp, storage });
  await assert.rejects(newClient(world).login(), (e) => e instanceof sdk.LoginError && e.code === 'storage_unavailable');
  assert.equal(world.calls.navigate.length, 0);
});

test('config ที่ผิดถูกปฏิเสธตอนสร้าง client', async () => {
  const { world } = await fresh();
  const bad = (options, why) => assert.throws(() => newClient(world, options), (e) => e.code === 'invalid_configuration' && e.message.includes(why));
  bad({ redirectUri: 'http://other.example:3060/auth/callback' }, 'same origin');
  bad({ issuer: 'http://localhost:8080/realms/central#frag' }, 'without a query or fragment');
  bad({ issuer: 'not a url' }, 'absolute URL');
  bad({ clientId: '' }, 'clientId');
});

// ───────────────────────── callback ─────────────────────────

test('callback สำเร็จ: แลก code ด้วย verifier, ตรวจ id_token, เก็บ session ในหน่วยความจำ, ลบพารามิเตอร์ออกจาก URL', async () => {
  const { idp, world } = await fresh();
  await startLogin(world, newClient(world), { returnTo: '/orders' });
  const verifier = JSON.parse(world.storage.getItem(TXN_KEY)).verifier;
  const nonce = JSON.parse(world.storage.getItem(TXN_KEY)).nonce;
  const tokens = await makeTokens(idp, world, { nonce });
  world.routes.push({ body: tokens });

  world.location.pathname = '/auth/callback';
  world.location.search = `?${new URLSearchParams({ code: 'authz-123', state: JSON.parse(world.storage.getItem(TXN_KEY)).state, iss: ISSUER })}`;
  const page = newClient(world);
  const events = [];
  page.on('authenticated', () => events.push('authenticated'));
  assert.deepEqual(await page.init({ silent: false }), { status: 'authenticated' });

  assert.deepEqual(events, ['authenticated']);
  assert.deepEqual(world.calls.token, [
    { client_id: CLIENT_ID, grant_type: 'authorization_code', code: 'authz-123', redirect_uri: REDIRECT, code_verifier: verifier },
  ]);
  assert.equal(page.getAccessToken(), tokens.access_token);
  assert.equal(page.getIdToken(), tokens.id_token);
  assert.deepEqual(page.getUser().username, 'buyer-user');
  assert.equal(page.getUser().subject, 'user-1');
  const info = page.getTokenInfo();
  assert.deepEqual(info.audiences, ['buyer-api']);
  assert.deepEqual(info.scopes, ['openid', 'orders.read']);
  assert.equal(info.expiresIn, 300);
  // URL ถูกทำความสะอาด และ transaction ถูกลบ — code ไม่สามารถถูกใช้ซ้ำผ่าน reload/ย้อนกลับได้
  assert.deepEqual(world.calls.replaceState, ['/orders']);
  assert.equal(world.location.search, '');
  assert.equal(world.storage.getItem(TXN_KEY), null);
  // ค่า default: token ไม่ถูกเขียนลง storage ใด ๆ
  assert.equal(JSON.stringify(world.storage.dump()).includes(tokens.access_token), false);
  assert.equal(JSON.stringify(world.storage.dump()).includes(tokens.refresh_token), false);
  assert.equal(world.storage.getItem(SESSION_KEY), null);
});

test('callback ที่ state ไม่มีใครรู้จัก (login ข้ามแท็บ) → ไม่แลก code และลบ code ออกจาก URL ทันที', async () => {
  const { world } = await fresh();
  const { page, result } = await arrive(world, { code: 'stolen-or-reused', state: 'nobody-knows', iss: ISSUER });
  assert.equal(result.error.code, 'unrecognized_state');
  assert.equal(world.calls.token.length, 0);
  assert.deepEqual(world.calls.replaceState, ['/']);
  assert.equal(page.isAuthenticated(), false);
});

test('callback ที่ state ไม่ตรงกับ transaction ของ tab นี้ → ไม่แลก code และ transaction ถูกลบ', async () => {
  const { world } = await fresh();
  await startLogin(world, newClient(world));
  const { result } = await arrive(world, { code: 'c', state: 'another-state', iss: ISSUER });
  assert.equal(result.error.code, 'unrecognized_state');
  assert.equal(world.calls.token.length, 0);
  assert.equal(world.storage.getItem(TXN_KEY), null);
});

test('callback ที่ iss ไม่ใช่ issuer ที่กำหนด (mix-up attack) → ปฏิเสธก่อนยิง token endpoint', async () => {
  const { world } = await fresh();
  const state = (await startLogin(world, newClient(world))).get('state');
  const { result } = await arrive(world, { code: 'c', state, iss: 'https://evil.example/realms/central' });
  assert.equal(result.error.code, 'issuer_mismatch');
  assert.equal(world.calls.token.length, 0);
});

test('callback ที่ OP ตอบ error → unauthenticated พร้อมรหัส error และ URL ถูกทำความสะอาด', async () => {
  const { world } = await fresh();
  const state = (await startLogin(world, newClient(world))).get('state');
  const { result } = await arrive(world, { error: 'access_denied', error_description: 'user cancelled', state, iss: ISSUER });
  assert.equal(result.status, 'unauthenticated');
  assert.equal(result.error.code, 'authorization_failed');
  assert.match(result.error.detail, /access_denied: user cancelled/);
  assert.deepEqual(world.calls.replaceState, ['/']);
  assert.equal(world.calls.token.length, 0);
});

test('id_token ที่ไม่ผ่านการตรวจ → ไม่มี session แม้ OP คืน token มาแล้ว', async (t) => {
  const probe = await fresh();
  const at = Math.floor(probe.world.now() / 1000);
  const idp = probe.idp;
  const cases = [
    ['nonce ไม่ตรงกับคำขอ', { tokens: { nonce: 'attacker-nonce' } }],
    ['aud ไม่ใช่ client นี้', { tokens: { id: { aud: 'buyer-web' } } }],
    ['iss เป็นของคนอื่น', { tokens: { id: { iss: 'https://evil.example' } } }],
    ['azp ไม่ใช่ client นี้', { tokens: { id: { azp: 'buyer-web' } } }],
    ['หมดอายุแล้ว', { tokens: { id: { iat: at - 900, exp: at - 600 } } }],
    ['iat อยู่ในอนาคต (นาฬิกาเครื่องไม่ตรง)', { tokens: { id: { iat: at + 600, exp: at + 900 } } }],
    ['alg เป็น HS256 (algorithm confusion)', { signer: { signJwt: (p) => idp.signJwt(p, { alg: 'HS256', kid: idp.kid }) } }],
    ['kid ไม่อยู่ใน JWKS', { signer: { signJwt: (p) => idp.signJwt(p, { alg: 'RS256', kid: 'unknown' }) } }],
    ['signature ถูกแก้', { mutate: (tk) => void (tk.id_token = tamperSignature(tk.id_token)) }],
    ['ไม่มี exp', { tokens: { id: { exp: undefined } } }],
    ['at_hash ไม่ตรงกับ access token', { tokens: { id: { at_hash: 'AAAAAAAAAAAAAAAAAAAAAA' } } }],
    ['ไม่ใช่ JWT', { mutate: (tk) => void (tk.id_token = 'not-a-jwt') }],
    ['ไม่มี id_token เลย', { mutate: (tk) => void delete tk.id_token }],
  ];
  for (const [name, c] of cases) {
    await t.test(name, async () => {
      const world = createWorld({ idp });
      const params = await startLogin(world, newClient(world));
      const tokens = await makeTokens(idp, world, { nonce: params.get('nonce'), ...c.tokens, signer: c.signer });
      c.mutate?.(tokens);
      world.routes.push({ body: tokens });
      const { page, result } = await arrive(world, { code: 'c', state: params.get('state'), iss: ISSUER });
      assert.equal(result.status, 'unauthenticated');
      assert.equal(result.error.code, 'invalid_id_token', result.error.message);
      assert.equal(page.isAuthenticated(), false);
      assert.equal(page.getAccessToken(), undefined);
      assert.deepEqual(world.calls.replaceState, ['/']);
    });
  }
});

test('token endpoint ปฏิเสธ (verifier ผิด) → token_rejected พร้อมรายละเอียดจาก OP', async () => {
  const { idp, world } = await fresh();
  const params = await startLogin(world, newClient(world));
  world.routes.push({ status: 400, body: { error: 'invalid_grant', error_description: 'PKCE verification failed: Invalid code verifier' } });
  const { page, result } = await arrive(world, { code: 'c', state: params.get('state'), iss: ISSUER });
  assert.equal(result.error.code, 'token_rejected');
  assert.match(result.error.detail, /PKCE verification failed/);
  assert.equal(page.isAuthenticated(), false);
  void idp;
});

test('token endpoint เรียกไม่ได้ (CORS ไม่ผ่านในเบราว์เซอร์) → network_error พร้อมคำใบ้ตรงจุด', async () => {
  const { idp, world } = await fresh();
  const params = await startLogin(world, newClient(world));
  world.routes.push({ networkError: true });
  const { result } = await arrive(world, { code: 'c', state: params.get('state'), iss: ISSUER });
  assert.equal(result.error.code, 'network_error');
  assert.match(result.error.message, /webOrigins/);
  void idp;
});

// ───────────────────────── logout ─────────────────────────

test('logout(): RP-initiated logout พร้อม id_token_hint + client_id + post-logout redirect และเคลียร์ session ก่อน navigate', async () => {
  const { idp, world } = await fresh();
  const { page } = await signIn(world, idp);
  const idToken = page.getIdToken();
  page.logout({ returnTo: '/orders' }).catch(() => {});
  await settled();
  const url = new URL(world.calls.navigate.at(-1));
  assert.equal(url.pathname, '/realms/central/protocol/openid-connect/logout');
  assert.equal(url.searchParams.get('id_token_hint'), idToken);
  assert.equal(url.searchParams.get('client_id'), CLIENT_ID);
  assert.equal(url.searchParams.get('post_logout_redirect_uri'), 'http://localhost:3060');
  assert.equal(url.searchParams.get('state'), '/orders');
  assert.equal(page.isAuthenticated(), false);
  assert.equal(typeof JSON.parse(world.storage.getItem('central-login.guard')).loggedOutAt, 'number');
});

test('logout() ตอนยังไม่ login → กลับหน้าแอปโดยไม่เรียก OP', async () => {
  const { idp, world } = await fresh();
  newClient(world).logout({ returnTo: '/' }).catch(() => {});
  await settled();
  assert.deepEqual(world.calls.navigate, ['http://localhost:3060/']);
  void idp;
});

// ───────────────────────── tokenStore (opt-in) ─────────────────────────

test('tokenStore: เมื่อแอปเลือกเก็บ token — session อยู่ต่อข้าม "หน้าใหม่" และถูกลบเมื่อเคลียร์', async () => {
  const { idp, world } = await fresh();
  const tokenStore = memoryStorage();
  const { page } = await signIn(world, idp, { clientOptions: { tokenStore } });
  assert.ok(tokenStore.getItem(SESSION_KEY), 'session ถูกเก็บตามที่แอปขอ');

  world.location.pathname = '/';
  world.location.search = '';
  const page2 = newClient(world, { tokenStore });
  assert.deepEqual(await page2.init({ silent: false }), { status: 'authenticated' });
  assert.equal(page2.getAccessToken(), page.getAccessToken());
  page2.clear();
  assert.equal(tokenStore.getItem(SESSION_KEY), null);
});
