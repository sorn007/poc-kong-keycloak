const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
require('reflect-metadata');
const { ForbiddenException, UnauthorizedException } = require('@nestjs/common');

const sdk = require('../dist');
const { newIdP } = require('./_support/idp');

let idp;
before(async () => {
  idp = await newIdP();
});
after(async () => {
  await idp.close();
});

// tamper — แก้ signature ตัวแรก (ห้ามแก้ตัวท้าย: padding bits ของ base64url ไม่ถูกตรวจ ค่า signature จริงอาจไม่เปลี่ยน)
const tamper = (tok) => {
  const i = tok.lastIndexOf('.') + 1;
  return tok.slice(0, i) + (tok[i] === 'A' ? 'B' : 'A') + tok.slice(i + 1);
};

// claim — claims มาตรฐาน + override (undefined = ลบ field)
const claim = (key, value) => {
  const c = idp.claims();
  if (value === undefined) delete c[key];
  else c[key] = value;
  return c;
};

const verifier = () =>
  new sdk.CentralVerifier({
    issuer: idp.issuer,
    audience: idp.audience,
    jwksUrl: idp.jwksUrl,
  });

test('central: token ถูกต้อง → Principal Context มาตรฐาน', async () => {
  const p = await verifier().verify(await idp.sign(idp.claims()));
  assert.deepEqual(p, {
    subject: 'user-1',
    clientId: 'buyer-web',
    principalType: 'user',
    scopes: ['orders.read'],
    tokenId: null,
    tenantId: null,
    issuer: idp.issuer,
  });
});

// signature ถูกไม่พอ — aud/iss/exp/alg/sub บังคับครบ
test('central: token ที่ต้องถูกปฏิเสธ', async (t) => {
  const v = verifier();
  const hs256 = (claims, secret) =>
    jwt.sign(claims, secret, { algorithm: 'HS256', header: { kid: 'test-key-1' } });
  const cases = [
    ['audience อื่น (cross-audience)', idp.sign(claim('aud', 'other-api'))],
    ['issuer อื่น', idp.sign(claim('iss', 'https://evil.test'))],
    ['หมดอายุ', idp.sign(claim('exp', Math.floor(Date.now() / 1000) - 60))],
    ['ไม่มี exp', idp.sign(claim('exp', undefined))],
    ['ไม่มี sub', idp.sign(claim('sub', undefined))],
    ['sub ว่าง', idp.sign(claim('sub', ''))],
    [
      'alg confusion: HS256 เซ็นด้วย public key',
      hs256(idp.claims(), JSON.stringify(idp.publicKey.export({ format: 'jwk' }))),
    ],
    ['signature ถูกแก้', tamper(await idp.sign(idp.claims()))],
    ['ไม่ใช่ JWT', Promise.resolve('not-a-jwt')],
  ];
  for (const [name, token] of cases) {
    await t.test(name, async () => {
      await assert.rejects(v.verify(await token));
    });
  }
});

test('central: clock tolerance 5 วินาที — exp ผ่านไป 2 วินาทียังผ่าน', async () => {
  const almost = idp.sign(claim('exp', Math.floor(Date.now() / 1000) - 2));
  const p = await verifier().verify(await almost);
  assert.equal(p.subject, 'user-1');
});

test('legacy: ถูกต้อง → Principal; secret/iss ผิดหรือเป็น RS256 → ปฏิเสธ', async () => {
  const legacy = new sdk.LegacyVerifier({
    issuer: 'legacy-svc',
    secret: 's3cr3t',
    clientId: 'legacy-svc-web',
    defaultScopes: ['orders.read'],
  });
  const live = { iss: 'legacy-svc', sub: 'u1', exp: Math.floor(Date.now() / 1000) + 300 };
  const p = legacy.verify(jwt.sign(live, 's3cr3t', { algorithm: 'HS256' }));
  assert.equal(p.subject, 'u1');
  assert.equal(p.clientId, 'legacy-svc-web');
  assert.deepEqual(p.scopes, ['orders.read'], 'token ไม่มี scope → ใช้ defaultScopes');

  assert.throws(() => legacy.verify(jwt.sign(live, 'other', { algorithm: 'HS256' })));
  assert.throws(() =>
    legacy.verify(jwt.sign({ ...live, iss: 'legacy-other' }, 's3cr3t', { algorithm: 'HS256' })),
  );
  const rs256 = await idp.sign(live); // token เดิมแต่เซ็น RS256 — legacy รับ HS256 เท่านั้น
  assert.throws(() => legacy.verify(rs256), /invalid algorithm/);

  // บังคับ exp + sub เหมือน central token และ central/auth-go — token legacy ไร้อายุต้องถูกปฏิเสธ
  assert.throws(() => legacy.verify(jwt.sign({ iss: 'legacy-svc', sub: 'u1' }, 's3cr3t', { algorithm: 'HS256' })), /missing_expiration/);
  assert.throws(() => legacy.verify(jwt.sign({ iss: 'legacy-svc', exp: live.exp }, 's3cr3t', { algorithm: 'HS256' })), /missing_subject/);
});

// requireLegacy — route ที่ยังใช้ guard ของ legacy/dual ต้องได้ guard จริง หรือ fail-fast ตอนโหลด
test('requireLegacy: คืน guard เมื่อเปิด legacy; throw ทันทีเมื่อปิด', () => {
  const central = { issuer: idp.issuer, audience: idp.audience, jwksUrl: idp.jwksUrl };
  const withLegacy = sdk.createAuth({ central, legacy: { issuer: 'legacy-svc', secret: 's3cr3t', clientId: 'c' } });
  const guards = sdk.requireLegacy(withLegacy);
  assert.ok(guards.legacy instanceof sdk.LegacyAuthGuard && guards.dual instanceof sdk.DualAuthGuard);

  const migrationDone = sdk.createAuth({ central }); // ถอด block legacy ไปแล้ว
  assert.throws(() => sdk.requireLegacy(migrationDone), /needs the legacy\/dual guards/);
});

// ── Nest guards: เนื้อหา error 401/403 ต้องตรงตาม contract ──
const response = (e) => e.getResponse();
const ctx = (req, handler = () => {}) => ({
  switchToHttp: () => ({ getRequest: () => req }),
  getHandler: () => handler,
  getClass: () => class Demo {},
});
const bearer = (token) => ({ headers: token ? { authorization: `Bearer ${token}` } : {} });
const expect401 = (promise, code) =>
  assert.rejects(promise, (e) => e instanceof UnauthorizedException && response(e).error === code);

const auth = () =>
  sdk.createAuth({
    central: { issuer: idp.issuer, audience: idp.audience, jwksUrl: idp.jwksUrl },
    legacy: { issuer: 'legacy-svc', secret: 's3cr3t', clientId: 'legacy-svc-web' },
  });
const legacyToken = (secret = 's3cr3t', iss = 'legacy-svc') =>
  jwt.sign({ iss, sub: 'u1', exp: Math.floor(Date.now() / 1000) + 300 }, secret, { algorithm: 'HS256' });

test('guards: ไม่มี legacy option → ไม่มี guard ของ legacy/dual (ปิด path หลัง migration)', () => {
  const { guards } = sdk.createAuth({
    central: { issuer: idp.issuer, audience: idp.audience, jwksUrl: idp.jwksUrl },
  });
  assert.ok(guards.central && guards.scope);
  assert.equal(guards.dual, undefined);
  assert.equal(guards.legacy, undefined);
});

test('CentralAuthGuard + ScopeGuard: 401 / 403 / 200', async () => {
  const { guards } = auth();

  class Orders {
    list() {
      return 'ok';
    }
  }
  sdk.RequireScope('orders.read')(Orders.prototype, 'list', Object.getOwnPropertyDescriptor(Orders.prototype, 'list'));

  // 401 — ไม่มี token / token เสีย / aud อื่น
  await expect401(guards.central.canActivate(ctx(bearer(null), Orders.prototype.list)), 'missing_access_token');
  await expect401(guards.central.canActivate(ctx(bearer('not-a-jwt'), Orders.prototype.list)), 'invalid_access_token');
  await expect401(guards.central.canActivate(ctx(bearer(await idp.sign(claim('aud', 'buyer-api'))), Orders.prototype.list)), 'invalid_access_token');

  // ผ่าน auth แต่ไม่มี scope → 403 พร้อม scope ที่ต้องการ (guard แบบ sync จึงใช้ assert.throws)
  const noScope = bearer(await idp.sign(claim('scope', 'profile')));
  assert.equal(await guards.central.canActivate(ctx(noScope, Orders.prototype.list)), true);
  assert.throws(
    () => guards.scope.canActivate(ctx(noScope, Orders.prototype.list)),
    (e) =>
      e instanceof ForbiddenException &&
      JSON.stringify(response(e)) === JSON.stringify({ error: 'insufficient_scope', required: 'orders.read' }),
  );

  // endpoint ไม่ประกาศ scope → ไม่บังคับ
  assert.equal(await guards.scope.canActivate(ctx(noScope)), true);

  // ผ่านครบ + req.auth ถูกตั้งเป็น Principal
  const ok = bearer(await idp.sign(idp.claims()));
  assert.equal(await guards.central.canActivate(ctx(ok, Orders.prototype.list)), true);
  assert.equal(await guards.scope.canActivate(ctx(ok, Orders.prototype.list)), true);
  assert.deepEqual(ok.auth, {
    subject: 'user-1',
    clientId: 'buyer-web',
    principalType: 'user',
    scopes: ['orders.read'],
    tokenId: null,
    tenantId: null,
    issuer: idp.issuer,
  });
});

test('DualAuthGuard: เลือก validator จาก allowlist — ห้าม fallback', async () => {
  const { guards } = auth();

  // ผ่าน: central และ legacy ใช้ endpoint เดียวกันได้
  const viaCentral = bearer(await idp.sign(idp.claims()));
  assert.equal(await guards.dual.canActivate(ctx(viaCentral)), true);
  assert.equal(viaCentral.auth.subject, 'user-1');
  const viaLegacy = bearer(legacyToken());
  assert.equal(await guards.dual.canActivate(ctx(viaLegacy)), true);
  assert.equal(viaLegacy.auth.clientId, 'legacy-svc-web');

  // ปฏิเสธ: iss นอก allowlist / alg ไม่ตรงโปรไฟล์ของ iss นั้น
  await expect401(guards.dual.canActivate(ctx(bearer(null))), 'missing_access_token');
  await expect401(guards.dual.canActivate(ctx(bearer('not-a-jwt'))), 'unsupported_token');
  await expect401(guards.dual.canActivate(ctx(bearer(await idp.sign(claim('iss', 'https://evil.test'))))), 'unsupported_token');
  await expect401(
    guards.dual.canActivate(ctx(bearer(jwt.sign(idp.claims(), 'x', { algorithm: 'HS256' })))),
    'unsupported_token',
    'iss central ต้องเป็น RS256',
  );
  await expect401(guards.dual.canActivate(ctx(bearer(await idp.sign({ iss: 'legacy-svc', sub: 'u1' })))), 'unsupported_token', 'iss legacy ต้องเป็น HS256');

  // ผ่าน allowlist แต่ verify จริงไม่ผ่าน
  await expect401(guards.dual.canActivate(ctx(bearer(legacyToken('wrong-secret')))), 'invalid_legacy_token');
  await expect401(guards.dual.canActivate(ctx(bearer(await idp.sign(claim('aud', 'buyer-api'))))), 'invalid_access_token');
});

test('LegacyAuthGuard: ใช้ central token ไม่ได้', async () => {
  const { guards } = auth();
  const centralToken = await idp.sign(idp.claims());
  assert.throws(() => guards.legacy.canActivate(ctx(bearer(null))), (e) => response(e).error === 'missing_access_token');
  assert.throws(() => guards.legacy.canActivate(ctx(bearer(centralToken))), (e) => response(e).error === 'invalid_legacy_token');
  assert.equal(await guards.legacy.canActivate(ctx(bearer(legacyToken()))), true);
});
