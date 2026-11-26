const { test } = require('node:test');
const assert = require('node:assert/strict');
const sdk = require('../dist');
const { newServer } = require('./_support/idp');

const H = sdk.GATEWAY_HEADERS;

// Gateway-trust: เชื่อ header ของ Kong ได้ก็ต่อเมื่อ shared secret ตรงเท่านั้น
test('verifyGatewayTrust: ตรวจ secret แบบ constant-time + แตก scope จาก header', () => {
  const headers = {
    [H.auth]: 'gw-secret',
    [H.scopes]: 'orders.read, orders.write',
    [H.owner]: 'buyer-user',
  };
  assert.deepEqual(sdk.verifyGatewayTrust(headers, 'gw-secret'), {
    owner: 'buyer-user',
    scopes: ['orders.read', 'orders.write'],
  });
  assert.equal(sdk.verifyGatewayTrust(headers, 'wrong-secret'), null);
  assert.equal(sdk.verifyGatewayTrust({ [H.scopes]: 'orders.read' }, 'gw-secret'), null, 'ไม่มี header gateway');
  assert.equal(sdk.verifyGatewayTrust(headers, undefined), null, 'ยังไม่ตั้ง secret ฝั่ง service → fail-closed');
  assert.deepEqual(sdk.verifyGatewayTrust({ [H.auth]: 'gw-secret' }, 'gw-secret'), { owner: '', scopes: [] });
});

// Ticket liveness: ตั๋วตายต้อง propagate logout; ตรวจไม่ได้ → fail-open (default) / fail-closed (เมื่อตั้ง)
test('TicketGuard: alive / dead / fail-open / fail-closed', async (t) => {
  const broker = await newServer((req, form, res) => {
    if (req.url !== '/sso/check') return res.writeHead(404).end();
    res.writeHead(200, { 'content-type': 'application/json' });
    if (form.get('ticket') === 't-alive') return res.end('{"alive":true}');
    if (form.get('ticket') === 't-dead') return res.end('{"alive":false}');
    res.end('not json');
  });
  const slow = await newServer(() => {}); // ไม่ตอบ — ใช้ทดสอบ timeout
  t.after(async () => {
    await broker.close();
    slow.close();
  });

  const guard = new sdk.TicketGuard({ brokerUrl: broker.url + '/' }); // trailing slash ต้องไม่ทำให้ URL พัง
  assert.equal(await guard.isAlive('t-alive'), true);
  assert.equal(await guard.isAlive('t-dead'), false, 'ตั๋วถูก revoke → session ต้องตาย');
  assert.equal(await guard.isAlive(''), true, 'session ไม่ได้ผูกตั๋ว → ไม่ตรวจ');

  const strict = (options) => new sdk.TicketGuard({ failOpen: false, ...options });
  assert.equal(await strict({ brokerUrl: broker.url }).isAlive('t-broken'), false, 'format เพี้ยน');
  assert.equal(await strict({ brokerUrl: broker.url + '/nope' }).isAlive('t-alive'), false, '404');
  assert.equal(await strict({ brokerUrl: 'http://127.0.0.1:1' }).isAlive('t-alive'), false, 'broker ล่ม');
  assert.equal(await strict({ brokerUrl: slow.url, timeoutMs: 50 }).isAlive('t-alive'), false, 'timeout');
  assert.equal(await new sdk.TicketGuard({ brokerUrl: 'http://127.0.0.1:1' }).isAlive('t-alive'), true, 'default: fail-open');
});

test('sessionCookieNames / clearSessionCookies: ชุด cookie เดียวกันทุกจุดของแอป', () => {
  assert.deepEqual(sdk.sessionCookieNames('buyer'), [
    'buyer_session',
    'buyer_id_token',
    'sso_bound',
    'sso_try_buyer',
    'central_sso',
  ]);
  const cleared = [];
  sdk.clearSessionCookies({ clearCookie: (name) => cleared.push(name) }, 'cis');
  assert.deepEqual(cleared, sdk.sessionCookieNames('cis'));
  assert.ok(cleared.includes('cis_id_token'), 'ต้องเคลียร์ id_token ด้วย (ไม่ให้หน้าหนึ่งค้าง)');
});

// Central API Key: fail-closed — ตรวจไม่ได้/ไม่ active → null
test('ApiKeyVerifier: extractKey + verify', async (t) => {
  const portal = await newServer((req, form, res) => {
    if (req.url !== '/apikeys/validate') return res.writeHead(404).end();
    res.writeHead(200, { 'content-type': 'application/json' });
    if (form.get('key') === 'central_good') return res.end('{"active":true,"owner":"buyer-user","scopes":["orders.read"]}');
    if (form.get('key') === 'central_noowner') return res.end('{"active":true}');
    res.end('{"active":false}');
  });
  t.after(() => portal.close());

  const v = new sdk.ApiKeyVerifier({ validationUrl: `${portal.url}/apikeys/validate` });
  assert.equal(v.extractKey({ apikey: 'central_good' }), 'central_good');
  assert.equal(v.extractKey({ authorization: 'Bearer central_good' }), 'central_good');
  assert.equal(v.extractKey({ authorization: 'Bearer eyJhbGciOi...' }), undefined, 'Bearer JWT ปกติไม่ใช่ API key');
  assert.equal(v.extractKey({}), undefined);

  assert.deepEqual(await v.verify('central_good'), { owner: 'buyer-user', scopes: ['orders.read'] });
  assert.equal(await v.verify('central_revoked'), null, 'key ถูก revoke');
  assert.equal(await v.verify('central_noowner'), null, 'active แต่ไม่มี owner');
  assert.equal(await v.verify(undefined), null);
  const broken = new sdk.ApiKeyVerifier({ validationUrl: `${portal.url}/nope` });
  assert.equal(await broken.verify('central_good'), null, 'endpoint ตอบ 404 → fail-closed');
  assert.equal(
    await new sdk.ApiKeyVerifier({ validationUrl: 'http://127.0.0.1:1/apikeys/validate' }).verify('central_good'),
    null,
    'ID Portal ล่ม → fail-closed',
  );
});

test('SDK version ถูกประกาศให้ service log ตอน startup', () => {
  assert.match(sdk.VERSION, /^\d+\.\d+\.\d+$/);
});
