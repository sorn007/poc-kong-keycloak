// ตัวช่วยสำหรับ unit test ของ @central/login-js
// • newIdP: IdP จำลอง — RSA key เซ็น JWT ด้วย WebCrypto จริง (SDK จึง verify ด้วย WebCrypto จริงเช่นกัน)
// • createWorld: แทนที่ทุกอย่างที่ SDK แตะโลกภายนอก (storage, location, navigation, fetch, นาฬิกา) ด้วยของจำลอง
//   นาฬิกาเป็นค่าตายตัวและเดินหน้าด้วย world.tick() เท่านั้น — test ไม่ขึ้นกับเวลาจริง
import { createHash, generateKeyPairSync, webcrypto } from 'node:crypto';
import * as sdk from '../../dist/index.js';

export const ISSUER = 'http://localhost:8080/realms/central';
export const CLIENT_ID = 'claw-web';
export const REDIRECT_URI = 'http://localhost:3060/auth/callback';
export const TXN_KEY = 'central-login.transaction';
export const GUARD_KEY = 'central-login.guard';
export const SESSION_KEY = 'central-login.session';

const b64url = (buffer) => Buffer.from(buffer).toString('base64url');
const settled = () => new Promise((resolve) => setImmediate(resolve));

/** atHash — at_hash ตาม OIDC Core 3.1.3.6 (SHA-256 ครึ่งซ้ายของ access token) */
export const atHash = (accessToken) => b64url(createHash('sha256').update(accessToken).digest().subarray(0, 16));

export async function newIdP(kid = 'test-key-1') {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const signKey = await webcrypto.subtle.importKey('jwk', privateKey.export({ format: 'jwk' }), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  return {
    kid,
    jwks: { keys: [{ ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' }] },
    async signJwt(payload, header = { alg: 'RS256', kid }) {
      const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
      const signature = await webcrypto.subtle.sign('RSASSA-PKCS1-v1_5', signKey, Buffer.from(signingInput));
      return `${signingInput}.${b64url(signature)}`;
    },
  };
}

export function memoryStorage() {
  const map = new Map();
  return {
    getItem: (key) => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => void map.set(key, String(value)),
    removeItem: (key) => void map.delete(key),
    // dump — ให้ test ตรวจได้ว่าไม่มี token หลุดเข้า storage
    dump: () => Object.fromEntries(map),
  };
}

const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

export function createWorld({ idp, path = '/', search = '', storage = memoryStorage() } = {}) {
  let clock = 1_800_000_000_000; // ค่าตายตัว (2027-01-15T08:00:00Z)
  const calls = { navigate: [], replaceState: [], token: [], jwks: 0 };
  const location = {
    origin: 'http://localhost:3060',
    pathname: path,
    search,
    hash: '',
    replaceState(url) {
      calls.replaceState.push(url);
      const next = new URL(url, this.origin);
      this.pathname = next.pathname;
      this.search = next.search;
      this.hash = next.hash;
    },
  };
  // routes: คำตอบของ token endpoint เรียงคิว — หมดคิวแล้ว = 400 invalid_grant
  //   { body, status? } · { networkError: true } = fetch โยน (เหมือน CORS ไม่ผ่าน) · { gate: Promise } = รอก่อนตอบ
  const routes = [];
  const fetch = async (url, init = {}) => {
    if (url.endsWith('/protocol/openid-connect/certs')) {
      calls.jwks += 1;
      return jsonResponse(idp.jwks);
    }
    calls.token.push(Object.fromEntries(new URLSearchParams(init.body)));
    const route = routes.shift();
    if (!route) return jsonResponse({ error: 'invalid_grant', error_description: 'no scripted response' }, 400);
    if (route.gate) await route.gate;
    if (route.networkError) throw new TypeError('Failed to fetch');
    return jsonResponse(route.body, route.status ?? 200);
  };
  return {
    env: { transactionStore: storage, location, now: () => clock, fetch, navigate: (url) => calls.navigate.push(url) },
    calls,
    routes,
    storage,
    location,
    now: () => clock,
    tick: (ms) => {
      clock += ms;
    },
  };
}

let refreshCounter = 0;

/** makeTokens — คำตอบของ token endpoint ที่ถูกต้องทุกเงื่อนไข (override ฟิลด์ที่จะทดสอบว่าถูกปฏิเสธ) */
export async function makeTokens(idp, world, { nonce = 'n-1', expiresIn = 300, access = {}, id = {}, signer, refreshToken } = {}) {
  const at = Math.floor(world.now() / 1000);
  const accessToken = await idp.signJwt({
    iss: ISSUER, sub: 'user-1', aud: 'buyer-api', azp: CLIENT_ID, scope: 'openid orders.read',
    principal_type: 'user', iat: at, exp: at + 300, ...access,
  });
  const idToken = await (signer ?? idp).signJwt({
    iss: ISSUER, sub: 'user-1', aud: CLIENT_ID, azp: CLIENT_ID, nonce, iat: at, exp: at + 300,
    preferred_username: 'buyer-user', email: 'buyer@example.test', at_hash: atHash(accessToken), ...id,
  });
  // refreshToken = null → OP ไม่ออก refresh token (เช่น public client ที่ไม่ใช้ PKCE บางตัว)
  return { access_token: accessToken, refresh_token: refreshToken === null ? undefined : `rt-${++refreshCounter}`, id_token: idToken, expires_in: expiresIn, token_type: 'Bearer' };
}

export function newClient(world, options = {}) {
  return sdk.createLogin({ issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, ...options }, world.env);
}

// waitForNavigate — รอจนมี navigation ใหม่ หรือ action โยน error ก่อน (ถ้าโยน = โยนต่อให้ test เห็น)
// ห้ามนับจำนวน tick ตายตัว: crypto.subtle ใช้เวลาไม่แน่นอน การอ่าน URL ก่อน navigate จะได้คำตอบผิดเป็นพัก ๆ
async function waitForNavigate(world, action) {
  const before = world.calls.navigate.length;
  let failure;
  action.catch((e) => void (failure = e));
  for (let i = 0; i < 5000; i += 1) {
    if (failure) throw failure;
    if (world.calls.navigate.length > before) return new URL(world.calls.navigate.at(-1)).searchParams;
    await settled();
  }
  throw new Error('no navigation happened');
}

/** startLogin — เรียก login() แล้วคืน query ของ URL ที่ navigate ไป (state, nonce, code_challenge, …) */
export function startLogin(world, client, options = {}) {
  return waitForNavigate(world, client.login(options));
}

/** navigateParams — คืน query ของ URL ที่ action (เช่น silentLogin/logout) navigate ไป */
export function navigateParams(world, action) {
  return waitForNavigate(world, action);
}

/** arrive — จำลอง OP redirect กลับมาที่ redirect URI ของ "หน้าใหม่" แล้ว init() หน้านั้น */
export async function arrive(world, params, initOptions = { silent: false }, clientOptions = {}) {
  world.location.pathname = '/auth/callback';
  world.location.hash = '';
  world.location.search = `?${new URLSearchParams(params).toString()}`;
  const page = newClient(world, clientOptions);
  return { page, result: await page.init(initOptions) };
}

/** signIn — happy path ทั้ง flow: login() → callback → token → คืน client ที่ login แล้ว */
export async function signIn(world, idp, { returnTo, tokens, clientOptions } = {}) {
  const params = await startLogin(world, newClient(world), { returnTo });
  const issued = await makeTokens(idp, world, { nonce: params.get('nonce'), ...tokens });
  world.routes.push({ body: issued });
  const { page, result } = await arrive(world, { code: 'authz-123', state: params.get('state'), iss: ISSUER }, { silent: false }, clientOptions);
  return { page, result, params, issued };
}

/** tamperSignature — แก้ "ตัวแรก" ของ signature (ตัวท้ายของ base64url มี padding bits ที่ decoder ไม่ตรวจ แก้แล้วค่าอาจไม่เปลี่ยน) */
export function tamperSignature(jwt) {
  const [h, p, s] = jwt.split('.');
  return `${h}.${p}.${s[0] === 'A' ? 'B' : 'A'}${s.slice(1)}`;
}
