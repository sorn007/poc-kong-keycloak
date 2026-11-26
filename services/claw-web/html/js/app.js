// Claw Web — logic ของแอป (vanilla ES module, ไม่มี framework ไม่มี bundler)
// เรื่อง login ทั้งหมดอยู่ใน SDK: หน้านี้มีแค่ "ปุ่ม → login.login()/logout()/updateToken()" และการแสดงผล
//   • token ไม่เคยออกนอก SDK: แอปขอผ่าน getAccessToken() เฉพาะตอนจะเรียก API
//   • ค่าจาก token ถูกแสดงผ่าน textContent หรือ HTML ที่ escape แล้วเท่านั้น
import { createLogin, LoginError } from '/vendor/login-js/index.js';
import { CONFIG } from './config.js';
import { detectLang, t } from './i18n.js';

const REDIRECT_PATH = '/auth/callback';
const API_URL = `${CONFIG.kongUrl}/openapi/oidc/orders`;
const $ = (id) => document.getElementById(id);

// ── ข้อความสองภาษา [ไทย, English] สำหรับ element ที่มี data-i18n ──
const TEXT = {
  brand: ['Claw Web', 'Claw Web'],
  'nav.id': ['Central ID ↗', 'Central ID ↗'],
  'nav.buyer': ['Buyer ↗', 'Buyer ↗'],
  'nav.cis': ['CIS ↗', 'CIS ↗'],
  'hero.title': ['Claw Web', 'Claw Web'],
  'hero.sub': [
    'แอปในเบราว์เซอร์ (SPA) ที่เข้าสู่ระบบด้วย Central ID ผ่าน Login SDK',
    'A browser single-page app that signs in to Central ID through the Login SDK',
  ],
  'hero.btn': ['เข้าสู่ระบบด้วย ID', 'Sign in with ID'],
  'hero.note': [
    'PKCE (S256) · token อยู่ในหน่วยความจำของแท็บนี้เท่านั้น ไม่เขียนลง storage',
    'PKCE (S256) · tokens live only in this tab’s memory and are never written to storage',
  ],
  'how.title': ['ทำงานอย่างไร', 'How it works'],
  'how.1': [
    'SDK สร้าง PKCE (verifier + challenge แบบ S256), state และ nonce แล้วพาไปหน้าเข้าสู่ระบบของ Central ID',
    'The SDK generates PKCE (verifier + S256 challenge), state and nonce, then redirects to the Central ID sign-in page',
  ],
  'how.2': [
    'Keycloak ส่ง authorization code กลับมาที่ /auth/callback — SDK ตรวจ state และ iss ก่อนแลก code ด้วย verifier',
    'Keycloak returns an authorization code to /auth/callback — the SDK checks state and iss before exchanging it with the verifier',
  ],
  'how.3': [
    'SDK ตรวจลายเซ็น id_token (RS256 จาก JWKS), aud, azp, exp และ nonce ก่อนเชื่อ claims',
    'The SDK verifies the id_token signature (RS256 via JWKS), aud, azp, exp and nonce before trusting any claim',
  ],
  'how.4': [
    'เรียก Buyer API ผ่าน Kong ด้วย Bearer token — Kong และ Buyer ตรวจ aud=buyer-api + scope อีกชั้น',
    'Calls the Buyer API through Kong with the Bearer token — Kong and Buyer each check aud=buyer-api and the scope',
  ],
  'profile.title': ['โปรไฟล์', 'Profile'],
  'profile.username': ['ชื่อผู้ใช้', 'Username'],
  'profile.name': ['ชื่อ', 'Name'],
  'profile.note': [
    'จาก id_token ที่ SDK ตรวจลายเซ็นแล้ว (RS256 · iss · aud · azp · nonce)',
    'From the id_token verified by the SDK (RS256 · iss · aud · azp · nonce)',
  ],
  'token.title': ['Access token', 'Access token'],
  'token.expires': ['หมดอายุใน', 'Expires in'],
  'token.seconds': ['วินาที', 'seconds'],
  'token.note': [
    'decode จาก token เพื่อแสดงผลเท่านั้น — ผู้ตรวจจริงคือ API ปลายทาง',
    'Decoded for display only — the API is what actually verifies the token',
  ],
  'api.title': ['เรียก Buyer API ผ่าน Kong', 'Call the Buyer API through Kong'],
  'api.url': ['GET/POST /openapi/oidc/orders', 'GET/POST /openapi/oidc/orders'],
  'api.refresh': ['ต่ออายุ token', 'Refresh token'],
  'logout.btn': ['Logout กลาง', 'Global logout'],
  'logout.note': [
    'จบ SSO session ที่ Keycloak และ Central ID → ทุกแอปต้องเข้าสู่ระบบใหม่',
    'Ends the SSO session at Keycloak and Central ID → every app needs a new sign-in',
  ],
};

// ── ข้อความของ error จาก SDK ──
const ERROR_TEXT = {
  authorization_failed: ['ID ปฏิเสธการเข้าสู่ระบบ', 'The identity provider rejected the sign-in'],
  unrecognized_state: [
    'การกลับมาครั้งนี้ไม่ตรงกับคำขอเข้าสู่ระบบของแท็บนี้ (เริ่มจากแท็บอื่น หรือถูกใช้ไปแล้ว) — กดเข้าสู่ระบบใหม่อีกครั้ง',
    'This sign-in response does not match a request made in this tab (started in another tab, or already used) — sign in again',
  ],
  issuer_mismatch: ['ผู้ออก token ไม่ตรงกับที่กำหนด', 'The token issuer is not the one this app trusts'],
  token_rejected: ['แลก authorization code ไม่สำเร็จ (หมดอายุหรือถูกใช้ไปแล้ว)', 'The authorization code could not be exchanged (expired or already used)'],
  network_error: ['เชื่อมต่อ Keycloak ไม่ได้ — ตรวจ webOrigins ของ client', 'Cannot reach Keycloak — check the client webOrigins'],
  invalid_id_token: ['id_token ไม่ผ่านการตรวจ', 'The id_token did not pass verification'],
  loop_detected: ['ถูกเปลี่ยนหน้าบ่อยเกินไป — รอสักครู่แล้วลองใหม่', 'Too many redirects — wait a moment and try again'],
  storage_unavailable: ['เบราว์เซอร์ไม่อนุญาตให้ใช้ sessionStorage', 'This browser blocks sessionStorage'],
  no_webcrypto: ['เบราว์เซอร์ไม่รองรับ WebCrypto (ต้องเป็น HTTPS หรือ localhost)', 'WebCrypto is not available (HTTPS or localhost is required)'],
  invalid_configuration: ['ตั้งค่าแอปผิด', 'The app is misconfigured'],
};

let lang = 'th';
let login = null;

const show = (id, visible) => $(id).classList.toggle('hidden', !visible);
const escapeHtml = (value) =>
  String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const pills = (values) => values.map((v) => `<span class="pill">${escapeHtml(v)}</span>`).join(' ');
const isSignedOut = (e) => e instanceof LoginError && (e.code === 'not_authenticated' || e.code === 'refresh_rejected');

let toastTimer;
function toast(message) {
  const el = $('toast');
  el.textContent = message;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 2600);
}

function showNotice(error) {
  const entry = ERROR_TEXT[error?.code] ?? ['เกิดข้อผิดพลาด', 'Something went wrong'];
  $('notice').textContent = `${t(lang, entry[0], entry[1])} — ${error?.detail ?? error?.code ?? error}`;
  show('notice', true);
}

function render() {
  for (const el of document.querySelectorAll('[data-i18n]')) {
    const entry = TEXT[el.dataset.i18n];
    if (entry) el.textContent = t(lang, entry[0], entry[1]);
  }
  document.documentElement.lang = lang;
  $('lang-cur').textContent = lang.toUpperCase();
  $('lang-link').textContent = lang === 'en' ? 'TH' : 'EN';
  $('lang-link').href = `?lang=${lang === 'en' ? 'th' : 'en'}`;

  const user = login?.getUser() ?? null;
  const info = login?.getTokenInfo() ?? null;
  show('view-landing', !user);
  show('view-dashboard', !!user);
  show('userchip', !!user);
  if (!user || !info) return;
  $('userchip-name').textContent = user.username ?? user.name ?? user.subject;
  $('p-sub').textContent = user.subject;
  $('p-username').textContent = user.username ?? '—';
  $('p-name').textContent = user.name ?? '—';
  $('p-email').textContent = user.email ?? '—';
  $('t-aud').innerHTML = pills(info.audiences);
  $('t-scope').innerHTML = pills(info.scopes);
  $('t-ptype').textContent = String(info.claims.principal_type ?? '—');
  $('t-tenant').textContent = String(info.claims.tenant_id ?? '—');
  $('t-expires').textContent = String(info.expiresIn);
}

// session หาดระหว่างทาง (refresh ถูกปฏิเสธ): ถ้าเบราว์เซอร์ยังมี SSO session อยู่ ให้กู้กลับมาแบบเงียบ ๆ
// ถ้าไม่มี → init() ของหน้าถัดไปจะคืน login_required และแสดงหน้าเข้าสู่ระบบ
async function recoverOrAskLogin(error) {
  toast(t(lang, 'session หมดอายุ — กำลังกู้กลับ…', 'Your session expired — restoring…'));
  try {
    await login.silentLogin({ returnTo: location.pathname, locale: lang });
  } catch {
    render();
    showNotice(error);
  }
}

async function callApi(method) {
  const out = $('api-out');
  const attempt = async () => {
    // ให้แน่ใจว่า token อายุเหลือมากกว่า 20 วินาที (SDK refresh ให้เองถ้าใกล้หมดอายุ)
    await login.updateToken(20);
    const res = await fetch(API_URL, {
      method,
      headers: { Authorization: `Bearer ${login.getAccessToken()}`, Accept: 'application/json' },
    });
    return { res, body: await res.text() };
  };
  const pretty = (body) => {
    try {
      return JSON.stringify(JSON.parse(body), null, 2);
    } catch {
      return body;
    }
  };
  try {
    let { res, body } = await attempt();
    if (res.status === 401) {
      // token ถูกเพิกถอนฝั่ง server ระหว่างทาง (ยังไม่หมดอายุตามนาฬิกาเครื่อง) → บังคับขอ token ใหม่แล้วลองซ้ำหนึ่งครั้ง
      await login.updateToken(-1);
      ({ res, body } = await attempt());
    }
    out.textContent = `${method} ${API_URL}\nHTTP ${res.status} ${res.statusText}\n\n${pretty(body)}`;
  } catch (e) {
    if (isSignedOut(e)) {
      await recoverOrAskLogin(e);
      return;
    }
    out.textContent = `${method} failed: ${e instanceof Error ? e.message : String(e)}`;
  }
}

async function forceRefresh() {
  try {
    await login.updateToken(-1);
    toast(t(lang, 'ได้ token ใหม่แล้ว', 'Token refreshed'));
    render();
  } catch (e) {
    if (isSignedOut(e)) await recoverOrAskLogin(e);
    else showNotice(e);
  }
}

function boot() {
  const detected = detectLang();
  lang = detected.lang;
  // เอา ?lang= ออกจาก URL (ค่าถูกจำใน cookie แล้ว) — ยกเว้นหน้า callback ซึ่ง SDK จะจัดการ URL เอง
  if (detected.fromQuery && location.pathname !== REDIRECT_PATH) {
    const url = new URL(location.href);
    url.searchParams.delete('lang');
    history.replaceState(history.state, '', url.pathname + url.search + url.hash);
  }

  try {
    login = createLogin({ issuer: CONFIG.issuer, clientId: CONFIG.clientId, redirectUri: `${CONFIG.baseUrl}${REDIRECT_PATH}` });
  } catch (e) {
    showNotice(e);
    render();
    return;
  }

  login.on('signedOut', () => render());
  login.on('tokenRefreshed', () => render());
  $('btn-login').addEventListener('click', () => login.login({ returnTo: '/', locale: lang }).catch(showNotice));
  $('btn-logout').addEventListener('click', () => login.logout({ returnTo: '/' }).catch(showNotice));
  $('btn-api-get').addEventListener('click', () => void callApi('GET'));
  $('btn-api-post').addEventListener('click', () => void callApi('POST'));
  $('btn-refresh').addEventListener('click', () => void forceRefresh());
  setInterval(() => {
    const info = login?.getTokenInfo();
    if (info) $('t-expires').textContent = String(info.expiresIn);
  }, 1000);

  // init: จัดการ callback ถ้า URL มี code/state, ไม่มี session → login เงียบ ๆ ด้วย SSO session ของเบราว์เซอร์
  login.init().then((result) => {
    // login_required = ไม่มี SSO session ในเบราว์เซอร์ — เป็นเรื่องปกติ ไม่ต้องแสดงเป็นข้อผิดพลาด
    if (result.status === 'unauthenticated' && result.error && !String(result.error.detail ?? '').startsWith('login_required')) {
      showNotice(result.error);
    }
    render();
  });
}

boot();
