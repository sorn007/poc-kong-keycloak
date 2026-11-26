// @central/login-js — Login SDK สำหรับแอปในเบราว์เซอร์ (SPA) · ADR-009
//
// OIDC Authorization Code + PKCE (S256) แบบไม่มี dependency (WebCrypto ล้วน)
//   • token อยู่ในหน่วยความจำของ tab เท่านั้น — reload หน้าจะกู้ session ด้วย silent login (prompt=none)
//   • ตรวจ id_token ให้ครบก่อนเชื่อ claims (ลายเซ็น RS256 จาก JWKS ของ issuer, iss, aud, azp, exp, nonce, at_hash)
//   • refresh token rotation + กันใช้ซ้ำ (single-flight) · RP-initiated logout · กัน redirect loop
//
// ใช้งาน (สร้างครั้งเดียวต่อหน้า):
//   const login = createLogin({ issuer, clientId, redirectUri });
//   const result = await login.init();            // จัดการ callback / เก็บ SSO session เงียบ ๆ
//   if (!login.isAuthenticated()) await login.login();
//   await login.updateToken(20);                  // ก่อนเรียก API ทุกครั้ง
//   fetch(api, { headers: { Authorization: `Bearer ${login.getAccessToken()}` } });
import { LoginClient, type LoginEventName, type LoginEventHandler, type LoginOptions, type LoginRedirectOptions, type InitOptions, type InitResult, type TokenInfo, type UserProfile } from './client.js';
import { resolveEnv, type KeyValueStore, type LoginEnv, type LoginEnvOverrides } from './env.js';
export { LoginError, type LoginErrorCode } from './errors.js';

/** Version — รุ่นของ SDK */
export const VERSION = '0.1.0';

/**
 * createLogin — สร้าง client ของหน้านี้
 * @param options issuer / clientId / redirectUri ของแอป
 * @param env แทนที่ส่วนที่ SDK แตะโลกภายนอก (fetch, storage, location, navigation) — สำหรับ test; แอปไม่ต้องส่ง
 */
export function createLogin(options: LoginOptions, env: LoginEnvOverrides = {}): LoginClient {
  return new LoginClient(options, resolveEnv(env));
}

export type {
  LoginOptions,
  LoginRedirectOptions,
  InitOptions,
  InitResult,
  TokenInfo,
  UserProfile,
  LoginEventName,
  LoginEventHandler,
  KeyValueStore,
  LoginEnv,
  LoginEnvOverrides,
};
