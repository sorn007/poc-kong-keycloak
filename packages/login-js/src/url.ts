// จัดการ URL ของ callback และ returnTo ให้ปลอดภัย (กัน open redirect / กันวน callback)
const OIDC_PARAMS = ['code', 'state', 'iss', 'nonce', 'error', 'error_description', 'error_uri', 'session_state'];
const REDIRECT_PATH = '/auth/callback';

export interface CallbackParams {
  code?: string;
  state?: string;
  iss?: string;
  error?: string;
  error_description?: string;
}

export function parseCallbackParams(search: string): CallbackParams {
  const params = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search);
  const one = (name: string): string | undefined => {
    const value = params.get(name);
    return value === null ? undefined : value;
  };
  return {
    code: one('code'),
    state: one('state'),
    iss: one('iss'),
    error: one('error'),
    error_description: one('error_description'),
  };
}

/**
 * sanitizeReturnTo — returnTo ต้องเป็น "path ในแอปเดียวกัน" เท่านั้น
 * • กัน open redirect (https://evil, //evil, /\evil)
 * • ตัดพารามิเตอร์ OIDC ทิ้ง — กัน URL ของ callback ที่มี code ถูกเก็บไว้แล้ววนกลับมา
 * • path ของ redirect URI เอง → เปลี่ยนเป็น /
 * ค่าที่ไม่ผ่านทั้งหมด → '/'
 */
export function sanitizeReturnTo(value: unknown): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.length > 2048 || /[\r\n\\]/.test(value)) {
    return '/';
  }
  const base = 'http://return-to.invalid';
  const url = new URL(value, base);
  if (url.origin !== base) return '/';
  for (const name of OIDC_PARAMS) url.searchParams.delete(name);
  const path = url.pathname === REDIRECT_PATH ? '/' : url.pathname;
  const search = url.searchParams.toString();
  const hash = /[?&](code|state|error)=/.test(url.hash) ? '' : url.hash;
  return path + (search ? `?${search}` : '') + hash;
}

/** currentPath — path + query + hash ปัจจุบัน (ใช้เป็น returnTo เริ่มต้น) */
export function currentPath(location: { pathname: string; search: string; hash: string }): string {
  return location.pathname + location.search + location.hash;
}
