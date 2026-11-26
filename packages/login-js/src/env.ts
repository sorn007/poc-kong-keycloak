import { LoginError } from './errors.js';

/** RsaJwk — ส่วนของ JWK ที่ใช้ import เป็น key สำหรับ verify RS256 (รับเฉพาะจาก JWKS ของ issuer ที่กำหนด) */
export interface RsaJwk {
  kty: 'RSA';
  kid: string;
  n: string;
  e: string;
}

/** CryptoPrimitives — primitive ที่ SDK ใช้ (ทั้งหมดมาจาก WebCrypto — ไม่มีการ implement เอง) */
export interface CryptoPrimitives {
  randomBytes(length: number): Uint8Array;
  digest(algorithm: 'SHA-256', data: Uint8Array): Promise<ArrayBuffer>;
  importRsaVerifyKey(jwk: RsaJwk): Promise<CryptoKey>;
  verifyRs256(key: CryptoKey, data: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

/** KeyValueStore — รูปแบบเดียวกับ Storage ของเบราว์เซอร์ (sessionStorage/localStorage หรือตัวจำลองใน test) */
export interface KeyValueStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

/** LocationLike — ส่วนของ location/history ที่ SDK ใช้ */
export interface LocationLike {
  readonly origin: string;
  readonly pathname: string;
  readonly search: string;
  readonly hash: string;
  /** history.replaceState — ใช้ลบ code/state ออกจาก URL หลัง callback */
  replaceState(url: string): void;
}

/**
 * LoginEnv — ทุกอย่างที่ SDK แตะของโลกภายนอก (fetch, นาฬิกา, storage, location, navigation, crypto)
 * แอปไม่ต้องจัดหาเอง (ใช้ค่าของเบราว์เซอร์) — แทนที่ได้ผ่านพารามิเตอร์ที่สองของ createLogin() เพื่อใช้ใน test
 */
export interface LoginEnv {
  fetch(input: string, init?: RequestInit): Promise<Response>;
  /** มิลลิวินาทีตามนาฬิกาเครื่อง */
  now(): number;
  transactionStore: KeyValueStore;
  location: LocationLike;
  /** เปลี่ยนหน้าแบบ top-level navigation */
  navigate(url: string): void;
  crypto: CryptoPrimitives;
}

export type LoginEnvOverrides = Partial<Omit<LoginEnv, 'fetch' | 'crypto'>> & {
  fetch?: (input: string, init?: RequestInit) => Promise<Response>;
  crypto?: Partial<CryptoPrimitives>;
};

// webcryptoPrimitives — crypto.subtle มีเฉพาะใน secure context (HTTPS หรือ localhost)
// ถ้าไม่มี: throw — SDK ไม่ลดลงไปใช้ Math.random หรือข้ามการตรวจลายเซ็น
export function webcryptoPrimitives(): CryptoPrimitives {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new LoginError('no_webcrypto', 'WebCrypto (crypto.subtle) is not available — a secure context (HTTPS or localhost) is required');
  }
  return {
    randomBytes: (length) => globalThis.crypto.getRandomValues(new Uint8Array(length)),
    digest: (algorithm, data) => subtle.digest(algorithm, data as BufferSource),
    importRsaVerifyKey: (jwk) =>
      subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']),
    verifyRs256: (key, data, signature) => subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, signature as BufferSource, data as BufferSource),
  };
}

function defaultSessionStorage(): KeyValueStore {
  try {
    if (typeof globalThis !== 'undefined' && globalThis.sessionStorage) return globalThis.sessionStorage;
  } catch {
    /* Safari private mode โยน exception ตอนแตะ sessionStorage */
  }
  throw new LoginError('storage_unavailable', 'sessionStorage is not available in this browser context');
}

function browserLocation(): LocationLike {
  return {
    get origin() {
      return globalThis.location.origin;
    },
    get pathname() {
      return globalThis.location.pathname;
    },
    get search() {
      return globalThis.location.search;
    },
    get hash() {
      return globalThis.location.hash;
    },
    replaceState: (url) => globalThis.history.replaceState(globalThis.history.state, '', url),
  };
}

// resolveEnv — เติมส่วนที่แอปไม่ได้ override ด้วยค่าของเบราว์เซอร์
export function resolveEnv(overrides: LoginEnvOverrides = {}): LoginEnv {
  const transactionStore = overrides.transactionStore ?? defaultSessionStorage();
  const location = overrides.location ?? browserLocation();
  return {
    // ห้ามส่ง globalThis.fetch ตรง ๆ (บางเบราว์เซอร์ต้องเรียกด้วย this = window)
    fetch: overrides.fetch ?? ((input, init) => globalThis.fetch(input, init)),
    now: overrides.now ?? (() => Date.now()),
    transactionStore,
    location,
    navigate: overrides.navigate ?? ((url) => globalThis.location.assign(url)),
    crypto: { ...webcryptoPrimitives(), ...overrides.crypto },
  };
}
