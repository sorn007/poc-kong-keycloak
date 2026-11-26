import { LoginError } from './errors.js';
import type { LoginEnv } from './env.js';

const JWKS_TTL_MS = 5 * 60 * 1000;

/**
 * JwksClient — ดึง key สำหรับ verify จาก JWKS ของ **issuer ที่กำหนดใน config** เท่านั้น
 * (ไม่มีทางใช้ jku / x5u / kid จาก token ไปสร้าง URL — ตามกฎ allowlist ของ repo)
 * • cache ในหน่วยความจำ 5 นาที · kid ไม่ตรง cache → ดึงใหม่ 1 ครั้ง (รองรับ key rotation)
 * • kid ซ้ำใน JWKS = กำกวม → ไม่ใช้ kid นั้นเลย
 */
export class JwksClient {
  private keys = new Map<string, CryptoKey>();
  private fetchedAt = 0;

  constructor(
    private readonly env: Pick<LoginEnv, 'fetch' | 'now' | 'crypto'>,
    private readonly url: string,
  ) {}

  async verificationKey(kid: string): Promise<CryptoKey> {
    const cached = this.keys.get(kid);
    if (cached && this.env.now() - this.fetchedAt < JWKS_TTL_MS) return cached;
    await this.load();
    const key = this.keys.get(kid);
    if (!key) throw new LoginError('invalid_id_token', 'unknown signing key (kid)');
    return key;
  }

  private async load(): Promise<void> {
    let jwks: unknown;
    try {
      const res = await this.env.fetch(this.url, { headers: { Accept: 'application/json' }, cache: 'no-cache' });
      if (!res.ok) throw new Error(`http ${res.status}`);
      jwks = await res.json();
    } catch (e) {
      throw new LoginError('network_error', 'cannot fetch the JWKS of the configured issuer', e instanceof Error ? e.message : undefined);
    }
    const keys = (jwks as { keys?: unknown } | null)?.keys;
    if (!Array.isArray(keys)) throw new LoginError('invalid_id_token', 'JWKS has no keys');

    const seen = new Set<string>();
    const duplicated = new Set<string>();
    for (const k of keys as Array<Record<string, unknown>>) {
      const kid = k?.kid;
      if (typeof kid === 'string' && seen.has(kid)) duplicated.add(kid);
      if (typeof kid === 'string') seen.add(kid);
    }

    const next = new Map<string, CryptoKey>();
    for (const k of keys as Array<Record<string, unknown>>) {
      if (k?.kty !== 'RSA' || typeof k.kid !== 'string' || typeof k.n !== 'string' || typeof k.e !== 'string' || duplicated.has(k.kid)) continue;
      try {
        next.set(k.kid, await this.env.crypto.importRsaVerifyKey({ kty: 'RSA', kid: k.kid, n: k.n, e: k.e }));
      } catch {
        // key ที่ import ไม่ได้ (เช่นไม่ใช่ RSA มาตรฐาน) = ไม่ใช้
      }
    }
    this.keys = next;
    this.fetchedAt = this.env.now();
  }
}
