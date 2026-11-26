import * as jwt from 'jsonwebtoken';
import type { Principal } from './principal';

export interface LegacyVerifierOptions {
  /** iss ของ legacy token ของ service นี้ */
  issuer: string;
  /** shared secret ที่ service เดิมใช้เซ็น JWT (env แบบ LEGACY_<SERVICE>_JWT_SECRET) */
  secret: string;
  /** clientId ที่รายงานใน Principal (legacy token ไม่มี azp) */
  clientId: string;
  /** scope ที่ถือว่ามี ในกรณี token เดิมไม่มี claim scope */
  defaultScopes?: string[];
}

/**
 * LegacyVerifier — ตรวจ token ที่ service ออกเองด้วย shared secret (HS256)
 * ใช้เฉพาะช่วง migration (Dual Validation) — ปิดได้ด้วยการไม่ส่ง `legacy` ให้ createAuth
 */
export class LegacyVerifier {
  /** ค่า iss ของ legacy token — DualAuthGuard ใช้เป็น allowlist ในการเลือก validator */
  readonly issuer: string;

  constructor(private readonly options: LegacyVerifierOptions) {
    this.issuer = options.issuer;
  }

  verify(token: string): Principal {
    const payload = jwt.verify(token, this.options.secret, {
      algorithms: ['HS256'],
    }) as jwt.JwtPayload;

    if (payload.iss !== this.options.issuer) {
      throw new Error('legacy_issuer_mismatch');
    }
    // บังคับ exp + sub เช่นเดียวกับ central token และกับ central/auth-go (WithExpirationRequired):
    // jsonwebtoken ตรวจ exp เฉพาะเมื่อมี — token legacy ที่ไม่มี exp = ไม่มีวันหมดอายุ
    if (typeof payload.exp !== 'number') {
      throw new Error('missing_expiration');
    }
    if (typeof payload.sub !== 'string' || !payload.sub) {
      throw new Error('missing_subject');
    }

    return {
      subject: payload.sub,
      clientId: this.options.clientId,
      principalType: 'user',
      scopes:
        typeof payload.scope === 'string'
          ? payload.scope.split(' ')
          : (this.options.defaultScopes ?? []),
      tokenId: payload.jti ?? null,
      tenantId: payload.tenant_id ?? null,
      issuer: payload.iss,
    };
  }
}
